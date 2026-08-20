from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "claude-plugin" / "agentic-fuzz-engine"
VENDOR = PLUGIN / "vendor"
ENGINE_ENV = PLUGIN / "scripts" / "engine-env.sh"


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_snapshot(root: Path) -> dict[Path, str]:
    return {path.relative_to(root): _hash(path) for path in root.rglob("*") if path.is_file()}


class PluginReleaseTests(unittest.TestCase):
    def test_vendor_is_a_bidirectional_exact_python_source_snapshot(self) -> None:
        self.assertEqual([path for path in VENDOR.rglob("*") if path.is_file() and path.suffix != ".py"], [])
        for package in ("agentic_fuzz_engine", "agentic_fuzz_full"):
            canonical = {path.relative_to(ROOT / "src" / package): path for path in (ROOT / "src" / package).rglob("*.py")}
            vendored = {path.relative_to(VENDOR / package): path for path in (VENDOR / package).rglob("*.py")}
            self.assertEqual(set(vendored), set(canonical), package)
            for relative, source in canonical.items():
                self.assertEqual(_hash(vendored[relative]), _hash(source), f"{package}/{relative}")

    def test_clean_cache_mcp_uses_only_vendored_modules_and_external_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            installed = tmp_root / "plugin"
            tracked = subprocess.check_output(
                ["git", "ls-files", "-z", "--", "claude-plugin/agentic-fuzz-engine"], cwd=ROOT
            ).decode().split("\0")
            for raw in filter(None, tracked):
                source = ROOT / raw
                destination = installed / Path(raw).relative_to("claude-plugin/agentic-fuzz-engine")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)

            installed_before = _tree_snapshot(installed)
            temporary_before = _tree_snapshot(tmp_root)

            data_root = tmp_root / "external-state"
            env = {"PATH": os.environ["PATH"], "CLAUDE_PLUGIN_DATA": str(data_root)}
            for key in ("HOME", "PYTHONPATH", "AGENTIC_FUZZ_ENGINE_ROOT", "AGENTIC_FUZZ_PLUGIN_ROOT", "XDG_STATE_HOME"):
                env.pop(key, None)
            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "runtime_backend_status", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "engine_parity_audit", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "campaign_start", "arguments": {"target": "clean-cache", "name": "clean-cache"}}},
                {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "campaign_status", "arguments": {"run_id": "clean-cache"}}},
                {
                    "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                    "params": {
                        "name": "candidate_scoring",
                        "arguments": {
                            "action": "calibrate",
                            "labels": [
                                {"score": 0.8, "positive": True},
                                {"score": 0.2, "positive": False},
                            ],
                        },
                    },
                },
                {
                    "jsonrpc": "2.0", "id": 8, "method": "tools/call",
                    "params": {
                        "name": "campaign_db",
                        "arguments": {"action": "sync", "workspace_root": str(data_root / "workspace")},
                    },
                },
            ]
            process = subprocess.run(
                ["bash", str(installed / "scripts" / "mcp-server.sh")],
                cwd=tmp_root,
                env=env,
                input="".join(json.dumps(item) + "\n" for item in requests),
                text=True,
                capture_output=True,
                check=True,
                timeout=30,
            )
            responses = [json.loads(line) for line in process.stdout.splitlines()]
            self.assertEqual(responses[0]["result"]["serverInfo"]["name"], "agentic-fuzz-engine")
            tool_names = {item["name"] for item in responses[1]["result"]["tools"]}
            self.assertIn("engine_parity_audit", tool_names)
            self.assertTrue(
                {
                    "fork_scan", "entry_scan", "differential_run", "sanitizer_build",
                    "sanitizer_sweep", "candidate_scoring", "campaign_db",
                    "schedule_plan", "campaign_context",
                }.issubset(tool_names)
            )
            backend_status = json.loads(responses[2]["result"]["content"][0]["text"])
            self.assertIn("groups", backend_status)
            parity = json.loads(responses[3]["result"]["content"][0]["text"])
            self.assertTrue(parity["ok"], parity["blockers"])
            campaign = json.loads(responses[4]["result"]["content"][0]["text"])
            campaign_status = json.loads(responses[5]["result"]["content"][0]["text"])
            calibration = json.loads(responses[6]["result"]["content"][0]["text"])
            database = json.loads(responses[7]["result"]["content"][0]["text"])
            self.assertEqual(campaign["run_id"], "clean-cache")
            self.assertEqual(campaign_status["campaign"]["run_id"], "clean-cache")
            self.assertTrue(calibration["ok"], calibration)
            self.assertTrue(database["ok"], database)
            vendor = (installed / "vendor").resolve()
            for path in parity["module_paths"].values():
                self.assertTrue(Path(path).resolve().is_relative_to(vendor), path)
            self.assertTrue(data_root.is_dir())
            self.assertEqual(_tree_snapshot(installed), installed_before)
            temporary_after = _tree_snapshot(tmp_root)
            changed = {
                path
                for path in set(temporary_before) | set(temporary_after)
                if temporary_before.get(path) != temporary_after.get(path)
            }
            self.assertTrue(changed)
            self.assertTrue(all(path.is_relative_to(Path("external-state")) for path in changed), changed)

    def test_engine_env_discovers_future_python_and_rejects_invalid_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = Path(tmp) / "bin"
            fake_bin.mkdir()
            for name, status in (("python3.9", 1), ("python3.14", 0)):
                path = fake_bin / name
                path.write_text(f"#!/bin/sh\nif [ \"$1\" = \"-c\" ]; then exit {status}; fi\nexit 99\n", encoding="utf-8")
                path.chmod(0o755)
            env = {"PATH": f"{fake_bin}:{os.defpath}", "CLAUDE_PLUGIN_ROOT": str(PLUGIN)}
            selected = subprocess.run(
                ["bash", "-c", 'source "$1"; printf "%s" "$python_bin"', "bash", str(ENGINE_ENV)],
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertEqual(Path(selected.stdout).name, "python3.14")

            invalid = subprocess.run(
                ["bash", "-c", 'source "$1"', "bash", str(ENGINE_ENV)],
                env={**env, "AGENTIC_FUZZ_PYTHON": "python3.9"},
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("AGENTIC_FUZZ_PYTHON must refer to Python 3.11 or newer", invalid.stderr)

    def test_runtime_guard_allows_mentions_but_denies_invocation_forms(self) -> None:
        spec = importlib.util.spec_from_file_location("runtime_guard", PLUGIN / "scripts" / "runtime-guard.py")
        assert spec is not None and spec.loader is not None
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        self.assertFalse(guard.command_is_blocked("rg external_runtime.py docs"))
        self.assertFalse(guard.command_is_blocked("grep external_runtime.py docs"))
        self.assertFalse(guard.command_is_blocked("command -v external_runtime.py"))
        self.assertFalse(guard.command_is_blocked("command -V external_runtime.py"))
        self.assertFalse(guard.command_is_blocked("command -pv external_runtime.py"))
        self.assertFalse(guard.command_is_blocked("command -v -- external_runtime.py"))
        self.assertFalse(guard.command_is_blocked("command -V -- external_runtime.py"))
        self.assertFalse(guard.command_is_blocked("command -pv -- external_runtime.py"))
        self.assertFalse(guard.command_is_blocked("echo runtime-userspace/docker-run.py"))
        self.assertFalse(guard.command_is_blocked("python3 -c 'print(\"external_runtime.py\")'"))
        self.assertFalse(guard.command_is_blocked("python3 -m example.external_runtime.py"))
        for command in (
            "external_runtime.py",
            "python3 external_runtime.py",
            "env python3 external_runtime.py",
            "/usr/bin/env python3 external_runtime.py",
            "command python3 external_runtime.py",
            "bash -lc 'python3 external_runtime.py'",
            "bash -c 'python3 external_runtime.py'",
            "sh runtime-userspace/docker-run.py",
            "sh /checkout/runtime-multilang/run.py",
            "python3 external_runtime.py; true",
            "sudo -u root python3 external_runtime.py",
            "nice -n 5 python3 external_runtime.py",
            "timeout 10 python3 external_runtime.py",
            "timeout --signal KILL 10 python3 external_runtime.py",
            "timeout -s KILL 10 python3 external_runtime.py",
            "setsid python3 external_runtime.py",
            "xargs -n 1 python3 external_runtime.py",
            "xargs --process-slot-var SLOT python3 external_runtime.py",
            "true && python3 external_runtime.py",
            "true; python3 external_runtime.py",
            "true\npython3 external_runtime.py",
            "true | python3 external_runtime.py",
            "command -- python3 external_runtime.py",
            "command python3 -v external_runtime.py",
            "command -- python3 -v external_runtime.py",
            "sh -eu runtime-userspace/docker-run.py",
            "sh -c 'true; python3 external_runtime.py'",
            "bash --norc -c 'python3 external_runtime.py'",
            "bash --rcfile /dev/null -c 'python3 external_runtime.py'",
            "sudo -D /tmp python3 external_runtime.py",
            "sudo --chdir /tmp python3 external_runtime.py",
            ">/tmp/log python3 external_runtime.py",
            "2>/dev/null python3 external_runtime.py",
            "{ python3 external_runtime.py; }",
            "exec python3 external_runtime.py",
            'echo "$(python3 external_runtime.py)"',
            "echo $(python3 external_runtime.py)",
            "echo `python3 external_runtime.py`",
            'echo "`python3 external_runtime.py`"',
        ):
            self.assertTrue(guard.command_is_blocked(command), command)

        self.assertTrue(guard.command_is_blocked("python3 external_runtime.py 'unterminated"))
        self.assertTrue(guard.command_is_blocked("bash -c 'python3 /x/runtime-multilang/run.py"))

        for command in (
            'echo "$(printf external_runtime.py',
            'rg "$(printf external_runtime.py',
            "echo `printf external_runtime.py",
            "rg `printf external_runtime.py",
        ):
            self.assertFalse(guard.command_is_blocked(command), command)
        for value in (None, [], {}, 0, 1.5, b"external_runtime.py"):
            self.assertFalse(guard.command_is_blocked(value), repr(value))

        payload = json.dumps({"tool_input": {"command": "env python3 external_runtime.py"}})
        result = subprocess.run(
            ["bash", str(PLUGIN / "scripts" / "runtime-guard.sh")],
            input=payload,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

        def hook(raw: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["bash", str(PLUGIN / "scripts" / "runtime-guard.sh")],
                input=raw,
                text=True,
                capture_output=True,
                check=False,
            )

        for raw in (
            "{",
            "[]",
            "null",
            '"text"',
            "17",
            "{}",
            json.dumps({"tool_input": []}),
            json.dumps({"tool_input": None}),
            json.dumps({"tool_input": "invalid"}),
            json.dumps({"tool_input": {"command": []}}),
            json.dumps({"tool_input": {"command": None}}),
            json.dumps({"tool_input": {"command": 17}}),
            json.dumps({"tool_input": {"command": "command -v external_runtime.py"}}),
            json.dumps({"tool_input": {"command": "command -v -- external_runtime.py"}}),
            json.dumps({"tool_input": {"command": "command -V -- external_runtime.py"}}),
            json.dumps({"tool_input": {"command": "command -pv -- external_runtime.py"}}),
            json.dumps({"tool_input": {"command": 'echo "$(printf external_runtime.py'}}),
            json.dumps({"tool_input": {"command": "echo `printf external_runtime.py"}}),
        ):
            response = hook(raw)
            self.assertEqual(response.returncode, 0, raw)
            self.assertEqual(response.stdout, "", raw)

        for command in (
            "command python3 -v external_runtime.py",
            "command -- python3 -v external_runtime.py",
            "bash -c 'python3 /x/runtime-multilang/run.py",
        ):
            response = hook(json.dumps({"tool_input": {"command": command}}))
            self.assertEqual(response.returncode, 0, command)
            self.assertEqual(json.loads(response.stdout)["hookSpecificOutput"]["permissionDecision"], "deny", command)

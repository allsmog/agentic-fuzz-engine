from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.asan import parse_asan_signal
from agentic_fuzz_engine.engine import AgenticFuzzEngine
from agentic_fuzz_engine.fidelity import (
    DEFAULT_REFERENCE_ROOT,
    discover_reference_benchmarks,
    load_target_profile,
    resolve_reference_root,
    validate_reference_fixtures,
)
from agentic_fuzz_engine.guardrails import audit_runtime_guard_runtime_calls
from agentic_fuzz_engine.mcp_stdio import AgenticFuzzMcpServer
from agentic_fuzz_engine.parity import audit_engine_parity


class AgenticFuzzEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        if not DEFAULT_REFERENCE_ROOT.exists():
            self.skipTest(f"Benchmark fidelity fixture root is absent: {DEFAULT_REFERENCE_ROOT}")

    def test_discovers_local_reference_fixture_fidelity_corpus(self) -> None:
        all_benchmarks = discover_reference_benchmarks(include_disabled=True)
        enabled = discover_reference_benchmarks(include_disabled=False)

        self.assertEqual(len(all_benchmarks), 16)
        self.assertEqual(len(enabled), 14)
        self.assertEqual({item.project for item in all_benchmarks if item.disabled_project}, {"libexpat", "swftools"})
        self.assertIn(("binutils", "fixture_5", "fuzz_disassemble"), {(b.project, b.fixture, b.harness) for b in all_benchmarks})
        self.assertTrue(all(item.patch_valid for item in all_benchmarks))
        self.assertTrue(all(item.patch_sha256 for item in all_benchmarks))
        self.assertTrue(all(item.patch_changed_paths for item in all_benchmarks))

    def test_validates_reference_fixture_files(self) -> None:
        result = validate_reference_fixtures(include_disabled=True)

        self.assertTrue(result["ok"])
        self.assertEqual(result["total_fixtures"], 16)
        self.assertEqual(result["enabled_fixtures"], 14)
        self.assertEqual(result["disabled_fixtures"], 2)
        self.assertFalse(result["missing"])
        self.assertFalse(result["invalid_patches"])

    def test_unexpanded_plugin_reference_env_falls_back_to_default_fixture_root(self) -> None:
        self.assertEqual(resolve_reference_root("${AGENTIC_FUZZ_REFERENCE_ROOT}"), DEFAULT_REFERENCE_ROOT.resolve())
        self.assertEqual(len(discover_reference_benchmarks("${AGENTIC_FUZZ_REFERENCE_ROOT}", include_disabled=True)), 16)

    def test_loads_userspace_harness_inventory_for_target(self) -> None:
        mongoose = load_target_profile("localfuzz/c/mongoose")
        binutils = load_target_profile("binutils")

        self.assertEqual(mongoose.target, "localfuzz/c/mongoose")
        self.assertEqual(mongoose.sanitizers, ("address",))
        self.assertIn("fuzz", {harness.name for harness in mongoose.harnesses})
        self.assertGreaterEqual(len(binutils.harnesses), 16)
        self.assertIn("fuzz_nm", {harness.name for harness in binutils.harnesses})

    def test_parses_asan_signal_and_signature(self) -> None:
        output = """
ERROR: AddressSanitizer: heap-use-after-free on address 0x123
    #0 0xaaaa in bad_copy /src/project/parser.c:42
    #1 0xbbbb in LLVMFuzzerTestOneInput /src/project/fuzz.c:12
"""
        signal = parse_asan_signal(output)

        self.assertIsNotNone(signal)
        assert signal is not None
        self.assertEqual(signal.crash_type, "heap-use-after-free")
        self.assertEqual(signal.top_function, "bad_copy")
        self.assertEqual(signal.top_file, "/src/project/parser.c")
        self.assertRegex(signal.to_dict()["signature"], r"^[0-9a-f]{24}$")

    def test_mcp_server_exposes_fidelity_and_state_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = AgenticFuzzMcpServer(data_root=tmp, audit_roots=(Path(__file__).resolve().parents[1] / "src" / "agentic_fuzz_engine",))
            init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            fixtures = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "fidelity_validate_fixtures", "arguments": {"include_disabled": True}},
                }
            )
            campaign = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "campaign_start", "arguments": {"target": "localfuzz/c/mongoose", "name": "unit"}},
                }
            )
            artifact = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "artifact_put",
                        "arguments": {
                            "run_id": "unit",
                            "name": "poc.bin",
                            "content_b64": base64.b64encode(b"POC").decode("ascii"),
                        },
                    },
                }
            )
            checkpoint = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "campaign_checkpoint_record",
                        "arguments": {
                            "run_id": "unit",
                            "target": "localfuzz/c/mongoose",
                            "harness": "fuzz",
                            "phase": "scope",
                            "tool_evidence": ["target_validate: ok", "harness_list: fuzz"],
                            "blockers": [],
                            "next_command": "corpus-import unit seeds --kind seed",
                            "agent": "planner",
                        },
                    },
                }
            )
            checkpoint_list = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {"name": "campaign_checkpoint_list", "arguments": {"run_id": "unit"}},
                }
            )

            self.assertEqual(init["result"]["serverInfo"]["name"], "agentic-fuzz-engine")
            tool_names = {tool["name"] for tool in tools["result"]["tools"]}
            self.assertIn("target_validate", tool_names)
            self.assertIn("target_discover", tool_names)
            self.assertIn("target_build_probe", tool_names)
            self.assertIn("campaign_fidelity_audit", tool_names)
            self.assertIn("campaign_report", tool_names)
            self.assertIn("campaign_completion_audit", tool_names)
            self.assertIn("campaign_full_completion_audit", tool_names)
            self.assertIn("campaign_phase_audit", tool_names)
            self.assertIn("campaign_checkpoint_record", tool_names)
            self.assertIn("campaign_checkpoint_list", tool_names)
            self.assertIn("export_bundle_create", tool_names)
            self.assertIn("export_mock_api_submit_pov", tool_names)
            self.assertIn("export_mock_api_submit_patch", tool_names)
            self.assertIn("export_mock_api_submit_sarif", tool_names)
            self.assertIn("export_list", tool_names)
            self.assertIn("corpus_import", tool_names)
            self.assertIn("crash_import", tool_names)
            self.assertIn("dictionary_generate", tool_names)
            self.assertIn("grammar_infer", tool_names)
            self.assertIn("concolic_plan", tool_names)
            self.assertIn("finding_record", tool_names)
            self.assertIn("finding_grade", tool_names)
            self.assertIn("finding_classify", tool_names)
            self.assertIn("finding_lifecycle_audit", tool_names)
            self.assertIn("harness_run", tool_names)
            self.assertIn("pov_minimize", tool_names)
            self.assertIn("fidelity_replay_campaign", tool_names)
            self.assertIn("fuzz_campaign", tool_names)
            self.assertIn("patch_candidate_record", tool_names)
            self.assertIn("patch_grade", tool_names)
            self.assertIn("runtime_guard_audit", tool_names)
            self.assertIn("engine_parity_audit", tool_names)
            fixture_body = _tool_body(fixtures)
            self.assertTrue(fixture_body["ok"])
            self.assertEqual(fixture_body["total_fixtures"], 16)
            self.assertEqual(_tool_body(campaign)["run_id"], "unit")
            self.assertEqual(_tool_body(artifact)["sha256"], "dc8d5abd7616d5515acea2fcb66e3e1fa66e50dcc3cdd3ba9a323fbcfedc9835")
            checkpoint_body = _tool_body(checkpoint)
            self.assertEqual(checkpoint_body["checkpoint"]["phase"], "scope")
            self.assertEqual(checkpoint_body["checkpoint"]["harness"], "fuzz")
            self.assertFalse(checkpoint_body["checkpoint"]["blocked"])
            self.assertEqual(_tool_body(checkpoint_list)["checkpoints"][0]["next_command"], "corpus-import unit seeds --kind seed")

    def test_new_plugin_has_expected_components_and_no_runtime_calls(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        manifest = json.loads((plugin / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        mcp = json.loads((plugin / ".mcp.json").read_text(encoding="utf-8"))

        self.assertEqual(manifest["name"], "agentic-fuzz")
        self.assertIn("agentic_fuzz_engine", mcp["mcpServers"])
        self.assertGreaterEqual(len(list((plugin / "skills").glob("*/SKILL.md"))), 7)
        self.assertGreaterEqual(len(list((plugin / "agents").glob("*.md"))), 15)
        self.assertTrue((plugin / "agents" / "native-harness.md").exists())
        self.assertTrue((plugin / "agents" / "input-generator.md").exists())
        self.assertTrue((plugin / "agents" / "artifact-manager.md").exists())
        findings = audit_runtime_guard_runtime_calls((root / "src" / "agentic_fuzz_engine", plugin))
        self.assertEqual(findings, ())

    def test_engine_parity_audit_verifies_no_runtime_plugin_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            engine = AgenticFuzzEngine(
                data_root=tmp,
                audit_roots=(root / "src" / "agentic_fuzz_engine", plugin),
            )
            result = engine.call_tool("engine_parity_audit", {})

        self.assertTrue(result["ok"], result["blockers"])
        group_names = {group["name"] for group in result["groups"]}
        self.assertIn("fixture_fidelity", group_names)
        self.assertIn("grammar_and_concolic", group_names)
        self.assertIn("fuzzing_and_coverage_feedback", group_names)
        self.assertIn("external_crash_intake", group_names)
        self.assertIn("reference_shaped_no_runtime_subagents", group_names)
        self.assertIn("runtime_guardrails", group_names)
        self.assertGreaterEqual(result["score"]["coverage_ratio"], 1.0)
        self.assertTrue(result["guardrails"]["ok"])
        self.assertFalse(result["blockers"])

    def test_engine_parity_audit_catches_missing_tool_coverage(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            engine = AgenticFuzzEngine(data_root=tmp)
            degraded_specs = [spec for spec in engine.tool_specs() if spec["name"] != "fuzz_campaign"]
        result = audit_engine_parity(
            tool_specs=degraded_specs,
            plugin_root=plugin,
            engine_root=root / "src" / "agentic_fuzz_engine",
            audit_roots=(root / "src" / "agentic_fuzz_engine", plugin),
        )

        self.assertFalse(result["ok"])
        fuzz_group = next(group for group in result["groups"] if group["name"] == "fuzzing_and_coverage_feedback")
        self.assertFalse(fuzz_group["ok"])
        self.assertIn("fuzz_campaign", fuzz_group["missing_tools"])
        self.assertTrue(any("fuzzing_and_coverage_feedback" in blocker for blocker in result["blockers"]))

    def test_plugin_cli_runs_engine_parity_audit_strict(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp
            result = subprocess.run(
                [str(plugin / "scripts" / "run-engine.sh"), "engine-parity-audit", "--strict"],
                cwd=root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"], payload["blockers"])
        self.assertEqual(payload["score"]["failing_groups"], 0)

    def test_plugin_prompts_match_public_harness_fidelity_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        agent_paths = sorted((plugin / "agents").glob("*.md"))
        skill_paths = sorted((plugin / "skills").glob("*/SKILL.md"))
        agent_lines = {path.name: path.read_text(encoding="utf-8").splitlines() for path in agent_paths}
        prompt_text = "\n".join(path.read_text(encoding="utf-8") for path in [*agent_paths, *skill_paths])

        self.assertGreaterEqual(len(agent_paths), 13)
        self.assertGreaterEqual(len(skill_paths), 7)
        self.assertTrue(all(len(lines) >= 24 for lines in agent_lines.values()))
        self.assertGreaterEqual(sum(len(lines) for lines in agent_lines.values()), 430)
        for required in (
            "3 out of 3",
            "Crash Quality Tiers",
            "<poc_path>",
            "<dup_check>",
            "Five Criteria",
            "finding_grade",
            "WEAK_PASS",
            "DUP_BETTER",
            "DUP_SKIP",
            "finding_classify",
            "executable classifier",
            "finding_lifecycle_audit",
            "finding-lifecycle-audit",
            "finding lifecycle",
            "T0 apply and rebuild",
            "T3 focused re-attack",
            "<primitive>",
            "<reachability>",
            "untrusted data",
            "benchmark",
            "reference patch sha256",
            "patch changed paths",
            "Do not invoke external runtime",
            "target_discover",
            "target_build_probe",
            "campaign-local build probe",
            "campaign_fidelity_audit",
            "campaign-fidelity-audit",
            "campaign_report",
            "campaign-report",
            "campaign_completion_audit",
            "campaign-completion-audit",
            "final completion gate",
            "campaign_phase_audit",
            "campaign-phase-audit",
            "phase coverage",
            "campaign_checkpoint_record",
            "campaign-checkpoint-record",
            "campaign_checkpoint_list",
            "campaign-checkpoint-list",
            "checkpoint ledger",
            "report artifact",
            "corpus_import",
            "crash_import",
            "crash-import",
            "external fuzzer crash outputs",
            "libFuzzer/AFL-style",
            "seed_artifacts",
            "dictionary_tokens",
            "dictionary_generate",
            "dictionary-generate",
            "grammar_infer",
            "grammar-infer",
            "grammar artifact",
            "concolic_plan",
            "concolic-plan",
            "branch-plan artifact",
            "runnable harness commands",
            "harness_run",
            "pov_minimize",
            "signal-preservation",
            "fidelity_replay_campaign",
            "fuzz_campaign",
            "coverage feedback",
            "promoted corpus",
            "feedback_rounds",
            "later scheduler rounds",
            "patch_candidate_record",
            "patch-candidate-record",
            "patch_grade",
            "engine_parity_audit",
            "engine-parity-audit",
            "Campaign Phase Contract",
            "Phase 0: Engine Readiness",
            "Required Handoff Schema",
            "required phases",
            "readiness`, `scope`, `input-material`, `fuzzing`, `grading`, `dedupe`, and `report",
        ):
            self.assertIn(required, prompt_text)

    def test_plugin_stdio_mcp_runs_live_harness_and_records_finding(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            harness_script = Path(tmp) / "asan_harness.py"
            _write_live_harness_script(harness_script)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call(
                    "tools/call",
                    {"name": "campaign_start", "arguments": {"target": "localfuzz/c/live", "name": "live-e2e"}},
                )
                artifact = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "artifact_put",
                            "arguments": {
                                "run_id": "live-e2e",
                                "name": "live-poc.bin",
                                "content_b64": base64.b64encode(b"CRASH").decode("ascii"),
                            },
                        },
                    )
                )
                run = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "harness_run",
                            "arguments": {
                                "run_id": "live-e2e",
                                "target": "localfuzz/c/live",
                                "harness": "live_harness",
                                "artifact_name": artifact["name"],
                                "command": [sys.executable, str(harness_script), "{poc}"],
                                "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                                "repetitions": 3,
                                "timeout_seconds": 5,
                                "record_finding": True,
                            },
                        },
                    )
                )
                status = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "campaign_status", "arguments": {"run_id": "live-e2e"}})
                )

                self.assertTrue(run["verified"])
                self.assertEqual(run["crashes"], 3)
                self.assertEqual(run["matches_expected"], 3)
                self.assertEqual(len(run["runs"]), 3)
                self.assertEqual(run["finding"]["harness"], "live_harness")
                self.assertEqual(len(status["findings"]), 1)
                self.assertIn("live-poc.bin", status["artifacts"])
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_cli_runs_live_harness_flow(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            harness_script = Path(tmp) / "asan_harness.py"
            poc = Path(tmp) / "poc.bin"
            _write_live_harness_script(harness_script)
            poc.write_bytes(b"CRASH")
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/cli-live", "--name", "cli-live")
            artifact = run_cli("artifact-put", "cli-live", "cli-poc.bin", "--file", str(poc))
            run = run_cli(
                "harness-run",
                "--target",
                "localfuzz/c/cli-live",
                "--harness",
                "cli_harness",
                "--expected-error-token",
                "AddressSanitizer: heap-buffer-overflow",
                "--repetitions",
                "3",
                "--timeout-seconds",
                "5",
                "--record-finding",
                "cli-live",
                str(artifact["name"]),
                "--",
                sys.executable,
                str(harness_script),
                "{poc}",
            )
            missing_phase = run_cli("campaign-phase-audit", "cli-live")
            checkpoint = run_cli(
                "campaign-checkpoint-record",
                "cli-live",
                "--target",
                "localfuzz/c/cli-live",
                "--harness",
                "cli_harness",
                "--phase",
                "grading",
                "--tool-evidence",
                "harness-run cli-poc.bin: PASS 3/3",
                "--next-command",
                "finding-dedupe cli-live",
                "--agent",
                "crash-grader",
            )
            dedupe = run_cli("finding-dedupe", "cli-live")
            lifecycle = run_cli("finding-lifecycle-audit", "cli-live")
            dedupe_checkpoint = run_cli(
                "campaign-checkpoint-record",
                "cli-live",
                "--target",
                "localfuzz/c/cli-live",
                "--harness",
                "cli_harness",
                "--phase",
                "dedupe",
                "--tool-evidence",
                "finding-dedupe cli-live: 1 group",
                "--tool-evidence",
                "finding-lifecycle-audit cli-live: ok",
                "--next-command",
                "campaign-report cli-live --project localfuzz/c/cli-live",
                "--agent",
                "dedupe-judge",
            )
            phase_ok = run_cli("campaign-phase-audit", "cli-live")

            self.assertTrue(run["verified"])
            self.assertEqual(run["matches_expected"], 3)
            self.assertEqual(run["finding"]["harness"], "cli_harness")
            self.assertEqual(run["classification"]["verdict"], "NEW")
            self.assertFalse(missing_phase["coverage_ok"])
            self.assertIn("grading", missing_phase["missing_checkpoint_phases"])
            self.assertEqual(checkpoint["checkpoint"]["phase"], "grading")
            self.assertEqual(dedupe_checkpoint["checkpoint"]["phase"], "dedupe")
            self.assertTrue(phase_ok["coverage_ok"], phase_ok["blockers"])
            self.assertEqual(phase_ok["checkpointed_phases"], ["grading", "dedupe"])
            self.assertEqual(len(dedupe["groups"]), 1)
            self.assertTrue(lifecycle["ok"], lifecycle["blockers"])
            self.assertEqual(lifecycle["score"]["classified_findings"], 1)

    def test_finding_lifecycle_audit_accepts_manual_verify_classify_record_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            harness_script = Path(tmp) / "asan_harness.py"
            poc = Path(tmp) / "manual-poc.bin"
            _write_live_harness_script(harness_script)
            poc.write_bytes(b"CRASH")
            engine = AgenticFuzzEngine(data_root=tmp)

            engine.call_tool("campaign_start", {"target": "localfuzz/c/manual", "name": "manual-flow"})
            artifact = engine.call_tool(
                "artifact_put",
                {
                    "run_id": "manual-flow",
                    "name": "manual-poc.bin",
                    "content_b64": base64.b64encode(poc.read_bytes()).decode("ascii"),
                },
            )
            run = engine.call_tool(
                "harness_run",
                {
                    "run_id": "manual-flow",
                    "target": "localfuzz/c/manual",
                    "harness": "manual_harness",
                    "artifact_name": artifact["name"],
                    "command": [sys.executable, str(harness_script), "{poc}"],
                    "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                    "repetitions": 3,
                    "record_finding": False,
                },
            )
            classified = engine.call_tool(
                "finding_classify",
                {
                    "run_id": "manual-flow",
                    "target": "localfuzz/c/manual",
                    "harness": "manual_harness",
                    "sanitizer": "address",
                    "error_token": "AddressSanitizer: heap-buffer-overflow",
                    "crash_output": run["crash_output"],
                    "poc_artifact": artifact["name"],
                    "reproductions": 3,
                    "verified": True,
                },
            )
            engine.call_tool(
                "finding_record",
                {
                    "run_id": "manual-flow",
                    "target": "localfuzz/c/manual",
                    "harness": "manual_harness",
                    "sanitizer": "address",
                    "error_token": "AddressSanitizer: heap-buffer-overflow",
                    "crash_output": run["crash_output"],
                    "poc_artifact": artifact["name"],
                    "reproductions": 3,
                    "verified": True,
                },
            )
            engine.call_tool("finding_dedupe", {"run_id": "manual-flow"})
            lifecycle = engine.call_tool("finding_lifecycle_audit", {"run_id": "manual-flow"})

            self.assertTrue(run["verified"])
            self.assertEqual(classified["verdict"], "NEW")
            self.assertTrue(lifecycle["ok"], lifecycle["blockers"])
            self.assertEqual(lifecycle["score"]["verified_findings"], 1)
            self.assertEqual(lifecycle["score"]["classified_findings"], 1)

    def test_plugin_stdio_mcp_grades_finding_pass_and_records(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            harness_script = Path(tmp) / "asan_harness.py"
            _write_live_harness_script(harness_script)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call(
                    "tools/call",
                    {"name": "campaign_start", "arguments": {"target": "localfuzz/c/live", "name": "grade-e2e"}},
                )
                artifact = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "artifact_put",
                            "arguments": {
                                "run_id": "grade-e2e",
                                "name": "grade-poc.bin",
                                "content_b64": base64.b64encode(b"CRASH").decode("ascii"),
                            },
                        },
                    )
                )
                grade = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "finding_grade",
                            "arguments": {
                                "run_id": "grade-e2e",
                                "target": "localfuzz/c/live",
                                "harness": "live_harness",
                                "artifact_name": artifact["name"],
                                "command": [sys.executable, str(harness_script), "{poc}"],
                                "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                                "repetitions": 3,
                                "timeout_seconds": 5,
                                "record_finding": True,
                            },
                        },
                    )
                )
                status = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "campaign_status", "arguments": {"run_id": "grade-e2e"}})
                )

                self.assertEqual(grade["verdict"], "PASS")
                self.assertTrue(grade["record_recommended"])
                self.assertTrue(grade["criteria"]["reproduces_3_of_3"])
                self.assertTrue(grade["criteria"]["top_project_frame"])
                self.assertEqual(grade["reproduction"]["matching"], 3)
                self.assertEqual(grade["finding"]["poc_artifact"], "grade-poc.bin")
                self.assertTrue(any(event["type"] == "finding_graded" for event in status["events"]))
                self.assertEqual(len(status["findings"]), 1)
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_cli_grades_weak_pass_for_two_of_three_repro(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            harness_script = Path(tmp) / "flaky_harness.py"
            counter = Path(tmp) / "counter.txt"
            poc = Path(tmp) / "poc.bin"
            _write_flaky_harness_script(harness_script)
            poc.write_bytes(b"CRASH")
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/flaky", "--name", "grade-cli")
            artifact = run_cli("artifact-put", "grade-cli", "flaky-poc.bin", "--file", str(poc))
            grade = run_cli(
                "finding-grade",
                "grade-cli",
                str(artifact["name"]),
                "--target",
                "localfuzz/c/flaky",
                "--harness",
                "flaky_harness",
                "--harness-command-json",
                json.dumps([sys.executable, str(harness_script), "{poc}", str(counter)]),
                "--expected-error-token",
                "AddressSanitizer: heap-buffer-overflow",
                "--repetitions",
                "3",
                "--timeout-seconds",
                "5",
            )

            self.assertEqual(grade["verdict"], "WEAK_PASS")
            self.assertFalse(grade["record_recommended"])
            self.assertTrue(grade["criteria"]["reproduces_at_least_2_of_3"])
            self.assertFalse(grade["criteria"]["reproduces_3_of_3"])
            self.assertEqual(grade["reproduction"]["matching"], 2)

    def test_plugin_stdio_mcp_minimizes_pov_and_preserves_signal(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            harness_script = Path(tmp) / "minimize_harness.py"
            _write_minimization_harness(harness_script)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call(
                    "tools/call",
                    {"name": "campaign_start", "arguments": {"target": "localfuzz/c/minimize", "name": "minimize-e2e"}},
                )
                artifact = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "artifact_put",
                            "arguments": {
                                "run_id": "minimize-e2e",
                                "name": "bloated-pov.bin",
                                "content_b64": base64.b64encode(b"AAAAAAAACRASHBBBBBBBB").decode("ascii"),
                            },
                        },
                    )
                )
                minimized = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "pov_minimize",
                            "arguments": {
                                "run_id": "minimize-e2e",
                                "artifact_name": artifact["name"],
                                "output_artifact": "minimized-pov.bin",
                                "command": [sys.executable, str(harness_script), "{poc}"],
                                "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                                "repetitions": 3,
                                "timeout_seconds": 5,
                                "max_attempts": 80,
                            },
                        },
                    )
                )
                status = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "campaign_status", "arguments": {"run_id": "minimize-e2e"}})
                )

                self.assertTrue(minimized["ok"])
                self.assertEqual(minimized["verdict"], "MINIMIZED")
                self.assertLess(minimized["minimized_size"], minimized["original_size"])
                self.assertTrue(minimized["preserved_signal"])
                self.assertEqual(minimized["baseline_signal"]["top_function"], "minimize_parse")
                self.assertEqual(minimized["final_signal"]["top_function"], "minimize_parse")
                self.assertEqual(minimized["minimized_artifact"]["name"], "minimized-pov.bin")
                self.assertIn("minimized-pov.bin", status["artifacts"])
                self.assertTrue(any(event["type"] == "pov_minimize" for event in status["events"]))
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_cli_minimizes_pov_and_preserves_signal(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            harness_script = Path(tmp) / "minimize_harness.py"
            pov = Path(tmp) / "bloated-pov.bin"
            _write_minimization_harness(harness_script)
            pov.write_bytes(b"AAAAAAAACRASHBBBBBBBB")
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/minimize", "--name", "minimize-cli")
            artifact = run_cli("artifact-put", "minimize-cli", "bloated-pov.bin", "--file", str(pov))
            minimized = run_cli(
                "pov-minimize",
                "minimize-cli",
                str(artifact["name"]),
                "--output-artifact",
                "minimized-pov.bin",
                "--harness-command-json",
                json.dumps([sys.executable, str(harness_script), "{poc}"]),
                "--expected-error-token",
                "AddressSanitizer: heap-buffer-overflow",
                "--repetitions",
                "3",
                "--timeout-seconds",
                "5",
                "--max-attempts",
                "80",
            )

            self.assertTrue(minimized["ok"])
            self.assertEqual(minimized["verdict"], "MINIMIZED")
            self.assertLess(minimized["minimized_size"], minimized["original_size"])
            self.assertTrue(minimized["preserved_signal"])
            self.assertEqual(minimized["minimized_artifact"]["name"], "minimized-pov.bin")

    def test_plugin_stdio_mcp_classifies_new_and_better_duplicate_findings(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call(
                    "tools/call",
                    {"name": "campaign_start", "arguments": {"target": "localfuzz/c/dedupe", "name": "dedupe-e2e"}},
                )
                old_artifact = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "artifact_put",
                            "arguments": {
                                "run_id": "dedupe-e2e",
                                "name": "old-pov.bin",
                                "content_b64": base64.b64encode(b"AAAAAAAACRASHBBBBBBBB").decode("ascii"),
                            },
                        },
                    )
                )
                rpc.call(
                    "tools/call",
                    {
                        "name": "finding_record",
                        "arguments": {
                            "run_id": "dedupe-e2e",
                            "target": "localfuzz/c/dedupe",
                            "harness": "dedupe_harness",
                            "sanitizer": "address",
                            "error_token": "AddressSanitizer: heap-buffer-overflow",
                            "crash_output": _dedupe_trace("dedupe_parse"),
                            "poc_artifact": old_artifact["name"],
                            "reproductions": 3,
                            "verified": True,
                        },
                    },
                )
                small_artifact = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "artifact_put",
                            "arguments": {
                                "run_id": "dedupe-e2e",
                                "name": "small-pov.bin",
                                "content_b64": base64.b64encode(b"CRASH").decode("ascii"),
                            },
                        },
                    )
                )
                duplicate = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "finding_classify",
                            "arguments": {
                                "run_id": "dedupe-e2e",
                                "target": "localfuzz/c/dedupe",
                                "harness": "dedupe_harness",
                                "sanitizer": "address",
                                "error_token": "AddressSanitizer: heap-buffer-overflow",
                                "crash_output": _dedupe_trace("dedupe_parse"),
                                "poc_artifact": small_artifact["name"],
                                "reproductions": 3,
                                "verified": True,
                            },
                        },
                    )
                )
                new = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "finding_classify",
                            "arguments": {
                                "run_id": "dedupe-e2e",
                                "target": "localfuzz/c/dedupe",
                                "harness": "dedupe_harness",
                                "sanitizer": "address",
                                "error_token": "AddressSanitizer: heap-buffer-overflow",
                                "crash_output": _dedupe_trace("other_parse"),
                                "poc_artifact": small_artifact["name"],
                                "reproductions": 3,
                                "verified": True,
                            },
                        },
                    )
                )
                rpc.call(
                    "tools/call",
                    {
                        "name": "finding_record",
                        "arguments": {
                            "run_id": "dedupe-e2e",
                            "target": "localfuzz/c/dedupe",
                            "harness": "dedupe_harness",
                            "sanitizer": "address",
                            "error_token": "AddressSanitizer: heap-buffer-overflow",
                            "crash_output": _dedupe_trace("dedupe_parse"),
                            "poc_artifact": small_artifact["name"],
                            "reproductions": 3,
                            "verified": True,
                        },
                    },
                )
                dedupe = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "finding_dedupe", "arguments": {"run_id": "dedupe-e2e"}})
                )

                self.assertEqual(duplicate["verdict"], "DUP_BETTER")
                self.assertEqual(duplicate["candidate_quality"]["poc_size"], 5)
                self.assertGreater(duplicate["representative_quality"]["poc_size"], duplicate["candidate_quality"]["poc_size"])
                self.assertEqual(new["verdict"], "NEW")
                self.assertEqual(dedupe["groups"][0]["representative"]["poc_artifact"], "small-pov.bin")
                self.assertEqual(dedupe["groups"][0]["representative_quality"]["poc_size"], 5)
                self.assertEqual(dedupe["groups"][0]["duplicates"][0]["poc_artifact"], "old-pov.bin")
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_cli_classifies_better_duplicate_finding(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            harness_script = Path(tmp) / "dedupe_harness.py"
            old_pov = Path(tmp) / "old-pov.bin"
            small_pov = Path(tmp) / "small-pov.bin"
            crash_output = Path(tmp) / "crash.txt"
            _write_dedupe_harness(harness_script)
            old_pov.write_bytes(b"AAAAAAAACRASHBBBBBBBB")
            small_pov.write_bytes(b"CRASH")
            crash_output.write_text(_dedupe_trace("dedupe_parse"), encoding="utf-8")
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/dedupe", "--name", "dedupe-cli")
            old_artifact = run_cli("artifact-put", "dedupe-cli", "old-pov.bin", "--file", str(old_pov))
            small_artifact = run_cli("artifact-put", "dedupe-cli", "small-pov.bin", "--file", str(small_pov))
            run_cli(
                "harness-run",
                "--target",
                "localfuzz/c/dedupe",
                "--harness",
                "dedupe_harness",
                "--expected-error-token",
                "AddressSanitizer: heap-buffer-overflow",
                "--repetitions",
                "3",
                "--timeout-seconds",
                "5",
                "--record-finding",
                "dedupe-cli",
                str(old_artifact["name"]),
                "--",
                sys.executable,
                str(harness_script),
                "{poc}",
            )
            checkpoint = run_cli(
                "campaign-checkpoint-record",
                "dedupe-cli",
                "--target",
                "localfuzz/c/dedupe",
                "--harness",
                "dedupe_harness",
                "--phase",
                "grading",
                "--tool-evidence",
                "harness-run old-pov.bin: PASS 3/3",
                "--next-command",
                "finding-dedupe dedupe-cli",
                "--agent",
                "crash-grader",
            )
            checkpoints = run_cli("campaign-checkpoint-list", "dedupe-cli")
            classified = run_cli(
                "finding-classify",
                "dedupe-cli",
                "--target",
                "localfuzz/c/dedupe",
                "--harness",
                "dedupe_harness",
                "--error-token",
                "AddressSanitizer: heap-buffer-overflow",
                "--crash-output-file",
                str(crash_output),
                "--poc-artifact",
                str(small_artifact["name"]),
                "--reproductions",
                "3",
                "--verified",
            )
            run_cli(
                "harness-run",
                "--target",
                "localfuzz/c/dedupe",
                "--harness",
                "dedupe_harness",
                "--expected-error-token",
                "AddressSanitizer: heap-buffer-overflow",
                "--repetitions",
                "3",
                "--timeout-seconds",
                "5",
                "--record-finding",
                "dedupe-cli",
                str(small_artifact["name"]),
                "--",
                sys.executable,
                str(harness_script),
                "{poc}",
            )
            dedupe = run_cli("finding-dedupe", "dedupe-cli")
            report = run_cli(
                "campaign-report",
                "dedupe-cli",
                "--project",
                "localfuzz/c/dedupe",
                "--artifact-prefix",
                "reports/dedupe-cli",
            )
            status = run_cli("campaign-status", "dedupe-cli")

            self.assertEqual(checkpoint["checkpoint"]["phase"], "grading")
            self.assertEqual(checkpoints["checkpoints"][0]["agent"], "crash-grader")
            self.assertEqual(classified["verdict"], "DUP_BETTER")
            self.assertLess(classified["candidate_quality"]["poc_size"], classified["representative_quality"]["poc_size"])
            self.assertEqual(dedupe["groups"][0]["representative"]["poc_artifact"], "small-pov.bin")
            self.assertEqual(report["report"]["findings"][0]["poc_artifact"], "small-pov.bin")
            self.assertEqual(report["report"]["summary"]["dedupe_groups"], 1)
            self.assertEqual(report["report"]["summary"]["checkpoint_count"], 1)
            self.assertEqual(report["report"]["checkpoints"]["phases"], ["grading"])
            self.assertFalse(report["report"]["summary"]["phase_coverage_ok"])
            self.assertIn("grading", report["report"]["summary"]["phase_stale_checkpoints"])
            self.assertIn("dedupe", report["report"]["summary"]["phase_missing_checkpoints"])
            self.assertIn("Agentic Fuzz Campaign Report", report["markdown"])
            self.assertIn("Phase checkpoints: 1", report["markdown"])
            self.assertIn("Stale phase checkpoints: `grading`", report["markdown"])
            self.assertIn(report["markdown_artifact"]["name"], status["artifacts"])
            self.assertIn(report["json_artifact"]["name"], status["artifacts"])

    def test_plugin_stdio_mcp_discovers_local_target_harnesses_and_build_hints(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            _write_discovery_target(source)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                discovered = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "target_discover",
                            "arguments": {"source_dir": str(source), "project": "localfuzz/c/discovery"},
                        },
                    )
                )

                self.assertTrue(discovered["ok"], discovered["blockers"])
                self.assertEqual(discovered["metadata"]["localfuzz_config"], ".localfuzz/config.yaml")
                self.assertEqual({item["kind"] for item in discovered["build_systems"]}, {"make"})
                self.assertEqual(discovered["command_map"]["py_harness"][0], "python3")
                native = next(item for item in discovered["harnesses"] if item["name"] == "native_harness")
                self.assertFalse(native["runnable"])
                self.assertIn("harness source requires a build output", native["blockers"][0])
                self.assertEqual(discovered["dictionaries"][0]["path"], "tokens.dict")
                self.assertEqual(discovered["seed_corpora"][0]["path"], "seed_corpus")
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_cli_discovers_local_target_harnesses_and_build_hints(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            _write_discovery_target(source)
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            result = subprocess.run(
                [
                    str(plugin / "scripts" / "run-engine.sh"),
                    "target-discover",
                    str(source),
                    "--project",
                    "localfuzz/c/discovery",
                ],
                cwd=root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            discovered = json.loads(result.stdout)
            self.assertTrue(discovered["ok"], discovered["blockers"])
            self.assertIn("py_harness", discovered["command_map"])
            self.assertEqual(discovered["build_systems"][0]["recommended_probe_commands"][0][0], "make")

    def test_plugin_stdio_mcp_imports_discovered_corpus_and_fuzzes_with_dictionary(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            harness_script = Path(tmp) / "fuzz_harness.py"
            _write_discovery_target(source)
            _write_fuzz_campaign_harness(harness_script)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call(
                    "tools/call",
                    {"name": "campaign_start", "arguments": {"target": "localfuzz/c/fuzz", "name": "corpus-e2e"}},
                )
                seeds = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "corpus_import",
                            "arguments": {
                                "run_id": "corpus-e2e",
                                "source_path": str(source / "seed_corpus"),
                                "kind": "seed",
                                "artifact_prefix": "localfuzz/c/fuzz/seed",
                            },
                        },
                    )
                )
                dictionary = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "corpus_import",
                            "arguments": {
                                "run_id": "corpus-e2e",
                                "source_path": str(source / "tokens.dict"),
                                "kind": "dictionary",
                                "artifact_prefix": "localfuzz/c/fuzz/dict",
                            },
                        },
                    )
                )
                fuzz = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "fuzz_campaign",
                            "arguments": {
                                "run_id": "corpus-e2e",
                                "target": "localfuzz/c/fuzz",
                                "harness": "fuzz_harness",
                                "seed_artifacts": seeds["seed_artifacts"],
                                "dictionary": dictionary["dictionary_tokens"],
                                "harness_command": [sys.executable, str(harness_script), "{poc}"],
                                "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                                "max_iterations": 12,
                                "repetitions": 3,
                                "timeout_seconds": 5,
                                "record_findings": True,
                                "stop_on_first_finding": True,
                            },
                        },
                    )
                )
                status = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "campaign_status", "arguments": {"run_id": "corpus-e2e"}})
                )

                self.assertEqual(len(seeds["seed_artifacts"]), 1)
                self.assertEqual(len(dictionary["dictionary_artifacts"]), 1)
                self.assertIn("CRASH", dictionary["dictionary_tokens"])
                self.assertEqual(fuzz["seed_artifacts"], seeds["seed_artifacts"])
                self.assertEqual(fuzz["verified_findings"], 1)
                self.assertIn("parser.magic", fuzz["coverage_features"])
                self.assertTrue(any(name in status["artifacts"] for name in seeds["seed_artifacts"]))
                self.assertTrue(any(name in status["artifacts"] for name in dictionary["dictionary_artifacts"]))
                self.assertGreaterEqual(sum(1 for event in status["events"] if event["type"] == "corpus_import"), 2)
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_stdio_mcp_imports_external_crashes_and_dedupes(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            crash_dir = Path(tmp) / "fuzzer-output" / "crashes"
            crash_dir.mkdir(parents=True)
            crash = crash_dir / "crash-000001"
            crash.write_bytes(b"CRASH")
            crash.with_name(crash.name + ".log").write_text(
                "==11==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x41414141\n"
                "    #0 0xaaaa in fuzz_parse /src/fuzz/parser.c:9\n"
                "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/fuzz/parser.c:9 in fuzz_parse\n",
                encoding="utf-8",
            )
            harness_script = Path(tmp) / "fuzz_harness.py"
            _write_fuzz_campaign_harness(harness_script)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call(
                    "tools/call",
                    {"name": "campaign_start", "arguments": {"target": "localfuzz/c/crash", "name": "crash-import-e2e"}},
                )
                first = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "crash_import",
                            "arguments": {
                                "run_id": "crash-import-e2e",
                                "source_path": str(crash_dir),
                                "target": "localfuzz/c/crash",
                                "harness": "fuzz_harness",
                                "artifact_prefix": "localfuzz/c/crash/fuzz_harness/external-crashes",
                                "harness_command": [sys.executable, str(harness_script), "{poc}"],
                                "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                                "repetitions": 3,
                                "timeout_seconds": 5,
                            },
                        },
                    )
                )
                second = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "crash_import",
                            "arguments": {
                                "run_id": "crash-import-e2e",
                                "source_path": str(crash_dir),
                                "target": "localfuzz/c/crash",
                                "harness": "fuzz_harness",
                                "artifact_prefix": "localfuzz/c/crash/fuzz_harness/external-crashes",
                                "harness_command": [sys.executable, str(harness_script), "{poc}"],
                                "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                                "repetitions": 3,
                                "timeout_seconds": 5,
                            },
                        },
                    )
                )
                status = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "campaign_status", "arguments": {"run_id": "crash-import-e2e"}})
                )

                self.assertEqual(first["imported"], 1)
                self.assertEqual(first["verified"], 1)
                self.assertEqual(first["findings_recorded"], 1)
                self.assertEqual(first["cases"][0]["classification"]["verdict"], "NEW")
                self.assertEqual(first["cases"][0]["sidecar_signal"]["crash_type"], "heap-buffer-overflow")
                self.assertEqual(second["findings_recorded"], 0)
                self.assertEqual(second["cases"][0]["classification"]["verdict"], "DUP_SKIP")
                self.assertEqual(len(status["findings"]), 1)
                self.assertTrue(any(event["type"] == "crash_import" for event in status["events"]))
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_cli_imports_external_crash_directory_with_verification(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            crash_dir = Path(tmp) / "crashes"
            crash_dir.mkdir()
            (crash_dir / "crash-000001").write_bytes(b"CRASH")
            harness_script = Path(tmp) / "fuzz_harness.py"
            _write_fuzz_campaign_harness(harness_script)
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/crash", "--name", "crash-import-cli")
            imported = run_cli(
                "crash-import",
                "crash-import-cli",
                str(crash_dir),
                "--target",
                "localfuzz/c/crash",
                "--harness",
                "fuzz_harness",
                "--artifact-prefix",
                "localfuzz/c/crash/fuzz_harness/external-crashes",
                "--harness-command-json",
                json.dumps([sys.executable, str(harness_script), "{poc}"]),
                "--expected-error-token",
                "AddressSanitizer: heap-buffer-overflow",
                "--repetitions",
                "3",
                "--timeout-seconds",
                "5",
            )
            status = run_cli("campaign-status", "crash-import-cli")

            self.assertEqual(imported["imported"], 1)
            self.assertEqual(imported["verified"], 1)
            self.assertEqual(imported["findings_recorded"], 1)
            self.assertEqual(imported["cases"][0]["classification"]["verdict"], "NEW")
            self.assertEqual(len(status["findings"]), 1)

    def test_plugin_cli_imports_corpus_and_dictionary_with_provenance(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            _write_discovery_target(source)
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/fuzz", "--name", "corpus-cli")
            seeds = run_cli(
                "corpus-import",
                "corpus-cli",
                str(source / "seed_corpus"),
                "--kind",
                "seed",
                "--artifact-prefix",
                "localfuzz/c/fuzz/seed",
            )
            dictionary = run_cli(
                "corpus-import",
                "corpus-cli",
                str(source / "tokens.dict"),
                "--kind",
                "dictionary",
                "--artifact-prefix",
                "localfuzz/c/fuzz/dict",
            )
            status = run_cli("campaign-status", "corpus-cli")

            self.assertEqual(seeds["seed_artifacts"], [seeds["artifacts"][0]["name"]])
            self.assertEqual(dictionary["dictionary_artifacts"], [dictionary["artifacts"][0]["name"]])
            self.assertEqual(seeds["artifacts"][0]["source_rel"], "seed.bin")
            self.assertEqual(dictionary["artifacts"][0]["source_rel"], "tokens.dict")
            self.assertIn("MAGIC", dictionary["dictionary_tokens"])
            self.assertIn("CRASH", dictionary["dictionary_tokens"])
            self.assertIn(seeds["seed_artifacts"][0], status["artifacts"])
            self.assertIn(dictionary["dictionary_artifacts"][0], status["artifacts"])

    def test_plugin_stdio_mcp_generates_dictionary_from_source_and_fuzzes(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            harness_script = Path(tmp) / "fuzz_harness.py"
            _write_dictionary_generation_source(source)
            _write_fuzz_campaign_harness(harness_script)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call(
                    "tools/call",
                    {"name": "campaign_start", "arguments": {"target": "localfuzz/c/dictgen", "name": "dictgen-e2e"}},
                )
                seed = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "artifact_put",
                            "arguments": {
                                "run_id": "dictgen-e2e",
                                "name": "seed.bin",
                                "content_b64": base64.b64encode(b"seed").decode("ascii"),
                            },
                        },
                    )
                )
                dictionary = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "dictionary_generate",
                            "arguments": {
                                "run_id": "dictgen-e2e",
                                "source_dir": str(source),
                                "target": "localfuzz/c/dictgen",
                                "harness": "fuzz_harness",
                                "artifact_name": "localfuzz/c/dictgen/fuzz_harness/generated.dict",
                            },
                        },
                    )
                )
                fuzz = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "fuzz_campaign",
                            "arguments": {
                                "run_id": "dictgen-e2e",
                                "target": "localfuzz/c/dictgen",
                                "harness": "fuzz_harness",
                                "seed_artifacts": [seed["name"]],
                                "dictionary": dictionary["dictionary_tokens"],
                                "harness_command": [sys.executable, str(harness_script), "{poc}"],
                                "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                                "max_iterations": 12,
                                "repetitions": 3,
                                "timeout_seconds": 5,
                                "record_findings": True,
                                "stop_on_first_finding": True,
                            },
                        },
                    )
                )
                status = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "campaign_status", "arguments": {"run_id": "dictgen-e2e"}})
                )

                self.assertIn("MAGIC", dictionary["dictionary_tokens"])
                self.assertIn("CRASH", dictionary["dictionary_tokens"])
                self.assertEqual(dictionary["artifact"]["name"], "localfuzz_c_dictgen_fuzz_harness_generated.dict")
                self.assertTrue(any(entry["reason"] == "literal in comparison" for entry in dictionary["token_entries"]))
                self.assertEqual(fuzz["verified_findings"], 1)
                self.assertIn("parser.magic", fuzz["coverage_features"])
                self.assertIn(dictionary["artifact"]["name"], status["artifacts"])
                self.assertTrue(any(event["type"] == "dictionary_generate" for event in status["events"]))
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_cli_generates_dictionary_from_source_with_provenance(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            _write_dictionary_generation_source(source)
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/dictgen", "--name", "dictgen-cli")
            dictionary = run_cli(
                "dictionary-generate",
                "dictgen-cli",
                str(source),
                "--target",
                "localfuzz/c/dictgen",
                "--harness",
                "fuzz_harness",
                "--artifact-name",
                "localfuzz/c/dictgen/fuzz_harness/generated.dict",
            )
            status = run_cli("campaign-status", "dictgen-cli")

            self.assertIn("MAGIC", dictionary["dictionary_tokens"])
            self.assertIn("CRASH", dictionary["dictionary_tokens"])
            self.assertEqual(dictionary["token_entries"][0]["source_rel"], "parser.c")
            self.assertEqual(dictionary["artifact"]["name"], "localfuzz_c_dictgen_fuzz_harness_generated.dict")
            self.assertIn(dictionary["artifact"]["name"], status["artifacts"])

    def test_plugin_stdio_mcp_infers_grammar_and_fuzzes_generated_seed(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            harness_script = Path(tmp) / "fuzz_harness.py"
            _write_dictionary_generation_source(source)
            _write_fuzz_campaign_harness(harness_script)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call(
                    "tools/call",
                    {"name": "campaign_start", "arguments": {"target": "localfuzz/c/grammar", "name": "grammar-e2e"}},
                )
                grammar = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "grammar_infer",
                            "arguments": {
                                "run_id": "grammar-e2e",
                                "source_dir": str(source),
                                "target": "localfuzz/c/grammar",
                                "harness": "fuzz_harness",
                                "artifact_prefix": "localfuzz/c/grammar/fuzz_harness/grammar",
                                "max_seeds": 8,
                            },
                        },
                    )
                )
                fuzz = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "fuzz_campaign",
                            "arguments": {
                                "run_id": "grammar-e2e",
                                "target": "localfuzz/c/grammar",
                                "harness": "fuzz_harness",
                                "seed_artifacts": grammar["seed_artifacts"],
                                "dictionary": [],
                                "harness_command": [sys.executable, str(harness_script), "{poc}"],
                                "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                                "max_iterations": 12,
                                "repetitions": 3,
                                "timeout_seconds": 5,
                                "record_findings": True,
                                "stop_on_first_finding": True,
                            },
                        },
                    )
                )
                status = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "campaign_status", "arguments": {"run_id": "grammar-e2e"}})
                )

                self.assertFalse(grammar["blockers"])
                self.assertIn("MAGIC", grammar["dictionary_tokens"])
                self.assertIn("CRASH", grammar["dictionary_tokens"])
                self.assertGreaterEqual(len(grammar["seed_artifacts"]), 2)
                self.assertEqual(grammar["seeds"][0]["family"], "token")
                self.assertTrue(any(seed["family"] == "token-pair" for seed in grammar["seeds"]))
                self.assertIn(grammar["grammar_artifact"]["name"], status["artifacts"])
                self.assertIn(grammar["seed_artifacts"][0], status["artifacts"])
                self.assertEqual(fuzz["seed_artifacts"], grammar["seed_artifacts"])
                self.assertEqual(fuzz["verified_findings"], 1)
                self.assertIn("parser.magic", fuzz["coverage_features"])
                self.assertTrue(any(event["type"] == "grammar_infer" for event in status["events"]))
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_cli_infers_grammar_with_seed_artifact_provenance(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            _write_dictionary_generation_source(source)
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/grammar", "--name", "grammar-cli")
            grammar = run_cli(
                "grammar-infer",
                "grammar-cli",
                str(source),
                "--target",
                "localfuzz/c/grammar",
                "--harness",
                "fuzz_harness",
                "--artifact-prefix",
                "localfuzz/c/grammar/fuzz_harness/grammar",
                "--max-seeds",
                "8",
            )
            status = run_cli("campaign-status", "grammar-cli")

            self.assertFalse(grammar["blockers"])
            self.assertIn("MAGIC", grammar["dictionary_tokens"])
            self.assertIn("CRASH", grammar["dictionary_tokens"])
            self.assertEqual(grammar["grammar_artifact"]["name"], "localfuzz_c_grammar_fuzz_harness_grammar_grammar.json")
            self.assertGreaterEqual(len(grammar["seed_artifacts"]), 2)
            self.assertIn(grammar["grammar_artifact"]["name"], status["artifacts"])
            self.assertIn(grammar["seed_artifacts"][0], status["artifacts"])

    def test_plugin_stdio_mcp_plans_concolic_branches_and_fuzzes_seed(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            harness_script = Path(tmp) / "concolic_harness.py"
            _write_dictionary_generation_source(source)
            _write_concolic_harness(harness_script)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call(
                    "tools/call",
                    {"name": "campaign_start", "arguments": {"target": "localfuzz/c/concolic", "name": "concolic-e2e"}},
                )
                plan = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "concolic_plan",
                            "arguments": {
                                "run_id": "concolic-e2e",
                                "source_dir": str(source),
                                "target": "localfuzz/c/concolic",
                                "harness": "concolic_harness",
                                "artifact_prefix": "localfuzz/c/concolic/concolic_harness/concolic",
                                "max_seeds": 8,
                            },
                        },
                    )
                )
                fuzz = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "fuzz_campaign",
                            "arguments": {
                                "run_id": "concolic-e2e",
                                "target": "localfuzz/c/concolic",
                                "harness": "concolic_harness",
                                "seed_artifacts": plan["seed_artifacts"],
                                "dictionary": [],
                                "harness_command": [sys.executable, str(harness_script), "{poc}"],
                                "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                                "max_iterations": 8,
                                "repetitions": 3,
                                "timeout_seconds": 5,
                                "record_findings": True,
                                "stop_on_first_finding": True,
                            },
                        },
                    )
                )
                status = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "campaign_status", "arguments": {"run_id": "concolic-e2e"}})
                )

                self.assertFalse(plan["blockers"])
                self.assertIn("MAGIC", plan["dictionary_tokens"])
                self.assertIn("CRASH", plan["dictionary_tokens"])
                self.assertTrue(any(branch["risk_class"] == "parser-state-gate" for branch in plan["branches"]))
                self.assertTrue(any(branch["reason"] == "length predicate" for branch in plan["branches"]))
                self.assertEqual(plan["seeds"][0]["family"], "branch-chain")
                self.assertIn(plan["branch_plan_artifact"]["name"], status["artifacts"])
                self.assertIn(plan["seed_artifacts"][0], status["artifacts"])
                self.assertEqual(fuzz["seed_artifacts"], plan["seed_artifacts"])
                self.assertEqual(fuzz["verified_findings"], 1)
                self.assertIn("parser.magic", fuzz["coverage_features"])
                self.assertTrue(any(event["type"] == "concolic_plan" for event in status["events"]))
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_cli_plans_concolic_branches_with_seed_artifacts(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            _write_dictionary_generation_source(source)
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/concolic", "--name", "concolic-cli")
            plan = run_cli(
                "concolic-plan",
                "concolic-cli",
                str(source),
                "--target",
                "localfuzz/c/concolic",
                "--harness",
                "concolic_harness",
                "--artifact-prefix",
                "localfuzz/c/concolic/concolic_harness/concolic",
                "--max-seeds",
                "8",
            )
            status = run_cli("campaign-status", "concolic-cli")

            self.assertFalse(plan["blockers"])
            self.assertGreaterEqual(len(plan["branches"]), 2)
            self.assertEqual(plan["branch_plan_artifact"]["name"], "localfuzz_c_concolic_concolic_harness_concolic_branch_plan.json")
            self.assertEqual(plan["seeds"][0]["family"], "branch-chain")
            self.assertIn(plan["branch_plan_artifact"]["name"], status["artifacts"])
            self.assertIn(plan["seed_artifacts"][0], status["artifacts"])

    def test_plugin_stdio_mcp_build_probe_creates_campaign_local_harness_command(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            _write_discovery_target(source)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call(
                    "tools/call",
                    {"name": "campaign_start", "arguments": {"target": "localfuzz/c/discovery", "name": "build-probe-e2e"}},
                )
                probe = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "target_build_probe",
                            "arguments": {
                                "run_id": "build-probe-e2e",
                                "source_dir": str(source),
                                "project": "localfuzz/c/discovery",
                                "build_id": "native-build",
                                "timeout_seconds": 5,
                            },
                        },
                    )
                )
                status = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "campaign_status", "arguments": {"run_id": "build-probe-e2e"}})
                )

                self.assertTrue(probe["ok"], probe["blocker"])
                self.assertEqual(probe["runs"][0]["exit_code"], 0)
                self.assertIn("native_harness", probe["command_map"])
                self.assertTrue(Path(probe["command_map"]["native_harness"][0]).exists())
                self.assertTrue(str(probe["command_map"]["native_harness"][0]).startswith(probe["worktree_dir"]))
                self.assertFalse((source / "build" / "native_harness").exists())
                self.assertTrue(any(event["type"] == "target_build_probe" for event in status["events"]))
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_cli_build_probe_creates_campaign_local_harness_command(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            _write_discovery_target(source)
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/discovery", "--name", "build-probe-cli")
            probe = run_cli(
                "target-build-probe",
                "build-probe-cli",
                str(source),
                "--project",
                "localfuzz/c/discovery",
                "--build-id",
                "native-build",
                "--timeout-seconds",
                "5",
            )

            self.assertTrue(probe["ok"], probe["blocker"])
            self.assertIn("native_harness", probe["command_map"])
            self.assertTrue(Path(probe["command_map"]["native_harness"][0]).exists())
            self.assertFalse((source / "build" / "native_harness").exists())

    def test_plugin_stdio_mcp_replays_fixture_campaign_with_harness_map(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            harness_script = Path(tmp) / "mongoose_harness.py"
            _write_live_harness_script(harness_script, crash_type="dynamic-stack-buffer-overflow")
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call(
                    "tools/call",
                    {"name": "campaign_start", "arguments": {"target": "localfuzz/c/mongoose", "name": "mongoose-replay"}},
                )
                replay = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "fidelity_replay_campaign",
                            "arguments": {
                                "run_id": "mongoose-replay",
                                "project": "localfuzz/c/mongoose",
                                "command_map": {"fuzz": [sys.executable, str(harness_script), "{poc}"]},
                                "repetitions": 3,
                                "timeout_seconds": 5,
                                "record_findings": True,
                            },
                        },
                    )
                )
                status = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "campaign_status", "arguments": {"run_id": "mongoose-replay"}})
                )
                dedupe = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "finding_dedupe", "arguments": {"run_id": "mongoose-replay"}})
                )
                audit = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "campaign_fidelity_audit",
                            "arguments": {"run_id": "mongoose-replay", "project": "localfuzz/c/mongoose"},
                        },
                    )
                )

                self.assertEqual(replay["total_cases"], 1)
                self.assertEqual(replay["executed"], 1)
                self.assertEqual(replay["verified"], 1)
                self.assertEqual(replay["blocked"], 0)
                self.assertEqual(replay["findings_recorded"], 1)
                self.assertEqual(replay["cases"][0]["fixture"], "fixture_0")
                self.assertEqual(replay["cases"][0]["harness"], "fuzz")
                self.assertTrue(replay["cases"][0]["run"]["verified"])
                self.assertEqual(len(status["findings"]), 1)
                self.assertEqual(len(dedupe["groups"]), 1)
                self.assertTrue(audit["ok"], audit["blockers"])
                self.assertEqual(audit["score"]["enabled_fixtures"], 1)
                self.assertEqual(audit["score"]["represented_fixtures"], 1)
                self.assertEqual(audit["fixtures"][0]["status"], "represented")
                self.assertEqual(audit["fixtures"][0]["evidence_level"], "fixture-proof")
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_cli_replays_fixture_campaign_with_harness_map(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            harness_script = Path(tmp) / "mongoose_harness.py"
            _write_live_harness_script(harness_script, crash_type="dynamic-stack-buffer-overflow")
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/mongoose", "--name", "mongoose-cli-replay")
            run_cli(
                "campaign-checkpoint-record",
                "mongoose-cli-replay",
                "--target",
                "localfuzz/c/mongoose",
                "--phase",
                "readiness",
                "--tool-evidence",
                "engine-parity-audit --strict: ok",
                "--tool-evidence",
                "fidelity-validate-fixtures --include-disabled: ok",
                "--tool-evidence",
                "runtime-guard-audit --strict: ok",
                "--next-command",
                "target-validate localfuzz/c/mongoose",
                "--agent",
                "planner",
            )
            run_cli(
                "campaign-checkpoint-record",
                "mongoose-cli-replay",
                "--target",
                "localfuzz/c/mongoose",
                "--harness",
                "fuzz",
                "--phase",
                "scope",
                "--tool-evidence",
                "target-validate localfuzz/c/mongoose: ok",
                "--tool-evidence",
                "harness-list localfuzz/c/mongoose: fuzz",
                "--next-command",
                "fidelity-replay-campaign mongoose-cli-replay --project localfuzz/c/mongoose",
                "--agent",
                "harness-builder",
            )
            run_cli(
                "campaign-checkpoint-record",
                "mongoose-cli-replay",
                "--target",
                "localfuzz/c/mongoose",
                "--harness",
                "fuzz",
                "--phase",
                "input-material",
                "--tool-evidence",
                "benchmark proof fixture selected as read-only seed oracle",
                "--next-command",
                "fidelity-replay-campaign mongoose-cli-replay --project localfuzz/c/mongoose",
                "--agent",
                "corpus-manager",
            )
            replay = run_cli(
                "fidelity-replay-campaign",
                "mongoose-cli-replay",
                "--project",
                "localfuzz/c/mongoose",
                "--command-map-json",
                json.dumps({"fuzz": [sys.executable, str(harness_script), "{poc}"]}),
                "--repetitions",
                "3",
                "--timeout-seconds",
                "5",
            )
            audit = run_cli("campaign-fidelity-audit", "mongoose-cli-replay", "--project", "localfuzz/c/mongoose")
            early_completion = run_cli(
                "campaign-completion-audit",
                "mongoose-cli-replay",
                "--project",
                "localfuzz/c/mongoose",
            )
            run_cli(
                "campaign-checkpoint-record",
                "mongoose-cli-replay",
                "--target",
                "localfuzz/c/mongoose",
                "--harness",
                "fuzz",
                "--phase",
                "fuzzing",
                "--tool-evidence",
                "fidelity-replay-campaign: 1/1 verified",
                "--next-command",
                "campaign-checkpoint-record mongoose-cli-replay --phase grading",
                "--agent",
                "corpus-manager",
            )
            run_cli(
                "campaign-checkpoint-record",
                "mongoose-cli-replay",
                "--target",
                "localfuzz/c/mongoose",
                "--harness",
                "fuzz",
                "--phase",
                "grading",
                "--tool-evidence",
                "finding_recorded from verified fixture replay",
                "--next-command",
                "campaign-report mongoose-cli-replay --project localfuzz/c/mongoose",
                "--agent",
                "crash-grader",
            )
            dedupe = run_cli("finding-dedupe", "mongoose-cli-replay")
            lifecycle = run_cli("finding-lifecycle-audit", "mongoose-cli-replay")
            run_cli(
                "campaign-checkpoint-record",
                "mongoose-cli-replay",
                "--target",
                "localfuzz/c/mongoose",
                "--harness",
                "fuzz",
                "--phase",
                "dedupe",
                "--tool-evidence",
                "finding-dedupe: 1 representative group",
                "--tool-evidence",
                "finding-lifecycle-audit: ok",
                "--next-command",
                "campaign-report mongoose-cli-replay --project localfuzz/c/mongoose",
                "--agent",
                "dedupe-judge",
            )
            report = run_cli(
                "campaign-report",
                "mongoose-cli-replay",
                "--project",
                "localfuzz/c/mongoose",
                "--artifact-prefix",
                "reports/mongoose-cli-replay",
            )
            run_cli(
                "campaign-checkpoint-record",
                "mongoose-cli-replay",
                "--target",
                "localfuzz/c/mongoose",
                "--harness",
                "fuzz",
                "--phase",
                "report",
                "--tool-evidence",
                "campaign-report: REPORT.md and REPORT.json",
                "--next-command",
                "campaign-completion-audit mongoose-cli-replay --project localfuzz/c/mongoose --strict",
                "--agent",
                "reporter",
            )
            fixtures = run_cli("fidelity-list-fixtures")
            mongoose_fixture = next(
                fixture for fixture in fixtures["benchmarks"] if fixture["project"] == "mongoose" and fixture["fixture"] == "fixture_0"
            )
            finding_id = replay["cases"][0]["finding"]["finding_id"]
            patch_candidate = run_cli(
                "patch-candidate-record",
                "mongoose-cli-replay",
                "--patch-file",
                str(mongoose_fixture["patch_path"]),
                "--artifact-name",
                "reference/mongoose-fixture0.patch.diff",
                "--finding-id",
                str(finding_id),
                "--rationale",
                "read-only benchmark reference patch linked for fidelity",
                "--variant-checked",
                "fixture proof replay",
            )
            patch_required_completion = run_cli(
                "campaign-completion-audit",
                "mongoose-cli-replay",
                "--project",
                "localfuzz/c/mongoose",
            )
            run_cli(
                "campaign-checkpoint-record",
                "mongoose-cli-replay",
                "--target",
                "localfuzz/c/mongoose",
                "--harness",
                "fuzz",
                "--phase",
                "patch",
                "--tool-evidence",
                "patch-candidate-record: read-only benchmark reference patch stored",
                "--next-command",
                "campaign-completion-audit mongoose-cli-replay --project localfuzz/c/mongoose --strict",
                "--agent",
                "patch-grader",
            )
            completion = run_cli(
                "campaign-completion-audit",
                "mongoose-cli-replay",
                "--project",
                "localfuzz/c/mongoose",
            )

            self.assertEqual(replay["total_cases"], 1)
            self.assertEqual(replay["verified"], 1)
            self.assertEqual(replay["findings_recorded"], 1)
            self.assertTrue(audit["ok"], audit["blockers"])
            self.assertEqual(audit["score"]["coverage_ratio"], 1.0)
            self.assertFalse(early_completion["ok"])
            self.assertFalse(early_completion["gates"]["finding_lifecycle"]["ok"])
            self.assertFalse(early_completion["gates"]["phase_coverage"]["ok"])
            self.assertFalse(early_completion["gates"]["report_artifacts"]["ok"])
            self.assertIn("fuzzing", early_completion["gates"]["phase_coverage"]["missing_required_phases"])
            self.assertIn("report", early_completion["gates"]["phase_coverage"]["missing_required_phases"])
            self.assertEqual(len(dedupe["groups"]), 1)
            self.assertTrue(lifecycle["ok"], lifecycle["blockers"])
            self.assertEqual(lifecycle["score"]["classified_findings"], 1)
            self.assertEqual(report["report"]["summary"]["dedupe_groups"], 1)
            self.assertTrue(report["report"]["summary"]["finding_lifecycle_ok"])
            self.assertEqual(patch_candidate["candidate"]["finding_id"], finding_id)
            self.assertEqual(sorted(patch_candidate["candidate"]["changed_paths"]), ["mip/mip.c", "mongoose.c"])
            self.assertFalse(patch_required_completion["ok"])
            self.assertIn("patch", patch_required_completion["gates"]["phase_coverage"]["required_phases"])
            self.assertIn("patch", patch_required_completion["gates"]["phase_coverage"]["missing_required_phases"])
            self.assertTrue(completion["ok"], completion["blockers"])
            self.assertTrue(completion["gates"]["engine_parity"]["ok"])
            self.assertTrue(completion["gates"]["runtime_guard_runtime"]["ok"])
            self.assertTrue(completion["gates"]["fixture_validation"]["ok"])
            self.assertTrue(completion["gates"]["finding_lifecycle"]["ok"])
            self.assertTrue(completion["gates"]["phase_coverage"]["ok"])
            self.assertTrue(completion["gates"]["fixture_fidelity"]["ok"])
            self.assertTrue(completion["gates"]["report_artifacts"]["ok"])
            self.assertEqual(completion["gates"]["phase_coverage"]["missing_required_phases"], [])
            self.assertEqual(
                completion["gates"]["phase_coverage"]["required_phases"],
                ["readiness", "scope", "input-material", "fuzzing", "grading", "dedupe", "patch", "report"],
            )
            self.assertEqual(completion["gates"]["fixture_fidelity"]["score"]["coverage_ratio"], 1.0)

    def test_engine_full_completion_requires_mock_exports_and_specialist_subagents(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            harness_script = tmp_path / "mongoose_harness.py"
            source = tmp_path / "source"
            input_source = tmp_path / "input-source"
            source.mkdir()
            _write_live_harness_script(harness_script, crash_type="dynamic-stack-buffer-overflow")
            _write_patch_grade_source(source)
            _write_dictionary_generation_source(input_source)
            engine = AgenticFuzzEngine(
                data_root=tmp,
                audit_roots=(root / "src" / "agentic_fuzz_engine", plugin),
            )
            run_id = "full-e2e"

            def checkpoint(phase: str, agent: str, evidence: list[str], next_command: str, harness: str = "fuzz") -> dict[str, object]:
                return engine.call_tool(
                    "campaign_checkpoint_record",
                    {
                        "run_id": run_id,
                        "target": "localfuzz/c/mongoose",
                        "harness": harness,
                        "phase": phase,
                        "tool_evidence": evidence,
                        "blockers": [],
                        "next_command": next_command,
                        "agent": agent,
                    },
                )

            engine.call_tool("campaign_start", {"target": "localfuzz/c/mongoose", "name": run_id})
            checkpoint("readiness", "planner", ["engine-parity-audit --strict: ok"], "target-validate localfuzz/c/mongoose")
            checkpoint("scope", "harness-builder", ["target-validate: ok", "harness-list: fuzz"], "dictionary-generate")
            dictionary = engine.call_tool(
                "dictionary_generate",
                {
                    "run_id": run_id,
                    "source_dir": str(input_source),
                    "target": "localfuzz/c/mongoose",
                    "harness": "fuzz",
                },
            )
            grammar = engine.call_tool(
                "grammar_infer",
                {
                    "run_id": run_id,
                    "source_dir": str(input_source),
                    "target": "localfuzz/c/mongoose",
                    "harness": "fuzz",
                    "max_seeds": 2,
                },
            )
            concolic = engine.call_tool(
                "concolic_plan",
                {
                    "run_id": run_id,
                    "source_dir": str(input_source),
                    "target": "localfuzz/c/mongoose",
                    "harness": "fuzz",
                    "max_seeds": 2,
                },
            )
            checkpoint("input-material", "corpus-manager", ["fixture proof selected as seed oracle"], "fidelity-replay-campaign")
            checkpoint("input-material", "dictionary-generator", [f"dictionary_generate: {dictionary['artifact']['name']}"], "grammar-infer")
            checkpoint("input-material", "grammar-reverser", [f"grammar_infer: {grammar['grammar_artifact']['name']}"], "concolic-plan")
            checkpoint("input-material", "concolic-generator", [f"concolic_plan: {concolic['branch_plan_artifact']['name']}"], "fidelity-replay-campaign")

            replay = engine.call_tool(
                "fidelity_replay_campaign",
                {
                    "run_id": run_id,
                    "project": "localfuzz/c/mongoose",
                    "command_map": {"fuzz": [sys.executable, str(harness_script), "{poc}"]},
                    "timeout_seconds": 5,
                    "repetitions": 3,
                    "record_findings": True,
                },
            )
            checkpoint("fuzzing", "fuzz-finder", ["fidelity_replay_campaign: 1/1 verified"], "finding-dedupe")
            finding = replay["cases"][0]["finding"]
            checkpoint("grading", "crash-grader", [f"finding_recorded: {finding['finding_id']}"], "finding-dedupe")
            dedupe = engine.call_tool("finding_dedupe", {"run_id": run_id})
            lifecycle = engine.call_tool("finding_lifecycle_audit", {"run_id": run_id})
            checkpoint("dedupe", "dedupe-judge", ["finding_dedupe: 1 representative group", "finding_lifecycle_audit: ok"], "campaign-report")
            report = engine.call_tool(
                "campaign_report",
                {
                    "run_id": run_id,
                    "project": "localfuzz/c/mongoose",
                    "artifact_prefix": "reports/full-e2e",
                },
            )
            checkpoint("report", "reporter", ["campaign_report: REPORT.md and REPORT.json"], "patch-candidate-record")

            patch_candidate = engine.call_tool(
                "patch_candidate_record",
                {
                    "run_id": run_id,
                    "patch_content_b64": base64.b64encode(_fixed_marker_patch()).decode("ascii"),
                    "artifact_name": "fix.diff",
                    "finding_id": finding["finding_id"],
                    "rationale": "create fixed marker for harness regression",
                    "variants_checked": ["original PoV", "reattack PoV"],
                },
            )
            checkpoint("patch", "patcher", ["patch_candidate_record: fix.diff"], "patch-grade")
            patch_grade = engine.call_tool(
                "patch_grade",
                {
                    "run_id": run_id,
                    "source_dir": str(source),
                    "patch_artifact": patch_candidate["patch_artifact"]["name"],
                    "pov_artifact": finding["poc_artifact"],
                    "harness_command": [sys.executable, "harness.py", "{poc}"],
                    "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                    "build_command": [sys.executable, "build.py"],
                    "test_command": [sys.executable, "test_target.py"],
                    "reattack_artifacts": [finding["poc_artifact"]],
                    "timeout_seconds": 5,
                    "repetitions": 3,
                },
            )
            checkpoint("patch", "patch-grader", ["patch_grade: PASS"], "export-bundle-create")
            bundle = engine.call_tool("export_bundle_create", {"run_id": run_id, "project": "localfuzz/c/mongoose"})
            pov_export = engine.call_tool(
                "export_mock_api_submit_pov",
                {"run_id": run_id, "project": "localfuzz/c/mongoose", "finding_id": finding["finding_id"]},
            )
            patch_export = engine.call_tool(
                "export_mock_api_submit_patch",
                {
                    "run_id": run_id,
                    "project": "localfuzz/c/mongoose",
                    "patch_artifact": patch_candidate["patch_artifact"]["name"],
                },
            )
            sarif_export = engine.call_tool(
                "export_mock_api_submit_sarif",
                {
                    "run_id": run_id,
                    "project": "localfuzz/c/mongoose",
                    "report_artifact": report["json_artifact"]["name"],
                },
            )
            checkpoint(
                "export",
                "export-agent",
                ["export_bundle_create: ok", "mock export receipts accepted"],
                "campaign-full-completion-audit full-e2e --project localfuzz/c/mongoose --strict",
            )
            exports = engine.call_tool("export_list", {"run_id": run_id})
            missing_subsystems = engine.call_tool(
                "campaign_full_completion_audit",
                {"run_id": run_id, "project": "localfuzz/c/mongoose"},
            )
            checkpoint(
                "fuzzing",
                "native-harness",
                ["local userspace-style harness replay, crash verification, dedupe, and lifecycle evidence complete"],
                "input-generator generator handoff reviewed",
            )
            checkpoint(
                "input-material",
                "input-generator",
                ["dictionary, grammar, and concolic artifacts generated without external generator runtime"],
                "artifact-manager package and receipt review",
            )
            checkpoint(
                "export",
                "artifact-manager",
                ["export_bundle_create: ok", "mock PoV, patch, and SARIF receipts accepted"],
                "campaign-full-completion-audit full-e2e --project localfuzz/c/mongoose --strict",
            )
            completion = engine.call_tool(
                "campaign_full_completion_audit",
                {"run_id": run_id, "project": "localfuzz/c/mongoose"},
            )

            self.assertEqual(replay["verified"], 1)
            self.assertEqual(len(dedupe["groups"]), 1)
            self.assertTrue(lifecycle["ok"], lifecycle["blockers"])
            self.assertTrue(patch_grade["passed"], patch_grade)
            self.assertTrue(bundle["ok"], bundle["bundle"]["blockers"])
            self.assertTrue(pov_export["accepted"], pov_export)
            self.assertTrue(patch_export["accepted"], patch_export)
            self.assertTrue(sarif_export["accepted"], sarif_export)
            self.assertEqual(exports["counts"]["accepted"], 3)
            self.assertFalse(missing_subsystems["ok"])
            self.assertEqual(
                missing_subsystems["gates"]["subagent_orchestration"]["missing_agents"],
                ["native-harness", "input-generator", "artifact-manager"],
            )
            self.assertTrue(completion["ok"], completion["blockers"])
            self.assertTrue(completion["gates"]["export"]["ok"], completion["gates"]["export"])
            self.assertTrue(completion["gates"]["subagent_orchestration"]["ok"], completion["gates"]["subagent_orchestration"])
            self.assertIn("export", completion["gates"]["phase_coverage"]["required_phases"])
            self.assertIn("native-harness", completion["gates"]["subagent_orchestration"]["checkpoint_agents"])
            self.assertIn("input-generator", completion["gates"]["subagent_orchestration"]["checkpoint_agents"])
            self.assertIn("artifact-manager", completion["gates"]["subagent_orchestration"]["checkpoint_agents"])
            self.assertIn("export-agent", completion["gates"]["subagent_orchestration"]["checkpoint_agents"])
            self.assertEqual(completion["gates"]["fixture_fidelity"]["score"]["coverage_ratio"], 1.0)

    def test_plugin_stdio_mcp_grades_patch_ladder_in_temp_source_copy(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            source.mkdir()
            _write_patch_grade_source(source)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call("tools/call", {"name": "campaign_start", "arguments": {"target": "localfuzz/c/patch", "name": "patch-e2e"}})
                patch_candidate = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "patch_candidate_record",
                            "arguments": {
                                "run_id": "patch-e2e",
                                "artifact_name": "fix.diff",
                                "patch_content_b64": base64.b64encode(_fixed_marker_patch()).decode("ascii"),
                                "finding_id": "finding-patch-e2e",
                                "rationale": "create fixed marker for harness regression",
                                "variants_checked": ["original PoV", "reattack PoV"],
                            },
                        },
                    )
                )
                pov_artifact = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "artifact_put",
                            "arguments": {
                                "run_id": "patch-e2e",
                                "name": "pov.bin",
                                "content_b64": base64.b64encode(b"CRASH").decode("ascii"),
                            },
                        },
                    )
                )
                grade = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "patch_grade",
                            "arguments": {
                                "run_id": "patch-e2e",
                                "source_dir": str(source),
                                "patch_artifact": patch_candidate["patch_artifact"]["name"],
                                "pov_artifact": pov_artifact["name"],
                                "harness_command": [sys.executable, "harness.py", "{poc}"],
                                "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                                "build_command": [sys.executable, "build.py"],
                                "test_command": [sys.executable, "test_target.py"],
                                "reattack_artifacts": [pov_artifact["name"]],
                                "timeout_seconds": 5,
                                "repetitions": 3,
                            },
                        },
                    )
                )
                status = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "campaign_status", "arguments": {"run_id": "patch-e2e"}})
                )

                self.assertEqual(patch_candidate["candidate"]["finding_id"], "finding-patch-e2e")
                self.assertIn("fixed.txt", patch_candidate["candidate"]["changed_paths"])
                self.assertIn(patch_candidate["metadata_artifact"]["name"], status["artifacts"])
                self.assertTrue(grade["passed"])
                self.assertEqual(grade["tier"], "PASS")
                self.assertEqual(grade["evidence"]["pov"]["matches_expected"], 0)
                self.assertFalse((source / "fixed.txt").exists())
                self.assertTrue(any(event["type"] == "patch_candidate_recorded" for event in status["events"]))
                self.assertTrue(any(event["type"] == "patch_grade" for event in status["events"]))
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_cli_grades_patch_ladder(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            patch = Path(tmp) / "fix.diff"
            pov = Path(tmp) / "pov.bin"
            source.mkdir()
            _write_patch_grade_source(source)
            patch.write_bytes(_fixed_marker_patch())
            pov.write_bytes(b"CRASH")
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/patch", "--name", "patch-cli")
            patch_candidate = run_cli(
                "patch-candidate-record",
                "patch-cli",
                "--patch-file",
                str(patch),
                "--artifact-name",
                "fix.diff",
                "--finding-id",
                "finding-patch-cli",
                "--rationale",
                "create fixed marker for harness regression",
                "--variant-checked",
                "original PoV",
            )
            pov_artifact = run_cli("artifact-put", "patch-cli", "pov.bin", "--file", str(pov))
            grade = run_cli(
                "patch-grade",
                "patch-cli",
                "--source-dir",
                str(source),
                "--patch-artifact",
                str(patch_candidate["patch_artifact"]["name"]),
                "--pov-artifact",
                str(pov_artifact["name"]),
                "--harness-command-json",
                json.dumps([sys.executable, "harness.py", "{poc}"]),
                "--expected-error-token",
                "AddressSanitizer: heap-buffer-overflow",
                "--build-command-json",
                json.dumps([sys.executable, "build.py"]),
                "--test-command-json",
                json.dumps([sys.executable, "test_target.py"]),
                "--reattack-artifact",
                str(pov_artifact["name"]),
                "--timeout-seconds",
                "5",
                "--repetitions",
                "3",
            )

            self.assertEqual(patch_candidate["candidate"]["finding_id"], "finding-patch-cli")
            self.assertIn("fixed.txt", patch_candidate["candidate"]["changed_paths"])
            self.assertTrue(grade["passed"])
            self.assertEqual(grade["tier"], "PASS")
            self.assertFalse((source / "fixed.txt").exists())

    def test_plugin_cli_rejects_patch_export_without_passing_grade(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            patch = Path(tmp) / "fix.diff"
            patch.write_bytes(_fixed_marker_patch())
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/patch", "--name", "export-cli")
            patch_candidate = run_cli(
                "patch-candidate-record",
                "export-cli",
                "--patch-file",
                str(patch),
                "--artifact-name",
                "fix.diff",
                "--finding-id",
                "finding-export-cli",
                "--rationale",
                "create fixed marker for harness regression",
            )
            rejected = run_cli(
                "export-mock-api-submit-patch",
                "export-cli",
                "--project",
                "localfuzz/c/patch",
                "--patch-artifact",
                str(patch_candidate["patch_artifact"]["name"]),
            )
            exports = run_cli("export-list", "export-cli")

            self.assertFalse(rejected["accepted"])
            self.assertIn("passing patch_grade", " ".join(rejected["blockers"]))
            self.assertEqual(exports["counts"]["rejected"], 1)
            self.assertEqual(exports["rejected"][0]["kind"], "patch")

    def test_plugin_stdio_mcp_runs_agentic_fuzz_campaign_with_feedback(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            harness_script = Path(tmp) / "fuzz_harness.py"
            _write_fuzz_campaign_harness(harness_script)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call("tools/call", {"name": "campaign_start", "arguments": {"target": "localfuzz/c/fuzz", "name": "fuzz-e2e"}})
                seed = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "artifact_put",
                            "arguments": {
                                "run_id": "fuzz-e2e",
                                "name": "seed.bin",
                                "content_b64": base64.b64encode(b"seed").decode("ascii"),
                            },
                        },
                    )
                )
                fuzz = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "fuzz_campaign",
                            "arguments": {
                                "run_id": "fuzz-e2e",
                                "target": "localfuzz/c/fuzz",
                                "harness": "fuzz_harness",
                                "seed_artifacts": [seed["name"]],
                                "dictionary": ["MAGIC", "CRASH"],
                                "harness_command": [sys.executable, str(harness_script), "{poc}"],
                                "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                                "max_iterations": 12,
                                "repetitions": 3,
                                "timeout_seconds": 5,
                                "record_findings": True,
                                "stop_on_first_finding": True,
                            },
                        },
                    )
                )
                status = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "campaign_status", "arguments": {"run_id": "fuzz-e2e"}})
                )

                self.assertEqual(fuzz["verified_findings"], 1)
                self.assertGreaterEqual(fuzz["promoted_corpus"], 1)
                self.assertIn("parser.magic", fuzz["coverage_features"])
                self.assertTrue(fuzz["stopped_on_first_finding"])
                self.assertEqual(len(fuzz["findings"]), 1)
                self.assertTrue(any(event["type"] == "fuzz_campaign" for event in status["events"]))
                self.assertEqual(len(status["findings"]), 1)
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_cli_runs_agentic_fuzz_campaign_with_feedback(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            harness_script = Path(tmp) / "fuzz_harness.py"
            seed_path = Path(tmp) / "seed.bin"
            _write_fuzz_campaign_harness(harness_script)
            seed_path.write_bytes(b"seed")
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = str(root)
            env["CLAUDE_PLUGIN_DATA"] = tmp

            def run_cli(*args: str) -> dict[str, object]:
                result = subprocess.run(
                    [str(plugin / "scripts" / "run-engine.sh"), *args],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)

            run_cli("campaign-start", "localfuzz/c/fuzz", "--name", "fuzz-cli")
            seed = run_cli("artifact-put", "fuzz-cli", "seed.bin", "--file", str(seed_path))
            fuzz = run_cli(
                "fuzz-campaign",
                "fuzz-cli",
                "--target",
                "localfuzz/c/fuzz",
                "--harness",
                "fuzz_harness",
                "--seed-artifact",
                str(seed["name"]),
                "--dictionary-json",
                json.dumps(["MAGIC", "CRASH"]),
                "--harness-command-json",
                json.dumps([sys.executable, str(harness_script), "{poc}"]),
                "--expected-error-token",
                "AddressSanitizer: heap-buffer-overflow",
                "--max-iterations",
                "12",
                "--repetitions",
                "3",
                "--timeout-seconds",
                "5",
                "--stop-on-first-finding",
            )

            self.assertEqual(fuzz["verified_findings"], 1)
            self.assertGreaterEqual(fuzz["promoted_corpus"], 1)
            self.assertIn("parser.magic", fuzz["coverage_features"])

    def test_plugin_stdio_mcp_feedback_rounds_requeue_promoted_corpus(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            harness_script = Path(tmp) / "feedback_harness.py"
            _write_feedback_scheduler_harness(harness_script)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                rpc.call("initialize")
                rpc.call(
                    "tools/call",
                    {"name": "campaign_start", "arguments": {"target": "localfuzz/c/scheduler", "name": "scheduler-e2e"}},
                )
                seed = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "artifact_put",
                            "arguments": {
                                "run_id": "scheduler-e2e",
                                "name": "seed.bin",
                                "content_b64": base64.b64encode(b"seed").decode("ascii"),
                            },
                        },
                    )
                )
                fuzz = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "fuzz_campaign",
                            "arguments": {
                                "run_id": "scheduler-e2e",
                                "target": "localfuzz/c/scheduler",
                                "harness": "feedback_harness",
                                "seed_artifacts": [seed["name"]],
                                "dictionary": ["MAGIC", "CRASH"],
                                "harness_command": [sys.executable, str(harness_script), "{poc}"],
                                "expected_error_token": "AddressSanitizer: heap-buffer-overflow",
                                "max_iterations": 12,
                                "feedback_rounds": 2,
                                "repetitions": 3,
                                "timeout_seconds": 5,
                                "record_findings": True,
                                "stop_on_first_finding": True,
                            },
                        },
                    )
                )

                self.assertEqual(fuzz["scheduler"]["feedback_rounds"], 2)
                self.assertEqual(fuzz["rounds_executed"], 2)
                self.assertEqual(fuzz["verified_findings"], 1)
                self.assertEqual(fuzz["iterations"][-1]["round"], 1)
                self.assertIn("parser.magic", fuzz["coverage_features"])
                self.assertIn(fuzz["rounds"][0]["promoted"][0]["artifact"], fuzz["iterations"][-1]["parent_artifacts"])
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_plugin_stdio_mcp_end_to_end_replays_enabled_fixture_fixtures(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root / "src")
            env["CLAUDE_PLUGIN_DATA"] = tmp
            proc = subprocess.Popen(
                [str(plugin / "scripts" / "mcp-server.sh")],
                cwd=root,
                env=env,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                rpc = _RpcClient(self, proc)
                init = rpc.call("initialize")
                self.assertEqual(init["serverInfo"]["name"], "agentic-fuzz-engine")

                tools = rpc.call("tools/list")
                tool_names = {tool["name"] for tool in tools["tools"]}
                self.assertIn("artifact_put", tool_names)
                self.assertIn("finding_record", tool_names)

                fixtures = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "fidelity_list_fixtures", "arguments": {"include_disabled": False}})
                )["benchmarks"]
                self.assertEqual(len(fixtures), 14)

                campaign = _tool_body_from_result(
                    rpc.call(
                        "tools/call",
                        {
                            "name": "campaign_start",
                            "arguments": {"target": "localfuzz/c/fidelity-replay", "name": "e2e-fidelity"},
                        },
                    )
                )
                self.assertEqual(campaign["run_id"], "e2e-fidelity")

                for benchmark in fixtures:
                    proof_bytes = Path(str(benchmark["proof_path"])).read_bytes()
                    artifact_name = f"{benchmark['project']}_{benchmark['fixture']}_proof.bin"
                    artifact = _tool_body_from_result(
                        rpc.call(
                            "tools/call",
                            {
                                "name": "artifact_put",
                                "arguments": {
                                    "run_id": "e2e-fidelity",
                                    "name": artifact_name,
                                    "content_b64": base64.b64encode(proof_bytes).decode("ascii"),
                                },
                            },
                        )
                    )
                    self.assertEqual(artifact["sha256"], benchmark["proof_sha256"])
                    crash_output = _synthetic_asan_trace(benchmark)
                    finding = _tool_body_from_result(
                        rpc.call(
                            "tools/call",
                            {
                                "name": "finding_record",
                                "arguments": {
                                    "run_id": "e2e-fidelity",
                                    "target": benchmark["target"],
                                    "harness": benchmark["harness"],
                                    "sanitizer": benchmark["sanitizer"],
                                    "error_token": benchmark["error_token"],
                                    "crash_output": crash_output,
                                    "poc_artifact": artifact["name"],
                                },
                            },
                        )
                    )
                    self.assertRegex(str(finding["signature"]), r"^[0-9a-f]{24}$")

                status = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "campaign_status", "arguments": {"run_id": "e2e-fidelity"}})
                )
                dedupe = _tool_body_from_result(
                    rpc.call("tools/call", {"name": "finding_dedupe", "arguments": {"run_id": "e2e-fidelity"}})
                )
                resource = rpc.call("resources/read", {"uri": "agentic-fuzz://fidelity/reference-fixtures"})

                self.assertEqual(len(status["artifacts"]), 14)
                self.assertEqual(len(status["findings"]), 14)
                self.assertEqual(len(dedupe["groups"]), 14)
                self.assertIn("binutils", resource["contents"][0]["text"])
            finally:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
                stderr = proc.stderr.read() if proc.stderr else ""
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(proc.returncode, 0, stderr)

    def test_claude_code_validates_agentic_fuzz_plugin_manifest(self) -> None:
        if shutil.which("claude") is None:
            self.skipTest("Claude Code CLI is not installed")
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            ["claude", "plugin", "validate", "claude-plugin/agentic-fuzz-engine"],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


def _tool_body(response: dict[str, object]) -> dict[str, object]:
    result = response["result"]
    assert isinstance(result, dict)
    content = result["content"]
    assert isinstance(content, list)
    first = content[0]
    assert isinstance(first, dict)
    return json.loads(str(first["text"]))


def _tool_body_from_result(result: dict[str, object]) -> dict[str, object]:
    content = result["content"]
    assert isinstance(content, list)
    first = content[0]
    assert isinstance(first, dict)
    return json.loads(str(first["text"]))


def _synthetic_asan_trace(benchmark: dict[str, object]) -> str:
    token = str(benchmark["error_token"])
    header = token if token.startswith("ERROR:") else f"ERROR: {token}"
    function = f"{benchmark['project']}_{benchmark['fixture']}_{benchmark['harness']}_top".replace("-", "_")
    return "\n".join(
        [
            f"==1=={header} on address 0x41414141",
            f"    #0 0xaaaa in {function} /src/{benchmark['project']}/{benchmark['harness']}.c:42",
            f"    #1 0xbbbb in LLVMFuzzerTestOneInput /src/{benchmark['project']}/fuzz_driver.c:12",
            f"SUMMARY: {token} /src/{benchmark['project']}/{benchmark['harness']}.c:42 in {function}",
        ]
    )


def _dedupe_trace(function: str) -> str:
    return "\n".join(
        [
            "==3==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x41414141",
            f"    #0 0xaaaa in {function} /src/dedupe/parser.c:21",
            "    #1 0xbbbb in LLVMFuzzerTestOneInput /src/dedupe/fuzz.c:4",
            f"SUMMARY: AddressSanitizer: heap-buffer-overflow /src/dedupe/parser.c:21 in {function}",
        ]
    )


def _write_live_harness_script(path: Path, *, crash_type: str = "heap-buffer-overflow") -> None:
    path.write_text(
        "\n".join(
            [
                "import sys",
                "data = open(sys.argv[1], 'rb').read()",
                "if data:",
                f"    sys.stderr.write('==9==ERROR: AddressSanitizer: {crash_type} on address 0x41414141\\n')",
                "    sys.stderr.write('    #0 0xaaaa in live_parse /src/live/parser.c:7\\n')",
                "    sys.stderr.write('    #1 0xbbbb in LLVMFuzzerTestOneInput /src/live/fuzz.c:3\\n')",
                f"    sys.stderr.write('SUMMARY: AddressSanitizer: {crash_type} /src/live/parser.c:7 in live_parse\\n')",
                "    raise SystemExit(134)",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_flaky_harness_script(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "import pathlib, sys",
                "data = open(sys.argv[1], 'rb').read()",
                "counter = pathlib.Path(sys.argv[2])",
                "count = int(counter.read_text()) if counter.exists() else 0",
                "counter.write_text(str(count + 1))",
                "if data and count < 2:",
                "    sys.stderr.write('==2==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x41414141\\n')",
                "    sys.stderr.write('    #0 0xaaaa in flaky_parse /src/flaky/parser.c:6\\n')",
                "    sys.stderr.write('    #1 0xbbbb in LLVMFuzzerTestOneInput /src/flaky/fuzz.c:3\\n')",
                "    sys.stderr.write('SUMMARY: AddressSanitizer: heap-buffer-overflow /src/flaky/parser.c:6 in flaky_parse\\n')",
                "    raise SystemExit(134)",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_dedupe_harness(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "import sys",
                "data = open(sys.argv[1], 'rb').read()",
                "if b'CRASH' in data:",
                "    sys.stderr.write('==4==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x41414141\\n')",
                "    sys.stderr.write('    #0 0xaaaa in dedupe_parse /src/dedupe/parser.c:21\\n')",
                "    sys.stderr.write('    #1 0xbbbb in LLVMFuzzerTestOneInput /src/dedupe/fuzz.c:4\\n')",
                "    sys.stderr.write('SUMMARY: AddressSanitizer: heap-buffer-overflow /src/dedupe/parser.c:21 in dedupe_parse\\n')",
                "    raise SystemExit(134)",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_minimization_harness(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "import sys",
                "data = open(sys.argv[1], 'rb').read()",
                "if b'CRASH' in data:",
                "    sys.stderr.write('==5==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x41414141\\n')",
                "    sys.stderr.write('    #0 0xaaaa in minimize_parse /src/minimize/parser.c:17\\n')",
                "    sys.stderr.write('    #1 0xbbbb in LLVMFuzzerTestOneInput /src/minimize/fuzz.c:4\\n')",
                "    sys.stderr.write('SUMMARY: AddressSanitizer: heap-buffer-overflow /src/minimize/parser.c:17 in minimize_parse\\n')",
                "    raise SystemExit(134)",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_discovery_target(path: Path) -> None:
    (path / ".localfuzz").mkdir(parents=True)
    (path / "tools").mkdir()
    (path / "fuzz").mkdir()
    (path / "seed_corpus").mkdir()
    (path / ".localfuzz" / "config.yaml").write_text(
        "\n".join(
            [
                "harness_files:",
                "  - name: py_harness",
                "    path: tools/fuzz_driver.py",
                "  - name: native_harness",
                "    path: fuzz/native_harness.c",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (path / "tools" / "fuzz_driver.py").write_text(
        "import sys\nraise SystemExit(0 if sys.argv[1:] else 1)\n",
        encoding="utf-8",
    )
    (path / "fuzz" / "native_harness.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size ? data[0] : 0; }\n",
        encoding="utf-8",
    )
    (path / "Makefile").write_text(
        "all:\n"
        "\t@mkdir -p build\n"
        "\t@printf '#!/bin/sh\\nexit 0\\n' > build/native_harness\n"
        "\t@chmod +x build/native_harness\n",
        encoding="utf-8",
    )
    (path / "tokens.dict").write_text('"MAGIC"\n"CRASH"\n', encoding="utf-8")
    (path / "seed_corpus" / "seed.bin").write_bytes(b"seed")


def _write_dictionary_generation_source(path: Path) -> None:
    path.mkdir(parents=True)
    (path / "parser.c").write_text(
        "\n".join(
            [
                "#include <string.h>",
                "int parse_input(const unsigned char *data, unsigned long size) {",
                "  if (size >= 5 && memcmp(data, \"MAGIC\", 5) == 0) {",
                "    return 1;",
                "  }",
                "  if (size >= 5 && memmem(data, size, \"CRASH\", 5) != 0) {",
                "    return 2;",
                "  }",
                "  if (size >= 4 && strcmp((const char *)data, \"PING\") == 0) {",
                "    return 3;",
                "  }",
                "  return 0;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_patch_grade_source(path: Path) -> None:
    (path / "harness.py").write_text(
        "\n".join(
            [
                "import pathlib, sys",
                "data = open(sys.argv[1], 'rb').read()",
                "if data and not pathlib.Path('fixed.txt').exists():",
                "    sys.stderr.write('==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x41414141\\n')",
                "    sys.stderr.write('    #0 0xaaaa in parse_patch /src/patch/parser.c:4\\n')",
                "    sys.stderr.write('SUMMARY: AddressSanitizer: heap-buffer-overflow /src/patch/parser.c:4 in parse_patch\\n')",
                "    raise SystemExit(134)",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (path / "build.py").write_text(
        "import pathlib, sys\nraise SystemExit(0 if pathlib.Path('fixed.txt').exists() else 1)\n",
        encoding="utf-8",
    )
    (path / "test_target.py").write_text(
        "import pathlib, sys\nraise SystemExit(0 if pathlib.Path('fixed.txt').read_text().strip() == 'fixed' else 1)\n",
        encoding="utf-8",
    )


def _write_fuzz_campaign_harness(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "import sys",
                "data = open(sys.argv[1], 'rb').read()",
                "if b'CRASH' in data:",
                "    sys.stderr.write('==8==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x41414141\\n')",
                "    sys.stderr.write('    #0 0xaaaa in fuzz_parse /src/fuzz/parser.c:9\\n')",
                "    sys.stderr.write('    #1 0xbbbb in LLVMFuzzerTestOneInput /src/fuzz/fuzz.c:3\\n')",
                "    sys.stderr.write('SUMMARY: AddressSanitizer: heap-buffer-overflow /src/fuzz/parser.c:9 in fuzz_parse\\n')",
                "    raise SystemExit(134)",
                "if b'MAGIC' in data:",
                "    print('COVERAGE: parser.magic')",
                "if data.startswith(b'MAGIC'):",
                "    print('EDGE: parser.magic_prefix')",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_concolic_harness(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "import sys",
                "data = open(sys.argv[1], 'rb').read()",
                "if b'MAGIC' in data:",
                "    print('COVERAGE: parser.magic')",
                "if b'MAGICCRASH' in data:",
                "    sys.stderr.write('==10==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x41414141\\n')",
                "    sys.stderr.write('    #0 0xaaaa in concolic_parse /src/concolic/parser.c:9\\n')",
                "    sys.stderr.write('    #1 0xbbbb in LLVMFuzzerTestOneInput /src/concolic/fuzz.c:3\\n')",
                "    sys.stderr.write('SUMMARY: AddressSanitizer: heap-buffer-overflow /src/concolic/parser.c:9 in concolic_parse\\n')",
                "    raise SystemExit(134)",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_feedback_scheduler_harness(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "import sys",
                "data = open(sys.argv[1], 'rb').read()",
                "if b'MAGIC' in data:",
                "    print('COVERAGE: parser.magic')",
                "if b'MAGICCRASH' in data:",
                "    sys.stderr.write('==6==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x41414141\\n')",
                "    sys.stderr.write('    #0 0xaaaa in scheduled_parse /src/scheduler/parser.c:11\\n')",
                "    sys.stderr.write('SUMMARY: AddressSanitizer: heap-buffer-overflow /src/scheduler/parser.c:11 in scheduled_parse\\n')",
                "    raise SystemExit(134)",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _fixed_marker_patch() -> bytes:
    return (
        "diff --git a/fixed.txt b/fixed.txt\n"
        "new file mode 100644\n"
        "index 0000000..45b983b\n"
        "--- /dev/null\n"
        "+++ b/fixed.txt\n"
        "@@ -0,0 +1 @@\n"
        "+fixed\n"
    ).encode("utf-8")


class _RpcClient:
    def __init__(self, test: unittest.TestCase, proc: subprocess.Popen[str]) -> None:
        self.test = test
        self.proc = proc
        self.next_id = 1

    def call(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        msg_id = self.next_id
        self.next_id += 1
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        self.test.assertTrue(line, f"no MCP response for {method}")
        response = json.loads(line)
        self.test.assertEqual(response.get("id"), msg_id)
        self.test.assertNotIn("error", response, response.get("error"))
        result = response["result"]
        assert isinstance(result, dict)
        return result


if __name__ == "__main__":
    unittest.main()

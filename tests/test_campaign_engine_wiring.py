from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class CampaignEngineWiringTests(unittest.TestCase):
    def _engine(self, root: Path):
        from agentic_fuzz_engine.engine import AgenticFuzzEngine

        return AgenticFuzzEngine(data_root=root / "engine-data")

    def test_public_tools_are_advisory_and_do_not_expose_raw_sql(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(Path(tmp))
            specs = {spec["name"]: spec for spec in engine.tool_specs()}
        expected = {
            "fork_scan", "entry_scan", "differential_run", "sanitizer_build",
            "sanitizer_sweep", "candidate_scoring", "campaign_db",
            "schedule_plan", "campaign_context",
        }
        self.assertTrue(expected.issubset(specs))
        self.assertNotIn("query", specs["campaign_db"]["inputSchema"]["properties"])
        self.assertIn("intentionally unavailable", specs["campaign_db"]["description"])
        self.assertIn("never", specs["candidate_scoring"]["description"])
        self.assertIn("never", specs["schedule_plan"]["description"])
        self.assertIn("do not prove", specs["fork_scan"]["description"])
        command_schema = specs["differential_run"]["inputSchema"]["properties"]["commands"]
        self.assertEqual(command_schema["items"]["items"]["type"], "string")

    def test_discovery_tools_dispatch_to_bounded_scanners(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            (source / "main.cc").write_text("int main() { return 0; }\n", encoding="utf-8")
            engine = self._engine(root)

            entry = engine.call_tool(
                "entry_scan",
                {
                    "source_root": str(source),
                    "out": str(root / "entries.jsonl"),
                    "workspace_root": str(root),
                },
            )
            self.assertTrue(entry["ok"], entry)
            self.assertEqual(json.loads((root / "entries.jsonl").read_text())["entry_kind"], "program-main")

            manifests = root / "repo"
            manifests.mkdir()
            (manifests / "packages.txt").write_text("libcodec=1.0-vpatch\n", encoding="utf-8")
            fork = engine.call_tool(
                "fork_scan",
                {
                    "source_root": str(manifests),
                    "out": str(root / "forks.jsonl"),
                    "vendor_markers": ["vpatch"],
                    "manifest_globs": ["packages.txt"],
                    "dpkg_info_dir": str(root / "missing-dpkg"),
                    "workspace_root": str(root),
                },
            )
            self.assertTrue(fork["ok"], fork)
            self.assertEqual(json.loads((root / "forks.jsonl").read_text())["package"], "libcodec")

    def test_differential_requires_an_array_of_argv_arrays(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(Path(tmp))
            with self.assertRaisesRegex(ValueError, "array of non-empty argv arrays"):
                engine.call_tool(
                    "differential_run",
                    {"target": "demo", "commands": ["python3", "replay.py"], "workspace_root": tmp},
                )
            with self.assertRaisesRegex(ValueError, "auto must be a boolean"):
                engine.call_tool(
                    "differential_run",
                    {"target": "demo", "commands": [], "auto": "false", "workspace_root": tmp},
                )

    def test_scoring_and_database_dispatch_use_typed_named_operations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = self._engine(root)
            calibrated = engine.call_tool(
                "candidate_scoring",
                {
                    "action": "calibrate",
                    "labels": [{"score": 0.8, "positive": True}, {"score": 0.2, "positive": False}],
                },
            )
            self.assertTrue(calibrated["ok"], calibrated)
            synced = engine.call_tool("campaign_db", {"action": "sync", "workspace_root": str(root)})
            self.assertTrue(synced["ok"], synced)
            report = engine.call_tool(
                "campaign_db",
                {"action": "report", "report": "summary", "workspace_root": str(root)},
            )
            self.assertTrue(report["ok"], report)
            self.assertIn("counts", report)
            unknown = engine.call_tool(
                "campaign_db",
                {"action": "report", "report": "SELECT * FROM candidates", "workspace_root": str(root)},
            )
            self.assertFalse(unknown["ok"])

    def test_cli_preserves_structured_argv_and_declared_environment(self) -> None:
        from agentic_fuzz_engine import cli
        from agentic_fuzz_engine.engine import AgenticFuzzEngine

        output = io.StringIO()
        with mock.patch.object(AgenticFuzzEngine, "call_tool", autospec=True, return_value={"ok": True}) as call:
            with contextlib.redirect_stdout(output):
                exit_code = cli.main(
                    [
                        "differential-run", "demo",
                        "--command-json", '["python3", "replay one.py", "{input}"]',
                        "--command-json", '["python3", "replay two.py", "{input}"]',
                        "--label", "one", "--label", "two",
                        "--env", "CUSTOM_BUILD_FLAG=enabled",
                    ]
                )
        self.assertEqual(exit_code, 0)
        _, tool_name, payload = call.call_args.args
        self.assertEqual(tool_name, "differential_run")
        self.assertEqual(payload["commands"][0][1], "replay one.py")
        self.assertEqual(payload["declared_env"], {"CUSTOM_BUILD_FLAG": "enabled"})

    def test_cli_helpers_reject_ambiguous_argv_and_environment(self) -> None:
        from agentic_fuzz_engine.cli import _load_json_argv, _parse_env_pairs

        with self.assertRaisesRegex(ValueError, "argv array"):
            _load_json_argv('"python3 replay.py"', key="--command-json")
        with self.assertRaisesRegex(ValueError, "unique"):
            _parse_env_pairs(["FLAG=one", "FLAG=two"])


if __name__ == "__main__":
    unittest.main()

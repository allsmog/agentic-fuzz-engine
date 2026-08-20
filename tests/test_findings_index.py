from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.findings_index import (
    collect_target_findings,
    fold_index,
    index_path,
    load_index,
)
from agentic_fuzz_engine.state import EngineState

CRASH_OUTPUT = """\
==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010 at pc 0x400b12
READ of size 8 at 0x602000000010 thread T0
    #0 0x51fa22 in ParsePieces /work/src/pkg/package.cpp:147
    #1 0x51fb44 in Initialize /work/src/pkg/package.cpp:218
"""


class FindingsIndexTest(unittest.TestCase):
    def test_recorded_events_mirror_and_survive_run_removal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = EngineState(tmp)
            state.campaign_start("localfuzz/c/demo", name="run-a")
            state.finding_record(
                "run-a",
                target="localfuzz/c/demo",
                harness="demo",
                sanitizer="address",
                error_token="heap-buffer-overflow",
                crash_output=CRASH_OUTPUT,
                verified=True,
                reproductions=3,
            )
            self.assertTrue(index_path(tmp).is_file())
            rows = load_index(tmp, target="localfuzz/c/demo")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["event"], "recorded")
            self.assertTrue(rows[0]["finding_id"].startswith("finding-"))
            self.assertNotIn("crash_output", rows[0])
            self.assertIn("ParsePieces", rows[0]["crash_excerpt"])

            # The index answers after the run dir is gone — the whole point.
            import shutil

            shutil.rmtree(Path(tmp) / "runs" / "run-a")
            rows = load_index(tmp, target="localfuzz/c/demo")
            self.assertEqual(len(rows), 1)

    def test_fold_reduces_lifecycle_to_latest_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = EngineState(tmp)
            state.campaign_start("localfuzz/c/demo", name="run-a")
            finding = state.finding_record(
                "run-a",
                target="localfuzz/c/demo",
                harness="demo",
                sanitizer="address",
                error_token="heap-buffer-overflow",
                crash_output=CRASH_OUTPUT,
                verified=True,
            )
            state.event_append(
                "run-a",
                "finding_classified",
                {"signature": finding["signature"], "target": "localfuzz/c/demo",
                 "harness": "demo", "verdict": "NEW", "reason": "first of its group"},
            )
            state.event_append(
                "run-a",
                "finding_dedupe",
                {"groups": 1, "representatives": [finding["finding_id"]]},
            )
            folded = fold_index(load_index(tmp))
            self.assertEqual(len(folded), 1)
            entry = folded[0]
            self.assertEqual(entry["finding_id"], finding["finding_id"])
            self.assertTrue(entry["verified"])
            self.assertEqual(entry["classification"], "NEW")
            self.assertTrue(entry["dedupe_representative"])
            self.assertEqual(entry["runs"], ["run-a"])

    def test_collect_target_findings_spans_runs_and_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = EngineState(tmp)
            state.campaign_start("localfuzz/c/demo", name="run-live")
            live = state.finding_record(
                "run-live",
                target="localfuzz/c/demo",
                harness="demo",
                sanitizer="address",
                error_token="heap-buffer-overflow",
                crash_output=CRASH_OUTPUT,
                verified=True,
            )
            # Simulate an archived (pruned) run holding a different finding.
            archived_dir = Path(tmp) / "archive" / "runs" / "run-old"
            archived_dir.mkdir(parents=True)
            other = dict(live)
            other["finding_id"] = "finding-deadbeef"
            other["signature"] = "deadbeef"
            other["error_token"] = "heap-use-after-free"
            (archived_dir / "findings.jsonl").write_text(json.dumps(other) + "\n", encoding="utf-8")

            findings = collect_target_findings(tmp, "localfuzz/c/demo")
            ids = {item["finding_id"] for item in findings}
            self.assertEqual(ids, {live["finding_id"], "finding-deadbeef"})
            sources = {item["source_run"] for item in findings}
            self.assertEqual(sources, {"run-live", "run-old"})

            grouped = state.finding_dedupe_across("localfuzz/c/demo")
            self.assertTrue(grouped["across_runs"])
            self.assertEqual(sorted(grouped["source_runs"]), ["run-live", "run-old"])
            self.assertGreaterEqual(len(grouped["groups"]), 1)

    def test_duplicate_finding_keeps_richest_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = EngineState(tmp)
            state.campaign_start("localfuzz/c/demo", name="run-a")
            unverified = state.finding_record(
                "run-a",
                target="localfuzz/c/demo",
                harness="demo",
                sanitizer="address",
                error_token="heap-buffer-overflow",
                crash_output=CRASH_OUTPUT,
            )
            state.campaign_start("localfuzz/c/demo", name="run-b")
            state.finding_record(
                "run-b",
                target="localfuzz/c/demo",
                harness="demo",
                sanitizer="address",
                error_token="heap-buffer-overflow",
                crash_output=CRASH_OUTPUT,
                verified=True,
                reproductions=3,
            )
            findings = collect_target_findings(tmp, "localfuzz/c/demo")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["finding_id"], unverified["finding_id"])
            self.assertTrue(findings[0]["verified"])
            self.assertEqual(findings[0]["source_run"], "run-b")


if __name__ == "__main__":
    unittest.main()

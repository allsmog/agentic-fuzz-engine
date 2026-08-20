from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.engine import RESERVED_EVENT_TYPES, AgenticFuzzEngine

CRASH_OUTPUT = """\
==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010 at pc 0x400b12
WRITE of size 8 at 0x602000000010 thread T0
    #0 0x51fa22 in CopyBlock /work/src/codec/block.cpp:88
    #1 0x51fb44 in DecodeExtent /work/src/codec/extent.cpp:141
"""


class FindingRecordGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.engine = AgenticFuzzEngine(data_root=Path(self._tmp.name) / "state")
        start = self.engine.call_tool("campaign_start", {"target": "localfuzz/c/demo"})
        self.run_id = str(start["run_id"])

    def _record(self, **overrides):
        args = {
            "run_id": self.run_id,
            "target": "localfuzz/c/demo",
            "harness": "demo",
            "error_token": "heap-buffer-overflow",
            "crash_output": CRASH_OUTPUT,
            "poc_artifact": "povs/demo.bin",
            "verified": True,
        }
        args.update(overrides)
        return self.engine.call_tool("finding_record", args)

    def test_verified_claim_without_evidence_is_rejected(self) -> None:
        result = self._record()

        self.assertFalse(result["ok"])
        self.assertFalse(result["recorded"])
        self.assertTrue(any("verification evidence" in blocker for blocker in result["blockers"]))
        self.assertEqual(self.engine.state.finding_list(self.run_id), [])
        rejected = [e for e in self.engine.state.event_list(self.run_id) if e["type"] == "finding_record_rejected"]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["payload"]["poc_artifact"], "povs/demo.bin")

    def test_verified_claim_without_poc_artifact_is_rejected(self) -> None:
        result = self._record(poc_artifact=None)

        self.assertFalse(result["ok"])
        self.assertTrue(any("PoV artifact" in blocker for blocker in result["blockers"]))

    def test_unverified_record_still_allowed(self) -> None:
        result = self._record(verified=None)

        self.assertIn("finding_id", result)
        self.assertEqual(len(self.engine.state.finding_list(self.run_id)), 1)

    def test_engine_emitted_evidence_unlocks_verified_record(self) -> None:
        # Simulate the engine-internal verification path (harness_run emits
        # this event via state directly after observing the crash).
        self.engine.state.event_append(
            self.run_id,
            "harness_run",
            {
                "target": "localfuzz/c/demo",
                "harness": "demo",
                "artifact": "povs/demo.bin",
                "verified": True,
                "crashes": 3,
                "matches_expected": 3,
                "observed_error_token": "heap-buffer-overflow",
            },
        )

        result = self._record()

        self.assertIn("finding_id", result)
        finding = self.engine.state.finding_list(self.run_id)[0]
        self.assertTrue(finding["verified"])
        self.assertEqual(finding["crash_state"], ["CopyBlock", "DecodeExtent"])
        self.assertTrue(finding["root_signature"])

    def test_evidence_for_other_artifact_does_not_unlock(self) -> None:
        self.engine.state.event_append(
            self.run_id,
            "harness_run",
            {
                "target": "localfuzz/c/demo",
                "harness": "demo",
                "artifact": "povs/other.bin",
                "verified": True,
                "crashes": 3,
                "matches_expected": 3,
            },
        )

        result = self._record()

        self.assertFalse(result["ok"])

    def test_reserved_event_types_cannot_be_forged(self) -> None:
        for event_type in ("finding_verified", "harness_run", "finding_graded"):
            with self.subTest(event_type=event_type):
                result = self.engine.call_tool(
                    "event_append",
                    {"run_id": self.run_id, "event_type": event_type, "payload": {"verified": True}},
                )
                self.assertFalse(result["ok"])
        self.assertIn("finding_verified", RESERVED_EVENT_TYPES)

    def test_unreserved_event_types_still_append(self) -> None:
        result = self.engine.call_tool(
            "event_append",
            {"run_id": self.run_id, "event_type": "duplicate_rationale", "payload": {"note": "dup of finding-x"}},
        )
        self.assertEqual(result["type"], "duplicate_rationale")

    def test_internal_record_path_bypasses_guard(self) -> None:
        # crash_import/harness_run/finding_grade record through
        # _classify_verify_and_record -> state.finding_record directly; the
        # guard must not break that path.
        artifact = self.engine.call_tool(
            "artifact_put",
            {
                "run_id": self.run_id,
                "name": "povs/internal.bin",
                "content_b64": base64.b64encode(b"AAAA").decode("ascii"),
            },
        )
        recorded = self.engine.state.finding_record(
            self.run_id,
            target="localfuzz/c/demo",
            harness="demo",
            sanitizer="address",
            error_token="heap-buffer-overflow",
            crash_output=CRASH_OUTPUT,
            poc_artifact=artifact["name"],
            reproductions=3,
            verified=True,
        )
        self.assertIn("finding_id", recorded)


if __name__ == "__main__":
    unittest.main()

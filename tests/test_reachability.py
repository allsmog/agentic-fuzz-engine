from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.reachability import finding_reachability
from agentic_fuzz_engine.reporting import build_campaign_report
from agentic_fuzz_engine.state import EngineState

CRASH = """\
==11==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010 at pc 0x400b12
READ of size 8 at 0x602000000010 thread T0
    #0 0x51fa22 in ReverseChain {src}/ops.cpp:30
"""

OPS_CPP = """\
#include "flags.h"
DEFINE_bool(use_digest_index, true, "route reverses through fingerprints");

int ReverseChain(const Chain& chain) {
  if (FLAGS_use_digest_index) {
    return ReverseWithFingerprints(chain);
  }
  return plain_reverse(chain);  // line 8
}
"""

CALLER_CPP = """\
void Simulate() {
  ReverseChain(chain);
}
"""


def _record(state: EngineState, src: Path) -> dict:
    state.campaign_start("localfuzz/c/demo", name="run-a")
    return state.finding_record(
        "run-a",
        target="localfuzz/c/demo",
        harness="demo",
        sanitizer="address",
        error_token="heap-buffer-overflow",
        crash_output=CRASH.format(src=src),
        verified=True,
    )


class ReachabilityTest(unittest.TestCase):
    def _setup(self, tmp: str) -> tuple[Path, Path, EngineState, dict]:
        root = Path(tmp)
        src = root / "src"
        src.mkdir()
        # Frame path in the crash is absolute; write the file there.
        ops = src / "ops.cpp"
        ops.write_text(OPS_CPP, encoding="utf-8")
        (src / "caller.cpp").write_text(CALLER_CPP, encoding="utf-8")
        state = EngineState(root / "data")
        finding = _record(state, src)
        return root, src, state, finding

    def test_block_assembles_callers_flags_and_services(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, src, state, finding = self._setup(tmp)
            services = root / "work" / "services.json"
            services.parent.mkdir(parents=True)
            services.write_text(
                json.dumps({"services": [{"name": "demo_main", "binds": "localhost",
                                          "targets": ["demo"], "flags": {"use_digest_index": "true"}}]}),
                encoding="utf-8",
            )
            result = finding_reachability(
                state=state,
                run_id="run-a",
                finding_id=finding["finding_id"],
                entry_symbol="ReverseChain",
                workspace_root=root,
                source_dir=src,
            )
            self.assertTrue(result["ok"], result.get("blockers"))
            block = result["reachability"]
            self.assertEqual(block["verdict"], "unknown")  # judgment stays with the operator
            caller_files = {item["file"] for item in block["production_callers"]}
            self.assertIn("caller.cpp", caller_files)
            flags = {item["flag"]: item["default"] for item in block["flag_gates"]}
            self.assertEqual(flags.get("use_digest_index"), "true")
            self.assertEqual(block["bind_surface"], "localhost")

    def test_explicit_verdict_recorded_and_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, src, state, finding = self._setup(tmp)
            result = finding_reachability(
                state=state,
                run_id="run-a",
                finding_id=finding["finding_id"],
                entry_symbol="ReverseChain",
                workspace_root=root,
                source_dir=src,
                verdict="flag-gated",
                note="production default routes around the sink",
            )
            self.assertEqual(result["reachability"]["verdict"], "flag-gated")
            from agentic_fuzz_engine.findings_index import fold_index, load_index

            folded = fold_index(load_index(state.data_root, finding_id=finding["finding_id"]))
            self.assertEqual(folded[0]["reachability"]["verdict"], "flag-gated")

    def test_report_gate_block_fails_coverage_until_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, src, state, finding = self._setup(tmp)
            dedupe = state.finding_dedupe("run-a")

            def _build(gate):
                return build_campaign_report(
                    run_id="run-a",
                    project=None,
                    campaign={"target": "localfuzz/c/demo", "status": "started"},
                    findings=state.finding_list("run-a"),
                    artifacts=[],
                    checkpoints=[],
                    phase_audit={"coverage_ok": True},
                    finding_lifecycle_audit={"ok": True},
                    fidelity_audit={"ok": True, "score": {}},
                    dedupe=dedupe,
                    reachability_gate=gate,
                )

            blocked = _build({"mode": "block", "verdicts": {}})
            summary = blocked["report"]["summary"]
            self.assertFalse(summary["phase_coverage_ok"])
            self.assertIn("blocker", summary["reachability_gate"])
            # The rendered artifact carries the gate, not just the return.
            self.assertIn("reachability", blocked["markdown"].lower() + json.dumps(summary))

            passed = _build({"mode": "block", "verdicts": {finding["finding_id"]: "reachable"}})
            summary = passed["report"]["summary"]
            self.assertTrue(summary["phase_coverage_ok"])
            self.assertEqual(summary["reachability_gate"]["missing"], [])
            entry = passed["report"]["findings"][0]
            self.assertEqual(entry["reachability_verdict"], "reachable")

            warned = _build({"mode": "warn", "verdicts": {}})
            self.assertTrue(warned["report"]["summary"]["phase_coverage_ok"])
            self.assertTrue(warned["report"]["summary"]["reachability_gate"]["missing"])


if __name__ == "__main__":
    unittest.main()

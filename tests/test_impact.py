from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.impact import _adjacency_leads, crash_primitive, finding_impact
from agentic_fuzz_engine.crash_identity import parse_crash_output
from agentic_fuzz_engine.state import EngineState

READ_CRASH = """\
==11==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010 at pc 0x400b12
READ of size 8 at 0x602000000010 thread T0
    #0 0x51fa22 in GetSize {src}/patch_file.cpp:1390
    #1 0x51fb44 in AdvanceAndTakeAction {src}/blobstore_ops.cpp:351
"""

WRITE_CRASH = READ_CRASH.replace("READ of size 8", "WRITE of size 8")

SOURCE = """\
namespace demo {{
int64_t GetSize(const Value& value) {{
  int64_t raw_size = value.size();
  return raw_size - 8;  // line 4 is far from the sink
}}
}}
"""

CRASH_SOURCE_LINES = (
    ["// filler\n"] * 1385
    + [
        "int64_t GetSize(const Value& raw_value) {\n",           # 1386
        "  size_t chunk_size = raw_value.size() - 8;\n",         # 1387
        "  char buffer[65536];\n",                                # 1388
        "  size_t out_len = chunk_size;\n",                       # 1389
        "  return lookup(raw_value, chunk_size);\n",              # 1390 crash line
        "  // later:\n",                                          # 1391
        "  memcpy(buffer, raw_value.data(), chunk_size);\n",      # 1392 lead
    ]
)

UBSAN_STUB = """#!/bin/sh
echo "{src}/patch_file.cpp:1387:21: runtime error: unsigned integer overflow: 3 - 8 cannot be represented in type 'size_t'" >&2
exit 0
"""


class ImpactTest(unittest.TestCase):
    def test_crash_primitive_tokens(self) -> None:
        self.assertEqual(crash_primitive(READ_CRASH.format(src="/work")), "read")
        self.assertEqual(crash_primitive(WRITE_CRASH.format(src="/work")), "write")
        self.assertEqual(crash_primitive("CHECK failed: !empty()"), "abort")
        self.assertEqual(crash_primitive(""), "unknown")

    def test_finding_record_stamps_primitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = EngineState(tmp)
            state.campaign_start("localfuzz/c/demo", name="run-a")
            finding = state.finding_record(
                "run-a",
                target="localfuzz/c/demo",
                harness="demo",
                sanitizer="address",
                error_token="heap-buffer-overflow",
                crash_output=WRITE_CRASH.format(src="/work"),
            )
            self.assertEqual(finding["primitive"], "write")

    def test_impact_block_ubsan_wraps_and_leads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            src.mkdir()
            (src / "patch_file.cpp").write_text("".join(CRASH_SOURCE_LINES), encoding="utf-8")

            crash = READ_CRASH.format(src=src)
            state = EngineState(root / "data")
            state.campaign_start("localfuzz/c/demo", name="run-a")
            pov = b"POV"
            import base64

            state.artifact_put("run-a", "crash-1.bin", base64.b64encode(pov).decode())
            finding = state.finding_record(
                "run-a",
                target="localfuzz/c/demo",
                harness="demo",
                sanitizer="address",
                error_token="heap-buffer-overflow",
                crash_output=crash,
                poc_artifact="crash-1.bin",
                verified=True,
            )

            ubsan = root / "bin" / "demo" / "fuzzer-ubsan"
            ubsan.parent.mkdir(parents=True)
            ubsan.write_text(UBSAN_STUB.format(src=src), encoding="utf-8")
            ubsan.chmod(ubsan.stat().st_mode | stat.S_IXUSR)

            result = finding_impact(
                state=state,
                run_id="run-a",
                finding_id=finding["finding_id"],
                workspace_root=root,
            )
            self.assertTrue(result["ok"])
            impact = result["impact"]
            self.assertEqual(impact["primitive"], "read")
            self.assertEqual(impact["write_evidence"], "none")
            self.assertEqual(len(impact["ubsan_wraps"]), 1)
            wrap = impact["ubsan_wraps"][0]
            self.assertTrue(wrap["on_crash_path"])
            self.assertIn("unsigned integer overflow", wrap["error"])
            # The memcpy two lines below the crash shares chunk_size/raw_value.
            self.assertTrue(impact["leads"])
            lead = impact["leads"][0]
            self.assertEqual(lead["callee"], "memcpy")
            self.assertIn("chunk_size", lead["shared_idents"])
            self.assertTrue(lead["advisory"])

            # The impact event was mirrored into the durable index fold.
            from agentic_fuzz_engine.findings_index import fold_index, load_index

            folded = fold_index(load_index(state.data_root, finding_id=finding["finding_id"]))
            self.assertEqual(folded[0]["impact"]["ubsan_wraps"], 1)

    def test_leads_require_shared_identifiers(self) -> None:
        crash = READ_CRASH.format(src="/nonexistent")
        signal = parse_crash_output(crash)
        self.assertEqual(_adjacency_leads(signal, source_dir=None, window=60), [])


if __name__ == "__main__":
    unittest.main()

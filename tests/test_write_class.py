"""Write-class hunting fixes: access-type parsing, write-first ranking,
UBSan scaffold defaults, and the coverage-vs-sink frontier report."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.asan import parse_asan_signal
from agentic_fuzz_engine.dedupe import classify_finding_candidate, finding_quality
from agentic_fuzz_engine.scaffold import _render_build_json, _render_project_yaml
from agentic_fuzz_engine.sink_coverage import sink_coverage
from agentic_fuzz_engine.sink_scan import run_sink_scan

WRITE_CRASH = """
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000eff0
WRITE of size 128 at 0x60200000eff0 thread T0
    #0 0xaaaa in bad_copy /src/project/parser.c:42
    #1 0xbbbb in LLVMFuzzerTestOneInput /src/project/fuzz.c:12
"""

READ_CRASH = """
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000eff0
READ of size 20 at 0x60200000eff0 thread T0
    #0 0xaaaa in bad_copy /src/project/parser.c:42
    #1 0xbbbb in LLVMFuzzerTestOneInput /src/project/fuzz.c:12
"""

WRITE_HEAVY_MODULE = """\
#include <cstring>

void CopyChunk(char* dst, const char* src, size_t n) {
  memcpy(dst, src, n);
}

void AppendName(char* dst, const char* src) {
  strcat(dst, src);
}
"""

ENTRY_ONLY_MODULE = """\
#include <string>

int ParseAlpha(const std::string& blob) { return blob.size(); }
int ParseBeta(const std::string& blob) { return blob.size(); }
int ParseGamma(const std::string& blob) { return blob.size(); }
"""


class AsanAccessTests(unittest.TestCase):
    def test_parses_write_access_and_size(self) -> None:
        signal = parse_asan_signal(WRITE_CRASH)
        assert signal is not None
        self.assertEqual(signal.access, "WRITE")
        self.assertEqual(signal.access_size, 128)
        self.assertEqual(signal.to_dict()["access"], "WRITE")

    def test_parses_read_access(self) -> None:
        signal = parse_asan_signal(READ_CRASH)
        assert signal is not None
        self.assertEqual(signal.access, "READ")
        self.assertEqual(signal.access_size, 20)

    def test_no_access_line_is_none(self) -> None:
        signal = parse_asan_signal("ERROR: AddressSanitizer: SEGV on unknown address 0x0\n")
        assert signal is not None
        self.assertIsNone(signal.access)
        self.assertIsNone(signal.access_size)

    def test_access_does_not_change_signature(self) -> None:
        write_signal = parse_asan_signal(WRITE_CRASH)
        read_signal = parse_asan_signal(READ_CRASH)
        assert write_signal is not None and read_signal is not None
        self.assertEqual(
            write_signal.to_dict()["signature"], read_signal.to_dict()["signature"]
        )


class DedupeWriteBoostTests(unittest.TestCase):
    def _finding(self, crash_output: str) -> dict:
        return {
            "target": "localfuzz/c/demo",
            "harness": "fuzz",
            "sanitizer": "address",
            "error_token": "heap-buffer-overflow",
            "crash_output": crash_output,
            "verified": True,
        }

    def test_write_outscores_read_same_crash_type(self) -> None:
        write_quality = finding_quality(self._finding(WRITE_CRASH), artifact_sizes={})
        read_quality = finding_quality(self._finding(READ_CRASH), artifact_sizes={})
        self.assertEqual(write_quality["access"], "WRITE")
        self.assertEqual(read_quality["access"], "READ")
        self.assertGreater(write_quality["score"], read_quality["score"])

    def test_write_candidate_replaces_read_representative(self) -> None:
        read_finding = {**self._finding(READ_CRASH), "signature": None}
        # Same signature (access is excluded from it), so the write candidate
        # dedupes against the read representative and must win.
        verdict = classify_finding_candidate(
            existing_findings=[
                {
                    **read_finding,
                    "signature": classify_finding_candidate(
                        existing_findings=[], candidate=self._finding(READ_CRASH), artifact_sizes={}
                    )["signature"],
                }
            ],
            candidate=self._finding(WRITE_CRASH),
            artifact_sizes={},
        )
        self.assertEqual(verdict["verdict"], "DUP_BETTER")


class SinkScanPrimitiveTests(unittest.TestCase):
    def test_rows_tagged_and_write_modules_rank_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code = Path(tmp) / "code"
            (code / "writer").mkdir(parents=True)
            (code / "parser").mkdir()
            (code / "writer" / "copy.cpp").write_text(WRITE_HEAVY_MODULE, encoding="utf-8")
            (code / "parser" / "entries.cpp").write_text(ENTRY_ONLY_MODULE, encoding="utf-8")
            out = Path(tmp) / "sinks.jsonl"

            result = run_sink_scan(source_root=code, out_path=out, workspace_root=tmp)

            self.assertTrue(result["ok"])
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            sink_rows = [row for row in rows if row["kind"] == "sink"]
            self.assertTrue(sink_rows)
            self.assertTrue(all(row["primitive"] == "write" for row in sink_rows))
            entry_rows = [row for row in rows if row["kind"] == "entry"]
            self.assertTrue(all(row["primitive"] is None for row in entry_rows))
            # writer has 2 sinks (weight 6); parser has 3 entries (weight 3):
            # write weighting must beat raw row count.
            tags = [module["tag"] for module in result["modules"]]
            self.assertLess(tags.index("writer"), tags.index("parser"))
            writer = next(m for m in result["modules"] if m["tag"] == "writer")
            self.assertEqual(writer["write_sinks"], 2)


class ScaffoldUbsanTests(unittest.TestCase):
    def test_build_json_enables_ubsan(self) -> None:
        payload = json.loads(_render_build_json("demo"))
        libfuzzer = next(step for step in payload["steps"] if step["name"] == "libfuzzer")
        self.assertIn("-fsanitize=fuzzer,address,undefined", libfuzzer["argv"])
        self.assertIn("-fno-sanitize-recover=undefined", libfuzzer["argv"])

    def test_project_yaml_lists_undefined(self) -> None:
        self.assertIn("- undefined", _render_project_yaml("demo"))


class SinkCoverageTests(unittest.TestCase):
    def _workspace(self, tmp: Path, *, covered_lines: list[str]) -> Path:
        bin_dir = tmp / "bin" / "demo"
        bin_dir.mkdir(parents=True)
        fuzzer = bin_dir / "fuzzer"
        script = "#!/bin/sh\n" + "".join(f"echo '{line}' >&2\n" for line in covered_lines)
        fuzzer.write_text(script, encoding="utf-8")
        fuzzer.chmod(fuzzer.stat().st_mode | stat.S_IXUSR)
        seeds = tmp / "work" / "demo" / "seeds"
        seeds.mkdir(parents=True)
        (seeds / "seed-0").write_bytes(b"\x00")
        data = tmp / "data"
        data.mkdir()
        rows = [
            {"kind": "sink", "method": "CopyChunk", "callee": "memcpy", "primitive": "write",
             "file": "writer/copy.cpp", "line": 4, "tag": "writer"},
            {"kind": "sink", "method": "DecodeGated", "callee": "memcpy", "primitive": "write",
             "file": "writer/gated.cpp", "line": 9, "tag": "writer"},
            {"kind": "sink", "method": "RunTool", "callee": "system", "primitive": "exec",
             "file": "shell/run.cpp", "line": 3, "tag": "shell"},
            {"kind": "entry", "method": "ParseAlpha", "callee": "entry-point", "primitive": None,
             "file": "parser/entries.cpp", "line": 3, "tag": "parser"},
        ]
        with (data / "sink-scan.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
        return tmp

    def test_reports_uncovered_sinks_write_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._workspace(
                Path(tmp),
                covered_lines=[
                    "COVERED_FUNC: hits: 3 edges: 9/9 CopyChunk(char*, char const*, unsigned long) /src/writer/copy.cpp:4",
                    "COVERED_FUNC: hits: 1 edges: 2/2 ParseAlpha /src/parser/entries.cpp:3",
                ],
            )
            result = sink_coverage(target="localfuzz/c/demo", workspace_root=root)

            self.assertTrue(result["ok"], result.get("blockers"))
            self.assertEqual(result["sinks_total"], 3)  # entry rows excluded
            self.assertEqual(result["sinks_covered"], 1)
            self.assertEqual(result["sinks_uncovered"], 2)
            uncovered_methods = [row["method"] for row in result["uncovered"]]
            self.assertEqual(sorted(uncovered_methods), ["DecodeGated", "RunTool"])
            self.assertEqual(result["uncovered_by_primitive"], {"write": 1, "exec": 1})
            report = json.loads(Path(result["report"]).read_text(encoding="utf-8"))
            self.assertEqual(report["sinks_uncovered"], 2)

    def test_missing_fuzzer_is_a_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = sink_coverage(target="localfuzz/c/demo", workspace_root=tmp)
            self.assertFalse(result["ok"])
            self.assertTrue(any("fuzzer binary" in blocker for blocker in result["blockers"]))

    def test_policy_coverage_max_inputs_samples_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._workspace(
                Path(tmp),
                covered_lines=[
                    "COVERED_FUNC: hits: 3 edges: 9/9 CopyChunk(char*, char const*, unsigned long) /src/writer/copy.cpp:4",
                ],
            )
            seeds = root / "work" / "demo" / "seeds"
            for index in range(1, 5):
                (seeds / f"seed-{index}").write_bytes(b"\x00")
            (root / "campaign-policy.json").write_text(
                json.dumps({"frontier": {"coverage_max_inputs": 2}}), encoding="utf-8"
            )
            fuzzer = root / "bin" / "demo" / "fuzzer"
            count_file = root / "replayed-count"
            fuzzer.write_text(
                "#!/bin/sh\n"
                f"ls \"$3\" | wc -l > {count_file}\n"
                "echo 'COVERED_FUNC: hits: 3 edges: 9/9 CopyChunk(char*, char const*, unsigned long) /src/writer/copy.cpp:4' >&2\n",
                encoding="utf-8",
            )
            fuzzer.chmod(fuzzer.stat().st_mode | stat.S_IXUSR)

            result = sink_coverage(target="localfuzz/c/demo", workspace_root=root)

            self.assertTrue(result["ok"], result.get("blockers"))
            self.assertEqual(count_file.read_text(encoding="utf-8").strip(), "2")
            # Explicit max_inputs overrides the policy value.
            result = sink_coverage(
                target="localfuzz/c/demo", workspace_root=root, max_inputs=3
            )
            self.assertTrue(result["ok"], result.get("blockers"))
            self.assertEqual(count_file.read_text(encoding="utf-8").strip(), "3")


if __name__ == "__main__":
    unittest.main()

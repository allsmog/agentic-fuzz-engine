from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.sink_scan import run_sink_scan


ALPHA_PARSER = """\
#include <string>
#include <cstring>

namespace alpha {

struct Frame { int kind; };

Frame ParseFrame(const std::string& blob) {
  Frame f{};
  f.kind = blob.empty() ? 0 : blob[0];
  return f;
}

void CopyBits(char* dst, const char* src, size_t n) {
  memcpy(dst, src, n);
}

void DecodeBuf(const uint8_t* data, size_t size) {
  char tmp[8];
  memcpy(tmp, data, size);
}

static void helper(const std::string& s) { (void)s; }

}  // namespace alpha

int main(int argc, char** argv) { return 0; }
"""

BETA_MISC = """\
#include <string>

namespace beta {

void SetName(const std::string& name) { (void)name; }

int Add(int a, int b) { return a + b; }

}  // namespace beta
"""


class SinkScanTests(unittest.TestCase):
    def _make_tree(self, tmp_path: Path) -> Path:
        code = tmp_path / "code"
        (code / "alpha").mkdir(parents=True)
        (code / "beta").mkdir()
        (code / "alpha" / "parser.cpp").write_text(ALPHA_PARSER, encoding="utf-8")
        (code / "alpha" / "parser_test.cpp").write_text(ALPHA_PARSER, encoding="utf-8")
        (code / "beta" / "misc.cpp").write_text(BETA_MISC, encoding="utf-8")
        (code / "beta" / "tests").mkdir()
        (code / "beta" / "tests" / "excluded.cpp").write_text(ALPHA_PARSER, encoding="utf-8")
        return code

    def test_scans_entries_and_sinks_by_module(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            code = self._make_tree(tmp_path)
            out = tmp_path / "sinks.jsonl"

            result = run_sink_scan(source_root=code, out_path=out, env={})

            self.assertTrue(result["ok"], result["blockers"])
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            by_key = {(r["tag"], r["method"], r["kind"]): r for r in rows}

            # ParseFrame: fuzzable shape + parser name -> entry
            entry = by_key[("alpha", "ParseFrame", "entry")]
            self.assertEqual(entry["callee"], "entry-point")
            self.assertEqual(entry["file"], "alpha/parser.cpp")
            self.assertEqual(entry["via"], "sink-scan")

            # CopyBits: memcpy call site attributed to enclosing function,
            # but 3 params is not a fuzzable shape -> sink only, no entry.
            sink = by_key[("alpha", "CopyBits", "sink")]
            self.assertEqual(sink["callee"], "memcpy")
            self.assertNotIn(("alpha", "CopyBits", "entry"), by_key)

            # DecodeBuf: ptr+len shape with a dangerous body -> both rows.
            self.assertIn(("alpha", "DecodeBuf", "sink"), by_key)
            self.assertIn(("alpha", "DecodeBuf", "entry"), by_key)

            # main() never becomes a row; boring beta functions produce none;
            # *_test.cpp files and tests/ dirs are excluded.
            self.assertNotIn("main", {r["method"] for r in rows})
            self.assertFalse([r for r in rows if r["tag"] == "beta"])
            self.assertFalse([r for r in rows if "test" in r["file"]])

            # Module ranking includes only modules with rows.
            tags = [m["tag"] for m in result["modules"]]
            self.assertEqual(tags, ["alpha"])

    def test_row_caps_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            code = self._make_tree(tmp_path)
            out = tmp_path / "sinks.jsonl"

            result = run_sink_scan(source_root=code, out_path=out, max_rows_per_module=1, env={})

            self.assertTrue(result["ok"])
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len([r for r in rows if r["tag"] == "alpha"]), 1)

    def test_missing_source_root_is_a_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Point workspace_root at an empty dir so the machine's real
            # workspace (and its source_dir) cannot leak into the test.
            result = run_sink_scan(
                source_root=None,
                out_path=Path(tmp) / "unused.jsonl",
                workspace_root=Path(tmp) / "no-workspace",
                env={},
            )
        self.assertFalse(result["ok"])
        self.assertTrue(result["blockers"])


if __name__ == "__main__":
    unittest.main()


class MergeSinkJsonlTests(unittest.TestCase):
    def test_merge_prefers_joern_provenance(self) -> None:
        from agentic_fuzz_engine.sink_scan import merge_sink_jsonl

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            auto = tmp_path / "auto.jsonl"
            joern = tmp_path / "joern.jsonl"
            auto.write_text(
                "\n".join([
                    json.dumps({"file": "a.c", "line": 10, "callee": "memcpy", "method": "AutoName", "via": "sink-scan"}),
                    json.dumps({"file": "b.c", "line": 5, "callee": "strcpy", "method": "OnlyAuto", "via": "sink-scan"}),
                ]) + "\n",
                encoding="utf-8",
            )
            joern.write_text(
                json.dumps({"file": "a.c", "line": 10, "callee": "memcpy", "method": "JoernName", "via": "joern-callsite"}) + "\n",
                encoding="utf-8",
            )
            out = tmp_path / "merged.jsonl"

            result = merge_sink_jsonl(inputs=[auto, joern], out_path=out)

            self.assertTrue(result["ok"])
            self.assertEqual(result["rows_written"], 2)
            rows = {((r["file"], r["line"])): r for r in map(json.loads, out.read_text(encoding="utf-8").splitlines())}
            self.assertEqual(rows[("a.c", 10)]["method"], "JoernName")  # joern wins the dupe
            self.assertEqual(rows[("b.c", 5)]["method"], "OnlyAuto")

    def test_merge_is_idempotent(self) -> None:
        from agentic_fuzz_engine.sink_scan import merge_sink_jsonl

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            src = tmp_path / "src.jsonl"
            src.write_text(json.dumps({"file": "a.c", "line": 1, "callee": "memcpy", "via": "joern"}) + "\n", encoding="utf-8")
            out = tmp_path / "merged.jsonl"
            merge_sink_jsonl(inputs=[src], out_path=out)
            again = merge_sink_jsonl(inputs=[src, out], out_path=out)
            self.assertEqual(again["rows_written"], 1)

    def test_merge_prefers_new_discovery_evidence_over_regex_scan(self) -> None:
        from agentic_fuzz_engine.sink_scan import merge_sink_jsonl

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scan = root / "scan.jsonl"
            entry = root / "entry.jsonl"
            key = {"file": "a.cpp", "line": 9, "callee": "native_parse"}
            scan.write_text(json.dumps({**key, "method": "guess", "via": "sink-scan"}) + "\n")
            entry.write_text(json.dumps({**key, "method": "Owner", "via": "entry-scan"}) + "\n")
            out = root / "merged.jsonl"
            result = merge_sink_jsonl(inputs=[scan, entry], out_path=out)
            self.assertTrue(result["ok"], result)
            row = json.loads(out.read_text().strip())
            self.assertEqual(row["method"], "Owner")

    def test_merge_refuses_symlink_destination(self) -> None:
        from agentic_fuzz_engine.sink_scan import merge_sink_jsonl

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.jsonl"
            source.write_text(json.dumps({"file": "a", "line": 1, "callee": "f"}) + "\n")
            victim = root / "victim"
            victim.write_text("keep")
            out = root / "out.jsonl"
            out.symlink_to(victim)
            result = merge_sink_jsonl(inputs=[source], out_path=out)
            self.assertFalse(result["ok"])
            self.assertEqual(victim.read_text(), "keep")

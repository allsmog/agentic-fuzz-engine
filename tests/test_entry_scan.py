from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentic_fuzz_engine import entry_scan
from agentic_fuzz_engine.entry_scan import run_entry_scan


SOURCE = """\
class RequestHandler : public RpcInterface {
 public:
  void Handle();
};

class CacheHandler : public PlainThing {
 public:
  void Cache();
};

void DecodePacket(const char* input) {
  native_parse(input);
}

int main(int argc, char** argv) { return argc > 1; }
"""

CONFIGURED_HANDLER = """\
class Endpoint : public WireBoundary {
 public:
  void Receive();
};
"""


class EntryScanTests(unittest.TestCase):
    def test_reports_generic_candidates_and_attributes_library_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "service"
            source.mkdir(parents=True)
            (source / "server.cpp").write_text(SOURCE, encoding="utf-8")
            out = root / "entries.jsonl"
            result = run_entry_scan(
                source_root=root / "src", out_path=out, workspace_root=root / "absent",
                lib_prefixes=["native_"], service_base_suffixes=["Interface"], env={},
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["extractor"], "tree-sitter")
            rows = list(map(json.loads, out.read_text().splitlines()))
            by_kind = {row["entry_kind"]: row for row in rows}
            self.assertEqual(by_kind["service-handler"]["service_interface"], "RpcInterface")
            self.assertNotIn("CacheHandler", {row["method"] for row in rows})
            self.assertEqual(by_kind["program-main"]["method"], "main")
            self.assertEqual(by_kind["library-call"]["method"], "DecodePacket")
            self.assertEqual(by_kind["library-call"]["callee"], "native_parse")
            self.assertIn("candidate_evidence", by_kind["library-call"])
            self.assertEqual(by_kind["library-call"]["heuristic_confidence"], "configured-symbol-prefix")

    def test_excludes_symlinked_sources_and_rejects_bad_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            outside = root / "outside.cpp"
            outside.write_text(SOURCE, encoding="utf-8")
            (source / "linked.cpp").symlink_to(outside)
            out = root / "entries.jsonl"
            result = run_entry_scan(
                source_root=source, out_path=out, workspace_root=root / "absent", env={}
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["rows_written"], 0)
            result = run_entry_scan(
                source_root=source, out_path=out, workspace_root=root / "absent",
                lib_prefixes=["bad-prefix!"], env={},
            )
            self.assertFalse(result["ok"])

    def test_service_base_suffixes_are_configurable_and_labeled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            (source / "endpoint.hpp").write_text(CONFIGURED_HANDLER)
            out = root / "entries.jsonl"
            without = run_entry_scan(
                source_root=source, out_path=out, workspace_root=root / "absent", env={}
            )
            self.assertEqual(without["counts"]["service-handler"], 0)
            configured = run_entry_scan(
                source_root=source, out_path=out, workspace_root=root / "absent",
                service_base_suffixes=["Boundary"], env={},
            )
            self.assertTrue(configured["ok"], configured)
            row = json.loads(out.read_text().strip())
            self.assertEqual(row["heuristic_confidence"], "configured-base-suffix")

    def test_initialized_workspace_output_cannot_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            source = workspace / "src"
            source.mkdir(parents=True)
            (source / "server.cpp").write_text(SOURCE)
            (workspace / "workspace.json").write_text(json.dumps({"source_dir": str(source)}))
            victim = root / "victim"
            victim.write_text("keep")
            result = run_entry_scan(
                source_root=source, workspace_root=workspace,
                out_path=workspace / "data" / ".." / ".." / "victim", env={},
            )
            self.assertFalse(result["ok"])
            self.assertEqual(victim.read_text(), "keep")

    def test_source_tree_enumeration_cap_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            (source / "one.cpp").write_text(SOURCE, encoding="utf-8")
            (source / "two.cpp").write_text(SOURCE, encoding="utf-8")
            out = root / "entries.jsonl"
            with mock.patch.object(entry_scan, "MAX_TREE_ENTRIES", 1):
                result = run_entry_scan(
                    source_root=source, out_path=out,
                    workspace_root=root / "absent", env={},
                )
            self.assertFalse(result["ok"])
            self.assertIn("source tree exceeds 1 entries", result["blockers"][0])
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()

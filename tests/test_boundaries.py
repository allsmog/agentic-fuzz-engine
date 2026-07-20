from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.boundaries import classify_path, load_boundaries
from agentic_fuzz_engine.scaffold import select_targets

BOUNDARIES = {
    "classes": {"stored-data": 4, "peer-service": 3, "internal": 1},
    "globs": [
        {"glob": "pkgstore/*", "class": "stored-data"},
        {"glob": "nas/smb/*", "class": "peer-service"},
    ],
    "default_class": "internal",
}


def _write_boundaries(root: Path) -> None:
    path = root / "work" / "boundaries.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(BOUNDARIES), encoding="utf-8")


class BoundariesTest(unittest.TestCase):
    def test_classify_first_glob_wins_and_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_boundaries(root)
            boundaries = load_boundaries(root)
            self.assertEqual(classify_path("pkgstore/pkg_file_reader.cpp", boundaries), ("stored-data", 4))
            self.assertEqual(classify_path("nas/smb/security_descriptor.cpp", boundaries), ("peer-service", 3))
            self.assertEqual(classify_path("utils/stringpiece.cpp", boundaries), ("internal", 1))

    def test_missing_map_is_neutral(self) -> None:
        self.assertEqual(classify_path("anything/at/all.cpp", None), ("internal", 1))
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(load_boundaries(Path(tmp)))

    def test_select_targets_ranks_boundary_weight_over_sink_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_boundaries(root)
            sinks = root / "sinks.jsonl"
            rows = []
            # internal module: many sinks, weight 1 each
            for index in range(10):
                rows.append({"tag": "utils", "file": f"utils/f{index}.cpp", "line": 1,
                             "method": "m", "callee": "memcpy", "kind": "sink", "primitive": "write"})
            # stored-data module: fewer sinks, class weight 4
            for index in range(5):
                rows.append({"tag": "pkgstore", "file": f"pkgstore/f{index}.cpp", "line": 1,
                             "method": "m", "callee": "memcpy", "kind": "sink", "primitive": "write"})
            sinks.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

            result = select_targets(sinks_jsonl=sinks, workspace_root=root, top=10)
            ordered = [vector["tag"] for vector in result["vectors"]]
            # 5 sinks * 3 * 4 = 60 beats 10 sinks * 3 * 1 = 30
            self.assertEqual(ordered[0], "pkgstore")
            router = result["vectors"][0]
            self.assertEqual(router["boundary_weight"], 60)
            self.assertEqual(router["entry_classes"], {"stored-data": 5})

    def test_select_targets_without_map_orders_by_sink_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sinks = root / "sinks.jsonl"
            rows = [
                {"tag": "big", "file": f"big/f{index}.cpp", "line": 1, "method": "m",
                 "callee": "memcpy", "kind": "sink", "primitive": "write"}
                for index in range(4)
            ] + [
                {"tag": "small", "file": "small/f.cpp", "line": 1, "method": "m",
                 "callee": "memcpy", "kind": "sink", "primitive": "write"}
            ]
            sinks.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            result = select_targets(sinks_jsonl=sinks, workspace_root=root, top=10)
            self.assertEqual([vector["tag"] for vector in result["vectors"]], ["big", "small"])


if __name__ == "__main__":
    unittest.main()

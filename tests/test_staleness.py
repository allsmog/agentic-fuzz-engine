from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from agentic_fuzz_engine.staleness import (
    check_target_staleness,
    collect_build_inputs,
    write_manifest,
)


def _make_target(root: Path, name: str = "demo") -> tuple[Path, dict]:
    target_dir = root / "targets" / "c" / name
    (target_dir / ".localfuzz").mkdir(parents=True)
    (target_dir / "harness.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    (target_dir / "seeds").mkdir()
    (target_dir / "seeds" / "seed-0").write_bytes(b"corpus noise, not a build input")
    source = root / "src" / "lib.cpp"
    source.parent.mkdir(parents=True)
    source.write_text("void lib() {}\n", encoding="utf-8")
    config = {
        "steps": [
            {"name": "fuzzer", "argv": ["clang++", "-O1", "harness.cpp", str(source), "-o", "{bin_dir}/fuzzer"]}
        ]
    }
    (target_dir / ".localfuzz" / "build.json").write_text(json.dumps(config), encoding="utf-8")
    return target_dir, config


class StalenessTest(unittest.TestCase):
    def test_inputs_cover_target_dir_and_argv_sources_not_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_dir, config = _make_target(root)
            inputs, truncated = collect_build_inputs(
                target_dir=target_dir,
                build_config=config,
                placeholders={"bin_dir": str(root / "bin" / "demo")},
            )
            names = {path.name for path in inputs}
            self.assertIn("harness.cpp", names)
            self.assertIn("lib.cpp", names)  # argv token resolved to a file
            self.assertIn("build.json", names)
            self.assertNotIn("seed-0", names)  # corpus excluded
            self.assertFalse(truncated)

    def test_fresh_build_not_stale_then_edit_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_dir, config = _make_target(root)
            write_manifest(
                root=root,
                name="demo",
                target_dir=target_dir,
                build_config=config,
                placeholders={"bin_dir": str(root / "bin" / "demo")},
            )
            result = check_target_staleness(root, "demo")
            self.assertFalse(result["stale"])

            source = root / "src" / "lib.cpp"
            source.write_text("void lib() { /* moved on */ }\n", encoding="utf-8")
            os.utime(source, (time.time() + 5, time.time() + 5))
            result = check_target_staleness(root, "demo")
            self.assertTrue(result["stale"])
            self.assertTrue(any("lib.cpp" in item for item in result["changed"]))

    def test_touched_but_identical_file_is_not_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_dir, config = _make_target(root)
            write_manifest(
                root=root,
                name="demo",
                target_dir=target_dir,
                build_config=config,
                placeholders={"bin_dir": str(root / "bin" / "demo")},
            )
            source = root / "src" / "lib.cpp"
            os.utime(source, (time.time() + 5, time.time() + 5))
            result = check_target_staleness(root, "demo")
            self.assertFalse(result["stale"])  # rehashed, content unchanged
            self.assertEqual(result["checked"], 1)

    def test_removed_input_and_missing_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_dir, config = _make_target(root)
            missing = check_target_staleness(root, "demo")
            self.assertIsNone(missing["stale"])
            self.assertTrue(missing["missing_manifest"])

            write_manifest(
                root=root,
                name="demo",
                target_dir=target_dir,
                build_config=config,
                placeholders={"bin_dir": str(root / "bin" / "demo")},
            )
            (root / "src" / "lib.cpp").unlink()
            result = check_target_staleness(root, "demo")
            self.assertTrue(result["stale"])
            self.assertTrue(any("removed" in item for item in result["changed"]))


if __name__ == "__main__":
    unittest.main()

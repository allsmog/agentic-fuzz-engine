from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.harness_gen import _generate_sequence

SPEC = {
    "type": "sequence",
    "includes": ["store.h"],
    "context": {
        "type": "Store",
        "setup": "Store ctx;\nif (!ctx.Init()) return 0;",
        "teardown": "ctx.Close();",
    },
    "ops": [
        {"name": "put", "call": "ctx.Put(key, val);",
         "args": [{"name": "key", "kind": "bytes", "max": 64},
                  {"name": "val", "kind": "bytes", "max": 4096}]},
        {"name": "get", "call": "ctx.Get(key);",
         "args": [{"name": "key", "kind": "bytes", "max": 64}]},
        {"name": "seek", "call": "ctx.Seek(offset);",
         "args": [{"name": "offset", "kind": "u64"}]},
        {"name": "reverse", "call": "ctx.Reverse();", "args": []},
    ],
    "max_ops": 8,
    "build": {"steps": [{"name": "fuzzer", "argv": ["true"]}]},
}

STORE_H = """\
#pragma once
#include <cstdint>
#include <map>
#include <string>

struct Store {
  std::map<std::string, std::string> kv;
  bool open = false;
  int puts = 0, gets = 0, seeks = 0, reverses = 0;
  bool Init() { open = true; return true; }
  void Put(const std::string& k, const std::string& v) { puts++; kv[k] = v; }
  void Get(const std::string& k) { gets++; (void)kv.count(k); }
  void Seek(uint64_t off) { seeks++; (void)off; }
  void Reverse() { reverses++; }
  void Close() { open = false; }
};
"""


class SequenceGeneratorTest(unittest.TestCase):
    def _generate(self, tmp: str, spec: dict) -> tuple[Path, dict]:
        target_dir = Path(tmp) / "target"
        target_dir.mkdir()
        outcome = _generate_sequence(spec, target_dir=target_dir, placeholders={})
        return target_dir, outcome

    def test_codegen_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target_dir, outcome = self._generate(tmp, SPEC)
            self.assertFalse(outcome["blockers"], outcome)
            self.assertEqual(outcome["summary"]["ops"], 4)
            harness = (target_dir / "harness.cpp").read_text(encoding="utf-8")
            self.assertIn("static const unsigned kOpCount = 4;", harness)
            self.assertIn("static const unsigned kMaxOps = 8;", harness)
            self.assertIn("std::string key = tape.bytes(64);", harness)
            self.assertIn("uint64_t offset = tape.u64();", harness)
            self.assertIn("try { ctx.Put(key, val); } catch (...) {}", harness)
            self.assertIn("ctx.Close();", harness)
            # Tape format documented in the header for seedgen/grammar lanes.
            self.assertIn("op byte", harness.splitlines()[1])

    def test_rejects_unknown_arg_kind_and_empty_ops(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = dict(SPEC, ops=[{"name": "x", "call": "f();", "args": [{"name": "a", "kind": "float"}]}])
            _, outcome = self._generate(tmp, bad)
            self.assertTrue(outcome["needs_authoring"])
            self.assertTrue(any("float" in blocker for blocker in outcome["blockers"]))
        with tempfile.TemporaryDirectory() as tmp:
            _, outcome = self._generate(tmp, dict(SPEC, ops=[]))
            self.assertTrue(outcome["needs_authoring"])

    @unittest.skipUnless(shutil.which("clang++") or shutil.which("g++"), "no C++ compiler")
    def test_generated_harness_compiles_and_replays_tape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target_dir, outcome = self._generate(tmp, SPEC)
            self.assertFalse(outcome["blockers"])
            (target_dir / "store.h").write_text(STORE_H, encoding="utf-8")
            compiler = shutil.which("clang++") or shutil.which("g++")
            binary = target_dir / "replay"
            compile_run = subprocess.run(
                [compiler, "-std=c++17", "-DFUZZ_MAIN", "-I", str(target_dir),
                 str(target_dir / "harness.cpp"), "-o", str(binary)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(compile_run.returncode, 0, compile_run.stderr)

            # Tape: put(key="k", val="v") then reverse then truncated get.
            tape = bytes([0]) + b"\x01\x00k" + b"\x01\x00v" + bytes([3]) + bytes([1])
            tape_file = target_dir / "tape.bin"
            tape_file.write_bytes(tape)
            replay = subprocess.run([str(binary), str(tape_file)], capture_output=True, text=True, timeout=30)
            self.assertEqual(replay.returncode, 0, replay.stderr)


if __name__ == "__main__":
    unittest.main()

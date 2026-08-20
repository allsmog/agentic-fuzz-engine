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
  Store() = default;
  explicit Store(int) {}
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

    def test_slot_pool_uses_initializer_list_and_reports_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spec = dict(
                SPEC,
                context={},
                handles={"type": "Store", "slots": 2, "init": "Store(7)"},
                ops=[{"name": "use", "call": "handles[slot].Get(key);",
                      "args": [{"name": "slot", "kind": "slot"},
                               {"name": "key", "kind": "bytes", "max": 8}]}],
            )
            target, result = self._generate(tmp, spec)
            self.assertEqual(result["blockers"], [])
            self.assertEqual(result["summary"]["slots"], 2)
            harness = (target / "harness.cpp").read_text(encoding="utf-8")
            self.assertIn("Store handles[2] = {Store(7), Store(7)};", harness)
            self.assertIn("tape.u8()) % 2", harness)

    def test_slot_schema_fails_closed(self) -> None:
        cases = [
            {"type": "Store", "slots": 0, "init": "Store()"},
            {"type": "Store", "slots": 17, "init": "Store()"},
            {"type": "Store", "slots": True, "init": "Store()"},
            {"type": "Store", "slots": 2},
        ]
        for handles in cases:
            with self.subTest(handles=handles), tempfile.TemporaryDirectory() as tmp:
                _, result = self._generate(tmp, dict(
                    SPEC, handles=handles,
                    ops=[{"name": "use", "call": "handles[s].Get(\"x\");",
                          "args": [{"name": "s", "kind": "slot"}]}],
                ))
                self.assertTrue(result["needs_authoring"])
                self.assertTrue(result["blockers"])

    def test_slot_arg_requires_pool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _, result = self._generate(tmp, dict(
                SPEC,
                ops=[{"name": "use", "call": "f(s);", "args": [{"name": "s", "kind": "slot"}]}],
            ))
            self.assertTrue(any("requires a handles declaration" in item for item in result["blockers"]))

    def test_malformed_ops_args_and_bounds_are_authoring_blockers(self) -> None:
        cases = [
            dict(SPEC, ops=["not-an-object"]),
            dict(SPEC, ops=[{"name": "op", "args": ["not-an-object"]}]),
            dict(SPEC, ops=[{"name": "bad-name!", "args": []}]),
            dict(SPEC, ops=[{"name": "op", "args": [{"name": "bad-name!", "kind": "u8"}]}]),
            dict(SPEC, max_ops=float("inf")),
            dict(SPEC, ops=[{"name": "op", "args": [{"name": "data", "kind": "bytes", "max": float("inf")}]}]),
        ]
        for spec in cases:
            with self.subTest(spec=spec), tempfile.TemporaryDirectory() as tmp:
                _, result = self._generate(tmp, spec)
                self.assertTrue(result["needs_authoring"])
                self.assertTrue(result["blockers"])

    @unittest.skipUnless(shutil.which("clang++") or shutil.which("g++"), "no C++ compiler")
    def test_generated_slot_pool_compiles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spec = dict(
                SPEC,
                context={},
                handles={"type": "Store", "slots": 2, "init": "Store(7)"},
                ops=[{"name": "use", "call": "handles[slot].Get(key);",
                      "args": [{"name": "slot", "kind": "slot"},
                               {"name": "key", "kind": "bytes", "max": 8}]}],
            )
            target, outcome = self._generate(tmp, spec)
            self.assertFalse(outcome["blockers"], outcome)
            (target / "store.h").write_text(STORE_H, encoding="utf-8")
            compiler = shutil.which("clang++") or shutil.which("g++")
            compiled = subprocess.run(
                [compiler, "-std=c++17", "-DFUZZ_MAIN", "-I", str(target),
                 str(target / "harness.cpp"), "-o", str(target / "replay")],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)

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
            tape = bytes([0]) + b"\x01\x00k" + b"\x01\x00v" + bytes([3]) + bytes([1])
            tape_file = target_dir / "tape.bin"
            tape_file.write_bytes(tape)
            replay = subprocess.run([str(binary), str(tape_file)], capture_output=True, text=True, timeout=30)
            self.assertEqual(replay.returncode, 0, replay.stderr)


if __name__ == "__main__":
    unittest.main()

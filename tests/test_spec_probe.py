from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.spec_probe import _classify_errors, _syslib_for, spec_probe

LINK_ERRORS = """\
/usr/bin/ld: harness.o: in function `main':
harness.cpp:(.text+0x10): undefined reference to `mylib::Codec::Decode(char const*, int)'
clang: error: linker command failed
"""

DARWIN_LINK_ERRORS = """\
Undefined symbols for architecture arm64:
  "mylib::Codec::Decode(char const*, int)", referenced from:
      _main in harness.o
ld: symbol(s) not found for architecture arm64
"""

HEADER_ERROR = """\
harness.cpp:3:10: fatal error: 'mylib/api.h' file not found
    3 | #include "mylib/api.h"
"""


class ClassifyTest(unittest.TestCase):
    def test_error_taxonomy(self) -> None:
        errors = _classify_errors(HEADER_ERROR + LINK_ERRORS)
        kinds = {(item["kind"], item["value"]) for item in errors}
        self.assertIn(("missing-header", "mylib/api.h"), kinds)
        self.assertTrue(any(kind == "undefined-symbol" and "Decode" in value for kind, value in kinds))

    def test_classifies_darwin_undefined_symbol_diagnostic(self) -> None:
        errors = _classify_errors(DARWIN_LINK_ERRORS)
        self.assertIn(
            {"kind": "undefined-symbol", "value": "mylib::Codec::Decode(char const*, int)"},
            errors,
        )

    def test_syslib_table(self) -> None:
        self.assertEqual(_syslib_for("ZSTD_decompress"), "-lzstd")
        self.assertEqual(_syslib_for("inflateInit2_"), "-lz")
        self.assertEqual(_syslib_for("pthread_create"), "-lpthread")
        self.assertIsNone(_syslib_for("mylib::Codec::Decode(char const*, int)"))


@unittest.skipUnless(shutil.which("clang++") or shutil.which("g++"), "no C++ compiler")
class SpecProbeLoopTest(unittest.TestCase):
    def test_probe_grows_closure_to_buildable(self) -> None:
        compiler = shutil.which("clang++") or shutil.which("g++")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Scan tree: header under mylib/include/, impl under mylib/src/.
            scan = root / "sdcode"
            (scan / "include" / "mylib").mkdir(parents=True)
            (scan / "src").mkdir(parents=True)
            (scan / "include" / "mylib" / "api.h").write_text(
                "#pragma once\nnamespace mylib { int decode_len(const char* d, int n); }\n",
                encoding="utf-8",
            )
            (scan / "src" / "impl.cpp").write_text(
                '#include "mylib/api.h"\n'
                "namespace mylib { int decode_len(const char* d, int n) { (void)d; return n; } }\n",
                encoding="utf-8",
            )

            # Target: hand-authored harness missing both the -I and the impl.
            target_dir = root / "targets" / "c" / "demo"
            (target_dir / ".localfuzz").mkdir(parents=True)
            (target_dir / "harness.cpp").write_text(
                '#include "mylib/api.h"\n'
                "int main(int argc, char** argv) { (void)argv; return mylib::decode_len(\"x\", argc) > 99; }\n",
                encoding="utf-8",
            )
            spec_path = root / "generators" / "demo.json"
            spec_path.parent.mkdir(parents=True)
            spec_path.write_text(
                json.dumps({"build": {"steps": [{"name": "fuzzer",
                    "argv": [compiler, "-std=c++17", "harness.cpp", "-o", "{bin_dir}/fuzzer"]}]}}),
                encoding="utf-8",
            )

            result = spec_probe(root=root, name="demo", spec=spec_path, scan_root=scan)
            self.assertEqual(result["status"], "buildable", result)
            self.assertTrue((root / "bin" / "demo" / "fuzzer").is_file())

            # The spec accumulated exactly the two fixes.
            spec_data = json.loads(spec_path.read_text(encoding="utf-8"))
            argv = spec_data["build"]["steps"][0]["argv"]
            self.assertTrue(any(token.startswith("-I") and token.endswith("include") for token in argv), argv)
            self.assertTrue(any(token.endswith("impl.cpp") for token in argv), argv)

            probe_state = json.loads((root / "work" / "demo" / "probe-state.json").read_text(encoding="utf-8"))
            self.assertEqual(probe_state["status"], "buildable")
            self.assertGreaterEqual(len(probe_state["iterations"]), 2)

    def test_ambiguous_header_becomes_residue(self) -> None:
        compiler = shutil.which("clang++") or shutil.which("g++")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scan = root / "sdcode"
            for variant in ("a", "b"):
                (scan / variant / "mylib").mkdir(parents=True)
                (scan / variant / "mylib" / "api.h").write_text("#pragma once\n", encoding="utf-8")
            target_dir = root / "targets" / "c" / "demo"
            (target_dir / ".localfuzz").mkdir(parents=True)
            (target_dir / "harness.cpp").write_text(
                '#include "mylib/api.h"\nint main() { return 0; }\n', encoding="utf-8"
            )
            spec_path = root / "generators" / "demo.json"
            spec_path.parent.mkdir(parents=True)
            spec_path.write_text(
                json.dumps({"build": {"steps": [{"name": "fuzzer",
                    "argv": [compiler, "harness.cpp", "-o", "{bin_dir}/fuzzer"]}]}}),
                encoding="utf-8",
            )
            result = spec_probe(root=root, name="demo", spec=spec_path, scan_root=scan)
            self.assertNotEqual(result["status"], "buildable")
            kinds = {item["kind"] for item in result["residue"]}
            self.assertIn("ambiguous-header", kinds)
            ambiguous = next(item for item in result["residue"] if item["kind"] == "ambiguous-header")
            self.assertEqual(len(ambiguous["candidates"]), 2)


if __name__ == "__main__":
    unittest.main()

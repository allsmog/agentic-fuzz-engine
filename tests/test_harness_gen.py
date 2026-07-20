from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.harness_gen import (
    extract_function_signature,
    generate_target,
)
from agentic_fuzz_engine.workspace import workspace_init


SYNTH_SOURCE = """\
#include <string>

namespace acme {
namespace io {

static int helper_internal(const char* p, size_t n) { return n ? p[0] : 0; }

int ParseFrame(const char* data, size_t size) {
  if (size < 4) return -1;
  return data[0];
}

std::string BuildCommand(const std::string& host, int port) {
  std::string cmd = "ping -c1 " + host;
  (void)port;
  return cmd;
}

}  // namespace io
}  // namespace acme

class Codec {
 public:
  int Decode(const std::string& blob);
};

int Codec::Decode(const std::string& blob) { return blob.size(); }
"""


def _make_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    workspace_init(root=ws, source_dir=tmp_path / "srcroot", env={})
    return ws


class SignatureExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.source = Path(self.tmp.name) / "synth.cpp"
        self.source.write_text(SYNTH_SOURCE, encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_extracts_namespaced_free_function_with_ptr_len(self) -> None:
        extraction = extract_function_signature(self.source, "ParseFrame")
        self.assertIsNotNone(extraction)
        self.assertEqual(extraction["qualified"], "acme::io::ParseFrame")
        self.assertEqual([param["name"] for param in extraction["params"]], ["data", "size"])
        self.assertFalse(extraction["is_class_method"])
        self.assertFalse(extraction["is_static"])

    def test_flags_static_and_class_methods(self) -> None:
        static_fn = extract_function_signature(self.source, "helper_internal")
        self.assertIsNotNone(static_fn)
        self.assertTrue(static_fn["is_static"])

        method = extract_function_signature(self.source, "Decode")
        self.assertIsNotNone(method)
        self.assertTrue(method["is_class_method"])

    def test_string_returning_builder(self) -> None:
        extraction = extract_function_signature(self.source, "BuildCommand")
        self.assertIsNotNone(extraction)
        self.assertIn("string", extraction["returns"])
        self.assertEqual(extraction["qualified"], "acme::io::BuildCommand")


class TypeEnumGeneratorTests(unittest.TestCase):
    def test_generates_selector_harness_from_headers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_workspace(tmp_path)
            headers = tmp_path / "gen-cpp"
            headers.mkdir()
            (headers / "alpha_types.h").write_text(
                "namespace acme { namespace wire {\nclass FooResponse {};\nclass BarResponse {};\nclass Ignored {};\n}}\n",
                encoding="utf-8",
            )
            spec_path = tmp_path / "spec.json"
            spec_path.write_text(
                json.dumps(
                    {
                        "type": "type_enum",
                        "header_globs": [str(headers / "*_types.h")],
                        "class_regex": "^class ([A-Za-z0-9_]+Response)\\b",
                        "include_root": str(tmp_path),
                        "decoder": {
                            "includes": [],
                            "template": "template <class T>\nstatic inline void DecodeOne(const uint8_t* d, int n) { (void)d; (void)n; T v; (void)v; }",
                        },
                        "build": {"steps": [{"name": "libfuzzer", "argv": ["/bin/true"], "env": {}}]},
                    }
                ),
                encoding="utf-8",
            )

            result = generate_target(name="wire_gen", spec=str(spec_path), workspace_root=ws, env={})

            self.assertTrue(result["ok"], result["blockers"])
            self.assertEqual(result["summary"]["types"], 2)
            harness = (ws / "targets" / "c" / "wire_gen" / "harness.cpp").read_text(encoding="utf-8")
            self.assertIn("DecodeOne<acme::wire::BarResponse>", harness)
            self.assertIn("kTypeCount = 2", harness)
            self.assertIn("LLVMFuzzerTestOneInput", harness)
            build = json.loads((ws / "targets" / "c" / "wire_gen" / ".localfuzz" / "build.json").read_text())
            self.assertEqual(build["steps"][0]["name"], "libfuzzer")
            manifest = json.loads((ws / "targets" / "c" / "wire_gen" / ".localfuzz" / "generate.json").read_text())
            self.assertEqual(manifest["status"], "generated")

    def test_no_types_emits_workorder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_workspace(tmp_path)
            spec_path = tmp_path / "spec.json"
            spec_path.write_text(
                json.dumps({"type": "type_enum", "header_globs": [str(tmp_path / "none" / "*.h")], "include_root": str(tmp_path), "build": {"steps": []}}),
                encoding="utf-8",
            )

            result = generate_target(name="empty_gen", spec=str(spec_path), workspace_root=ws, env={})

            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], "awaiting-authoring")
            self.assertTrue(Path(result["workorder"]).is_file())


class DirectCallGeneratorTests(unittest.TestCase):
    def test_generates_direct_call_harness_and_skip_reasons(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_workspace(tmp_path)
            source_root = tmp_path / "code"
            source_root.mkdir()
            (source_root / "synth.cpp").write_text(SYNTH_SOURCE, encoding="utf-8")
            sinks = tmp_path / "sinks.jsonl"
            rows = [
                {"tag": "mem-copy", "file": "synth.cpp", "line": 9, "method": "ParseFrame", "callee": "memcpy"},
                {"tag": "mem-copy", "file": "synth.cpp", "line": 40, "method": "Decode", "callee": "memcpy"},
                {"tag": "mem-copy", "file": "synth.cpp", "line": 6, "method": "helper_internal", "callee": "memcpy"},
                {"tag": "mem-copy", "file": "missing.cpp", "line": 1, "method": "Nope", "callee": "memcpy"},
            ]
            sinks.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            spec_path = tmp_path / "spec.json"
            spec_path.write_text(
                json.dumps(
                    {
                        "type": "direct_call",
                        "source_root": str(source_root),
                        "build": {"steps": [{"name": "libfuzzer", "argv": ["/bin/true", "{extra_sources}"], "env": {}}]},
                    }
                ),
                encoding="utf-8",
            )

            result = generate_target(
                name="mem_copy_gen", spec=str(spec_path), workspace_root=ws,
                sinks_jsonl=sinks, sink_tag="mem-copy", env={},
            )

            self.assertTrue(result["ok"], result["blockers"])
            self.assertEqual(result["summary"]["candidates"], 1)
            self.assertIn("acme::io::ParseFrame", result["summary"]["functions"])
            reasons = {item["method"]: item["reason"] for item in result["skipped"]}
            self.assertIn("instance/class method", reasons["Decode"])
            self.assertIn("static", reasons["helper_internal"])
            self.assertIn("source file not found", reasons["Nope"])
            harness = (ws / "targets" / "c" / "mem_copy_gen" / "harness.cpp").read_text(encoding="utf-8")
            self.assertIn("namespace acme { namespace io {", harness.replace("namespace acme {  namespace io {", "namespace acme { namespace io {"))
            self.assertIn("acme::io::ParseFrame(reinterpret_cast<const char*>(payload)", harness)
            # skipped methods still produce a workorder for authoring
            self.assertEqual(result["status"], "awaiting-authoring")
            workorder = json.loads(Path(result["workorder"]).read_text(encoding="utf-8"))
            self.assertTrue(workorder["skipped"])


    def test_harness_includes_replace_prototypes(self) -> None:
        # Functions returning project types need the module header included in
        # the harness; rendered prototypes cannot provide complete types.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_workspace(tmp_path)
            source_root = tmp_path / "code"
            source_root.mkdir()
            (source_root / "synth.cpp").write_text(SYNTH_SOURCE, encoding="utf-8")
            sinks = tmp_path / "sinks.jsonl"
            rows = [{"tag": "mem-copy", "file": "synth.cpp", "line": 9, "method": "ParseFrame", "callee": "memcpy"}]
            sinks.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            spec_path = tmp_path / "spec.json"
            spec_path.write_text(
                json.dumps(
                    {
                        "type": "direct_call",
                        "source_root": str(source_root),
                        "harness_includes": ["acme/io.h"],
                        "build": {"steps": [{"name": "libfuzzer", "argv": ["/bin/true", "{extra_sources}"], "env": {}}]},
                    }
                ),
                encoding="utf-8",
            )

            result = generate_target(
                name="mem_copy_inc", spec=str(spec_path), workspace_root=ws,
                sinks_jsonl=sinks, sink_tag="mem-copy", env={},
            )

            self.assertTrue(result["ok"], result["blockers"])
            harness = (ws / "targets" / "c" / "mem_copy_inc" / "harness.cpp").read_text(encoding="utf-8")
            self.assertIn('#include "acme/io.h"', harness)
            self.assertNotIn("namespace acme { namespace io {", harness)
            self.assertIn("acme::io::ParseFrame(reinterpret_cast<const char*>(payload)", harness)


class SymbolicStringGeneratorTests(unittest.TestCase):
    def test_generates_klee_harness_and_ci_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_workspace(tmp_path)
            source_root = tmp_path / "code"
            source_root.mkdir()
            (source_root / "synth.cpp").write_text(SYNTH_SOURCE, encoding="utf-8")
            sinks = tmp_path / "sinks.jsonl"
            rows = [
                {"tag": "exec-L1", "file": "synth.cpp", "line": 15, "method": "BuildCommand", "callee": "popen"},
                {"tag": "exec-L1", "file": "synth.cpp", "line": 40, "method": "Decode", "callee": "system"},
            ]
            sinks.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            spec_path = tmp_path / "spec.json"
            spec_path.write_text(
                json.dumps(
                    {
                        "type": "symbolic_string",
                        "source_root": str(source_root),
                        "assert_header": "cmdsink_assert.h",
                        "sym_size": 8,
                        "ci_defaults": {"libcxx": True, "externalCalls": "concrete", "kleeArgs": ["--max-time=60"]},
                    }
                ),
                encoding="utf-8",
            )

            result = generate_target(
                name="exec_gen", spec=str(spec_path), workspace_root=ws,
                sinks_jsonl=sinks, sink_tag="exec-L1", env={},
            )

            self.assertTrue(result["ok"], result["blockers"])
            self.assertEqual(result["summary"]["klee_targets"], 1)
            ci = json.loads(Path(result["summary"]["ci_config"]).read_text(encoding="utf-8"))
            self.assertEqual(len(ci["targets"]), 1)
            target = ci["targets"][0]
            self.assertTrue(target["source"].startswith("/work/harnesses/gen/"))
            self.assertTrue(target["linkSources"][0].endswith("synth.cpp"))
            self.assertEqual(target["kleeArgs"], ["--max-time=60"])
            harness_path = ws / "klee" / "harnesses" / "gen" / Path(target["source"]).name
            harness = harness_path.read_text(encoding="utf-8")
            self.assertIn("klee_make_symbolic_std_string_n", harness)
            self.assertIn("acme::io::BuildCommand", harness)
            self.assertIn("klee_ng_assert_shell_safe", harness)


if __name__ == "__main__":
    unittest.main()

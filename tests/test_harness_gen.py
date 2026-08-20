from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentic_fuzz_engine.harness_gen import (
    _canonical_extra_mounts,
    _map_pack_path,
    _stage_header_tree,
    extract_function_signature,
    generate_klee_pack,
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


def _make_pack_target(ws: Path, name: str = "demo") -> Path:
    target = ws / "targets" / "c" / name
    (target / ".localfuzz").mkdir(parents=True)
    (target / "harness.cpp").write_text("// harness\n", encoding="utf-8")
    (target / ".localfuzz" / "build.json").write_text(
        json.dumps({"steps": [{"name": "symcc", "argv": ["sym++", str(target / "harness.cpp")]}]}),
        encoding="utf-8",
    )
    return target


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


class KleePackPathTests(unittest.TestCase):
    def test_extra_mounts_use_canonical_longest_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "ws"
            generated = root / "klee" / "harnesses" / "gen"
            generated.mkdir(parents=True)
            parent = tmp_path / "cache"
            nested = parent / "project"
            nested.mkdir(parents=True)
            source = nested / "include" / "api.h"
            source.parent.mkdir()
            source.write_text("#pragma once\n", encoding="utf-8")
            alias = root / "cache-link"
            alias.symlink_to(nested, target_is_directory=True)
            mounts = _canonical_extra_mounts(
                [
                    {"host": str(parent), "container": "/mnt/cache"},
                    {"host": str(nested), "container": "/mnt/project"},
                ]
            )

            mapped = _map_pack_path(
                str(alias / "include" / "api.h"), source_dir="", root=root,
                gen_dir=generated, short="demo", notes=[], extra_mounts=mounts,
            )

            self.assertEqual(mapped, "/mnt/project/include/api.h")

    def test_extra_mount_prefix_collision_does_not_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "ws"
            generated = root / "klee" / "harnesses" / "gen"
            generated.mkdir(parents=True)
            mounted = tmp_path / "cache"
            collision = tmp_path / "cache-other" / "api.h"
            mounted.mkdir()
            collision.parent.mkdir()
            collision.write_text("#pragma once\n", encoding="utf-8")
            mounts = _canonical_extra_mounts(
                [{"host": str(mounted), "container": "/mnt/cache"}]
            )

            mapped = _map_pack_path(
                str(collision), source_dir="", root=root, gen_dir=generated,
                short="demo", notes=[], extra_mounts=mounts,
            )

            self.assertEqual(mapped, str(collision))

    def test_extra_mount_container_paths_must_be_canonical(self) -> None:
        invalid = ("relative", "/mnt/./cache", "/mnt//cache", "/mnt/../cache", "/mnt\\cache", "/mnt/\tcache")
        for container in invalid:
            with self.subTest(container=container), self.assertRaises(ValueError):
                _canonical_extra_mounts([{"host": "/host/cache", "container": container}])

    def test_extra_mount_hosts_are_absolute_and_container_identities_are_unique(self) -> None:
        with self.assertRaisesRegex(ValueError, "host must be an absolute path"):
            _canonical_extra_mounts([{"host": "relative/cache", "container": "/mnt/cache"}])
        with self.assertRaisesRegex(ValueError, "duplicate container identity"):
            _canonical_extra_mounts(
                [
                    {"host": "/host/one", "container": "/mnt/cache"},
                    {"host": "/host/two", "container": "/mnt/cache"},
                ]
            )
        with self.assertRaisesRegex(ValueError, "duplicate container identity"):
            _canonical_extra_mounts(
                [
                    {"host": "/host/one", "container": "/mnt/cache"},
                    {"host": "/host/one", "container": "/mnt/cache"},
                ]
            )

    def test_workspace_paths_keep_canonical_relative_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ws"
            first = root / "targets" / "c" / "one" / "shared.cpp"
            second = root / "targets" / "c" / "two" / "shared.cpp"
            first.parent.mkdir(parents=True)
            second.parent.mkdir(parents=True)
            first.write_text("int first() { return 1; }\n", encoding="utf-8")
            second.write_text("int second() { return 2; }\n", encoding="utf-8")
            generated = root / "klee" / "harnesses" / "gen"
            generated.mkdir(parents=True)
            notes: list[str] = []

            first_path = _map_pack_path(str(first), source_dir="", root=root, gen_dir=generated, short="demo", notes=notes)
            second_path = _map_pack_path(str(second), source_dir="", root=root, gen_dir=generated, short="demo", notes=notes)

            self.assertNotEqual(first_path, second_path)
            self.assertEqual(first_path, "/work/harnesses/gen/workspace/targets/c/one/shared.cpp")
            self.assertEqual(second_path, "/work/harnesses/gen/workspace/targets/c/two/shared.cpp")
            self.assertIn("first", (generated / "workspace" / "targets" / "c" / "one" / "shared.cpp").read_text())
            self.assertIn("second", (generated / "workspace" / "targets" / "c" / "two" / "shared.cpp").read_text())

    def test_workspace_include_is_dropped_when_copy_would_recurse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ws"
            generated = root / "klee" / "harnesses" / "gen"
            generated.mkdir(parents=True)
            notes: list[str] = []

            mapped = _map_pack_path(str(root), source_dir="", root=root, gen_dir=generated, short="demo", notes=notes)

            self.assertIsNone(mapped)
            self.assertTrue(any("copy destination is inside source" in note for note in notes))
            self.assertFalse((root / "klee" / "gen-include" / "demo" / "workspace").exists())

    def test_workspace_symlink_escape_requires_a_declared_mount(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root_alias = tmp_path / "ws"
            generated = root_alias / "klee" / "harnesses" / "gen"
            generated.mkdir(parents=True)
            root = root_alias.resolve()
            outside = tmp_path / "outside"
            outside.mkdir()
            (outside / "api.h").write_text("#pragma once\n", encoding="utf-8")
            (root_alias / "linked").symlink_to(outside, target_is_directory=True)
            notes: list[str] = []
            blockers: list[str] = []

            mapped = _map_pack_path(
                str(root_alias / "linked" / "api.h"), source_dir="", root=root,
                gen_dir=generated, short="demo", notes=notes, blockers=blockers,
            )

            self.assertIsNone(mapped)
            self.assertTrue(any("escapes through a symbolic link" in item for item in blockers))

    def test_header_staging_is_recursive_and_selective(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "include"
            destination = tmp_path / "stage" / "include"
            (source / "nested").mkdir(parents=True)
            destination.parent.mkdir(parents=True)
            (source / "BUILD").write_text("metadata\n", encoding="utf-8")
            (source / "api.h").write_text("#pragma once\n", encoding="utf-8")
            (source / "impl.cpp").write_text("int root_impl;\n", encoding="utf-8")
            (source / "nested" / "api.hpp").write_text("#pragma once\n", encoding="utf-8")
            (source / "nested" / "impl.cpp").write_text("int impl;\n", encoding="utf-8")

            result = _stage_header_tree(source, destination)

            self.assertTrue(result["ok"], result)
            self.assertFalse((destination / "BUILD").exists())
            self.assertTrue((destination / "api.h").is_file())
            self.assertFalse((destination / "impl.cpp").exists())
            self.assertTrue((destination / "nested" / "api.hpp").is_file())
            self.assertFalse((destination / "nested" / "impl.cpp").exists())

    def test_header_staging_cap_failure_keeps_previous_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "include"
            destination = tmp_path / "stage" / "include"
            source.mkdir()
            destination.mkdir(parents=True)
            (source / "large.h").write_bytes(b"x" * 9)
            (destination / "previous.h").write_text("old\n", encoding="utf-8")

            result = _stage_header_tree(source, destination, per_file_byte_cap=8)

            self.assertFalse(result["ok"])
            self.assertTrue((destination / "previous.h").is_file())
            self.assertFalse((destination / "large.h").exists())
            self.assertEqual(list(destination.parent.glob(".include.stage-*")), [])

    def test_header_staging_rejects_symlinks_without_publishing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "include"
            destination = tmp_path / "stage" / "include"
            outside = tmp_path / "outside.h"
            source.mkdir()
            destination.parent.mkdir(parents=True)
            outside.write_text("secret\n", encoding="utf-8")
            (source / "escape.h").symlink_to(outside)

            result = _stage_header_tree(source, destination)

            self.assertFalse(result["ok"])
            self.assertIn("refuses symlink", result["blocker"])
            self.assertFalse(destination.exists())

    def test_header_staging_enforces_each_walk_cap(self) -> None:
        cases = (
            ("directory", {"directory_cap": 1}, lambda root: (root / "child").mkdir()),
            ("depth", {"depth_cap": 0}, lambda root: (root / "child").mkdir()),
            ("file", {"file_cap": 1}, lambda root: [
                (root / name).write_text("x", encoding="utf-8") for name in ("one.h", "two.h")
            ]),
            ("aggregate", {"total_byte_cap": 3}, lambda root: [
                (root / name).write_bytes(b"xx") for name in ("one.h", "two.h")
            ]),
        )
        for label, limits, populate in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                source = tmp_path / "include"
                destination = tmp_path / "stage" / "include"
                source.mkdir()
                destination.mkdir(parents=True)
                (destination / "previous.h").write_text("old\n", encoding="utf-8")
                populate(source)

                result = _stage_header_tree(source, destination, **limits)

                self.assertFalse(result["ok"])
                self.assertIn(label, result["blocker"])
                self.assertTrue((destination / "previous.h").is_file())

    def test_header_staging_rejects_a_file_changed_during_copy(self) -> None:
        for replacement in (b"short\n", b"original-header-with-growth\n"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                source = tmp_path / "include"
                destination = tmp_path / "stage" / "include"
                source.mkdir()
                destination.mkdir(parents=True)
                header = source / "api.h"
                header.write_bytes(b"original-header\n")
                (destination / "previous.h").write_text("old\n", encoding="utf-8")
                real_fstat = os.fstat
                calls = 0

                def changing_fstat(descriptor: int):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        header.write_bytes(replacement)
                    return real_fstat(descriptor)

                with mock.patch(
                    "agentic_fuzz_engine.harness_gen.os.fstat", side_effect=changing_fstat
                ):
                    result = _stage_header_tree(source, destination)

                self.assertFalse(result["ok"])
                self.assertIn("changed while being copied", result["blocker"])
                self.assertEqual(
                    (destination / "previous.h").read_text(encoding="utf-8"), "old\n"
                )
                self.assertFalse((destination / "api.h").exists())


class KleePackPolicyTests(unittest.TestCase):
    def test_pack_target_name_rejects_traversal_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_workspace(tmp_path)
            outside = tmp_path / "outside-pack.cpp"
            outside.write_text("sentinel\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "target slug"):
                generate_klee_pack(name="../../outside", workspace_root=ws, env={})

            self.assertEqual(outside.read_text(encoding="utf-8"), "sentinel\n")
            self.assertFalse((ws / "klee" / "gen-packs.ci.json").exists())

    def test_pack_outputs_reject_final_symlinks(self) -> None:
        outputs = ("demo-pack.cpp", "demo-pack-main.cpp", "gen-packs.ci.json")
        for output_name in outputs:
            with self.subTest(output=output_name), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                ws = _make_workspace(tmp_path)
                _make_pack_target(ws)
                outside = tmp_path / "outside"
                outside.write_text("sentinel\n", encoding="utf-8")
                if output_name == "gen-packs.ci.json":
                    output = ws / "klee" / output_name
                else:
                    output = ws / "klee" / "harnesses" / "gen" / output_name
                    output.parent.mkdir(parents=True)
                output.symlink_to(outside)

                with self.assertRaisesRegex(ValueError, "symbolic link"):
                    generate_klee_pack(name="demo", workspace_root=ws, env={})

                self.assertEqual(outside.read_text(encoding="utf-8"), "sentinel\n")
                self.assertTrue(output.is_symlink())

    def test_pack_output_directory_rejects_symlinked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_workspace(tmp_path)
            _make_pack_target(ws)
            outside = tmp_path / "outside"
            outside.mkdir()
            harnesses = ws / "klee" / "harnesses"
            harnesses.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "symlinked managed directory"):
                generate_klee_pack(name="demo", workspace_root=ws, env={})

            self.assertEqual(list(outside.iterdir()), [])

    def test_explicit_source_drop_and_forced_include_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "source"
            source.mkdir()
            keep = source / "keep.cpp"
            drop = source / "drop.cpp"
            keep.write_text("int keep;\n", encoding="utf-8")
            drop.write_text("int drop;\n", encoding="utf-8")
            ws = _make_workspace(tmp_path)
            config_path = ws / "workspace.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["source_dir"] = str(source)
            forced = ws / "targets" / "c" / "shared" / "shim.h"
            forced.parent.mkdir(parents=True)
            forced.write_text("#pragma once\n", encoding="utf-8")
            config["klee"] = {
                "drop_link_sources": ["drop.cpp"],
                "force_includes": [str(forced)],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            target = ws / "targets" / "c" / "demo"
            (target / ".localfuzz").mkdir(parents=True)
            (target / "harness.cpp").write_text("// harness\n", encoding="utf-8")
            (target / ".localfuzz" / "build.json").write_text(
                json.dumps({"steps": [{"name": "symcc", "argv": [
                    "sym++", str(target / "harness.cpp"), str(keep), str(drop)
                ]}]}),
                encoding="utf-8",
            )

            result = generate_klee_pack(name="demo", workspace_root=ws, env={})

            self.assertTrue(result["ok"], result)
            self.assertIn(str(keep.resolve()), result["entry"]["linkSources"])
            self.assertNotIn(str(drop.resolve()), result["entry"]["linkSources"])
            self.assertNotIn("/work/stub-include/klee_thread_shims.h", result["entry"]["compileArgs"])
            self.assertIn("-include", result["entry"]["compileArgs"])
            self.assertTrue(any("semantic reduction" in note for note in result["notes"]))
            self.assertGreaterEqual(sum("semantic reduction" in note for note in result["notes"]), 2)

    def test_forced_include_must_be_an_existing_regular_non_symlink_file(self) -> None:
        for kind in ("missing", "directory", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                ws = _make_workspace(tmp_path)
                _make_pack_target(ws)
                if kind == "missing":
                    forced = tmp_path / "missing.h"
                elif kind == "directory":
                    forced = tmp_path / "include-dir"
                    forced.mkdir()
                else:
                    real = tmp_path / "real.h"
                    real.write_text("#pragma once\n", encoding="utf-8")
                    forced = tmp_path / "linked.h"
                    forced.symlink_to(real)
                config_path = ws / "workspace.json"
                config = json.loads(config_path.read_text(encoding="utf-8"))
                config["klee"] = {"force_includes": [str(forced)]}
                config_path.write_text(json.dumps(config), encoding="utf-8")

                result = generate_klee_pack(name="demo", workspace_root=ws, env={})

                self.assertFalse(result["ok"], result)
                self.assertTrue(any("klee.force_includes" in item for item in result["blockers"]))
                self.assertFalse((ws / "klee" / "gen-packs.ci.json").exists())

    def test_pack_output_group_rolls_back_when_late_publication_fails(self) -> None:
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                ws = _make_workspace(tmp_path)
                _make_pack_target(ws)
                gen = ws / "klee" / "harnesses" / "gen"
                gen.mkdir(parents=True)
                pack = gen / "demo-pack.cpp"
                wrapper = gen / "demo-pack-main.cpp"
                ci = ws / "klee" / "gen-packs.ci.json"
                if existing:
                    pack.write_text("old pack\n", encoding="utf-8")
                    wrapper.write_text("old wrapper\n", encoding="utf-8")
                    ci.write_text(json.dumps({"targets": []}) + "\n", encoding="utf-8")
                previous = {
                    path: path.read_bytes() if path.exists() else None
                    for path in (pack, wrapper, ci)
                }
                real_replace = os.replace
                failed = False

                def fail_ci_once(
                    source: str | os.PathLike[str], destination: str | os.PathLike[str]
                ):
                    nonlocal failed
                    source_path = Path(source)
                    destination_path = Path(destination)
                    if (
                        not failed
                        and destination_path.resolve(strict=False) == ci.resolve(strict=False)
                        and source_path.name.startswith(".gen-packs.ci.json.")
                    ):
                        failed = True
                        raise OSError("injected late CI publication failure")
                    return real_replace(source, destination)

                with mock.patch(
                    "agentic_fuzz_engine.harness_gen.os.replace", side_effect=fail_ci_once
                ):
                    with self.assertRaisesRegex(OSError, "injected late CI"):
                        generate_klee_pack(name="demo", workspace_root=ws, env={})

                self.assertTrue(failed)
                for path, payload in previous.items():
                    if payload is None:
                        self.assertFalse(path.exists())
                    else:
                        self.assertEqual(path.read_bytes(), payload)
                self.assertEqual(list(gen.glob(".*.old-*")), [])
                self.assertEqual(list((ws / "klee").glob(".*.old-*")), [])

    def test_klee_policy_lists_are_typed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_workspace(tmp_path)
            config_path = ws / "workspace.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["klee"] = {"drop_link_sources": "not-an-array"}
            config_path.write_text(json.dumps(config), encoding="utf-8")
            target = ws / "targets" / "c" / "demo"
            (target / ".localfuzz").mkdir(parents=True)
            (target / "harness.cpp").write_text("// harness\n", encoding="utf-8")
            (target / ".localfuzz" / "build.json").write_text(
                json.dumps({"steps": [{"name": "symcc", "argv": ["sym++"]}]}), encoding="utf-8"
            )

            with self.assertRaisesRegex(ValueError, "must be an array"):
                generate_klee_pack(name="demo", workspace_root=ws, env={})


if __name__ == "__main__":
    unittest.main()

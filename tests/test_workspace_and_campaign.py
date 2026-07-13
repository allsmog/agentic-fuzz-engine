from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.scaffold import scaffold_target, select_targets
from agentic_fuzz_engine.workspace import (
    WORKSPACE_CONFIG_NAME,
    load_workspace,
    translate_host_path,
    workspace_init,
)


class WorkspaceTests(unittest.TestCase):
    def test_workspace_init_creates_layout_config_and_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ws"
            result = workspace_init(
                root=root,
                path_maps=["/home/user/.cache=/mnt/disks/data/cache"],
                source_dir=tmp,
                klee_image="klee-ng:test",
                build_container="sddev",
                env={},
            )

            self.assertTrue(result["ok"], result["blockers"])
            for relative in ("data", "targets/c", "benchmark/projects", "bin", "work", "klee"):
                self.assertTrue((root / relative).is_dir(), relative)
            config = json.loads((root / WORKSPACE_CONFIG_NAME).read_text(encoding="utf-8"))
            self.assertEqual(config["docker"]["klee_image"], "klee-ng:test")
            self.assertEqual(config["docker"]["build_container"], "sddev")
            self.assertEqual(config["path_maps"], [{"host": "/home/user/.cache", "outer": "/mnt/disks/data/cache"}])
            env_text = (root / "env.sh").read_text(encoding="utf-8")
            self.assertIn("AGENTIC_FUZZ_REFERENCE_ROOT", env_text)
            self.assertIn("CLAUDE_PLUGIN_DATA", env_text)

            loaded = load_workspace(root, env={})
            self.assertEqual(loaded["docker"]["klee_image"], "klee-ng:test")

    def test_workspace_init_copies_assets_and_reports_missing_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "legacy"
            (source / "sub").mkdir(parents=True)
            (source / "a.bin").write_bytes(b"a")
            (source / "sub" / "b.bin").write_bytes(b"b")
            (source / ".git").mkdir()
            (source / ".git" / "junk").write_bytes(b"x")

            result = workspace_init(
                root=tmp_path / "ws",
                copies=[f"{source}=klee/legacy", f"{tmp_path / 'missing'}=klee/nope"],
                env={},
            )

            self.assertFalse(result["ok"])
            copied = result["copies"][0]
            self.assertEqual(copied["copied_files"], 2)
            self.assertTrue((tmp_path / "ws" / "klee" / "legacy" / "sub" / "b.bin").is_file())
            self.assertFalse((tmp_path / "ws" / "klee" / "legacy" / ".git").exists())
            self.assertIn("copy source missing", result["copies"][1]["blocker"])

    def test_workspace_init_rejects_copy_destination_escaping_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "src"
            source.mkdir()
            result = workspace_init(root=tmp_path / "ws", copies=[f"{source}=../outside"], env={})
        self.assertFalse(result["ok"])
        self.assertIn("escapes workspace", result["blockers"][0])

    def test_translate_host_path_uses_longest_prefix_and_identity_fallback(self) -> None:
        workspace = {
            "path_maps": [
                {"host": "/home/user", "outer": "/mnt/outer/home"},
                {"host": "/home/user/.cache", "outer": "/mnt/disks/data/cache"},
            ]
        }
        self.assertEqual(
            translate_host_path("/home/user/.cache/klee-work", workspace),
            "/mnt/disks/data/cache/klee-work",
        )
        self.assertEqual(translate_host_path("/home/user/notes", workspace), "/mnt/outer/home/notes")
        self.assertEqual(translate_host_path("/srv/other", workspace), "/srv/other")


class ContainerBuildTests(unittest.TestCase):
    def test_build_target_runs_steps_with_placeholders_and_stops_on_failure(self) -> None:
        from agentic_fuzz_engine.container_build import build_target
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, source_dir=tmp, env={})
            target_dir = ws / "targets" / "c" / "demo"
            (target_dir / ".localfuzz").mkdir(parents=True)
            (target_dir / ".localfuzz" / "build.json").write_text(
                json.dumps(
                    {
                        "steps": [
                            {"name": "ok", "argv": ["/usr/bin/touch", "{bin_dir}/fuzzer"], "env": {}},
                            {"name": "boom", "argv": ["/bin/false"], "env": {}},
                            {"name": "after", "argv": ["/bin/true"], "env": {}},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = build_target(project="localfuzz/c/demo", workspace_root=ws, timeout_seconds=30, env=dict(os.environ))

        self.assertFalse(result["ok"])
        self.assertEqual([step["name"] for step in result["steps"]], ["ok", "boom", "after"])
        self.assertTrue(result["steps"][0]["ok"])
        self.assertFalse(result["steps"][1]["ok"])
        self.assertTrue(result["steps"][2]["skipped"])
        self.assertEqual(result["blockers"], ["boom: exit 1"])
        self.assertEqual(result["artifacts"][0]["path"].rsplit("/", 1)[-1], "fuzzer")


class ScaffoldTests(unittest.TestCase):
    def _write_sinks(self, path: Path) -> None:
        rows = [
            {"tag": "exec-L0", "file": "a.cpp", "line": 10, "method": "Run", "callee": "system", "code": "system(x)"},
            {"tag": "exec-L0", "file": "b.cpp", "line": 20, "method": "Go", "callee": "popen", "code": "popen(y)"},
            {"tag": "mem-parse", "file": "c.cpp", "line": 30, "method": "Parse", "callee": "memcpy", "code": "memcpy(d, s, n)"},
        ]
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    def test_select_targets_ranks_unharnessed_vectors_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sinks = tmp_path / "sinks.jsonl"
            self._write_sinks(sinks)
            (tmp_path / "ws" / "targets" / "c" / "mem_parse").mkdir(parents=True)
            (tmp_path / "ws" / "targets" / "c" / "_legacy").mkdir(parents=True)

            result = select_targets(sinks_jsonl=sinks, workspace_root=tmp_path / "ws", env={})

        self.assertEqual(result["existing_targets"], ["mem_parse"])
        self.assertEqual(result["unharnessed"], ["exec_l0"])
        first = result["vectors"][0]
        self.assertEqual(first["suggested_name"], "exec_l0")
        self.assertEqual(first["sink_count"], 2)
        self.assertFalse(first["harnessed"])

    def test_scaffold_target_generates_profile_config_build_and_harness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sinks = tmp_path / "sinks.jsonl"
            self._write_sinks(sinks)
            ws = tmp_path / "ws"

            result = scaffold_target(name="exec_l0", workspace_root=ws, sinks_jsonl=sinks, sink_tag="exec-L0", env={})

            self.assertTrue(result["ok"])
            self.assertEqual(result["sink_refs"], 2)
            target_dir = ws / "targets" / "c" / "exec_l0"
            config_text = (target_dir / ".localfuzz" / "config.yaml").read_text(encoding="utf-8")
            self.assertIn("- name: exec_l0", config_text)
            harness_text = (target_dir / "harness.cpp").read_text(encoding="utf-8")
            self.assertIn("TODO(human)", harness_text)
            self.assertIn("a.cpp:10", harness_text)
            self.assertIn("FUZZ_MAIN", harness_text)
            build = json.loads((target_dir / ".localfuzz" / "build.json").read_text(encoding="utf-8"))
            self.assertEqual([step["name"] for step in build["steps"]], ["libfuzzer", "symcc"])
            self.assertTrue((ws / "benchmark" / "projects" / "exec_l0" / "project.yaml").is_file())

            with self.assertRaises(FileExistsError):
                scaffold_target(name="exec_l0", workspace_root=ws, env={})

    def test_scaffold_target_rejects_bad_names(self) -> None:
        with self.assertRaises(ValueError):
            scaffold_target(name="Bad Name", workspace_root="/tmp/nowhere", env={})


if __name__ == "__main__":
    unittest.main()

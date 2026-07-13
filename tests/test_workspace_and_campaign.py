from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()

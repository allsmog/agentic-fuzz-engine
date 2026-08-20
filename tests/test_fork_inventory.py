from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentic_fuzz_engine import fork_inventory
from agentic_fuzz_engine.fork_inventory import _BoundedTree, _atomic_jsonl, run_fork_scan


class ForkInventoryTests(unittest.TestCase):
    def _repo(self, root: Path) -> Path:
        repo = root / "repo"
        manifest = repo / "deployment" / "packages.txt"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(
            "libpacket=2.1-vpatch7\n"
            "vpatch-nomarker=1.0.0\n"
            "libambiguous=4.2-vpatch3\n"
            "liblocal=3.0-vpatch2\n"
            "libsamepkg=3.1-vpatch2\n"
            "libextcodec=5.0-vpatch4\n"
            "libdebugtarget=6.0-vpatch1\n",
            encoding="utf-8",
        )
        (repo / "MODULE.bazel").write_text(
            '# module(name = "commented-fake")\n'
            'description = "module(name = \\"string-fake\\")"\n'
            'module(name = "module-name", repo_name = "primaryrepo")\n'
        )
        (repo / "BUILD").write_text(
            'cc_library(name = "packet-shadow")\ncc_import(name = "packet")\n', encoding="utf-8"
        )
        (repo / "BUILD.extra.bazel").write_text(
            'cc_import(name = "ambiguous-one")\ncc_import(name = "ambiguous-two")\n',
            encoding="utf-8",
        )
        (repo / "BUILD.vendorlibs.bazel").write_text('cc_import(name = "extcodec")\n')
        (repo / "BUILD.debug.bazel").write_text('cc_import(name = "debugtarget")\n')
        native = repo / "native"
        native.mkdir()
        (native / "BUILD.bazel").write_text('cc_import(name = "local")\n')
        consumer = repo / "src" / "codec"
        consumer.mkdir(parents=True)
        (consumer / "BUILD.bazel").write_text(
            'cc_import(name = "samepkg")\n'
            'cc_library(name = "codec", deps = [\n'
            '  "//:packet", "@primaryrepo//:packet", "//native:local", ":samepkg",\n'
            '  "@vendorlibs//:extcodec", "@debug//:debugtarget", "@unrelated//:packet",\n'
            '])\n', encoding="utf-8"
        )
        return repo

    def test_marker_must_be_in_version_and_build_names_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self._repo(root)
            out = root / "forks.jsonl"
            result = run_fork_scan(
                source_root=repo, consumer_root=repo / "src", out_path=out,
                workspace_root=root / "absent", vendor_markers=["vpatch"],
                manifest_globs=["deployment/*.txt"], dpkg_info_dir=root / "none", env={},
            )
            self.assertTrue(result["ok"], result)
            rows = {row["package"]: row for row in map(json.loads, out.read_text().splitlines())}
            self.assertNotIn("vpatch-nomarker", rows)
            self.assertEqual(rows["libpacket"]["bazel_lib"], "packet")
            self.assertEqual(rows["libpacket"]["bazel_label"], "//:packet")
            self.assertEqual(rows["libpacket"]["bazel_repository"], "primaryrepo")
            self.assertEqual(rows["libpacket"]["consumer_files"], ["codec/BUILD.bazel"])
            self.assertEqual(rows["libpacket"]["consumer_match_confidence"], "exact-canonical-bazel-label")
            self.assertEqual(rows["libpacket"]["candidate_evidence"], "version-marker")
            self.assertEqual(rows["liblocal"]["bazel_label"], "//native:local")
            self.assertEqual(rows["liblocal"]["consumer_files"], ["codec/BUILD.bazel"])
            self.assertEqual(rows["libsamepkg"]["bazel_label"], "//src/codec:samepkg")
            self.assertEqual(rows["libsamepkg"]["consumer_files"], ["codec/BUILD.bazel"])
            self.assertIsNone(rows["libextcodec"]["bazel_label"])
            self.assertIsNone(rows["libextcodec"]["bazel_repository"])
            self.assertEqual(rows["libextcodec"]["bazel_label_confidence"], "alternate-build-file-unbound")
            self.assertEqual(rows["libextcodec"]["consumer_files"], [])
            self.assertIsNone(rows["libdebugtarget"]["bazel_label"])
            self.assertEqual(rows["libdebugtarget"]["consumer_files"], [])

    def test_ambiguous_name_match_is_not_asserted_as_a_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self._repo(root)
            out = root / "forks.jsonl"
            run_fork_scan(
                source_root=repo, out_path=out, workspace_root=root / "absent",
                vendor_markers=["vpatch"], manifest_globs=["deployment/*.txt"], env={},
            )
            rows = {row["package"]: row for row in map(json.loads, out.read_text().splitlines())}
            ambiguous = rows["libambiguous"]
            self.assertIsNone(ambiguous["bazel_lib"])
            self.assertEqual(ambiguous["bazel_match"], "ambiguous-partial")
            self.assertEqual(
                ambiguous["bazel_lib_candidates"],
                ["unbound:BUILD.extra.bazel#ambiguous-one", "unbound:BUILD.extra.bazel#ambiguous-two"],
            )

    def test_rejects_escaping_glob_and_symlink_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self._repo(root)
            result = run_fork_scan(
                source_root=repo, out_path=root / "unused", workspace_root=root / "absent",
                vendor_markers=["vpatch"], manifest_globs=["../*.txt"], env={},
            )
            self.assertFalse(result["ok"])
            victim = root / "victim"
            victim.write_text("keep", encoding="utf-8")
            output = root / "forks.jsonl"
            output.symlink_to(victim)
            result = run_fork_scan(
                source_root=repo, out_path=output, workspace_root=root / "absent",
                vendor_markers=["vpatch"], manifest_globs=["deployment/*.txt"], env={},
            )
            self.assertFalse(result["ok"])
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep")

    def test_workspace_output_cannot_escape_with_parent_traversal_or_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            workspace = base / "workspace"
            workspace.mkdir()
            (workspace / "workspace.json").write_text(json.dumps({"source_dir": str(workspace)}))
            repo = self._repo(base)
            victim = base / "victim"
            victim.write_text("keep")
            result = run_fork_scan(
                source_root=repo, workspace_root=workspace,
                out_path=workspace / "data" / ".." / ".." / "victim",
                vendor_markers=["vpatch"], manifest_globs=["deployment/*.txt"], env={},
            )
            self.assertFalse(result["ok"])
            self.assertEqual(victim.read_text(), "keep")

            outside = base / "outside"
            outside.mkdir()
            (workspace / "linked").symlink_to(outside, target_is_directory=True)
            result = run_fork_scan(
                source_root=repo, workspace_root=workspace, out_path=workspace / "linked" / "forks.jsonl",
                vendor_markers=["vpatch"], manifest_globs=["deployment/*.txt"], env={},
            )
            self.assertFalse(result["ok"])
            self.assertFalse((outside / "forks.jsonl").exists())

    def test_conflicting_module_and_workspace_aliases_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self._repo(root)
            (repo / "WORKSPACE").write_text('workspace(name = "legacyrepo")\n', encoding="utf-8")
            out = root / "forks.jsonl"
            out.write_text("sentinel\n", encoding="utf-8")

            result = run_fork_scan(
                source_root=repo, consumer_root=repo / "src", out_path=out,
                workspace_root=root / "absent", vendor_markers=["vpatch"],
                manifest_globs=["deployment/*.txt"], env={},
            )

            self.assertFalse(result["ok"])
            self.assertIn("conflicting Bazel self-repository aliases", result["blockers"][0])
            self.assertEqual(out.read_text(encoding="utf-8"), "sentinel\n")

    def test_explicit_repository_alias_resolves_conflicting_declarations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self._repo(root)
            (repo / "WORKSPACE.bazel").write_text(
                'workspace(name = "legacyrepo")\n', encoding="utf-8"
            )
            (repo / "src" / "codec" / "BUILD.bazel").write_text(
                'cc_library(name = "codec", deps = ["@chosenrepo//:packet"])\n',
                encoding="utf-8",
            )
            out = root / "forks.jsonl"

            result = run_fork_scan(
                source_root=repo, consumer_root=repo / "src", out_path=out,
                workspace_root=root / "absent", vendor_markers=["vpatch"],
                manifest_globs=["deployment/*.txt"], repository_alias="chosenrepo", env={},
            )

            self.assertTrue(result["ok"], result)
            rows = {row["package"]: row for row in map(json.loads, out.read_text().splitlines())}
            self.assertEqual(rows["libpacket"]["bazel_repository"], "chosenrepo")
            self.assertEqual(rows["libpacket"]["consumer_files"], ["codec/BUILD.bazel"])

    def test_tree_enumeration_is_bounded_before_scan_results_are_materialized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self._repo(root)
            out = root / "forks.jsonl"
            with mock.patch.object(fork_inventory, "MAX_TREE_ENTRIES", 1):
                result = run_fork_scan(
                    source_root=repo, out_path=out, workspace_root=root / "absent",
                    vendor_markers=["vpatch"], manifest_globs=["deployment/*.txt"], env={},
                )
            self.assertFalse(result["ok"])
            self.assertIn("source tree exceeds 1 entries", result["blockers"][0])
            self.assertFalse(out.exists())

    def test_anchored_source_read_rejects_path_swap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.txt"
            outside = root.parent / f"{root.name}-outside.txt"
            source.write_text("SAFE", encoding="utf-8")
            outside.write_text("OUTSIDE_SECRET", encoding="utf-8")
            try:
                with _BoundedTree(root) as tree:
                    candidate = next(tree.regular_files())
                    source.unlink()
                    source.symlink_to(outside)
                    with self.assertRaisesRegex(ValueError, "changed before opening"):
                        tree.read_text(candidate, max_bytes=100)
            finally:
                outside.unlink(missing_ok=True)

    def test_atomic_report_is_anchored_across_parent_swap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "reports"
            moved = root / "reports-moved"
            victim = root / "victim"
            parent.mkdir()
            victim.mkdir()
            output = parent / "report.jsonl"
            victim_output = victim / output.name
            victim_output.write_text("KEEP\n", encoding="utf-8")
            real_replace = os.replace

            def swap_then_replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                parent.rename(moved)
                parent.symlink_to(victim, target_is_directory=True)
                return real_replace(
                    src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd
                )

            with mock.patch.object(fork_inventory.os, "replace", side_effect=swap_then_replace):
                with self.assertRaisesRegex(ValueError, "directory identity changed"):
                    _atomic_jsonl(output, [{"safe": True}])

            self.assertEqual(victim_output.read_text(encoding="utf-8"), "KEEP\n")
            self.assertEqual(
                json.loads((moved / output.name).read_text(encoding="utf-8")),
                {"safe": True},
            )

    def test_atomic_report_rejects_regular_parent_swap_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "reports"
            moved = root / "reports-moved"
            victim = root / "victim"
            parent.mkdir()
            victim.mkdir()
            output = parent / "report.jsonl"
            victim_output = victim / output.name
            victim_output.write_text("KEEP\n", encoding="utf-8")
            real_open = fork_inventory._open_output_parent

            def swap_then_open(path, *, ancestor, ancestor_expected, missing_parts):
                parent.rename(moved)
                victim.rename(parent)
                try:
                    return real_open(
                        path,
                        ancestor=ancestor,
                        ancestor_expected=ancestor_expected,
                        missing_parts=missing_parts,
                    )
                finally:
                    parent.rename(victim)
                    moved.rename(parent)

            with mock.patch.object(
                fork_inventory, "_open_output_parent", side_effect=swap_then_open
            ):
                with self.assertRaisesRegex(ValueError, "changed before opening"):
                    _atomic_jsonl(output, [{"safe": True}])

            self.assertEqual(victim_output.read_text(encoding="utf-8"), "KEEP\n")
            self.assertFalse(output.exists())

    def test_atomic_report_rejects_substituted_missing_intermediate_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / "victim"
            victim_nested = victim / "reports"
            victim_nested.mkdir(parents=True)
            victim_output = victim_nested / "report.jsonl"
            victim_output.write_text("KEEP\n", encoding="utf-8")
            injected = root / "new"
            output = injected / "reports" / "report.jsonl"
            real_open = fork_inventory._open_output_parent

            def inject_then_open(path, *, ancestor, ancestor_expected, missing_parts):
                victim.rename(injected)
                try:
                    return real_open(
                        path,
                        ancestor=ancestor,
                        ancestor_expected=ancestor_expected,
                        missing_parts=missing_parts,
                    )
                finally:
                    injected.rename(victim)

            with mock.patch.object(
                fork_inventory, "_open_output_parent", side_effect=inject_then_open
            ):
                with self.assertRaisesRegex(ValueError, "must already exist"):
                    _atomic_jsonl(output, [{"safe": True}])

            self.assertEqual(victim_output.read_text(encoding="utf-8"), "KEEP\n")
            self.assertFalse(output.exists())

    def test_atomic_report_requires_an_existing_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "new" / "reports" / "report.jsonl"
            with self.assertRaisesRegex(ValueError, "must already exist"):
                _atomic_jsonl(output, [{"safe": True}])
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from agentic_fuzz_engine.process_safety import BoundedRun
from agentic_fuzz_engine.sanitizer_variants import (
    derive_variant_config,
    ensure_sanitizer_dep,
    iter_crash_signals,
    load_sanitizer_deps,
    sanitizer_build,
    sanitizer_sweep,
    variant_step_names,
)

ASAN = """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
    #0 0x1000 in Decode /src/decode.cpp:19:3
"""


class SanitizerConfigTests(unittest.TestCase):
    def test_derives_only_exact_fuzzer_step_and_component_safe_rewrites(self) -> None:
        config = {"steps": [
            {"name": "fuzzer", "argv": ["clang++", "-fsanitize=address,undefined", "-I/dep-old/include", "/dep-old/lib.a", "{bin_dir}/fuzzer"]},
            {"name": "neighbor", "argv": ["clang++", "-fsanitize=address", "/dep-old2/lib.a", "{bin_dir}/fuzzer-other"]},
        ]}
        derived, blocker = derive_variant_config(
            config, sanitizer="msan", path_rewrites=[("/dep-old", "/dep-new")]
        )
        self.assertIsNone(blocker)
        self.assertIsNotNone(derived)
        argv = derived["steps"][0]["argv"]
        self.assertIn("-fsanitize=memory", argv)
        self.assertIn("-I/dep-new/include", argv)
        self.assertIn("/dep-new/lib.a", argv)
        self.assertEqual(derived["steps"][1], config["steps"][1])
        self.assertEqual(variant_step_names(derived, sanitizer="msan"), ["fuzzer"])

    def test_iterates_multiple_unique_reports(self) -> None:
        reports = iter_crash_signals(ASAN + "\n" + ASAN.replace("heap-buffer-overflow", "heap-use-after-free"))
        self.assertEqual(len(reports), 2)

    def test_incomplete_dependency_destination_is_never_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "configure").write_text("configure")
            dest = root / "dep-msan"
            dest.mkdir()
            sentinel = dest / "keep"
            sentinel.write_text("keep")
            result = ensure_sanitizer_dep(
                root=root,
                dep={"name": "dep", "source": "source", "dest": "dep-{sanitizer}", "artifacts": ["lib/lib.a"]},
                sanitizer="msan", timeout_seconds=10, env={},
            )
            self.assertEqual(result["status"], "failed")
            self.assertEqual(sentinel.read_text(), "keep")

    def test_failed_dependency_build_never_promotes_or_damages_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            sentinel = source / "sentinel"
            sentinel.write_text("keep")
            configure = source / "configure"
            configure.write_text("#!/bin/sh\nexit 9\n")
            configure.chmod(configure.stat().st_mode | stat.S_IXUSR)
            result = ensure_sanitizer_dep(
                root=root,
                dep={"name": "dep", "source": "source", "dest": "dep-{sanitizer}", "artifacts": ["lib/lib.a"]},
                sanitizer="msan", timeout_seconds=10,
                env={"PATH": os.environ.get("PATH", "")},
            )
            self.assertEqual(result["status"], "failed")
            self.assertFalse((root / "dep-msan").exists())
            self.assertEqual(sentinel.read_text(), "keep")
            self.assertFalse(Path(result["staging"]).exists())
            self.assertEqual(list(root.glob(".dep-msan.stage-*")), [])

    def test_dependency_copy_rejects_same_size_mutation_and_cleans_staging(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            configure = source / "configure"
            configure.write_bytes(b"abcdefgh")
            configure.chmod(configure.stat().st_mode | stat.S_IXUSR)
            original_read = os.read
            changed = False

            def mutating_read(descriptor, amount):
                nonlocal changed
                chunk = original_read(descriptor, amount)
                if chunk and not changed:
                    changed = True
                    configure.write_bytes(b"ABCDEFGH")
                return chunk

            with mock.patch("agentic_fuzz_engine.sanitizer_variants.os.read", side_effect=mutating_read):
                result = ensure_sanitizer_dep(
                    root=root,
                    dep={"name": "dep", "source": "source", "dest": "dep-{sanitizer}", "artifacts": ["lib/lib.a"]},
                    sanitizer="msan", timeout_seconds=10, env={},
                )
            self.assertEqual(result["status"], "failed")
            self.assertTrue(any("changed" in item for item in result["blockers"]))
            self.assertEqual(list(root.glob(".dep-msan.stage-*")), [])

    def test_dependency_staging_budget_failure_is_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "configure").write_text("configure")
            with mock.patch(
                "agentic_fuzz_engine.sanitizer_variants._copy_dep_tree_fds",
                side_effect=ValueError("total dependency build budget exhausted during staging"),
            ):
                result = ensure_sanitizer_dep(
                    root=root,
                    dep={"name": "dep", "source": "source", "dest": "dep-{sanitizer}", "artifacts": ["lib/lib.a"]},
                    sanitizer="msan", timeout_seconds=10, env={},
                )
            self.assertEqual(result["status"], "failed")
            self.assertIn("budget exhausted", result["blockers"][0])
            self.assertEqual(list(root.glob(".dep-msan.stage-*")), [])

    def test_dependency_promotion_is_anchored_against_parent_swap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "workspace"
            root.mkdir()
            source = root / "source"
            source.mkdir()
            configure = source / "configure"
            configure.write_text("configure")
            configure.chmod(configure.stat().st_mode | stat.S_IXUSR)
            moved = base / "workspace-original"
            original_replace = os.replace
            swapped = False

            def successful_build(_argv, **kwargs):
                staging = Path(kwargs["cwd"])
                artifact = staging / "lib" / "lib.a"
                artifact.parent.mkdir(exist_ok=True)
                artifact.write_bytes(b"archive")
                return BoundedRun(0, False, 1, "", "")

            def swapping_replace(source_name, destination_name, **kwargs):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    root.rename(moved)
                    root.mkdir()
                return original_replace(source_name, destination_name, **kwargs)

            with mock.patch(
                "agentic_fuzz_engine.sanitizer_variants.bounded_run", side_effect=successful_build
            ), mock.patch(
                "agentic_fuzz_engine.sanitizer_variants.os.replace", side_effect=swapping_replace
            ):
                result = ensure_sanitizer_dep(
                    root=root,
                    dep={"name": "dep", "source": "source", "dest": "dep-{sanitizer}", "artifacts": ["lib/lib.a"]},
                    sanitizer="msan", timeout_seconds=10, env={},
                )
            self.assertEqual(result["status"], "failed")
            self.assertEqual(list(root.iterdir()), [])
            self.assertFalse((moved / "dep-msan").exists())
            self.assertEqual(list(moved.glob(".dep-msan.stage-*")), [])

    def test_dependency_success_promotes_one_complete_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            configure = source / "configure"
            configure.write_text("configure")
            configure.chmod(configure.stat().st_mode | stat.S_IXUSR)

            def successful_build(_argv, **kwargs):
                artifact = Path(kwargs["cwd"]) / "lib" / "lib.a"
                artifact.parent.mkdir(exist_ok=True)
                artifact.write_bytes(b"archive")
                return BoundedRun(0, False, 1, "", "")

            with mock.patch(
                "agentic_fuzz_engine.sanitizer_variants.bounded_run", side_effect=successful_build
            ):
                result = ensure_sanitizer_dep(
                    root=root,
                    dep={"name": "dep", "source": "source", "dest": "dep-{sanitizer}", "artifacts": ["lib/lib.a"]},
                    sanitizer="msan", timeout_seconds=10, env={},
                )
            self.assertEqual(result["status"], "built")
            self.assertEqual((root / "dep-msan" / "lib" / "lib.a").read_bytes(), b"archive")
            self.assertEqual(list(root.glob(".dep-msan.stage-*")), [])

    def test_dependency_recipe_read_is_nofollow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            local = target / ".localfuzz"
            local.mkdir()
            recipe = local / "sanitizer-deps.json"
            recipe.write_text(json.dumps({"deps": [{
                "name": "dep", "source": "src", "dest": "out-{sanitizer}",
                "artifacts": ["lib.a"], "env": {"FLAG": "value"},
            }]}))
            deps, blockers = load_sanitizer_deps(target)
            self.assertEqual(deps, [])
            self.assertTrue(any("declared_env" in item for item in blockers))

            actual = target / "actual.json"
            actual.write_text('{"deps": []}')
            recipe.unlink()
            recipe.symlink_to(actual)
            deps, blockers = load_sanitizer_deps(target)
            self.assertEqual(deps, [])
            self.assertTrue(blockers)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO regression")
    def test_dependency_and_build_recipe_fifos_are_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "targets" / "c" / "demo"
            local = target / ".localfuzz"
            local.mkdir(parents=True)
            dep_recipe = local / "sanitizer-deps.json"
            os.mkfifo(dep_recipe)

            started = time.monotonic()
            deps, blockers = load_sanitizer_deps(target)
            self.assertEqual(deps, [])
            self.assertTrue(blockers)
            self.assertLess(time.monotonic() - started, 1.0)

            dep_recipe.unlink()
            os.mkfifo(local / "build.json")
            started = time.monotonic()
            result = sanitizer_build(
                target="demo", sanitizer="msan", workspace_root=root, env={},
            )
            self.assertFalse(result["ok"])
            self.assertLess(time.monotonic() - started, 1.0)


class SanitizerSweepTests(unittest.TestCase):
    def _workspace(self, root: Path) -> tuple[Path, Path]:
        seeds = root / "work" / "demo" / "seeds"
        seeds.mkdir(parents=True)
        (seeds / "ok").write_bytes(b"OK")
        (seeds / "bad").write_bytes(b"BAD")
        variant = root / "variant"
        variant.write_text(
            f"#!{sys.executable}\nimport pathlib,sys\ndata=pathlib.Path(sys.argv[1]).read_bytes()\n"
            f"if data == b'BAD':\n print({ASAN!r}, file=sys.stderr); raise SystemExit(1)\n"
        )
        variant.chmod(variant.stat().st_mode | stat.S_IXUSR)
        return seeds, variant

    def test_sweep_groups_candidate_and_uses_evidence_language(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seeds, variant = self._workspace(root)
            result = sanitizer_sweep(
                target="demo", sanitizer="tsan", binary=variant, workspace_root=root,
                env={"PATH": os.environ.get("PATH", "")},
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["unique_signatures"], 1)
            report = json.loads(Path(result["report"]).read_text())
            self.assertIn("candidates", report["interpretation"])
            self.assertIn("not absence evidence", report["interpretation"])

    def test_sweep_sanitizes_env_and_refuses_report_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seeds, variant = self._workspace(root)
            with mock.patch(
                "agentic_fuzz_engine.sanitizer_variants.bounded_run",
                return_value=BoundedRun(0, False, 1, "", ""),
            ) as run:
                result = sanitizer_sweep(
                    target="demo", sanitizer="msan", binary=variant, workspace_root=root,
                    env={"PATH": os.environ.get("PATH", ""), "TOP_SECRET": "hidden", "LD_PRELOAD": "inject"},
                )
            self.assertTrue(result["ok"], result)
            for call in run.call_args_list:
                passed = call.kwargs["env"]
                self.assertNotIn("TOP_SECRET", passed)
                self.assertNotIn("LD_PRELOAD", passed)
                self.assertEqual(passed["DEBUGINFOD_URLS"], "")

            victim = root / "victim"
            victim.write_text("keep")
            report = root / "work" / "demo" / "msan-sweep.json"
            report.unlink()
            report.symlink_to(victim)
            result = sanitizer_sweep(
                target="demo", sanitizer="msan", binary=variant, workspace_root=root,
                env={"PATH": os.environ.get("PATH", "")},
            )
            self.assertFalse(result["ok"])
            self.assertEqual(victim.read_text(), "keep")

    def test_nonzero_without_sanitizer_report_is_infrastructure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seeds, variant = self._workspace(root)
            runs = [
                BoundedRun(0, False, 1, "", ""),
                BoundedRun(2, False, 1, "", "ordinary failure"),
                BoundedRun(0, False, 1, "", ""),
            ]
            with mock.patch("agentic_fuzz_engine.sanitizer_variants.bounded_run", side_effect=runs):
                result = sanitizer_sweep(
                    target="demo", sanitizer="msan", binary=variant, workspace_root=root,
                )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["infrastructure_failures"], 1)
            self.assertEqual(result["unique_signatures"], 0)

    def test_forbidden_declared_env_is_rejected_before_runtime_setup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = sanitizer_sweep(
                target="demo", sanitizer="msan", workspace_root=tmp,
                declared_env={"PYTHONPATH": "blocked"},
            )
        self.assertFalse(result["ok"])
        self.assertIn("forbidden", result["blockers"][0])

    def test_baseline_cleanup_is_anchored_against_parent_swap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seeds, variant = self._workspace(root)
            report_dir = root / "work" / "demo"
            moved = root / "work" / "demo-original"
            victim_dir = root / "victim"
            victim_dir.mkdir()
            victim_file: Path | None = None

            def swap_parent(argv, **_kwargs):
                nonlocal victim_file
                baseline = Path(argv[1])
                report_dir.rename(moved)
                report_dir.symlink_to(victim_dir, target_is_directory=True)
                victim_file = victim_dir / baseline.name
                victim_file.write_text("keep", encoding="utf-8")
                return BoundedRun(0, False, 1, "", "")

            with mock.patch(
                "agentic_fuzz_engine.sanitizer_variants.bounded_run", side_effect=swap_parent
            ):
                result = sanitizer_sweep(
                    target="demo", sanitizer="msan", binary=variant, workspace_root=root,
                )

            self.assertFalse(result["ok"])
            self.assertTrue(any("baseline cleanup failed" in item for item in result["blockers"]))
            self.assertIsNotNone(victim_file)
            self.assertEqual(victim_file.read_text(encoding="utf-8"), "keep")
            self.assertEqual(list(moved.glob(".sanitizer-baseline-*")), [])

    def test_rejects_nonfinite_budget_and_bad_target(self) -> None:
        result = sanitizer_sweep(target="../escape", sanitizer="msan", binary="/bin/true", workspace_root="/tmp")
        self.assertFalse(result["ok"])
        result = sanitizer_sweep(
            target="demo", sanitizer="msan", binary="/bin/true", max_seconds=float("inf"), workspace_root="/tmp"
        )
        self.assertFalse(result["ok"])

    def test_rejects_symlinked_binary_and_corpus_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seeds = root / "work" / "demo" / "seeds"
            seeds.mkdir(parents=True)
            outside_seed = root / "outside-seed"
            outside_seed.write_bytes(b"x")
            (seeds / "linked").symlink_to(outside_seed)
            (seeds / "regular").write_bytes(b"x")
            linked_binary = root / "linked-binary"
            linked_binary.symlink_to("/bin/true")
            result = sanitizer_sweep(
                target="demo", sanitizer="msan", binary=linked_binary, workspace_root=root
            )
            self.assertFalse(result["ok"])
            self.assertTrue(any("symlinked variant binary" in item for item in result["blockers"]))

            real_binary = root / "binary"
            real_binary.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n")
            real_binary.chmod(real_binary.stat().st_mode | stat.S_IXUSR)
            (seeds / "regular").unlink()
            result = sanitizer_sweep(
                target="demo", sanitizer="msan", binary=real_binary, workspace_root=root
            )
            self.assertFalse(result["ok"])
            self.assertTrue(any("no bounded regular inputs" in item for item in result["blockers"]))

            real_corpus = root / "real-corpus"
            real_corpus.mkdir()
            (real_corpus / "one").write_bytes(b"x")
            linked_corpus = root / "linked-corpus"
            linked_corpus.symlink_to(real_corpus, target_is_directory=True)
            result = sanitizer_sweep(
                target="demo", sanitizer="msan", binary=real_binary,
                corpus_dir=linked_corpus, workspace_root=root,
            )
            self.assertFalse(result["ok"])
            self.assertTrue(any("symlinked corpus" in item for item in result["blockers"]))

    def test_rejects_wrapper_binary_primary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seeds = root / "work" / "demo" / "seeds"
            seeds.mkdir(parents=True)
            (seeds / "one").write_bytes(b"x")
            result = sanitizer_sweep(
                target="demo", sanitizer="msan", binary="/usr/bin/env", workspace_root=root
            )
            self.assertFalse(result["ok"])
            self.assertTrue(any("wrapper" in item for item in result["blockers"]))

    def test_refuses_symlinked_hit_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seeds, variant = self._workspace(root)
            victim = root / "victim-dir"
            victim.mkdir()
            (root / "work" / "demo" / "tsan-hits").symlink_to(victim, target_is_directory=True)
            result = sanitizer_sweep(
                target="demo", sanitizer="tsan", binary=variant, workspace_root=root,
                env={"PATH": os.environ.get("PATH", "")},
            )
            self.assertFalse(result["ok"])
            self.assertEqual(list(victim.iterdir()), [])


if __name__ == "__main__":
    unittest.main()

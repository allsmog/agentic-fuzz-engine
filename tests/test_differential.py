from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from hashlib import sha256
from pathlib import Path
from unittest import mock

from agentic_fuzz_engine.differential import (
    _ExemplarLimit,
    _atomic_json,
    _copy_exemplar,
    _corpus_inputs,
    classify_execution,
    differential_run,
    diverges,
    load_differential_recipe,
)
from agentic_fuzz_engine.process_safety import BoundedRun

ASAN = """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
    #0 0x1000 in ParseHeader /src/parse.cpp:42:3
"""


class DifferentialPureTests(unittest.TestCase):
    def test_explicit_exit_policy_separates_rejection_from_infrastructure(self) -> None:
        self.assertEqual(classify_execution(-11, "", reject_exit_codes=[2]), "crash")
        self.assertEqual(classify_execution(0, "", reject_exit_codes=[2]), "ok")
        self.assertEqual(classify_execution(2, "", reject_exit_codes=[2]), "error")
        self.assertEqual(classify_execution(3, "", reject_exit_codes=[2]), "infrastructure")
        self.assertEqual(
            classify_execution(127, "", accept_exit_codes=[0, 127], reject_exit_codes=[2]),
            "infrastructure",
        )
        sanitizer_shaped_launch_error = (
            "[Errno 2] No such file or directory: "
            "'ERROR: AddressSanitizer: heap-buffer-overflow'"
        )
        self.assertEqual(
            classify_execution(127, sanitizer_shaped_launch_error, reject_exit_codes=[2]),
            "infrastructure",
        )
        self.assertEqual(classify_execution(0, ASAN, reject_exit_codes=[2]), "crash")
        self.assertIsNone(diverges([{"exit_class": "error"}], compare="behavior"))
        self.assertEqual(diverges([{"exit_class": "crash"}], compare="behavior"), "self-check")

    def test_infrastructure_cannot_create_a_divergence(self) -> None:
        rows = [
            {"exit_class": "infrastructure", "stdout_sha": None},
            {"exit_class": "ok", "stdout_sha": "a"},
        ]
        self.assertIsNone(diverges(rows, compare="behavior"))
        rows = [
            {"exit_class": "ok", "stdout_sha": "a"},
            {"exit_class": "error", "stdout_sha": None},
        ]
        self.assertEqual(diverges(rows, compare="behavior"), "validity-split")

    def test_recipe_rejects_shell_and_overlapping_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            config = target / ".localfuzz"
            config.mkdir()
            (config / "differential.json").write_text(json.dumps({"implementations": [{
                "label": "one", "binary": "bin/one", "command": ["sh", "-c", "true"],
                "accept_exit_codes": [0], "reject_exit_codes": [0],
            }]}))
            recipe, blockers = load_differential_recipe(target)
            self.assertIsNone(recipe)
            self.assertTrue(any("shell" in item for item in blockers))
            self.assertTrue(any("overlap" in item for item in blockers))

    def test_recipe_rejects_implicit_environment_channels_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            config = target / ".localfuzz"
            config.mkdir()
            recipe_path = config / "differential.json"
            recipe_path.write_text(json.dumps({"implementations": [{
                "label": "one", "binary": "bin/one", "env": {"FLAG": "value"},
            }]}))
            recipe, blockers = load_differential_recipe(target)
            self.assertIsNone(recipe)
            self.assertTrue(any("declared_env" in item for item in blockers))

            actual = target / "actual.json"
            actual.write_text('{"implementations": []}')
            recipe_path.unlink()
            recipe_path.symlink_to(actual)
            recipe, blockers = load_differential_recipe(target)
            self.assertIsNone(recipe)
            self.assertTrue(blockers)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO regression")
    def test_recipe_fifo_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            config = target / ".localfuzz"
            config.mkdir()
            os.mkfifo(config / "differential.json")

            started = time.monotonic()
            recipe, blockers = load_differential_recipe(target)

            self.assertIsNone(recipe)
            self.assertTrue(blockers)
            self.assertLess(time.monotonic() - started, 1.0)


class DifferentialRunTests(unittest.TestCase):
    def _seeds(self, root: Path) -> None:
        seeds = root / "work" / "demo" / "seeds"
        seeds.mkdir(parents=True)
        (seeds / "agree").write_bytes(b"OK")
        (seeds / "reject").write_bytes(b"NO")
        (seeds / "crash").write_bytes(b"BAD")

    def test_classifies_candidates_and_ranks_crash_split_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._seeds(root)
            first = "import pathlib,sys; d=pathlib.Path(sys.argv[1]).read_bytes(); print(d.hex()); raise SystemExit(2 if d==b'NO' else 0)"
            second = f"import pathlib,sys; d=pathlib.Path(sys.argv[1]).read_bytes(); print(d.hex());\nif d==b'BAD':\n print({ASAN!r}, file=sys.stderr); raise SystemExit(1)"
            result = differential_run(
                target="demo",
                commands=[[sys.executable, "-c", first], [sys.executable, "-c", second]],
                labels=["first", "second"], reject_exit_codes=[2], workspace_root=root,
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["divergent"], 2)
            self.assertEqual(result["counts_by_kind"], {"crash-split": 1, "validity-split": 1})
            self.assertEqual(result["divergences"][0]["kind"], "crash-split")
            report = json.loads(Path(result["report"]).read_text())
            self.assertIn("not proof", report["interpretation"])
            self.assertNotIn("commands", report)

    def test_unknown_exit_is_infrastructure_not_a_lead(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seeds = root / "work" / "demo" / "seeds"
            seeds.mkdir(parents=True)
            (seeds / "one").write_bytes(b"x")
            result = differential_run(
                target="demo",
                commands=[[sys.executable, "-c", "raise SystemExit(3)"],
                          [sys.executable, "-c", "raise SystemExit(0)"]],
                labels=["broken", "ok"], reject_exit_codes=[2], workspace_root=root,
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["divergent"], 0)
            self.assertEqual(result["infrastructure_failures"], 1)

    def test_sanitizer_shaped_missing_executable_is_launch_infrastructure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seeds = root / "work" / "demo" / "seeds"
            seeds.mkdir(parents=True)
            (seeds / "one").write_bytes(b"x")
            missing = root / "ERROR: AddressSanitizer: heap-buffer-overflow"

            result = differential_run(
                target="demo", commands=[[str(missing)]], labels=["missing"],
                accept_exit_codes=[0, 127], reject_exit_codes=[2], workspace_root=root,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["divergent"], 0)
            self.assertEqual(result["infrastructure_failures"], 1)

    def test_runtime_env_is_sanitized_and_report_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seeds = root / "work" / "demo" / "seeds"
            seeds.mkdir(parents=True)
            (seeds / "one").write_bytes(b"x")
            with mock.patch(
                "agentic_fuzz_engine.differential.bounded_run",
                return_value=BoundedRun(0, False, 1, "same", ""),
            ) as run:
                result = differential_run(
                    target="demo", commands=[[sys.executable, "-c", "pass"]], labels=["one"],
                    workspace_root=root,
                    env={"PATH": os.environ.get("PATH", ""), "TOP_SECRET": "hidden", "PYTHONPATH": "inject"},
                )
            self.assertTrue(result["ok"], result)
            passed_env = run.call_args.kwargs["env"]
            self.assertNotIn("TOP_SECRET", passed_env)
            self.assertNotIn("PYTHONPATH", passed_env)
            self.assertEqual(passed_env["DEBUGINFOD_URLS"], "")

            victim = root / "victim"
            victim.write_text("keep")
            report = root / "work" / "demo" / "differential-run.json"
            report.unlink()
            report.symlink_to(victim)
            result = differential_run(
                target="demo", commands=[[sys.executable, "-c", "pass"]], labels=["one"],
                workspace_root=root,
            )
            self.assertFalse(result["ok"])
            self.assertEqual(victim.read_text(), "keep")

    def test_rejects_target_traversal_and_nonfinite_budget(self) -> None:
        result = differential_run(target="../escape", commands=[[sys.executable]], workspace_root="/tmp")
        self.assertFalse(result["ok"])
        result = differential_run(target="demo", commands=[[sys.executable]], max_seconds=float("nan"), workspace_root="/tmp")
        self.assertFalse(result["ok"])

    def test_forbidden_declared_env_is_rejected_before_missing_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = differential_run(
                target="demo", commands=[], workspace_root=tmp,
                declared_env={"LD_PRELOAD": "blocked"},
            )
        self.assertFalse(result["ok"])
        self.assertIn("forbidden", result["blockers"][0])

    def test_rejects_wrapper_primary_and_symlinked_corpus_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seeds = root / "work" / "demo" / "seeds"
            seeds.mkdir(parents=True)
            outside = root / "outside"
            outside.write_bytes(b"x")
            (seeds / "linked").symlink_to(outside)
            result = differential_run(
                target="demo", commands=[["env", "X=1", "tool"]], labels=["wrapped"], workspace_root=root
            )
            self.assertFalse(result["ok"])
            self.assertTrue(any("wrapper" in item for item in result["blockers"]))

            result = differential_run(
                target="demo", commands=[[sys.executable, "-c", "pass"]], labels=["one"], workspace_root=root
            )
            self.assertFalse(result["ok"])
            self.assertTrue(any("no bounded regular inputs" in item for item in result["blockers"]))

            real_corpus = root / "real-corpus"
            real_corpus.mkdir()
            (real_corpus / "one").write_bytes(b"x")
            linked_corpus = root / "linked-corpus"
            linked_corpus.symlink_to(real_corpus, target_is_directory=True)
            result = differential_run(
                target="demo", commands=[[sys.executable, "-c", "pass"]], labels=["one"],
                corpus_dir=linked_corpus, workspace_root=root,
            )
            self.assertFalse(result["ok"])
            self.assertTrue(any("symlinked corpus" in item for item in result["blockers"]))

    def test_lane_reaps_descendants_and_does_not_persist_output_flood(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seeds = root / "work" / "demo" / "seeds"
            seeds.mkdir(parents=True)
            (seeds / "one").write_bytes(b"x")
            pid_file = root / "child.pid"
            child = "import time; time.sleep(30)"
            parent = (
                "import pathlib,subprocess,sys; "
                f"p=subprocess.Popen([sys.executable,'-c',{child!r}]); "
                f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid)); "
                "sys.stdout.write('x'*3000000)"
            )
            result = differential_run(
                target="demo", commands=[[sys.executable, "-c", parent]], labels=["one"], workspace_root=root
            )
            self.assertTrue(result["ok"], result)
            pid = int(pid_file.read_text())
            time.sleep(0.1)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            self.assertLess(Path(result["report"]).stat().st_size, 100_000)

    def test_total_wall_budget_bounds_the_whole_command_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seeds = root / "work" / "demo" / "seeds"
            seeds.mkdir(parents=True)
            (seeds / "one").write_bytes(b"x")
            started = time.monotonic()
            result = differential_run(
                target="demo",
                commands=[[sys.executable, "-c", "import time; time.sleep(2)"],
                          [sys.executable, "-c", "import time; time.sleep(2)"]],
                labels=["one", "two"], per_input_timeout=2, max_seconds=0.05,
                workspace_root=root,
            )
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["budget_exhausted"])
            self.assertLess(time.monotonic() - started, 1.0)

    def test_refuses_symlinked_hit_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work" / "demo"
            seeds = work / "seeds"
            seeds.mkdir(parents=True)
            (seeds / "one").write_bytes(b"x")
            victim = root / "victim-dir"
            victim.mkdir()
            (work / "differential-hits").symlink_to(victim, target_is_directory=True)
            result = differential_run(
                target="demo",
                commands=[[sys.executable, "-c", "raise SystemExit(0)"],
                          [sys.executable, "-c", "raise SystemExit(2)"]],
                labels=["ok", "reject"], reject_exit_codes=[2], workspace_root=root,
            )
            self.assertFalse(result["ok"])
            self.assertEqual(list(victim.iterdir()), [])

    def test_report_publication_is_anchored_against_parent_swap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "reports"
            parent.mkdir()
            moved = root / "reports-original"
            victim = root / "victim"
            victim.mkdir()
            original_replace = os.replace
            swapped = False

            def swapping_replace(source, destination, **kwargs):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    parent.rename(moved)
                    parent.symlink_to(victim, target_is_directory=True)
                return original_replace(source, destination, **kwargs)

            with mock.patch("agentic_fuzz_engine.differential.os.replace", side_effect=swapping_replace):
                with self.assertRaisesRegex(ValueError, "directory changed"):
                    _atomic_json(parent / "report.json", {"ok": True})
            self.assertEqual(list(victim.iterdir()), [])

    def test_corpus_enumeration_and_exemplar_growth_are_aggregate_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus"
            corpus.mkdir()
            for index in range(5):
                (corpus / str(index)).write_bytes(b"x")
            with mock.patch("agentic_fuzz_engine.differential.MAX_CORPUS_ENTRIES", 2):
                inputs, skipped, truncated = _corpus_inputs(corpus, 10)
            self.assertEqual(len(inputs), 2)
            self.assertGreaterEqual(skipped, 1)
            self.assertTrue(truncated)

            hits = root / "hits"
            hits.mkdir()
            first = root / "first"
            second = root / "second"
            first.write_bytes(b"a")
            second.write_bytes(b"b")
            budget = {"files": 0, "bytes": 0}
            with mock.patch("agentic_fuzz_engine.differential.MAX_EXEMPLAR_FILES", 1):
                _copy_exemplar(first, hits, budget=budget)
                with self.assertRaises(_ExemplarLimit):
                    _copy_exemplar(second, hits, budget=budget)
            self.assertEqual(len(list(hits.iterdir())), 1)

    def test_exemplar_write_failure_leaves_no_poison_and_retry_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hits = root / "hits"
            hits.mkdir()
            source = root / "source"
            source.write_bytes(b"retry-bytes")

            with mock.patch(
                "agentic_fuzz_engine.differential.os.write",
                side_effect=OSError("forced write failure"),
            ):
                with self.assertRaisesRegex(OSError, "forced write failure"):
                    _copy_exemplar(source, hits, budget={"files": 0, "bytes": 0})
            self.assertEqual(list(hits.iterdir()), [])

            published = _copy_exemplar(source, hits, budget={"files": 0, "bytes": 0})
            self.assertEqual(published.read_bytes(), b"retry-bytes")

            poison_source = root / "poison-source"
            poison_source.write_bytes(b"poison")
            poison_name = sha256(b"poison").hexdigest()[:16]
            (hits / poison_name).write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "does not match"):
                _copy_exemplar(poison_source, hits, budget={"files": 0, "bytes": 0})


if __name__ == "__main__":
    unittest.main()

"""Per-seed weighted scheduling: coverage index, BIT scoring, focus split."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def _write_cov_fuzzer(path: Path, *, sleep_token: str | None = None) -> None:
    """Fake libFuzzer: prints one COVERED_FUNC line per whitespace token in
    the input, so a seed's content declares its coverage. The replay
    primitive stages the entry into a one-file directory (libFuzzer's
    single-file path collects no features), so the last argument may be a
    file or a directory holding one file."""
    sleep_clause = ""
    if sleep_token:
        sleep_clause = f'if grep -q {sleep_token} "$last" 2>/dev/null; then sleep 5; fi\n'
    path.write_text(
        "#!/bin/sh\n"
        'for last; do :; done\n'
        'if [ -d "$last" ]; then last=$(find "$last" -type f | head -1); fi\n'
        f"{sleep_clause}"
        'if [ -f "$last" ]; then\n'
        '  for tok in $(cat "$last"); do\n'
        '    echo "COVERED_FUNC: hits: 1 edges: 1/1 in $tok /src/lib.c:1" >&2\n'
        "  done\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


class SeedCovIndexTests(unittest.TestCase):
    def _setup(self, tmp: str) -> tuple[Path, Path, Path]:
        work = Path(tmp) / "work"
        corpus = work / "seeds"
        corpus.mkdir(parents=True)
        fuzzer = Path(tmp) / "fuzzer"
        _write_cov_fuzzer(fuzzer, sleep_token="SLEEP")
        return work, corpus, fuzzer

    def _update(self, work: Path, corpus: Path, fuzzer: Path, universe: set[str], **kwargs):
        from agentic_fuzz_engine.seed_weights import update_seed_cov_index

        defaults = dict(
            work_dir=work,
            fuzzer=fuzzer,
            corpus=corpus,
            universe=universe,
            universe_sha="u1",
            max_new=10,
            max_seconds=30,
            per_input_timeout=10,
            env=dict(os.environ),
        )
        defaults.update(kwargs)
        return update_seed_cov_index(**defaults)

    def test_incremental_index_skips_already_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work, corpus, fuzzer = self._setup(tmp)
            (corpus / "a").write_text("alpha beta")
            (corpus / "b").write_text("alpha")

            first = self._update(work, corpus, fuzzer, {"alpha", "beta"})
            self.assertEqual(first["new_indexed"], 2)
            self.assertEqual(first["indexed_total"], 2)

            second = self._update(work, corpus, fuzzer, {"alpha", "beta"})
            self.assertEqual(second["new_indexed"], 0)
            self.assertEqual(second["indexed_total"], 2)

    def test_universe_intersection_keeps_rows_small(self) -> None:
        from agentic_fuzz_engine.seed_weights import load_seed_cov_rows

        with tempfile.TemporaryDirectory() as tmp:
            work, corpus, fuzzer = self._setup(tmp)
            (corpus / "a").write_text("alpha gamma noise_func other")
            self._update(work, corpus, fuzzer, {"alpha"})
            rows = load_seed_cov_rows(work)
            self.assertEqual(rows["a"]["funcs"], ["alpha"])

    def test_per_round_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work, corpus, fuzzer = self._setup(tmp)
            for index in range(5):
                (corpus / f"s{index}").write_text("alpha")
            result = self._update(work, corpus, fuzzer, {"alpha"}, max_new=2)
            self.assertEqual(result["new_indexed"], 2)
            self.assertEqual(result["unindexed_remaining"], 3)

    def test_timeout_recorded_and_not_retried(self) -> None:
        from agentic_fuzz_engine.seed_weights import load_seed_cov_rows

        with tempfile.TemporaryDirectory() as tmp:
            work, corpus, fuzzer = self._setup(tmp)
            (corpus / "slow").write_text("SLEEP")
            first = self._update(work, corpus, fuzzer, {"alpha"}, per_input_timeout=1)
            self.assertEqual(first["timeouts"], 1)
            rows = load_seed_cov_rows(work)
            self.assertEqual(rows["slow"]["error"], "replay-timeout")
            self.assertEqual(rows["slow"]["funcs"], [])
            # A pathological entry never burns replay budget twice.
            second = self._update(work, corpus, fuzzer, {"alpha"}, per_input_timeout=1)
            self.assertEqual(second["new_indexed"], 0)
            self.assertEqual(second["timeouts"], 0)

    def test_sha_rebind_after_gc_rename(self) -> None:
        from agentic_fuzz_engine.seed_weights import load_seed_cov_rows

        with tempfile.TemporaryDirectory() as tmp:
            work, corpus, fuzzer = self._setup(tmp)
            (corpus / "old-name").write_text("alpha")
            self._update(work, corpus, fuzzer, {"alpha"})
            # GC -merge=1 renames surviving units to fresh content hashes.
            (corpus / "old-name").rename(corpus / "new-hash-name")
            result = self._update(work, corpus, fuzzer, {"alpha"}, max_new=0)
            self.assertEqual(result["rebound"], 1)
            self.assertEqual(result["new_indexed"], 0)
            rows = load_seed_cov_rows(work)
            self.assertEqual(rows["new-hash-name"]["funcs"], ["alpha"])

    def test_compaction_rewrites_when_mostly_dead(self) -> None:
        from agentic_fuzz_engine.seed_weights import SEED_COV_FILE

        with tempfile.TemporaryDirectory() as tmp:
            work, corpus, fuzzer = self._setup(tmp)
            for index in range(4):
                (corpus / f"s{index}").write_text(f"alpha token{index}")
            self._update(work, corpus, fuzzer, {"alpha"})
            for index in range(3):
                (corpus / f"s{index}").unlink()
            self._update(work, corpus, fuzzer, {"alpha"})
            lines = [
                line
                for line in (work / SEED_COV_FILE).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["name"], "s3")

    def test_universe_change_invalidates_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work, corpus, fuzzer = self._setup(tmp)
            (corpus / "a").write_text("alpha beta")
            self._update(work, corpus, fuzzer, {"alpha"}, universe_sha="u1")
            result = self._update(work, corpus, fuzzer, {"alpha", "beta"}, universe_sha="u2")
            self.assertEqual(result["new_indexed"], 1)
            from agentic_fuzz_engine.seed_weights import load_seed_cov_rows

            self.assertEqual(load_seed_cov_rows(work)["a"]["funcs"], ["alpha", "beta"])


class SeedWeightScoringTests(unittest.TestCase):
    def _write_index(self, work: Path, entries: dict[str, list[str]]) -> None:
        work.mkdir(parents=True, exist_ok=True)
        with (work / "seed-cov.jsonl").open("w", encoding="utf-8") as handle:
            for name, funcs in entries.items():
                handle.write(json.dumps({"name": name, "sha": name, "size": 1, "funcs": funcs}) + "\n")

    def _compute(self, work: Path, sink_rows, bits=None):
        from agentic_fuzz_engine.seed_weights import compute_seed_weights

        return compute_seed_weights(
            work_dir=work,
            sink_rows=sink_rows,
            bits=bits or [],
            universe_sha="u1",
            round_index=1,
            bit_weight_default=8.0,
            top_k=8,
        )

    def test_primitive_weight_orders_seeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            self._write_index(work, {"writer": ["write_sink"], "reader": ["plain_sink"], "cold": []})
            report = self._compute(
                work,
                [
                    {"method": "write_sink", "primitive": "write"},
                    {"method": "plain_sink", "primitive": None},
                ],
            )
            weights = report["weights"]
            self.assertGreater(weights["writer"], weights["reader"])
            self.assertGreater(weights["reader"], weights["cold"])
            self.assertEqual(weights["cold"], 1.0)
            self.assertEqual(report["top"][0]["name"], "writer")

    def test_exploited_sink_deprioritized_to_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            self._write_index(work, {"s": ["write_sink"]})
            (work / "sink-status.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "sinks": {
                            "f.c:1:write_sink": {"method": "write_sink", "status": "exploited"}
                        },
                    }
                ),
                encoding="utf-8",
            )
            report = self._compute(work, [{"method": "write_sink", "primitive": "write"}])
            # Deprioritized hypothesis contributes a flat +1 (never removed).
            self.assertEqual(report["weights"]["s"], 2.0)
            self.assertEqual(report["bits_deprioritized"], 1)

    def test_known_crash_frame_deprioritizes(self) -> None:
        from agentic_fuzz_engine.known_crashes import record_known

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            self._write_index(work, {"s": ["crashed_func"]})
            record_known(
                work,
                root_sig="sig-1",
                crash_state=["crashed_func", "caller"],
                round_index=1,
            )
            report = self._compute(work, [{"method": "crashed_func", "primitive": "write"}])
            self.assertEqual(report["weights"]["s"], 2.0)

    def test_bits_key_and_should_be_taken_contributions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            self._write_index(
                work,
                {"vuln": ["target_func"], "key": ["check_func"], "sbt": ["path_func"], "cold": []},
            )
            bits = [
                {
                    "id": "b1",
                    "func_name": "target_func",
                    "weight": 8.0,
                    "key_conditions": ["check_func"],
                    "should_be_taken": ["path_func"],
                    "deprioritized": False,
                }
            ]
            report = self._compute(work, [], bits=bits)
            weights = report["weights"]
            self.assertEqual(weights["vuln"], 9.0)  # 1 + 8
            self.assertEqual(weights["key"], 5.0)  # 1 + 8/2
            self.assertEqual(weights["sbt"], 3.0)  # 1 + 8/4
            self.assertEqual(weights["cold"], 1.0)

    def test_corrupt_bits_json_is_ignored_with_note(self) -> None:
        from agentic_fuzz_engine.seed_weights import load_bits

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            work.joinpath("bits.json").write_text("{not json", encoding="utf-8")
            bits, blockers = load_bits(work)
            self.assertEqual(bits, [])
            self.assertTrue(blockers)


class FocusDirTests(unittest.TestCase):
    def test_build_top_k_and_merge_back_non_baseline(self) -> None:
        from agentic_fuzz_engine.seed_weights import build_focus_dir, merge_back_focus

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "work"
            corpus = work / "seeds"
            corpus.mkdir(parents=True)
            for name in ("a", "b", "c"):
                (corpus / name).write_text(name)
            top = [{"name": "a", "score": 9}, {"name": "b", "score": 5}, {"name": "gone", "score": 4}]

            built = build_focus_dir(work_dir=work, corpus=corpus, top=top, top_k=2)
            focus = Path(built["focus_dir"])
            self.assertEqual(sorted(built["baseline"]), ["a", "b"])
            self.assertEqual(sorted(p.name for p in focus.iterdir()), ["a", "b"])

            # libFuzzer wrote two new units into the focus dir; only those
            # merge back, and an existing corpus name is never clobbered.
            (focus / "new-unit-1").write_text("n1")
            (focus / "c").write_text("conflict")
            (corpus / "c").write_text("original")
            merged = merge_back_focus(focus_dir=focus, corpus=corpus, baseline=set(built["baseline"]))
            self.assertEqual(merged["merged_new"], 1)
            self.assertEqual((corpus / "new-unit-1").read_text(), "n1")
            self.assertEqual((corpus / "c").read_text(), "original")

    def test_build_falls_back_to_copy_when_link_fails(self) -> None:
        from agentic_fuzz_engine import seed_weights

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "work"
            corpus = work / "seeds"
            corpus.mkdir(parents=True)
            (corpus / "a").write_text("a")
            with mock.patch.object(seed_weights.os, "link", side_effect=OSError("EXDEV")):
                built = seed_weights.build_focus_dir(
                    work_dir=work, corpus=corpus, top=[{"name": "a"}], top_k=4
                )
            self.assertEqual(built["baseline"], ["a"])
            self.assertEqual((Path(built["focus_dir"]) / "a").read_text(), "a")

    def test_prepare_requires_min_indexed(self) -> None:
        from agentic_fuzz_engine.seed_weights import prepare_focus_round

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "work"
            corpus = work / "seeds"
            corpus.mkdir(parents=True)
            (work / "seed-weights.json").write_text(
                json.dumps({"indexed_total": 2, "top": [{"name": "a", "score": 3}]}),
                encoding="utf-8",
            )
            result = prepare_focus_round(
                work_dir=work, corpus=corpus, policy_weights={"focus_min_indexed": 8}
            )
            self.assertFalse(result["ready"])
            self.assertIn("focus_min_indexed", result["reason"])


class RoundLoopWeightsIntegrationTests(unittest.TestCase):
    def _workspace(self, tmp: str) -> tuple[Path, Path]:
        ws = Path(tmp) / "ws"
        bin_dir = ws / "bin" / "demo"
        bin_dir.mkdir(parents=True)
        fuzzer = bin_dir / "fuzzer"
        _write_cov_fuzzer(fuzzer)
        corpus = ws / "work" / "demo" / "seeds"
        corpus.mkdir(parents=True)
        (corpus / "seed-alpha").write_text("alpha")
        (corpus / "seed-cold").write_text("nothing")
        data = ws / "data"
        data.mkdir(parents=True)
        (data / "sink-scan.jsonl").write_text(
            json.dumps({"kind": "sink", "method": "alpha", "file": "x.c", "line": 1, "callee": "memcpy"})
            + "\n",
            encoding="utf-8",
        )
        return ws, corpus

    def test_weighted_rounds_run_focus_segment(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds
        from test_workspace_and_campaign import _StubEngine

        with tempfile.TemporaryDirectory() as tmp:
            ws, corpus = self._workspace(tmp)
            (ws / "campaign-policy.json").write_text(
                json.dumps(
                    {
                        "weights": {
                            "enabled": True,
                            "focus_min_indexed": 1,
                            "focus_top_k": 4,
                            "focus_fraction": 0.25,
                            "cov_max_new_per_round": 16,
                        }
                    }
                ),
                encoding="utf-8",
            )
            crash_dir = Path(tmp) / "crashes"
            crash_dir.mkdir()
            (crash_dir / "crash-1").write_bytes(b"boom")
            engine = _StubEngine(crash_dir)

            result = run_campaign_rounds(
                engine,
                project="localfuzz/c/demo",
                rounds=2,
                fuzz_seconds=8,
                workspace_root=ws,
                env=dict(os.environ),
            )

            self.assertTrue(result["ok"], result["blockers"])
            fuzz_calls = [args for name, args in engine.calls if name == "fuzz_ensemble_run"]
            # Round 1 has no prior weights (plain round); round 2 adds the
            # focus segment: 1 + 2 = 3 fuzz invocations.
            self.assertEqual(len(fuzz_calls), 3)
            focus_call = fuzz_calls[2]
            command = focus_call["harness_command"]
            self.assertTrue(str(command[1]).endswith("focus-seeds"))
            self.assertEqual(str(command[2]), str(corpus))
            self.assertEqual(focus_call["artifact_prefix"], "rounds/2/focus-crashes")
            # Main segment of round 2 shortened by the focus fraction.
            main_call = fuzz_calls[1]
            self.assertIn("-max_total_time=6", main_call["harness_command"])

            round_two = result["rounds"][1]
            self.assertTrue(round_two["weights"]["focus"]["ready"])
            self.assertTrue((ws / "work" / "demo" / "seed-weights.json").is_file())
            self.assertTrue((ws / "work" / "demo" / "seed-cov.jsonl").is_file())
            rounds_lines = (
                (ws / "work" / "demo" / "rounds.jsonl").read_text(encoding="utf-8").splitlines()
            )
            self.assertIn("weights", json.loads(rounds_lines[1]))
            report = json.loads((ws / "work" / "demo" / "seed-weights.json").read_text())
            top_names = [item["name"] for item in report["top"]]
            self.assertEqual(top_names[0], "seed-alpha")

    def test_disabled_policy_leaves_round_shape_unchanged(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds
        from test_workspace_and_campaign import _StubEngine

        with tempfile.TemporaryDirectory() as tmp:
            ws, _corpus = self._workspace(tmp)
            crash_dir = Path(tmp) / "crashes"
            crash_dir.mkdir()
            (crash_dir / "crash-1").write_bytes(b"boom")
            engine = _StubEngine(crash_dir)

            result = run_campaign_rounds(
                engine,
                project="localfuzz/c/demo",
                rounds=1,
                fuzz_seconds=5,
                workspace_root=ws,
                env=dict(os.environ),
            )

            self.assertTrue(result["ok"], result["blockers"])
            tool_names = [name for name, _ in engine.calls]
            self.assertEqual(tool_names.count("fuzz_ensemble_run"), 1)
            self.assertNotIn("weights", result["rounds"][0])
            self.assertFalse((ws / "work" / "demo" / "seed-cov.jsonl").exists())


if __name__ == "__main__":
    unittest.main()

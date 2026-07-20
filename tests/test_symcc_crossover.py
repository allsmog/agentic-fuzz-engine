from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.symcc_crossover import (
    SOLUTIONS_FILE,
    apply_solution,
    extract_solution,
    harvest_dictionary_tokens,
    load_solutions,
    measure_crossover_effectiveness,
    prune_solutions,
    record_solutions,
    run_crossover,
)


class ExtractSolutionTests(unittest.TestCase):
    def test_equal_length_bytewise_patches(self) -> None:
        parent = b"AAAAAAAA"
        child = b"AAXAAYAA"
        solution = extract_solution(parent, child)
        assert solution is not None
        self.assertEqual(solution["len_delta"], 0)
        self.assertEqual(solution["patches"], [[2, ord("X")], [5, ord("Y")]])
        self.assertIsNone(solution["tail_b64"])

    def test_extension_records_tail(self) -> None:
        parent = b"HEAD"
        child = b"HEADtail"
        solution = extract_solution(parent, child)
        assert solution is not None
        self.assertEqual(solution["len_delta"], 4)
        self.assertEqual(base64.b64decode(solution["tail_b64"]), b"tail")

    def test_truncation_records_negative_delta_only(self) -> None:
        solution = extract_solution(b"HEADtail", b"HEAD")
        assert solution is not None
        self.assertEqual(solution["len_delta"], -4)
        self.assertEqual(solution["patches"], [])
        self.assertIsNone(solution["tail_b64"])

    def test_too_many_patches_rejected(self) -> None:
        parent = bytes(64)
        child = bytes(range(64))  # 63 differing bytes
        self.assertIsNone(extract_solution(parent, child, max_patches=16))

    def test_oversize_length_delta_rejected(self) -> None:
        self.assertIsNone(extract_solution(b"x", b"x" + bytes(200), max_tail_bytes=64))

    def test_identical_bytes_yield_nothing(self) -> None:
        self.assertIsNone(extract_solution(b"same", b"same"))


class SolutionStoreTests(unittest.TestCase):
    def test_record_appends_and_load_caps_newest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "symcc-state"
            first = [{"parent_sha": f"a{i}", "len_delta": 0, "patches": [[0, i]], "tail_b64": None} for i in range(3)]
            self.assertEqual(record_solutions(state, first), 3)
            more = [{"parent_sha": f"b{i}", "len_delta": 0, "patches": [[1, i]], "tail_b64": None} for i in range(3)]
            record_solutions(state, more)
            loaded = load_solutions(state, max_entries=4)
            self.assertEqual(len(loaded), 4)
            self.assertEqual(loaded[-1]["parent_sha"], "b2")

    def test_load_tolerates_corrupt_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "symcc-state"
            state.mkdir()
            (state / SOLUTIONS_FILE).write_text(
                'not json\n{"patches": "wrong-type"}\n'
                + json.dumps({"parent_sha": "ok", "len_delta": 0, "patches": [[0, 1]], "tail_b64": None})
                + "\n",
                encoding="utf-8",
            )
            loaded = load_solutions(state)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["parent_sha"], "ok")

    def test_prune_rewrites_to_newest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "symcc-state"
            records = [{"parent_sha": f"s{i}", "len_delta": 0, "patches": [[0, i % 256]], "tail_b64": None} for i in range(20)]
            record_solutions(state, records)
            result = prune_solutions(state, max_entries=5)
            self.assertEqual(result, {"kept": 5, "removed": 15})
            loaded = load_solutions(state)
            self.assertEqual(len(loaded), 5)
            self.assertEqual(loaded[-1]["parent_sha"], "s19")
            self.assertEqual(prune_solutions(state, max_entries=5), {"kept": 5, "removed": 0})


class ApplySolutionTests(unittest.TestCase):
    def test_patches_offsets_and_tail(self) -> None:
        record = {"len_delta": 2, "patches": [[0, ord("Z")], [99, 1]], "tail_b64": base64.b64encode(b"!!").decode()}
        out = apply_solution(b"abcd", record)
        self.assertEqual(out, b"Zbcd!!")  # offset 99 skipped, tail appended

    def test_truncation_delta(self) -> None:
        out = apply_solution(b"abcdef", {"len_delta": -2, "patches": [], "tail_b64": None})
        self.assertEqual(out, b"abcd")

    def test_noop_returns_none(self) -> None:
        self.assertIsNone(apply_solution(b"abcd", {"len_delta": 0, "patches": [[50, 1]], "tail_b64": None}))
        self.assertIsNone(apply_solution(b"ab", {"len_delta": -5, "patches": [], "tail_b64": None}))

    def test_blob_cap(self) -> None:
        record = {"len_delta": 4, "patches": [], "tail_b64": base64.b64encode(b"xxxx").decode()}
        self.assertIsNone(apply_solution(b"12345", record, max_blob_bytes=6))


class RunCrossoverTests(unittest.TestCase):
    def _seed_state(self, work_dir: Path) -> None:
        record_solutions(
            work_dir / "symcc-state",
            [{"parent_sha": "p", "len_delta": 0, "patches": [[0, 0x7F], [1, 0x45], [2, 0x4C], [3, 0x46]], "tail_b64": None}],
        )

    def test_crossover_emits_deterministic_symx_offspring(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            corpus = work_dir / "seeds"
            corpus.mkdir()
            (corpus / "unit-a").write_bytes(b"AAAAAAAA")
            self._seed_state(work_dir)

            first = run_crossover(
                work_dir=work_dir, corpus=corpus, round_index=1,
                target_name="demo", policy={}, min_free_gb=0.0,
            )
            self.assertGreaterEqual(first["new_seeds"], 1)
            offspring = sorted(e.name for e in corpus.iterdir() if e.name.startswith("symx-"))
            self.assertTrue(offspring)
            self.assertTrue(all(len(name) == len("symx-") + 20 for name in offspring))

            # Same (target, round) over the same inputs is a no-op: offspring
            # already exist under their content-hash names.
            again = run_crossover(
                work_dir=work_dir, corpus=corpus, round_index=1,
                target_name="demo", policy={}, min_free_gb=0.0,
            )
            self.assertEqual(again["new_seeds"], 0)

    def test_crossover_skips_without_solutions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            corpus = work_dir / "seeds"
            corpus.mkdir()
            (corpus / "unit-a").write_bytes(b"AAAA")
            result = run_crossover(
                work_dir=work_dir, corpus=corpus, round_index=1,
                target_name="demo", policy={}, min_free_gb=0.0,
            )
            self.assertEqual(result["new_seeds"], 0)
            self.assertIn("skipped", result)

    def test_crossover_honors_new_seed_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            corpus = work_dir / "seeds"
            corpus.mkdir()
            for index in range(8):
                (corpus / f"unit-{index}").write_bytes(bytes([index]) * 16)
            record_solutions(
                work_dir / "symcc-state",
                [{"parent_sha": f"p{i}", "len_delta": 0, "patches": [[i, 0xFF]], "tail_b64": None} for i in range(8)],
            )
            result = run_crossover(
                work_dir=work_dir, corpus=corpus, round_index=3,
                target_name="demo", policy={"crossover_new_max": 2}, min_free_gb=0.0,
            )
            self.assertLessEqual(result["new_seeds"], 2)

    def test_effectiveness_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            corpus = work_dir / "seeds"
            corpus.mkdir()
            (corpus / "unit-a").write_bytes(b"AAAAAAAA")
            self._seed_state(work_dir)
            run_crossover(
                work_dir=work_dir, corpus=corpus, round_index=1,
                target_name="demo", policy={}, min_free_gb=0.0,
            )
            report = measure_crossover_effectiveness(work_dir=work_dir, corpus=corpus)
            self.assertGreaterEqual(report["surviving"], 1)
            self.assertGreaterEqual(report["generated_total"], report["surviving"])
            self.assertTrue((work_dir / "symx-effectiveness.json").is_file())


class DictionaryHarvestTests(unittest.TestCase):
    def test_harvest_runs_and_tails_with_quoting_and_dedup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dict_path = Path(tmp) / "demo.dict"
            dict_path.write_text('key_magic="MAGI"\n', encoding="utf-8")
            records = [
                # 4-byte consecutive run 0x7f E L F
                {"patches": [[0, 0x7F], [1, 0x45], [2, 0x4C], [3, 0x46]], "len_delta": 0, "tail_b64": None},
                # short run (below the 4-byte floor) — ignored
                {"patches": [[10, 0x41], [11, 0x42]], "len_delta": 0, "tail_b64": None},
                # extension tail becomes a token too
                {"patches": [], "len_delta": 5, "tail_b64": base64.b64encode(b"TRLR\n").decode()},
            ]
            result = harvest_dictionary_tokens(records=records, dict_path=dict_path, max_new=16, total_cap=256)
            self.assertEqual(result["tokens_added"], 2)
            text = dict_path.read_text(encoding="utf-8")
            self.assertIn("# symcc-harvest", text)
            self.assertIn('symx_000="\\x7fELF"', text)
            self.assertIn('symx_001="TRLR\\x0a"', text)
            self.assertIn('key_magic="MAGI"', text)  # agent lines untouched

            again = harvest_dictionary_tokens(records=records, dict_path=dict_path, max_new=16, total_cap=256)
            self.assertEqual(again["tokens_added"], 0)  # idempotent

    def test_harvest_total_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dict_path = Path(tmp) / "demo.dict"
            records = [
                {"patches": [[0, i], [1, i], [2, i], [3, i]], "len_delta": 0, "tail_b64": None}
                for i in range(1, 9)
            ]
            result = harvest_dictionary_tokens(records=records, dict_path=dict_path, max_new=16, total_cap=3)
            self.assertEqual(result["tokens_added"], 3)
            self.assertEqual(result["harvested_total"], 3)


class SyncRecordingTests(unittest.TestCase):
    def _write_mutating_symcc(self, path: Path) -> None:
        # Flips the first byte and appends a tail: both delta shapes recorded.
        path.write_text(
            "\n".join(
                [
                    "#!/usr/bin/env python3",
                    "import os, pathlib, sys",
                    "out = pathlib.Path(os.environ['SYMCC_OUTPUT_DIR'])",
                    "seed = bytearray(pathlib.Path(sys.argv[1]).read_bytes())",
                    "seed[0] ^= 0xFF",
                    "(out / 'variant0').write_bytes(bytes(seed) + b'TAIL')",
                    "raise SystemExit(0)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def test_corpus_sync_records_solution_deltas(self) -> None:
        from agentic_fuzz_engine.concolic_sync import run_corpus_sync

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            corpus = tmp_path / "corpus"
            corpus.mkdir()
            (corpus / "seed-a").write_bytes(b"abcdefgh")
            binary = tmp_path / "fake-symcc"
            self._write_mutating_symcc(binary)

            result = run_corpus_sync(
                corpus_dir=corpus,
                symcc_binary=binary,
                max_inputs=4,
                max_seconds=30,
                per_input_timeout=10,
                env=dict(os.environ),
            )
            self.assertTrue(result["ok"], result["blockers"])
            self.assertGreaterEqual(result["solutions_recorded"], 1)
            loaded = load_solutions(corpus.parent / "symcc-state")
            self.assertGreaterEqual(len(loaded), 1)
            record = loaded[0]
            self.assertEqual(record["parent"], "seed-a")
            self.assertEqual(record["patches"], [[0, ord("a") ^ 0xFF]])
            self.assertEqual(record["len_delta"], 4)
            self.assertEqual(base64.b64decode(record["tail_b64"]), b"TAIL")

    def test_recording_can_be_disabled(self) -> None:
        from agentic_fuzz_engine.concolic_sync import run_corpus_sync

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            corpus = tmp_path / "corpus"
            corpus.mkdir()
            (corpus / "seed-a").write_bytes(b"abcdefgh")
            binary = tmp_path / "fake-symcc"
            self._write_mutating_symcc(binary)

            result = run_corpus_sync(
                corpus_dir=corpus,
                symcc_binary=binary,
                max_inputs=4,
                max_seconds=30,
                per_input_timeout=10,
                env=dict(os.environ),
                record_solutions_enabled=False,
            )
            self.assertEqual(result["solutions_recorded"], 0)
            self.assertFalse((corpus.parent / "symcc-state" / SOLUTIONS_FILE).exists())


class _StubEngine:
    def __init__(self, crash_dir: Path) -> None:
        self.calls: list[tuple[str, dict]] = []
        self._crash_dir = crash_dir

    def call_tool(self, name: str, args: dict) -> dict:
        self.calls.append((name, args))
        if name == "campaign_start":
            return {"run_id": "run-test"}
        if name == "fuzz_ensemble_run":
            return {
                "ok": True,
                "crash_files": [],
                "worker_results": [{"worker": "libfuzzer", "executed": True, "crash_dir": str(self._crash_dir)}],
                "blockers": [],
            }
        if name == "crash_import":
            return {"findings": []}
        if name == "finding_dedupe":
            return {"groups": []}
        return {"ok": True}


class RoundLoopCrossoverTests(unittest.TestCase):
    def _workspace(self, tmp: Path) -> tuple[Path, Path]:
        ws = tmp / "ws"
        bin_dir = ws / "bin" / "demo"
        bin_dir.mkdir(parents=True)
        fuzzer = bin_dir / "fuzzer"
        fuzzer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fuzzer.chmod(0o755)
        work_dir = ws / "work" / "demo"
        seeds = work_dir / "seeds"
        seeds.mkdir(parents=True)
        (seeds / "unit-a").write_bytes(b"AAAAAAAA")
        record_solutions(
            work_dir / "symcc-state",
            [{"parent_sha": "p", "len_delta": 0, "patches": [[0, 0x7F], [1, 0x45], [2, 0x4C], [3, 0x46]], "tail_b64": None}],
        )
        return ws, seeds

    def test_round_runs_crossover_and_harvests_dictionary(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds

        with tempfile.TemporaryDirectory() as tmp:
            ws, seeds = self._workspace(Path(tmp))
            crash_dir = Path(tmp) / "crashes"
            crash_dir.mkdir()
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
            block = result["rounds"][0].get("symcc_crossover")
            assert block is not None
            self.assertGreaterEqual(block["new_seeds"], 1)
            self.assertGreaterEqual(block.get("dict_tokens_added", 0), 1)
            self.assertTrue(any(e.name.startswith("symx-") for e in seeds.iterdir()))
            dict_text = (ws / "targets" / "c" / "demo" / "demo.dict").read_text(encoding="utf-8")
            self.assertIn("# symcc-harvest", dict_text)

    def test_round_skips_crossover_when_disabled(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds

        with tempfile.TemporaryDirectory() as tmp:
            ws, seeds = self._workspace(Path(tmp))
            (ws / "campaign-policy.json").write_text(
                json.dumps({"symcc": {"crossover_enabled": False}}), encoding="utf-8"
            )
            crash_dir = Path(tmp) / "crashes"
            crash_dir.mkdir()
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
            self.assertNotIn("symcc_crossover", result["rounds"][0])
            self.assertFalse(any(e.name.startswith("symx-") for e in seeds.iterdir()))


class GcSolutionPruneTests(unittest.TestCase):
    def test_campaign_gc_prunes_solution_cache(self) -> None:
        from agentic_fuzz_engine.gc import run_campaign_gc

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            work_dir = ws / "work" / "demo"
            (work_dir / "seeds").mkdir(parents=True)
            (ws / "campaign-policy.json").write_text(
                json.dumps({"symcc": {"solutions_max": 5}}), encoding="utf-8"
            )
            record_solutions(
                work_dir / "symcc-state",
                [{"parent_sha": f"s{i}", "len_delta": 0, "patches": [[0, i % 256]], "tail_b64": None} for i in range(20)],
            )

            result = run_campaign_gc(workspace_root=ws, target="localfuzz/c/demo", env=dict(os.environ))

            self.assertEqual(result["solutions_pruned"], {"kept": 5, "removed": 15})
            self.assertEqual(len(load_solutions(work_dir / "symcc-state")), 5)


if __name__ == "__main__":
    unittest.main()

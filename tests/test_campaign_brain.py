from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.runtime_backends import parse_libfuzzer_stats


class LibFuzzerStatsTests(unittest.TestCase):
    def test_parses_last_status_line_and_final_stats(self) -> None:
        output = "\n".join(
            [
                "INFO: Seed: 1234",
                "#2\tINITED cov: 10 ft: 12 corp: 1 lim: 4 exec/s: 0 rss: 30Mb",
                "#100\tNEW    cov: 40 ft: 55 corp: 9 lim: 8 exec/s: 50 rss: 31Mb",
                "#730\tDONE   cov: 88 ft: 92 corp: 12 lim: 19 exec/s: 0 rss: 327Mb",
                "stat::number_of_executed_units: 730",
                "stat::peak_rss_mb:              327",
            ]
        )
        stats = parse_libfuzzer_stats(output)
        self.assertEqual(stats["covered_pcs"], 88)
        self.assertEqual(stats["features"], 92)
        self.assertEqual(stats["corpus_units"], 12)
        self.assertEqual(stats["execs"], 730)
        self.assertEqual(stats["stat_number_of_executed_units"], 730)

    def test_returns_none_without_status_lines(self) -> None:
        self.assertIsNone(parse_libfuzzer_stats("nothing useful here"))

    def test_run_command_parser_sees_output_beyond_clip_limit(self) -> None:
        # 20k of filler before the DONE line: _clip would drop it, the raw
        # parser must not.
        import sys

        from agentic_fuzz_engine.runtime_backends import _run_command

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            script = tmp_path / "noisy.py"
            script.write_text(
                "\n".join(
                    [
                        "import sys",
                        "sys.stderr.write('x' * 20000 + '\\n')",
                        "sys.stderr.write('#500\\tDONE   cov: 77 ft: 81 corp: 6 lim: 4 exec/s: 0 rss: 30Mb\\n')",
                    ]
                ),
                encoding="utf-8",
            )
            run = _run_command(
                [sys.executable, str(script)],
                cwd=tmp_path,
                timeout_seconds=30,
                env=dict(os.environ),
                raw_output_parser=parse_libfuzzer_stats,
            )
        self.assertTrue(run["stderr"].endswith("[truncated]"))
        self.assertEqual(run["parsed"]["covered_pcs"], 77)
        self.assertEqual(run["parsed"]["features"], 81)


class RoundMetricsTests(unittest.TestCase):
    def test_append_round_metrics_writes_jsonl(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import _append_round_metrics

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "work" / "demo" / "rounds.jsonl"
            _append_round_metrics(path, run_id="r1", summary={"round": 1, "corpus_size": 5})
            _append_round_metrics(path, run_id="r1", summary={"round": 2, "corpus_size": 9})
            lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([line["round"] for line in lines], [1, 2])
        self.assertEqual(lines[1]["corpus_size"], 9)


def _write_rounds(path: Path, features: list[int | None], findings: list[int] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for index, value in enumerate(features):
            record = {
                "round": index + 1,
                "corpus_size": 100 + index,
                "fuzz": {"stats": {"features": value} if value is not None else None},
                "intake": {"findings_recorded": (findings or [0] * len(features))[index]},
            }
            handle.write(json.dumps(record) + "\n")


class PlateauStatusTests(unittest.TestCase):
    def test_verdicts_growing_plateaued_insufficient(self) -> None:
        from agentic_fuzz_engine.campaign_metrics import plateau_status
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, env={})
            _write_rounds(ws / "work" / "grower" / "rounds.jsonl", [10, 20, 30, 40, 55])
            _write_rounds(ws / "work" / "flatliner" / "rounds.jsonl", [50, 90, 90, 90, 90])
            _write_rounds(ws / "work" / "newbie" / "rounds.jsonl", [10, 12])

            result = plateau_status(workspace_root=ws, env={})

        verdicts = {item["target"]: item["verdict"] for item in result["targets"]}
        self.assertEqual(verdicts["grower"], "growing")
        self.assertEqual(verdicts["flatliner"], "plateaued(3 rounds flat)")
        self.assertEqual(verdicts["newbie"], "insufficient-data")
        self.assertEqual(result["plateaued"], ["flatliner"])
        flat = next(item for item in result["targets"] if item["target"] == "flatliner")
        # "frontier" is the first ladder rung since the sinkpoint loop landed
        self.assertEqual(flat["next_rung"], "frontier")

    def test_falls_back_to_corpus_size_and_respects_tried_rungs(self) -> None:
        from agentic_fuzz_engine.campaign_metrics import ledger_append, plateau_status
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, env={})
            # no libfuzzer stats at all -> corpus_size (constant -> plateaued)
            path = ws / "work" / "nostats" / "rounds.jsonl"
            path.parent.mkdir(parents=True)
            with path.open("w", encoding="utf-8") as handle:
                for index in range(5):
                    handle.write(json.dumps({"round": index + 1, "corpus_size": 42, "fuzz": {}, "intake": {}}) + "\n")
            ledger_append(ws, name="nostats", status="escalated:dictionary")

            result = plateau_status(workspace_root=ws, target="nostats", env={})

        item = result["targets"][0]
        self.assertEqual(item["metric_used"], "corpus_size")
        self.assertTrue(item["verdict"].startswith("plateaued"))
        self.assertEqual(item["rungs_tried"], ["dictionary"])
        # dictionary tried; frontier (untried, earlier in the ladder) comes next
        self.assertEqual(item["next_rung"], "frontier")


class RoundLoopIntegrationTests(unittest.TestCase):
    def test_rounds_write_metrics_ledger_and_plateau_block(self) -> None:
        import sys

        sys.path.insert(0, str(Path(__file__).parent))
        from test_workspace_and_campaign import _StubEngine

        from agentic_fuzz_engine.campaign_metrics import candidates_list
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, env={})
            bin_dir = ws / "bin" / "demo"
            bin_dir.mkdir(parents=True)
            fuzzer = bin_dir / "fuzzer"
            fuzzer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fuzzer.chmod(0o755)
            crash_dir = Path(tmp) / "crashes"
            crash_dir.mkdir()
            (crash_dir / "crash-1").write_bytes(b"boom")
            engine = _StubEngine(crash_dir)

            result = run_campaign_rounds(
                engine, project="localfuzz/c/demo", rounds=2, fuzz_seconds=5,
                workspace_root=ws, env=dict(os.environ),
            )

            rounds_path = ws / "work" / "demo" / "rounds.jsonl"
            lines = [json.loads(line) for line in rounds_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(lines), 2)
            self.assertIn("plateau", result["rounds"][0])
            listing = candidates_list(workspace_root=ws, env={})

        # stub rounds record findings every round -> fuzzing then confirmed
        demo = next(item for item in listing["candidates"] if item["name"] == "demo")
        self.assertEqual(demo["status"], "confirmed")

    def test_policy_overrides_defaults_and_flags_override_policy(self) -> None:
        from agentic_fuzz_engine.workspace import load_policy, workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, env={})
            policy_path = ws / "campaign-policy.json"
            payload = json.loads(policy_path.read_text(encoding="utf-8"))
            payload["plateau"]["flat_rounds"] = 5
            policy_path.write_text(json.dumps(payload), encoding="utf-8")

            policy = load_policy(ws, env={})
            self.assertEqual(policy["plateau"]["flat_rounds"], 5)
            self.assertEqual(policy["round"]["fuzz_seconds"], 1800)  # untouched section key survives

            # re-init must not clobber the tuned policy
            workspace_init(root=ws, env={})
            self.assertEqual(load_policy(ws, env={})["plateau"]["flat_rounds"], 5)


class CandidateLedgerTests(unittest.TestCase):
    def test_ledger_append_fold_and_invalid_status(self) -> None:
        from agentic_fuzz_engine.campaign_metrics import (
            candidates_list,
            candidates_update,
            ledger_append,
        )
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, env={})
            ledger_append(ws, name="alpha", status="unharnessed", tag="exec-L1")
            ledger_append(ws, name="alpha", status="fuzzing", round_index=1)
            candidates_update(name="alpha", status="escalated:dictionary", note="flat", workspace_root=ws, env={})
            ledger_append(ws, name="beta", status="dead", note="barren")

            listing = candidates_list(workspace_root=ws, env={})
            self.assertEqual(listing["counts"], {"escalated:dictionary": 1, "dead": 1})
            alpha = next(item for item in listing["candidates"] if item["name"] == "alpha")
            self.assertEqual(alpha["status"], "escalated:dictionary")
            self.assertEqual(alpha["events"], 3)

            with self.assertRaises(ValueError):
                ledger_append(ws, name="alpha", status="bogus-status")

    def test_candidates_sync_is_idempotent_and_never_regresses(self) -> None:
        from agentic_fuzz_engine.campaign_metrics import candidates_sync, ledger_append
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = tmp_path / "ws"
            workspace_init(root=ws, env={})
            sinks = tmp_path / "sinks.jsonl"
            rows = [
                {"tag": "exec-L0", "file": "a.cpp", "line": 1, "method": "M", "callee": "system"},
                {"tag": "mem-copy", "file": "b.cpp", "line": 2, "method": "N", "callee": "memcpy"},
            ]
            sinks.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            # mem_copy already fuzzing -> sync must not regress it
            (ws / "targets" / "c" / "mem_copy").mkdir(parents=True)
            ledger_append(ws, name="mem_copy", status="fuzzing")

            first = candidates_sync(sinks_jsonl=sinks, workspace_root=ws, env={})
            second = candidates_sync(sinks_jsonl=sinks, workspace_root=ws, env={})

        appended = {event["name"]: event["status"] for event in first["events_appended"]}
        self.assertEqual(appended, {"exec_l0": "unharnessed"})
        self.assertEqual(second["events_appended"], [])


class KleePackGenTests(unittest.TestCase):
    def test_pack_derives_flags_and_link_sources(self) -> None:
        from agentic_fuzz_engine.harness_gen import generate_klee_pack
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            src_tree = tmp_path / "srcroot"
            (src_tree / "code").mkdir(parents=True)
            (src_tree / "code" / "dep.cpp").write_text("int dep() { return 1; }\n", encoding="utf-8")
            ws = tmp_path / "ws"
            workspace_init(root=ws, source_dir=src_tree, env={})
            target_dir = ws / "targets" / "c" / "demo"
            (target_dir / ".localfuzz").mkdir(parents=True)
            (target_dir / "harness.cpp").write_text("// harness with FUZZ_MAIN\n", encoding="utf-8")
            shared_inc = ws / "targets" / "c" / "_shared"
            shared_inc.mkdir(parents=True)
            (shared_inc / "helper.h").write_text("#pragma once\n", encoding="utf-8")
            (target_dir / ".localfuzz" / "build.json").write_text(
                json.dumps(
                    {
                        "steps": [
                            {
                                "name": "symcc",
                                "argv": [
                                    "sym++", "-std=c++17", "-DFUZZ_MAIN", "-DOPENSSL3",
                                    f"-I{src_tree}/code", f"-I{shared_inc}",
                                    str(target_dir / "harness.cpp"),
                                    f"{src_tree}/code/dep.cpp",
                                    "-o", "out",
                                ],
                                "env": {},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = generate_klee_pack(name="demo", workspace_root=ws, max_time_seconds=60, env={})

            entry = result["entry"]
            self.assertEqual(
                entry["linkSources"],
                ["/work/harnesses/gen/demo-pack.cpp", f"{src_tree.resolve()}/code/dep.cpp"],
            )
            self.assertTrue(entry["source"].endswith("demo-pack-main.cpp"))
            wrapper_text = (ws / "klee" / "harnesses" / "gen" / "demo-pack-main.cpp").read_text(encoding="utf-8")
            self.assertIn("klee_make_symbolic(data", wrapper_text)
            self.assertIn("klee_assume(size <= sizeof data)", wrapper_text)
            self.assertIn("-DOPENSSL3", entry["compileArgs"])
            self.assertIn(f"-I{src_tree.resolve()}/code", entry["compileArgs"])
            self.assertIn("-I/work/gen-include/demo/workspace/targets/c/_shared", entry["compileArgs"])
            self.assertTrue((ws / "klee" / "gen-include" / "demo" / "workspace" / "targets" / "c" / "_shared" / "helper.h").is_file())
            self.assertNotIn("--emit-all-errors", entry["kleeArgs"])
            self.assertNotIn("-DFUZZ_MAIN", entry["compileArgs"])
            ci = json.loads((ws / "klee" / "gen-packs.ci.json").read_text(encoding="utf-8"))
            self.assertEqual(len(ci["targets"]), 1)

            # regenerating replaces the entry rather than duplicating it
            generate_klee_pack(name="demo", workspace_root=ws, env={})
            ci = json.loads((ws / "klee" / "gen-packs.ci.json").read_text(encoding="utf-8"))
            self.assertEqual(len(ci["targets"]), 1)


class GcTests(unittest.TestCase):
    def _write_fake_merger(self, path: Path) -> None:
        # honors: fuzzer -merge=1 <new> <old> ... -> writes half the files
        path.write_text(
            "\n".join(
                [
                    "#!/usr/bin/env python3",
                    "import pathlib, sys",
                    "new_dir = pathlib.Path(sys.argv[2])",
                    "old_dir = pathlib.Path(sys.argv[3])",
                    "files = sorted(p for p in old_dir.iterdir() if p.is_file())",
                    "for p in files[: max(1, len(files) // 2)]:",
                    "    (new_dir / p.name).write_bytes(p.read_bytes())",
                    "raise SystemExit(0)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def test_corpus_merge_swap_and_retention(self) -> None:
        from agentic_fuzz_engine.gc import run_campaign_gc
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, env={})
            # tiny thresholds so the merge triggers
            policy_path = ws / "campaign-policy.json"
            payload = json.loads(policy_path.read_text(encoding="utf-8"))
            payload["gc"].update({"gc_corpus_min_files": 3, "gc_corpus_max_mb": 1, "run_retention": 2, "klee_out_retention": 1})
            policy_path.write_text(json.dumps(payload), encoding="utf-8")

            corpus = ws / "work" / "demo" / "seeds"
            corpus.mkdir(parents=True)
            for index in range(8):
                (corpus / f"seed-{index}").write_bytes(bytes([index]) * 100)
            bin_dir = ws / "bin" / "demo"
            bin_dir.mkdir(parents=True)
            self._write_fake_merger(bin_dir / "fuzzer")

            runs = ws / "data" / "runs"
            for index in range(4):
                run_dir = runs / f"run-{index}"
                run_dir.mkdir(parents=True)
                (run_dir / "blob").write_bytes(b"z" * 50)
            klee_out = ws / "klee" / "klee-ng-out"
            for index in range(3):
                (klee_out / f"tier-{index}").mkdir(parents=True)

            result = run_campaign_gc(workspace_root=ws, env=dict(os.environ))

            self.assertTrue(result["ok"], result["blockers"])
            merged = result["corpus"][0]
            self.assertEqual(merged["action"], "merged")
            self.assertEqual(merged["files_before"], 8)
            self.assertEqual(merged["files_after"], 4)
            self.assertEqual(len(list(corpus.iterdir())), 4)
            self.assertFalse((ws / "work" / "demo" / "seeds.old").exists())
            self.assertEqual(result["runs_pruned"]["removed"], 2)
            self.assertEqual(result["klee_out_pruned"]["removed"], 2)
            self.assertGreater(result["bytes_freed"], 0)

    def test_containment_check_refuses_outside_deletes(self) -> None:
        from agentic_fuzz_engine.gc import _contained_rmtree

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            victim = tmp_path / "victim"
            victim.mkdir()
            with self.assertRaises(ValueError):
                _contained_rmtree(victim, tmp_path / "unrelated")
            self.assertTrue(victim.exists())


if __name__ == "__main__":
    unittest.main()

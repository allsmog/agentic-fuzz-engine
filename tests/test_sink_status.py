from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.sink_status import (
    frontier_summary,
    load_sink_status,
    sample_close_seeds,
    sink_key,
    update_sink_status,
)

ROW_WRITE = {"tag": "codec", "file": "src/codec/block.cpp", "line": 88, "method": "CopyBlock", "callee": "memcpy", "primitive": "write"}
ROW_EXEC = {"tag": "exec", "file": "src/run.cpp", "line": 10, "method": "RunCmd", "callee": "system", "primitive": "exec"}


def _report(covered: list[dict], uncovered: list[dict]) -> dict:
    return {"covered": covered, "uncovered": uncovered}


class SinkStatusLatticeTests(unittest.TestCase):
    def test_unreached_to_reached_to_exploited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)

            first = update_sink_status(work_dir=work, coverage_report=_report([], [ROW_WRITE]), round_index=1)
            self.assertEqual(first["counts"], {"unreached": 1})

            second = update_sink_status(work_dir=work, coverage_report=_report([ROW_WRITE], []), round_index=2)
            self.assertEqual(second["counts"], {"reached": 1})
            self.assertEqual(second["changes"], [{"sink": sink_key(ROW_WRITE), "from": "unreached", "to": "reached", "round": 2}])
            entry = load_sink_status(work)["sinks"][sink_key(ROW_WRITE)]
            self.assertEqual(entry["first_reached_round"], 2)

            findings = [{"finding_id": "finding-x", "crash_state": ["CopyBlock", "DecodeExtent"]}]
            third = update_sink_status(work_dir=work, coverage_report=_report([ROW_WRITE], []), findings=findings, round_index=3)
            self.assertEqual(third["counts"], {"exploited": 1})
            entry = load_sink_status(work)["sinks"][sink_key(ROW_WRITE)]
            self.assertEqual(entry["exploited_by"], "finding-x")

    def test_never_demotes_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            update_sink_status(work_dir=work, coverage_report=_report([ROW_WRITE], []), round_index=1)
            # Coverage flap: the sink shows as uncovered next round.
            result = update_sink_status(work_dir=work, coverage_report=_report([], [ROW_WRITE]), round_index=2)
            self.assertEqual(result["counts"], {"reached": 1})
            self.assertEqual(result["changes"], [])
            # Same report again: no changes.
            again = update_sink_status(work_dir=work, coverage_report=_report([], [ROW_WRITE]), round_index=3)
            self.assertEqual(again["changes"], [])

    def test_close_seeds_sampled_only_on_transition(self) -> None:
        calls: list[list[str]] = []

        def sampler(methods: list[str]) -> dict[str, list[str]]:
            calls.append(methods)
            return {"CopyBlock": ["seedgen-aaa", "seedgen-bbb"]}

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            update_sink_status(
                work_dir=work, coverage_report=_report([ROW_WRITE], [ROW_EXEC]),
                round_index=1, close_seed_sampler=sampler,
            )
            entry = load_sink_status(work)["sinks"][sink_key(ROW_WRITE)]
            self.assertEqual(entry["close_seeds"], ["seedgen-aaa", "seedgen-bbb"])
            self.assertEqual(calls, [["CopyBlock"]])
            # Already reached: sampler not called again.
            update_sink_status(
                work_dir=work, coverage_report=_report([ROW_WRITE], [ROW_EXEC]),
                round_index=2, close_seed_sampler=sampler,
            )
            self.assertEqual(len(calls), 1)


class FrontierSummaryTests(unittest.TestCase):
    def test_top_uncovered_rows(self) -> None:
        report = {"uncovered": [ROW_WRITE, ROW_EXEC]}
        summary = frontier_summary(report, top=1)
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["method"], "CopyBlock")
        self.assertEqual(summary[0]["primitive"], "write")


class CloseSeedSamplingTests(unittest.TestCase):
    def test_stub_fuzzer_attributes_seeds_to_methods(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "seeds"
            corpus.mkdir()
            (corpus / "seed-hit").write_text("HIT\n", encoding="utf-8")
            (corpus / "seed-miss").write_text("MISS\n", encoding="utf-8")
            fuzzer = Path(tmp) / "fuzzer"
            fuzzer.write_text(
                "#!/bin/sh\n"
                "# last argument is the input file, or a one-file staging dir\n"
                "# (the replay primitive stages entries into a directory).\n"
                'for last in "$@"; do :; done\n'
                'if [ -d "$last" ]; then last=$(find "$last" -type f | head -1); fi\n'
                'key=$(head -n1 "$last")\n'
                'if [ "$key" = "HIT" ]; then echo "COVERED_FUNC: hits: 5 edges: 2/3 CopyBlock /src/block.cpp:80" >&2; fi\n'
                "exit 0\n",
                encoding="utf-8",
            )
            fuzzer.chmod(0o755)

            result = sample_close_seeds(
                fuzzer=fuzzer, corpus=corpus, methods=["CopyBlock"], max_inputs=10, max_seconds=30,
            )

            self.assertEqual(result, {"CopyBlock": ["seed-hit"]})


class RoundFrontierIntegrationTests(unittest.TestCase):
    def test_plateau_triggers_frontier_block(self) -> None:
        import os
        import sys

        sys.path.insert(0, str(Path(__file__).parent))
        from test_workspace_and_campaign import _StubEngine

        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, env={})
            bin_dir = ws / "bin" / "demo"
            bin_dir.mkdir(parents=True)
            fuzzer = bin_dir / "fuzzer"
            # Prints one COVERED_FUNC so sink-coverage has signal.
            fuzzer.write_text(
                "#!/bin/sh\n"
                'echo "COVERED_FUNC: hits: 5 edges: 2/3 CopyBlock /src/block.cpp:80" >&2\n'
                "exit 0\n",
                encoding="utf-8",
            )
            fuzzer.chmod(0o755)
            work = ws / "work" / "demo"
            (work / "seeds").mkdir(parents=True)
            (work / "seeds" / "seed-1").write_bytes(b"x")
            # Pre-seed flat rounds so the very first live round plateaus.
            with (work / "rounds.jsonl").open("w", encoding="utf-8") as handle:
                for index in range(1, 6):
                    handle.write(json.dumps({"round": index, "corpus_size": 1, "fuzz": {}, "intake": {}}) + "\n")
            # Sink inventory containing one covered and one uncovered sink.
            data = ws / "data"
            data.mkdir(exist_ok=True)
            with (data / "sink-scan.jsonl").open("w", encoding="utf-8") as handle:
                handle.write(json.dumps({"kind": "sink", "tag": "codec", "file": "src/block.cpp", "line": 80, "method": "CopyBlock", "callee": "memcpy", "primitive": "write"}) + "\n")
                handle.write(json.dumps({"kind": "sink", "tag": "exec", "file": "src/run.cpp", "line": 10, "method": "RunCmd", "callee": "system", "primitive": "exec"}) + "\n")
            crash_dir = Path(tmp) / "crashes"
            crash_dir.mkdir()
            (crash_dir / "crash-1").write_bytes(b"boom")
            engine = _StubEngine(crash_dir)

            result = run_campaign_rounds(
                engine, project="localfuzz/c/demo", rounds=1, fuzz_seconds=5,
                workspace_root=ws, env=dict(os.environ),
            )

            round_summary = result["rounds"][0]
            self.assertTrue(str(round_summary["plateau"]["verdict"]).startswith("plateaued"))
            frontier = round_summary["frontier"]
            self.assertEqual(frontier["sinks_covered"], 1)
            self.assertEqual(frontier["sinks_uncovered"], 1)
            self.assertEqual(frontier["top_uncovered"][0]["method"], "RunCmd")
            status = json.loads((work / "sink-status.json").read_text(encoding="utf-8"))
            self.assertEqual(status["counts"], {"reached": 1, "unreached": 1})


if __name__ == "__main__":
    unittest.main()

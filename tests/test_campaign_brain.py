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
        self.assertEqual(flat["next_rung"], "dictionary")

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
        self.assertEqual(item["next_rung"], "structured-seeds")


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


if __name__ == "__main__":
    unittest.main()

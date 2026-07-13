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


if __name__ == "__main__":
    unittest.main()

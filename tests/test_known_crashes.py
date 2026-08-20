from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from agentic_fuzz_engine.crash_identity import parse_crash_output, root_signature
from agentic_fuzz_engine.known_crashes import (
    load_known,
    probe_and_partition,
    prune_known_inputs,
    record_known,
    save_known,
)

KNOWN_CRASH_OUTPUT = """\
==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010 at pc 0x400b12
WRITE of size 8 at 0x602000000010 thread T0
    #0 0x51fa22 in CopyBlock /work/src/codec/block.cpp:88
    #1 0x51fb44 in DecodeExtent /work/src/codec/extent.cpp:141
    #2 0x520000 in ParseHeader /work/src/codec/header.cpp:52
"""

NOVEL_CRASH_OUTPUT = """\
==99==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000020 at pc 0x400c44
READ of size 4 at 0x603000000020 thread T0
    #0 0x600100 in TailerPeek /work/src/oplog/tailer.cpp:300
    #1 0x600200 in TailerLoop /work/src/oplog/tailer.cpp:410
"""


def _known_sig(output: str) -> str:
    signal = parse_crash_output(output)
    assert signal is not None
    return root_signature(signal)


def _write_replay_stub(path: Path, mapping: dict[str, str]) -> None:
    """Shell replay stub: prints canned ASAN output on stderr keyed by the
    crash file's contents (its first line)."""
    lines = ["#!/bin/sh", 'key=$(head -n1 "$1")', "case \"$key\" in"]
    for key, output in mapping.items():
        encoded = output.replace("\n", "\\n")
        lines.append(f'{key}) printf "%b" "{encoded}" >&2; exit 1 ;;')
    lines.append('*) echo "no crash" ; exit 0 ;;')
    lines.append("esac")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o755)


class KnownLedgerTests(unittest.TestCase):
    def test_record_roundtrip_and_increment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            sig = _known_sig(KNOWN_CRASH_OUTPUT)
            record_known(work, root_sig=sig, crash_type="heap-buffer-overflow",
                         crash_state=["CopyBlock", "DecodeExtent", "ParseHeader"],
                         error_token="heap-buffer-overflow", finding_id="finding-x", round_index=3)
            record_known(work, root_sig=sig, round_index=5)

            known = load_known(work)
            self.assertEqual(known[sig]["count"], 2)
            self.assertEqual(known[sig]["first_seen_round"], 3)
            self.assertEqual(known[sig]["last_seen_round"], 5)
            self.assertEqual(known[sig]["finding_id"], "finding-x")

    def test_load_tolerates_corrupt_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / "known-crashes.json").write_text("{corrupt", encoding="utf-8")
            self.assertEqual(load_known(work), {})


class ProbePartitionTests(unittest.TestCase):
    def test_partition_suppresses_known_and_keeps_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "work"
            work.mkdir()
            stub = Path(tmp) / "replay.sh"
            _write_replay_stub(stub, {"KNOWN": KNOWN_CRASH_OUTPUT, "NOVEL": NOVEL_CRASH_OUTPUT})
            known_file = Path(tmp) / "crash-known"
            known_file.write_text("KNOWN\n", encoding="utf-8")
            novel_file = Path(tmp) / "crash-novel"
            novel_file.write_text("NOVEL\n", encoding="utf-8")
            garbage_file = Path(tmp) / "crash-garbage"
            garbage_file.write_text("GARBAGE\n", encoding="utf-8")
            sig = _known_sig(KNOWN_CRASH_OUTPUT)
            save_known(work, {sig: {"count": 1}})

            result = probe_and_partition(
                [known_file, novel_file, garbage_file],
                known=load_known(work),
                replay_command=[str(stub), "{poc}"],
                work_dir=work,
                timeout_seconds=5,
            )

            self.assertEqual([p.name for p in result["unknown_files"]], ["crash-novel", "crash-garbage"])
            self.assertEqual(result["suppressed"], {sig: 1})
            self.assertEqual(result["probe_failures"], 1)  # garbage fails open
            self.assertFalse(known_file.exists())
            quarantined = list((work / "known-crash-inputs").iterdir())
            self.assertEqual(len(quarantined), 1)
            self.assertTrue(quarantined[0].name.startswith(sig[:8]))

    def test_empty_known_set_skips_probing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            crash = work / "crash-1"
            crash.write_bytes(b"boom")
            result = probe_and_partition(
                [crash], known={}, replay_command=["/bin/false"], work_dir=work,
            )
            self.assertEqual(result["unknown_files"], [crash])
            self.assertEqual(result["probed"], 0)


class PruneTests(unittest.TestCase):
    def test_prune_keeps_newest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            quarantine = work / "known-crash-inputs"
            quarantine.mkdir()
            for index in range(5):
                entry = quarantine / f"sig-{index}"
                entry.write_bytes(b"x" * 10)
                stamp = time.time() - (5 - index) * 60
                os.utime(entry, (stamp, stamp))

            result = prune_known_inputs(work, retention=2)

            self.assertEqual(result["removed"], 3)
            survivors = sorted(entry.name for entry in quarantine.iterdir())
            self.assertEqual(survivors, ["sig-3", "sig-4"])


class RoundLoopSuppressionTests(unittest.TestCase):
    def test_round_suppresses_known_crash_and_enables_fork_mode(self) -> None:
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
            _write_replay_stub(fuzzer, {"KNOWN": KNOWN_CRASH_OUTPUT})
            crash_dir = Path(tmp) / "crashes"
            crash_dir.mkdir()
            (crash_dir / "crash-1").write_text("KNOWN\n", encoding="utf-8")
            work_dir = ws / "work" / "demo"
            work_dir.mkdir(parents=True)
            sig = _known_sig(KNOWN_CRASH_OUTPUT)
            save_known(work_dir, {sig: {"count": 1, "finding_id": "finding-prior"}})
            engine = _StubEngine(crash_dir)

            result = run_campaign_rounds(
                engine, project="localfuzz/c/demo", rounds=1, fuzz_seconds=5,
                workspace_root=ws, env=dict(os.environ),
            )

            round_summary = result["rounds"][0]
            self.assertTrue(round_summary["fork_mode"])
            self.assertEqual(round_summary["intake"]["known_suppressed"], 1)
            self.assertEqual(round_summary["intake"]["findings_recorded"], 0)
            self.assertEqual(round_summary["new_root_signatures"], 0)
            # The 3x grading replay was skipped entirely.
            self.assertNotIn("crash_import", [name for name, _ in engine.calls])
            fuzz_args = next(args for name, args in engine.calls if name == "fuzz_ensemble_run")
            self.assertIn("-fork=1", fuzz_args["harness_command"])
            self.assertIn("-ignore_crashes=1", fuzz_args["harness_command"])
            # Quarantined, counted, and the known ledger incremented.
            self.assertEqual(load_known(work_dir)[sig]["count"], 2)
            self.assertTrue(any((work_dir / "known-crash-inputs").iterdir()))
            # Rediscovery of a known signature must not confirm the candidate.
            rounds_line = json.loads((work_dir / "rounds.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(rounds_line["new_root_signatures"], 0)


class RotateTargetSignalTests(unittest.TestCase):
    def test_known_only_rounds_drive_rotate_recommendation(self) -> None:
        from agentic_fuzz_engine.campaign_metrics import plateau_status
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, env={})
            work = ws / "work" / "stale"
            work.mkdir(parents=True)
            with (work / "rounds.jsonl").open("w", encoding="utf-8") as handle:
                # One legacy row without the counter (tolerated), then six
                # flat rounds whose only activity is known suppressions.
                handle.write(json.dumps({"round": 1, "corpus_size": 50, "fuzz": {}, "intake": {}}) + "\n")
                for index in range(2, 8):
                    handle.write(json.dumps({
                        "round": index,
                        "corpus_size": 50,
                        "fuzz": {},
                        "intake": {"findings_recorded": 0, "known_suppressed": 2},
                        "new_root_signatures": 0,
                    }) + "\n")

            result = plateau_status(workspace_root=ws, target="stale", env={})

        item = result["targets"][0]
        self.assertTrue(item["verdict"].startswith("plateaued"))
        self.assertEqual(item["known_only_rounds"], 6)
        self.assertEqual(item["recommendation"], "rotate-target")
        self.assertEqual(item["next_rung"], "rotate-target")

    def test_new_root_signature_resets_streak(self) -> None:
        from agentic_fuzz_engine.campaign_metrics import _known_only_streak

        rounds = [
            {"new_root_signatures": 0, "intake": {"findings_recorded": 0, "known_suppressed": 3}},
            {"new_root_signatures": 1, "intake": {"findings_recorded": 1, "known_suppressed": 0}},
            {"new_root_signatures": 0, "intake": {"findings_recorded": 0, "known_suppressed": 1}},
        ]
        self.assertEqual(_known_only_streak(rounds), 1)


class SeedgenEffectivenessTests(unittest.TestCase):
    def test_surviving_blobs_attributed_per_script(self) -> None:
        from agentic_fuzz_engine.seedgen import measure_seedgen_effectiveness

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            work = ws / "work" / "demo"
            seeds = work / "seeds"
            seeds.mkdir(parents=True)
            (seeds / "seedgen-aaaa").write_bytes(b"1")
            (seeds / "seedgen-bbbb").write_bytes(b"2")
            (seeds / "seedgen-orphan").write_bytes(b"3")
            (seeds / "klee-cccc").write_bytes(b"4")
            with (work / "seedgen.jsonl").open("w", encoding="utf-8") as handle:
                handle.write(json.dumps({
                    "script_sha256": "s1", "script": "gen1.py", "generated": 3,
                    "merged_new": 2, "blobs": ["seedgen-aaaa", "seedgen-gone"],
                }) + "\n")
                handle.write(json.dumps({
                    "script_sha256": "s2", "script": "gen2.py", "generated": 1,
                    "merged_new": 1, "blobs": ["seedgen-bbbb"],
                }) + "\n")

            result = measure_seedgen_effectiveness(target="demo", workspace_root=ws, env={})

            self.assertEqual(result["scripts"]["s1"]["surviving"], 1)
            self.assertEqual(result["scripts"]["s2"]["surviving"], 1)
            self.assertEqual(result["surviving_total"], 2)
            self.assertEqual(result["unattributed_seedgen_blobs"], 1)
            self.assertTrue((work / "seedgen-effectiveness.json").is_file())


if __name__ == "__main__":
    unittest.main()


class CampaignGcPruneTests(unittest.TestCase):
    def test_standalone_gc_prunes_quarantine(self) -> None:
        from agentic_fuzz_engine.gc import run_campaign_gc
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, env={})
            policy_path = ws / "campaign-policy.json"
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            policy["gc"]["known_crash_inputs_retention"] = 1
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            quarantine = ws / "work" / "demo" / "known-crash-inputs"
            quarantine.mkdir(parents=True)
            for index in range(3):
                entry = quarantine / f"sig-{index}"
                entry.write_bytes(b"y" * 8)
                stamp = time.time() - (3 - index) * 60
                os.utime(entry, (stamp, stamp))

            result = run_campaign_gc(workspace_root=ws, target="demo", env=dict(os.environ))

            self.assertEqual(result["known_inputs_pruned"]["removed"], 2)
            self.assertEqual(len(list(quarantine.iterdir())), 1)

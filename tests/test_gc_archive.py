from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.gc import (
    _archive_run,
    _contained_rmtree,
    _minimize_corpus,
    _prune_oldest,
    _prune_runs_with_archive,
    run_campaign_gc,
)
from agentic_fuzz_engine.workspace import workspace_init


def _make_run(runs_root: Path, name: str, *, poc: bytes | None = b"POV", big_events: bool = False) -> Path:
    run_dir = runs_root / name
    (run_dir / "artifacts").mkdir(parents=True)
    (run_dir / "campaign.json").write_text(json.dumps({"run_id": name, "target": "localfuzz/c/demo"}), encoding="utf-8")
    finding = {
        "finding_id": f"finding-{name}",
        "target": "localfuzz/c/demo",
        "poc_artifact": "crash-1.bin" if poc is not None else None,
        "verified": True,
    }
    (run_dir / "findings.jsonl").write_text(json.dumps(finding) + "\n", encoding="utf-8")
    (run_dir / "checkpoints.jsonl").write_text(json.dumps({"phase": "fuzzing"}) + "\n", encoding="utf-8")
    events = [json.dumps({"type": "noise", "payload": {"n": i}}) for i in range(2000 if big_events else 3)]
    (run_dir / "events.jsonl").write_text("\n".join(events) + "\n", encoding="utf-8")
    if poc is not None:
        (run_dir / "artifacts" / "crash-1.bin").write_bytes(poc)
    (run_dir / "artifacts" / "demo-report_REPORT.md").write_text("# report\n", encoding="utf-8")
    (run_dir / "artifacts" / "huge-corpus-dump.bin").write_bytes(b"x" * 4096)
    return run_dir


class GcArchiveTest(unittest.TestCase):
    def test_pruned_runs_archive_durable_core(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, env={})
            policy_path = ws / "campaign-policy.json"
            payload = json.loads(policy_path.read_text(encoding="utf-8"))
            payload["gc"].update({"run_retention": 1, "archive_events_tail_kb": 1})
            policy_path.write_text(json.dumps(payload), encoding="utf-8")

            runs_root = ws / "data" / "runs"
            old = _make_run(runs_root, "run-old", big_events=True)
            os.utime(old, (1_000_000, 1_000_000))
            _make_run(runs_root, "run-new")

            result = run_campaign_gc(workspace_root=ws, env=dict(os.environ))
            self.assertEqual(result["runs_pruned"]["removed"], 1)
            self.assertEqual(result["runs_pruned"]["archived"], 1)
            self.assertFalse(old.exists())

            archived = ws / "data" / "archive" / "runs" / "run-old"
            manifest = json.loads((archived / "manifest.json").read_text(encoding="utf-8"))
            # Ledgers, the PoV, and the report survive; the corpus dump does not.
            self.assertTrue((archived / "findings.jsonl").is_file())
            self.assertTrue((archived / "campaign.json").is_file())
            self.assertTrue((archived / "checkpoints.jsonl").is_file())
            self.assertTrue((archived / "artifacts" / "crash-1.bin").is_file())
            self.assertTrue((archived / "artifacts" / "demo-report_REPORT.md").is_file())
            self.assertFalse((archived / "artifacts" / "huge-corpus-dump.bin").exists())
            self.assertIn("findings.jsonl", manifest["files"])
            # Events tail respected the cap and is marked truncated.
            tail_meta = manifest["files"]["events-tail.jsonl"]
            self.assertLessEqual(tail_meta["size"], 1024)
            self.assertTrue(tail_meta["truncated"])
            # The surviving run is untouched.
            self.assertTrue((runs_root / "run-new" / "findings.jsonl").is_file())

    def test_archive_budget_skips_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, env={})
            policy_path = ws / "campaign-policy.json"
            payload = json.loads(policy_path.read_text(encoding="utf-8"))
            payload["gc"].update({"run_retention": 0, "archive_max_mb": 0})
            policy_path.write_text(json.dumps(payload), encoding="utf-8")

            runs_root = ws / "data" / "runs"
            _make_run(runs_root, "run-only")

            result = run_campaign_gc(workspace_root=ws, env=dict(os.environ))
            self.assertEqual(result["runs_pruned"]["removed"], 1)
            archived = ws / "data" / "archive" / "runs" / "run-only"
            manifest = json.loads((archived / "manifest.json").read_text(encoding="utf-8"))
            skipped = {item["file"] for item in manifest["skipped"]}
            self.assertIn("findings.jsonl", skipped)

    def test_gc_rejects_noncanonical_target_and_symlinked_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = tmp_path / "ws"
            workspace_init(root=ws, env={})
            with self.assertRaises(ValueError):
                run_campaign_gc(workspace_root=ws, target="../outside", env={})

            parent = tmp_path / "managed"
            parent.mkdir()
            outside = tmp_path / "outside"
            outside.mkdir()
            link = parent / "linked"
            link.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                _contained_rmtree(link, parent)
            with self.assertRaises(ValueError):
                _prune_oldest(link, keep=0)
            self.assertTrue(outside.exists())

    def test_archive_refuses_symlinked_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            run_dir = _make_run(tmp_path / "runs", "run-old")
            archive_root = tmp_path / "archive" / "runs"
            archive_root.mkdir(parents=True)
            outside = tmp_path / "outside"
            outside.mkdir()
            destination = archive_root / "run-old"
            destination.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                _archive_run(
                    run_dir,
                    destination,
                    archive_root=archive_root,
                    max_bytes=1024,
                    events_tail_bytes=128,
                )
            self.assertFalse((outside / "manifest.json").exists())

    def test_archive_symlink_inputs_leave_run_unpruned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            runs = tmp_path / "runs"
            run_dir = _make_run(runs, "run-old")
            victim = tmp_path / "victim"
            victim.write_bytes(b"do-not-read-or-change")
            (run_dir / "artifacts" / "crash-1.bin").unlink()
            (run_dir / "artifacts" / "crash-1.bin").symlink_to(victim)
            result = _prune_runs_with_archive(
                runs, keep=0, archive_root=tmp_path / "archive" / "runs", max_mb=1, events_tail_kb=1
            )
            self.assertEqual(result["removed"], 0)
            self.assertEqual(result["archived"], 0)
            self.assertEqual(len(result["archive_failures"]), 1)
            self.assertTrue(run_dir.exists())
            self.assertEqual(victim.read_bytes(), b"do-not-read-or-change")

    def test_archive_rejects_symlinked_events_and_existing_output_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            run_dir = _make_run(tmp_path / "runs", "run-old")
            archive_root = tmp_path / "archive" / "runs"
            archive_root.mkdir(parents=True)
            victim = tmp_path / "victim"
            victim.write_bytes(b"untouched")
            events = run_dir / "events.jsonl"
            events.unlink()
            events.symlink_to(victim)
            with self.assertRaises(ValueError):
                _archive_run(run_dir, archive_root / "run-old", archive_root=archive_root, max_bytes=1024, events_tail_bytes=128)
            self.assertFalse((archive_root / "run-old").exists())

            events.unlink()
            events.write_text("{}\n", encoding="utf-8")
            for output_name in ("events-tail.jsonl", "manifest.json"):
                destination = archive_root / "run-old"
                destination.mkdir()
                (destination / output_name).symlink_to(victim)
                with self.assertRaises(ValueError):
                    _archive_run(run_dir, destination, archive_root=archive_root, max_bytes=1024, events_tail_bytes=128)
                self.assertEqual(victim.read_bytes(), b"untouched")
                (destination / output_name).unlink()
                destination.rmdir()

    def test_merge_state_symlinks_never_touch_external_victim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            parent = tmp_path / "work" / "demo"
            corpus = parent / "seeds"
            corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"seed")
            fuzzer = tmp_path / "fuzzer"
            fuzzer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fuzzer.chmod(0o755)
            victim = tmp_path / "victim"
            victim.write_bytes(b"untouched")
            for state_name in ("merge.meta", "merge.ctl"):
                state = parent / state_name
                state.symlink_to(victim)
                with self.assertRaises(ValueError):
                    _minimize_corpus(
                        name="demo", fuzzer=fuzzer, corpus=corpus,
                        min_files=0, max_mb=0, env={},
                    )
                self.assertEqual(victim.read_bytes(), b"untouched")
                state.unlink()


if __name__ == "__main__":
    unittest.main()

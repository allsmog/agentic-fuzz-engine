from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.gc import run_campaign_gc
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


if __name__ == "__main__":
    unittest.main()

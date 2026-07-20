"""Fleet job ledger: sync triggers, idempotence, transitions, report."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from agentic_fuzz_engine.jobs import (
    fold_events,
    jobs_list,
    jobs_report,
    jobs_update,
    load_events,
    sync_jobs,
)


def _write_candidates(root: Path, events: list[dict]) -> None:
    path = root / "data" / "candidates.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")


def _write_known(root: Path, name: str, sigs: dict[str, dict]) -> None:
    work = root / "work" / name
    work.mkdir(parents=True, exist_ok=True)
    (work / "known-crashes.json").write_text(
        json.dumps({"version": 1, "signatures": sigs}), encoding="utf-8"
    )


def _write_plateaued_rounds(root: Path, name: str, *, features: int = 100, rounds: int = 6) -> None:
    work = root / "work" / name
    work.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps({"round": i, "fuzz": {"stats": {"features": features}}, "intake": {}})
        for i in range(rounds)
    ]
    (work / "rounds.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_coverage(root: Path, name: str, uncovered: list[dict]) -> None:
    work = root / "work" / name
    work.mkdir(parents=True, exist_ok=True)
    (work / "sink-coverage.json").write_text(
        json.dumps({"ok": True, "uncovered": uncovered}), encoding="utf-8"
    )


class SyncTests(unittest.TestCase):
    def test_harness_author_from_unharnessed_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_candidates(root, [{"name": "demo_vec", "status": "unharnessed", "tag": "demo"}])

            result = sync_jobs(workspace_root=root, types=["harness_author"])

            ids = [e["id"] for e in result["events_appended"]]
            self.assertEqual(ids, ["harness_author:demo_vec"])
            job = result["events_appended"][0]
            self.assertEqual(job["state"], "queued")
            self.assertEqual(job["attempt"], 1)
            self.assertEqual(job["playbook"], "harness-builder.md")
            self.assertEqual(job["evidence"]["candidate_status"], "unharnessed")
            self.assertGreater(job["budget"]["max_usd"], 0)

    def test_double_sync_appends_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_candidates(root, [{"name": "demo_vec", "status": "unharnessed"}])
            first = sync_jobs(workspace_root=root, types=["harness_author"])
            second = sync_jobs(workspace_root=root, types=["harness_author"])
            self.assertEqual(len(first["events_appended"]), 1)
            self.assertEqual(second["events_appended"], [])
            self.assertEqual(len(load_events(root)), 1)

    def test_done_job_reopens_only_on_gen_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_candidates(root, [{"name": "demo_vec", "status": "unharnessed"}])
            sync_jobs(workspace_root=root, types=["harness_author"])
            jobs_update(job_id="harness_author:demo_vec", state="done", workspace_root=root)

            unchanged = sync_jobs(workspace_root=root, types=["harness_author"])
            self.assertEqual(unchanged["events_appended"], [])

            # evidence changes (status flips) -> new gen -> reopen
            _write_candidates(
                root,
                [
                    {"name": "demo_vec", "status": "unharnessed"},
                    {"name": "demo_vec", "status": "awaiting-authoring"},
                ],
            )
            reopened = sync_jobs(workspace_root=root, types=["harness_author"])
            self.assertEqual([e["id"] for e in reopened["events_appended"]], ["harness_author:demo_vec"])

    def test_triage_from_known_crashes_skips_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_known(
                root, "tgt",
                {
                    "a" * 40: {"crash_type": "heap-buffer-overflow"},
                    "b" * 40: {"crash_type": "SEGV"},
                },
            )
            report_dir = root / "data" / "reports" / "tgt" / ("b" * 12)
            report_dir.mkdir(parents=True)
            (report_dir / "report.md").write_text("done", encoding="utf-8")

            result = sync_jobs(workspace_root=root, types=["triage"])

            ids = [e["id"] for e in result["events_appended"]]
            self.assertEqual(ids, [f"triage:tgt:{'a' * 12}"])
            self.assertEqual(result["events_appended"][0]["evidence"]["root_signature"], "a" * 40)

    def test_frontier_seed_on_plateau_with_uncovered_write_sink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_plateaued_rounds(root, "tgt")
            _write_coverage(root, "tgt", [
                {"method": "CopyBits", "primitive": "write", "file": "a.c", "line": 10},
                {"method": "ReadOnly", "primitive": "read", "file": "a.c", "line": 20},
            ])

            result = sync_jobs(workspace_root=root, types=["frontier_seed"])

            ids = [e["id"] for e in result["events_appended"]]
            self.assertEqual(ids, ["frontier_seed:tgt:CopyBits"])
            self.assertEqual(
                result["events_appended"][0]["evidence"]["uncovered_methods"], ["CopyBits"]
            )

    def test_steering_codec_when_sink_reached_without_codec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work" / "tgt"
            work.mkdir(parents=True)
            (work / "sink-status.json").write_text(
                json.dumps({"sinks": {"a.c:10:CopyBits": {"status": "reached"}}}), encoding="utf-8"
            )

            result = sync_jobs(workspace_root=root, types=["steering"])

            ids = [e["id"] for e in result["events_appended"]]
            self.assertEqual(ids, ["steering:tgt:codec"])
            self.assertEqual(result["events_appended"][0]["playbook"], "input-generator.md")

    def test_fleet_plan_daily(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = sync_jobs(workspace_root=root, types=["fleet_plan"])
            date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            self.assertEqual(
                [e["id"] for e in result["events_appended"]],
                [f"fleet_plan:_workspace:{date}"],
            )
            again = sync_jobs(workspace_root=root, types=["fleet_plan"])
            self.assertEqual(again["events_appended"], [])

    def test_fleet_plan_stale_auto_drop(self) -> None:
        from agentic_fuzz_engine.jobs import append_event

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            append_event(root, {
                "id": "fleet_plan:_workspace:2001-01-01",
                "type": "fleet_plan",
                "target": "_workspace",
                "qualifier": "2001-01-01",
                "state": "queued",
                "attempt": 1,
                "gen": "deadbeef",
            })
            result = sync_jobs(workspace_root=root, types=["fleet_plan"])
            self.assertEqual(result["dropped_stale"], ["fleet_plan:_workspace:2001-01-01"])
            date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            state = fold_events(load_events(root))
            self.assertEqual(state["fleet_plan:_workspace:2001-01-01"]["state"], "dropped")
            self.assertEqual(state[f"fleet_plan:_workspace:{date}"]["state"], "queued")

    def test_max_new_per_sync_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_candidates(root, [{"name": f"vec{i:02d}", "status": "unharnessed"} for i in range(20)])
            (root / "campaign-policy.json").write_text(
                json.dumps({"fleet": {"max_new_per_sync": 3, "max_open_per_type": 8}}), encoding="utf-8"
            )
            result = sync_jobs(workspace_root=root, types=["harness_author"])
            self.assertEqual(len(result["events_appended"]), 3)
            self.assertTrue(result["blockers"])

    def test_max_open_per_type_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_candidates(root, [{"name": f"vec{i:02d}", "status": "unharnessed"} for i in range(20)])
            (root / "campaign-policy.json").write_text(
                json.dumps({"fleet": {"max_open_per_type": 2, "max_new_per_sync": 12}}), encoding="utf-8"
            )
            result = sync_jobs(workspace_root=root, types=["harness_author"])
            self.assertEqual(len(result["events_appended"]), 2)


class RoboDuckLaneTests(unittest.TestCase):
    def test_vuln_hunt_from_dangerous_sinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work" / "tgt"
            work.mkdir(parents=True)
            (work / "sink-status.json").write_text(
                json.dumps({"sinks": {"a.c:10:CopyBits": {"status": "unreached"}}}), encoding="utf-8"
            )

            result = sync_jobs(workspace_root=root, types=["vuln_hunt"])

            ids = [e["id"] for e in result["events_appended"]]
            self.assertEqual(ids, ["vuln_hunt:tgt"])
            self.assertEqual(result["events_appended"][0]["playbook"], "vuln-hunter.md")
            self.assertIn("a.c:10:CopyBits", result["events_appended"][0]["evidence"]["sink_keys"])

    def test_vuln_hunt_done_not_reopened_by_own_artifact(self) -> None:
        """Writing hypotheses.json (the job's own deliverable) must not
        change the gen hash and reopen the done job on the next sync."""
        from agentic_fuzz_engine.jobs import jobs_update

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work" / "tgt"
            work.mkdir(parents=True)
            (work / "sink-status.json").write_text(
                json.dumps({"sinks": {"a.c:10:CopyBits": {"status": "unreached"}}}), encoding="utf-8"
            )
            sync_jobs(workspace_root=root, types=["vuln_hunt"])
            jobs_update(workspace_root=root, job_id="vuln_hunt:tgt", state="done")
            (work / "hypotheses.json").write_text(
                json.dumps({"hypotheses": [{"id": "H1", "function": "CopyBits", "file": "a.c",
                                            "line": 10, "bug_class": "oob-write",
                                            "predicate_in_english": "x", "status": "open"}]}),
                encoding="utf-8",
            )
            again = sync_jobs(workspace_root=root, types=["vuln_hunt"])
            self.assertEqual(again["events_appended"], [])

    def test_pov_produce_from_open_hypothesis_and_reached_sink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work" / "tgt"
            work.mkdir(parents=True)
            (work / "hypotheses.json").write_text(
                json.dumps({"hypotheses": [
                    {"id": "hyp-01", "function": "CopyBits", "file": "a.c", "line": 10,
                     "bug_class": "heap-buffer-overflow-write", "status": "open"},
                    {"id": "hyp-02", "function": "Other", "file": "b.c", "line": 5,
                     "bug_class": "oob-read", "status": "refuted"},
                ]}),
                encoding="utf-8",
            )
            (work / "sink-status.json").write_text(
                json.dumps({"sinks": {"c.c:9:RunCmd": {"status": "reached", "method": "RunCmd"}}}),
                encoding="utf-8",
            )

            result = sync_jobs(workspace_root=root, types=["pov_produce"])

            ids = sorted(e["id"] for e in result["events_appended"])
            self.assertEqual(ids, ["pov_produce:tgt:RunCmd", "pov_produce:tgt:hyp-01"])


class UpdateTests(unittest.TestCase):
    def _queued_job(self, root: Path) -> str:
        _write_candidates(root, [{"name": "demo_vec", "status": "unharnessed"}])
        sync_jobs(workspace_root=root, types=["harness_author"])
        return "harness_author:demo_vec"

    def test_failed_requeues_with_next_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            job_id = self._queued_job(root)
            result = jobs_update(
                job_id=job_id, state="failed", failure_class="predicate_failed", workspace_root=root
            )
            self.assertTrue(result["ok"])
            folded = fold_events(load_events(root))[job_id]
            self.assertEqual(folded["state"], "queued")
            self.assertEqual(folded["attempt"], 2)

    def test_failed_at_max_attempts_parks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            job_id = self._queued_job(root)
            for _ in range(3):
                jobs_update(job_id=job_id, state="failed", workspace_root=root)
            folded = fold_events(load_events(root))[job_id]
            self.assertEqual(folded["state"], "parked")
            self.assertEqual(folded["attempt"], 3)

    def test_infra_failure_does_not_consume_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            job_id = self._queued_job(root)
            jobs_update(
                job_id=job_id, state="failed", failure_class="infra",
                consume_attempt=False, workspace_root=root,
            )
            folded = fold_events(load_events(root))[job_id]
            self.assertEqual(folded["state"], "queued")
            self.assertEqual(folded["attempt"], 1)

    def test_update_unknown_job_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = jobs_update(job_id="nope:x", state="done", workspace_root=Path(tmp))
            self.assertFalse(result["ok"])

    def test_worker_fields_merge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            job_id = self._queued_job(root)
            jobs_update(
                job_id=job_id, state="done",
                fields={"worker": {"cost_usd": 1.25, "num_turns": 12}, "predicate": {"ok": True}},
                workspace_root=root,
            )
            folded = fold_events(load_events(root))[job_id]
            self.assertEqual(folded["worker"]["cost_usd"], 1.25)
            self.assertTrue(folded["predicate"]["ok"])


class ListReportTests(unittest.TestCase):
    def test_list_filters_and_report_totals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_candidates(root, [
                {"name": "vec_a", "status": "unharnessed"},
                {"name": "vec_b", "status": "unharnessed"},
            ])
            sync_jobs(workspace_root=root, types=["harness_author"])
            jobs_update(
                job_id="harness_author:vec_a", state="done",
                fields={"worker": {"cost_usd": 2.5}, "predicate": {"ok": True}},
                workspace_root=root,
            )

            listing = jobs_list(workspace_root=root, state="queued")
            self.assertEqual([row["id"] for row in listing["jobs"]], ["harness_author:vec_b"])
            self.assertEqual(listing["counts"], {"done": 1, "queued": 1})

            report = jobs_report(workspace_root=root)
            self.assertEqual(report["worker_cost_usd_total"], 2.5)
            self.assertEqual(report["by_type_state"]["harness_author"], {"done": 1, "queued": 1})
            self.assertEqual([row["id"] for row in report["done"]], ["harness_author:vec_a"])
            self.assertTrue(report["done"][0]["predicate_ok"])


if __name__ == "__main__":
    unittest.main()

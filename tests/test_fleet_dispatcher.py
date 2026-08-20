"""Fleet dispatcher offline tests: fake-claude stub, classification, brakes."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from fleet_dispatcher.config import load_config
from fleet_dispatcher.governor import select_wave
from fleet_dispatcher.runner import run_job, spend_today

from agentic_fuzz_engine.jobs import append_event, fold_events, load_events

ENGINE_ROOT = Path(__file__).resolve().parents[1]

FAKE_CLAUDE = r'''#!/bin/sh
# Fake headless claude: consumes stdin, emits canned stream-json per mode.
cat > /dev/null
mode="${FAKE_CLAUDE_MODE:-success}"
case "$mode" in
  success)
    printf '%s\n' '{"type":"system","subtype":"init","session_id":"fake-1"}'
    printf '%s\n' '{"type":"result","subtype":"success","total_cost_usd":0.42,"num_turns":7,"session_id":"fake-1","result":"artifact authored; predicate run"}'
    exit 0
    ;;
  blocked)
    printf '%s\n' '{"type":"result","subtype":"success","total_cost_usd":0.10,"num_turns":3,"session_id":"fake-2","result":"BLOCKED: build config missing for target"}'
    exit 0
    ;;
  infra)
    echo "API error 529 overloaded" >&2
    exit 1
    ;;
  api_error)
    printf '%s\n' '{"type":"result","subtype":"success","is_error":true,"total_cost_usd":0.30,"num_turns":9,"session_id":"fake-3","result":"API Error: Request rejected (429) RESOURCE_EXHAUSTED"}'
    exit 1
    ;;
esac
'''


def _make_workspace(tmp: Path, *, enabled: bool = True) -> Path:
    ws = tmp / "ws"
    (ws / "data").mkdir(parents=True)
    (ws / "work").mkdir()
    (ws / "workspace.json").write_text("{}", encoding="utf-8")
    (ws / "campaign-policy.json").write_text(
        json.dumps({"fleet": {"enabled": enabled, "max_workers": 4, "max_build_workers": 1,
                              "daily_usd_cap": 150.0, "max_attempts": 3,
                              "job_caps": {"steering": {"max_usd": 3.0, "wall_seconds": 60}}}}),
        encoding="utf-8",
    )
    return ws


def _make_fake_claude(tmp: Path) -> str:
    stub = tmp / "fake-claude"
    stub.write_text(FAKE_CLAUDE, encoding="utf-8")
    os.chmod(stub, 0o755)
    return str(stub)


def _seed_steering_dict_job(ws: Path, *, with_dict: bool) -> str:
    job_id = "steering:demo:dict"
    append_event(ws, {
        "id": job_id, "type": "steering", "target": "demo", "qualifier": "dict",
        "state": "queued", "attempt": 1, "gen": "cafe0001", "playbook": "dictionary-generator.md",
        "evidence": {"dict_path": str(ws / "targets" / "c" / "demo" / "demo.dict")},
        "budget": {"max_usd": 3.0, "wall_seconds": 60},
    })
    if with_dict:
        dict_path = ws / "targets" / "c" / "demo" / "demo.dict"
        dict_path.parent.mkdir(parents=True, exist_ok=True)
        dict_path.write_text('magic="\\x89PNG"\n', encoding="utf-8")
    return job_id


def _cfg(ws: Path, claude_bin: str):
    return load_config(
        workspace=str(ws), engine_root=str(ENGINE_ROOT),
        claude_bin=claude_bin, add_dir=[],
    )


class RunnerTests(unittest.TestCase):
    def test_dry_run_prints_exact_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            job_id = _seed_steering_dict_job(ws, with_dict=False)
            cfg = _cfg(ws, "claude")

            result = run_job(cfg, job_id, dry_run=True)

            self.assertTrue(result["ok"], result)
            argv = result["argv"]
            self.assertEqual(argv[0], "claude")
            self.assertIn("--max-budget-usd", argv)
            self.assertEqual(argv[argv.index("--max-budget-usd") + 1], "3.00")
            self.assertIn("--append-system-prompt-file", argv)
            self.assertIn("dictionary-generator.md", argv[argv.index("--append-system-prompt-file") + 1])
            self.assertIn("--no-session-persistence", argv)
            prompt = Path(result["prompt_path"]).read_text(encoding="utf-8")
            self.assertIn("jobs predicate steering:demo:dict", prompt)
            self.assertIn("BLOCKED:", prompt)
            self.assertIn("python3 - args < file.py", prompt)

    def test_happy_path_done_with_spend_and_predicate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            job_id = _seed_steering_dict_job(ws, with_dict=True)
            cfg = _cfg(ws, _make_fake_claude(Path(tmp)))
            os.environ["FAKE_CLAUDE_MODE"] = "success"
            try:
                result = run_job(cfg, job_id)
            finally:
                os.environ.pop("FAKE_CLAUDE_MODE", None)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["classification"], "done")
            folded = fold_events(load_events(ws))[job_id]
            self.assertEqual(folded["state"], "done")
            self.assertTrue(folded["predicate"]["ok"])
            self.assertEqual(folded["worker"]["cost_usd"], 0.42)
            self.assertAlmostEqual(spend_today(cfg), 0.42)
            attempt_dir = Path(result["attempt_dir"])
            self.assertTrue((attempt_dir / "transcript.stream.jsonl").is_file())
            self.assertTrue((attempt_dir / "prompt.md").is_file())

    def test_predicate_failure_requeues_with_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            job_id = _seed_steering_dict_job(ws, with_dict=False)  # predicate will fail
            cfg = _cfg(ws, _make_fake_claude(Path(tmp)))
            os.environ["FAKE_CLAUDE_MODE"] = "success"
            try:
                result = run_job(cfg, job_id)
            finally:
                os.environ.pop("FAKE_CLAUDE_MODE", None)

            self.assertFalse(result["ok"])
            self.assertEqual(result["classification"], "predicate_failed")
            folded = fold_events(load_events(ws))[job_id]
            self.assertEqual(folded["state"], "queued")  # auto-requeued
            self.assertEqual(folded["attempt"], 2)
            failure = Path(result["attempt_dir"]) / "failure.md"
            self.assertIn("predicate failed", failure.read_text(encoding="utf-8"))

    def test_blocked_parks_job(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            job_id = _seed_steering_dict_job(ws, with_dict=True)
            cfg = _cfg(ws, _make_fake_claude(Path(tmp)))
            os.environ["FAKE_CLAUDE_MODE"] = "blocked"
            try:
                result = run_job(cfg, job_id)
            finally:
                os.environ.pop("FAKE_CLAUDE_MODE", None)

            self.assertEqual(result["classification"], "agent_gave_up")
            folded = fold_events(load_events(ws))[job_id]
            self.assertEqual(folded["state"], "parked")
            self.assertIn("BLOCKED", folded["note"])

    def test_infra_failure_does_not_consume_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            job_id = _seed_steering_dict_job(ws, with_dict=True)
            cfg = _cfg(ws, _make_fake_claude(Path(tmp)))
            os.environ["FAKE_CLAUDE_MODE"] = "infra"
            try:
                result = run_job(cfg, job_id)
            finally:
                os.environ.pop("FAKE_CLAUDE_MODE", None)

            self.assertEqual(result["classification"], "infra")
            folded = fold_events(load_events(ws))[job_id]
            self.assertEqual(folded["state"], "queued")
            self.assertEqual(folded["attempt"], 1)  # not consumed

    def test_mid_run_api_error_is_infra_not_predicate_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            job_id = _seed_steering_dict_job(ws, with_dict=True)
            cfg = _cfg(ws, _make_fake_claude(Path(tmp)))
            os.environ["FAKE_CLAUDE_MODE"] = "api_error"
            try:
                result = run_job(cfg, job_id)
            finally:
                os.environ.pop("FAKE_CLAUDE_MODE", None)

            self.assertEqual(result["classification"], "infra")
            folded = fold_events(load_events(ws))[job_id]
            self.assertEqual(folded["state"], "queued")
            self.assertEqual(folded["attempt"], 1)  # not consumed

    def test_park_after_max_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            job_id = _seed_steering_dict_job(ws, with_dict=False)
            cfg = _cfg(ws, _make_fake_claude(Path(tmp)))
            os.environ["FAKE_CLAUDE_MODE"] = "success"
            try:
                for _ in range(3):
                    run_job(cfg, job_id)
            finally:
                os.environ.pop("FAKE_CLAUDE_MODE", None)

            folded = fold_events(load_events(ws))[job_id]
            self.assertEqual(folded["state"], "parked")
            self.assertEqual(folded["attempt"], 3)


class GovernorTests(unittest.TestCase):
    def test_disabled_fleet_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp), enabled=False)
            _seed_steering_dict_job(ws, with_dict=True)
            cfg = _cfg(ws, "claude")
            selection = select_wave(cfg, workers=2)
            self.assertEqual(selection["jobs"], [])
            self.assertIn("fleet.enabled", selection["blockers"][0])

    def test_daily_budget_brake(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            _seed_steering_dict_job(ws, with_dict=True)
            from datetime import datetime, timezone
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            (ws / "data" / "fleet-spend.json").write_text(
                json.dumps({day: {"total_usd": 200.0, "jobs": {}}}), encoding="utf-8"
            )
            cfg = _cfg(ws, "claude")
            selection = select_wave(cfg, workers=2)
            self.assertEqual(selection["jobs"], [])
            self.assertIn("daily budget exhausted", selection["blockers"][0])

    def test_build_sublimit_and_priority_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            for name in ("vec_a", "vec_b", "vec_c"):
                append_event(ws, {
                    "id": f"harness_author:{name}", "type": "harness_author", "target": name,
                    "state": "queued", "attempt": 1, "gen": "g", "playbook": "harness-builder.md",
                    "budget": {"max_usd": 8.0, "wall_seconds": 60},
                })
            append_event(ws, {
                "id": "triage:tgt:aaaabbbbcccc", "type": "triage", "target": "tgt",
                "state": "queued", "attempt": 1, "gen": "g", "playbook": "crash-grader.md",
                "budget": {"max_usd": 4.0, "wall_seconds": 60},
            })
            cfg = _cfg(ws, "claude")
            selection = select_wave(cfg, workers=4)
            picked = [row["id"] for row in selection["jobs"]]
            # triage first (priority), then only ONE harness_author (build sublimit 1)
            self.assertEqual(picked[0], "triage:tgt:aaaabbbbcccc")
            self.assertEqual(sum(1 for p in picked if p.startswith("harness_author:")), 1)

    def test_fleet_plan_runs_solo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            append_event(ws, {
                "id": "fleet_plan:_workspace:2026-07-16", "type": "fleet_plan", "target": "_workspace",
                "state": "queued", "attempt": 1, "gen": "g", "playbook": "planner.md",
                "budget": {"max_usd": 2.0, "wall_seconds": 60},
            })
            _seed_steering_dict_job(ws, with_dict=True)
            cfg = _cfg(ws, "claude")
            selection = select_wave(cfg, workers=4)
            self.assertEqual([row["id"] for row in selection["jobs"]], ["fleet_plan:_workspace:2026-07-16"])


if __name__ == "__main__":
    unittest.main()

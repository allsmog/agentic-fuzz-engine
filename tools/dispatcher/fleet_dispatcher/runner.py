"""Worker lifecycle: spawn one bounded headless claude, judge via engine."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import ALLOWED_TOOLS, DISALLOWED_TOOLS, Config
from .prompts import compose_prompt

KILL_GRACE_SECONDS = 60


def slugify(job_id: str) -> str:
    return "".join(c if c.isalnum() or c in "_-" else "_" for c in job_id)


def _engine_json(cfg: Config, *args: str, timeout: float = 600) -> dict[str, Any]:
    proc = subprocess.run(
        cfg.engine_cmd(*args),
        env=cfg.engine_env(),
        cwd=str(cfg.engine_root),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "blockers": [f"engine output unparseable (exit {proc.returncode}): {proc.stderr[-500:]}"]}


def get_job(cfg: Config, job_id: str) -> dict[str, Any] | None:
    listing = _engine_json(cfg, "jobs", "list")
    for row in listing.get("jobs", []):
        if row.get("id") == job_id:
            return row
    return None


def build_argv(cfg: Config, job: dict[str, Any]) -> list[str]:
    policy = cfg.fleet_policy()
    budget = job.get("budget") if isinstance(job.get("budget"), dict) else {}
    max_usd = float(budget.get("max_usd", 5.0))
    playbook = cfg.playbook_path(str(job.get("playbook") or "planner.md"))
    argv = [
        cfg.claude_bin,
        "-p",
        "--bare",
        "--output-format", "stream-json",
        "--verbose",
        "--no-session-persistence",
        "--max-budget-usd", f"{max_usd:.2f}",
        "--append-system-prompt-file", str(playbook),
        "--allowedTools", ALLOWED_TOOLS,
        "--disallowedTools", DISALLOWED_TOOLS,
        "--permission-mode", "acceptEdits",
    ]
    model = policy.get("model")
    if model:
        argv += ["--model", str(model)]
    for extra in cfg.add_dirs:
        if extra and Path(extra).is_dir():
            argv += ["--add-dir", extra]
    return argv


def run_job(cfg: Config, job_id: str, *, dry_run: bool = False) -> dict[str, Any]:
    job = get_job(cfg, job_id)
    if job is None:
        return {"ok": False, "job": job_id, "blockers": [f"unknown job: {job_id}"]}
    if job.get("state") not in ("queued",):
        return {"ok": False, "job": job_id, "blockers": [f"job not queued (state={job.get('state')})"]}

    attempt = int(job.get("attempt") or 1)
    attempt_dir = cfg.jobs_dir / slugify(job_id) / f"attempt-{attempt}"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    prompt = compose_prompt(cfg, job, attempt_dir)
    (attempt_dir / "prompt.md").write_text(prompt, encoding="utf-8")
    argv = build_argv(cfg, job)

    if dry_run:
        return {
            "ok": True,
            "job": job_id,
            "dry_run": True,
            "argv": argv,
            "prompt_path": str(attempt_dir / "prompt.md"),
            "wall_seconds": int((job.get("budget") or {}).get("wall_seconds", 1800)),
        }

    playbook = cfg.playbook_path(str(job.get("playbook") or "planner.md"))
    if not playbook.is_file():
        return {"ok": False, "job": job_id, "blockers": [f"playbook missing: {playbook}"]}

    _engine_json(cfg, "jobs", "update", job_id, "--state", "running",
                 "--fields-json", json.dumps({"transcript": str(attempt_dir / "transcript.stream.jsonl")}))

    wall = int((job.get("budget") or {}).get("wall_seconds", 1800))
    env = cfg.engine_env()
    env["DEBUGINFOD_URLS"] = ""
    # A worker is a fresh headless session, not a child of the launching one.
    for stale in ("CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_CHILD_SESSION", "CLAUDE_CODE_ENTRYPOINT", "CLAUDECODE"):
        env.pop(stale, None)
    started = time.time()
    transcript_path = attempt_dir / "transcript.stream.jsonl"
    stderr_path = attempt_dir / "stderr.log"
    with (attempt_dir / "prompt.md").open("rb") as stdin, \
            transcript_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        proc = subprocess.Popen(
            argv, stdin=stdin, stdout=stdout, stderr=stderr,
            cwd=str(cfg.workspace), env=env, start_new_session=True,
        )
        try:
            exit_code = proc.wait(timeout=wall)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            exit_code = -9
    duration = time.time() - started

    result_event = _parse_result(transcript_path)
    worker = {
        "exit_code": exit_code,
        "duration_s": round(duration, 1),
        "cost_usd": result_event.get("cost_usd"),
        "num_turns": result_event.get("num_turns"),
        "session_id": result_event.get("session_id"),
        "model": result_event.get("model"),
    }
    (attempt_dir / "result.json").write_text(json.dumps({"worker": worker, "result_text": result_event.get("text")}, indent=2), encoding="utf-8")
    _record_spend(cfg, job_id, worker.get("cost_usd"))

    outcome = _classify_and_update(cfg, job, attempt_dir, worker, result_event)
    outcome.update({"job": job_id, "attempt": attempt, "worker": worker, "attempt_dir": str(attempt_dir)})
    return outcome


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=KILL_GRACE_SECONDS)
            return
        except subprocess.TimeoutExpired:
            pass
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10)
    except (ProcessLookupError, PermissionError):
        pass


def _parse_result(transcript_path: Path) -> dict[str, Any]:
    """Last ``result`` event from the stream-json transcript (tolerant)."""
    result: dict[str, Any] = {}
    try:
        with transcript_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("type") == "result":
                    result = {
                        "cost_usd": event.get("total_cost_usd", event.get("cost_usd")),
                        "num_turns": event.get("num_turns"),
                        "session_id": event.get("session_id"),
                        "model": (event.get("modelUsage") and next(iter(event["modelUsage"]), None)) or event.get("model"),
                        "text": event.get("result") or "",
                        "is_error": bool(event.get("is_error")),
                        "subtype": event.get("subtype"),
                    }
    except OSError:
        pass
    return result


def _classify_and_update(
    cfg: Config,
    job: dict[str, Any],
    attempt_dir: Path,
    worker: dict[str, Any],
    result_event: dict[str, Any],
) -> dict[str, Any]:
    job_id = str(job["id"])
    text = str(result_event.get("text") or "")
    turns = worker.get("num_turns")

    # API/quota death mid-run (e.g. Vertex 429 RESOURCE_EXHAUSTED): the
    # stream ends with is_error + an "API Error" result. Infra, not the
    # agent's fault — unless it's the budget brake, which is a real stop.
    if (
        result_event.get("is_error")
        and result_event.get("subtype") != "error_max_budget_usd"
        and ("API Error" in text or "RESOURCE_EXHAUSTED" in text or '"code":429' in text)
    ):
        _write_failure(attempt_dir, f"infra failure (API error): {text[:300]}")
        _engine_json(cfg, "jobs", "update", job_id, "--state", "failed",
                     "--failure-class", "infra", "--no-consume-attempt",
                     "--fields-json", json.dumps({"worker": worker}))
        return {"ok": False, "classification": "infra", "detail": text[:200]}

    # infra: worker never really ran (no result event / zero turns / hard kill)
    if not result_event or (isinstance(turns, int) and turns == 0) or worker["exit_code"] == -9 and not result_event:
        _write_failure(attempt_dir, f"infra failure: exit={worker['exit_code']} turns={turns} — see stderr.log")
        _engine_json(cfg, "jobs", "update", job_id, "--state", "failed",
                     "--failure-class", "infra", "--no-consume-attempt",
                     "--fields-json", json.dumps({"worker": worker}))
        return {"ok": False, "classification": "infra"}

    if "BLOCKED:" in text:
        blocker = text.split("BLOCKED:", 1)[1].strip().splitlines()[0][:300]
        _write_failure(attempt_dir, f"agent gave up: BLOCKED: {blocker}")
        _engine_json(cfg, "jobs", "update", job_id, "--state", "parked",
                     "--failure-class", "agent_gave_up", "--note", f"BLOCKED: {blocker}",
                     "--fields-json", json.dumps({"worker": worker}))
        return {"ok": False, "classification": "agent_gave_up", "blocker": blocker}

    predicate_payload = _engine_json(cfg, "jobs", "predicate", job_id)
    predicate = predicate_payload.get("predicate") or {}
    if predicate.get("ok"):
        _engine_json(cfg, "jobs", "update", job_id, "--state", "done",
                     "--fields-json", json.dumps({"worker": worker, "predicate": predicate}))
        return {"ok": True, "classification": "done", "predicate": predicate}

    detail = str(predicate.get("detail") or predicate_payload.get("blockers") or "predicate failed")
    _write_failure(attempt_dir, f"predicate failed: {detail}")
    _engine_json(cfg, "jobs", "update", job_id, "--state", "failed",
                 "--failure-class", "predicate_failed",
                 "--fields-json", json.dumps({"worker": worker, "predicate": predicate}))
    return {"ok": False, "classification": "predicate_failed", "predicate": predicate}


def _write_failure(attempt_dir: Path, text: str) -> None:
    (attempt_dir / "failure.md").write_text(text + "\n", encoding="utf-8")


def _record_spend(cfg: Config, job_id: str, cost: Any) -> None:
    if not isinstance(cost, (int, float)):
        return
    path = cfg.spend_path
    try:
        ledger = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        ledger = {}
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    entry = ledger.setdefault(day, {"total_usd": 0.0, "jobs": {}})
    entry["total_usd"] = round(float(entry.get("total_usd", 0.0)) + float(cost), 4)
    entry["jobs"][job_id] = round(float(entry["jobs"].get(job_id, 0.0)) + float(cost), 4)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def spend_today(cfg: Config) -> float:
    try:
        ledger = json.loads(cfg.spend_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0.0
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return float((ledger.get(day) or {}).get("total_usd", 0.0))

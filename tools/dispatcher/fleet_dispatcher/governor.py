"""Wave governor: pick queued jobs by priority under concurrency + budget caps."""

from __future__ import annotations

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .config import BUILD_HEAVY, TYPE_ORDER, Config
from .runner import _engine_json, run_job, spend_today


def queued_jobs(cfg: Config, types: list[str] | None = None) -> list[dict[str, Any]]:
    listing = _engine_json(cfg, "jobs", "list", "--state", "queued")
    rows = [row for row in listing.get("jobs", []) if not types or row.get("type") in types]
    order = {name: index for index, name in enumerate(TYPE_ORDER)}
    rows.sort(key=lambda row: (order.get(str(row.get("type")), 99), str(row.get("id"))))
    return rows


def select_wave(cfg: Config, *, workers: int, types: list[str] | None = None) -> dict[str, Any]:
    """One wave's worth of launchable jobs, honoring every brake."""
    policy = cfg.fleet_policy()
    blockers: list[str] = []
    if not policy.get("enabled"):
        return {"jobs": [], "blockers": ["fleet.enabled is false in campaign policy — flip it to launch workers"]}
    cap = float(policy.get("daily_usd_cap", 150.0))
    spent = spend_today(cfg)
    if spent >= cap:
        return {"jobs": [], "blockers": [f"daily budget exhausted: ${spent:.2f} >= ${cap:.2f}"]}

    max_workers = min(int(workers), int(policy.get("max_workers", 4)))
    max_build = int(policy.get("max_build_workers", 2))
    rows = queued_jobs(cfg, types)

    # fleet_plan runs solo: a fresh plan changes what everything else should do.
    plan_rows = [row for row in rows if row.get("type") == "fleet_plan"]
    if plan_rows:
        return {"jobs": plan_rows[:1], "blockers": [], "note": "fleet_plan runs solo"}

    picked: list[dict[str, Any]] = []
    build_count = 0
    remaining = cap - spent
    for row in rows:
        if len(picked) >= max_workers:
            break
        job_type = str(row.get("type"))
        max_usd = float((row.get("budget") or {}).get("max_usd", 5.0))
        if max_usd > remaining:
            blockers.append(f"skipped {row.get('id')}: cap ${max_usd:.2f} exceeds remaining daily budget ${remaining:.2f}")
            continue
        if job_type in BUILD_HEAVY:
            if build_count >= max_build:
                continue
            build_count += 1
        picked.append(row)
        remaining -= max_usd
    return {"jobs": picked, "blockers": blockers}


def dispatch(cfg: Config, *, workers: int, once: bool = False, types: list[str] | None = None, max_waves: int = 50) -> dict[str, Any]:
    waves: list[dict[str, Any]] = []
    for wave_index in range(1 if once else max_waves):
        selection = select_wave(cfg, workers=workers, types=types)
        jobs = selection["jobs"]
        if not jobs:
            waves.append({"wave": wave_index + 1, "launched": [], "blockers": selection["blockers"]})
            break
        results = []
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {pool.submit(run_job, cfg, str(row["id"])): str(row["id"]) for row in jobs}
            for future in as_completed(futures):
                job_id = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:  # worker crash must not kill the wave
                    results.append({"ok": False, "job": job_id, "classification": "dispatcher_error", "error": str(exc)})
        waves.append({
            "wave": wave_index + 1,
            "launched": [r.get("job") for r in results],
            "results": results,
            "blockers": selection["blockers"],
        })
        # re-sync between waves so finished work re-derives the queue
        _engine_json(cfg, "jobs", "sync")
    report = _engine_json(cfg, "jobs", "report")
    return {"ok": True, "waves": waves, "report": {
        "by_type_state": report.get("by_type_state"),
        "worker_cost_usd_total": report.get("worker_cost_usd_total"),
    }}

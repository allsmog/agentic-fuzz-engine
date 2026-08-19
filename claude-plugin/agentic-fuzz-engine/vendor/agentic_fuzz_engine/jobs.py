"""Fleet job ledger: a typed queue of authoring work derived from workspace state.

The engine stays LLM-free. This module only *describes* work (jobs sync scans
the same deterministic state the session reads — candidates ledger, plateau
signals, sink frontier, directed queue, codec/bits state, known crashes) and
*judges* results (job_predicates). Any worker may drain the queue: the
interactive session, or the fleet dispatcher spawning bounded headless
workers. Storage mirrors the candidates ledger: ``data/jobs.jsonl`` is an
append-only event log and a job's current state is the fold of its events.

Job ids are deterministic (``<type>:<target>[:<qualifier>]``) and each job
carries ``gen`` — a short hash of the evidence that triggered it — so a done
or parked id reopens only when the underlying evidence actually changes.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .workspace import load_policy, resolve_workspace_root

JOBS_RELATIVE = Path("data/jobs.jsonl")
FLEET_JOBS_RELATIVE = Path("work/_fleet/jobs")
SPEND_RELATIVE = Path("data/fleet-spend.json")
FLEET_PLAN_RELATIVE = Path("data/fleet-plan.json")
MAX_LEDGER_EVENTS = 200_000
OPEN_STATES = ("queued", "running")
STATES = ("queued", "running", "done", "failed", "parked", "dropped")
FLEET_TARGET = "_workspace"

# Launch-priority order (first = drained first). ``build_heavy`` types share
# the dispatcher's build sublimit.
JOB_TYPES: dict[str, dict[str, Any]] = {
    "fleet_plan": {"playbook": "planner.md", "build_heavy": False},
    "triage": {"playbook": "crash-grader.md", "build_heavy": False},
    "allowlist_build": {"playbook": "harness-builder.md", "build_heavy": True},
    "harness_author": {"playbook": "harness-builder.md", "build_heavy": True},
    "frontier_seed": {"playbook": "input-generator.md", "build_heavy": False},
    "steering": {"playbook": "planner.md", "build_heavy": False},
    "solver_assist": {"playbook": "concolic-generator.md", "build_heavy": False},
    # RoboDuck-style LLM-first lanes: hypothesize from source, then iterate
    # a constructed PoV until the sanitizer (via finding-grade) decides.
    "vuln_hunt": {"playbook": "vuln-hunter.md", "build_heavy": False},
    "pov_produce": {"playbook": "pov-producer.md", "build_heavy": False},
}
STEERING_PLAYBOOKS = {
    "bits": "planner.md",
    "dict": "dictionary-generator.md",
    "codec": "input-generator.md",
}


def _now() -> float:
    return time.time()


def _gen_hash(evidence: Mapping[str, Any]) -> str:
    return sha256(json.dumps(evidence, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:8]


def job_slug(job_id: str) -> str:
    return "".join(char if char.isalnum() or char in "_-" else "_" for char in job_id)


def load_events(root: Path) -> list[dict[str, Any]]:
    path = root / JOBS_RELATIVE
    events: list[dict[str, Any]] = []
    if not path.is_file():
        return events
    with path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            if index >= MAX_LEDGER_EVENTS:
                break
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("id"):
                events.append(event)
    return events


def fold_events(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Last-event-wins per field; ``history`` accumulates state transitions."""
    state: dict[str, dict[str, Any]] = {}
    for event in events:
        job_id = str(event["id"])
        entry = state.setdefault(job_id, {"history": []})
        for key, value in event.items():
            if key == "id":
                continue
            entry[key] = value
        if event.get("state"):
            entry["history"].append(str(event["state"]))
    return state


def append_event(root: Path, event: dict[str, Any]) -> dict[str, Any]:
    if not event.get("id"):
        raise ValueError("job event requires an id")
    state = event.get("state")
    if state is not None and state not in STATES:
        raise ValueError(f"invalid job state {state!r} (allowed: {STATES})")
    event.setdefault("ts", _now())
    path = root / JOBS_RELATIVE
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    return event


def fleet_policy(root: Path, *, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    policy = load_policy(root, env=env)
    fleet = policy.get("fleet")
    return dict(fleet) if isinstance(fleet, dict) else {}


def _job_budget(policy: Mapping[str, Any], job_type: str) -> dict[str, Any]:
    caps = policy.get("job_caps") or {}
    cap = caps.get(job_type) or {}
    return {
        "max_usd": float(cap.get("max_usd", 5.0)),
        "wall_seconds": int(cap.get("wall_seconds", 1800)),
    }


# ---------------------------------------------------------------------------
# sync: derive open jobs from workspace state (idempotent)


def sync_jobs(
    *,
    workspace_root: str | Path | None = None,
    types: list[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = resolve_workspace_root(workspace_root, env=env)
    policy = fleet_policy(root, env=env)
    max_open_per_type = int(policy.get("max_open_per_type", 8))
    max_new = int(policy.get("max_new_per_sync", 12))
    wanted_types = [t for t in JOB_TYPES if types is None or t in types]

    current = fold_events(load_events(root))

    # A daily fleet_plan is superseded when the date rolls over: auto-drop
    # stale open plan jobs so the governor never spends budget on yesterday.
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    dropped_stale: list[str] = []
    for job_id, entry in current.items():
        if (
            entry.get("type") == "fleet_plan"
            and entry.get("state") in OPEN_STATES
            and str(entry.get("qualifier") or "") != today
        ):
            append_event(root, {
                "id": job_id,
                "type": "fleet_plan",
                "target": entry.get("target"),
                "state": "dropped",
                "attempt": entry.get("attempt", 1),
                "gen": entry.get("gen"),
                "note": f"stale daily plan superseded by {today}",
            })
            entry["state"] = "dropped"
            dropped_stale.append(str(job_id))

    open_by_type: dict[str, int] = {}
    for entry in current.values():
        if entry.get("state") in OPEN_STATES:
            open_by_type[str(entry.get("type"))] = open_by_type.get(str(entry.get("type")), 0) + 1

    desired = _desired_jobs(root, wanted_types, policy)
    appended: list[dict[str, Any]] = []
    blockers: list[str] = []
    for job in desired:
        if len(appended) >= max_new:
            blockers.append(f"max_new_per_sync {max_new} reached; re-run sync to enqueue the rest")
            break
        job_type = job["type"]
        existing = current.get(job["id"])
        if existing is not None:
            if existing.get("state") in OPEN_STATES:
                continue  # already queued/running
            if existing.get("state") in ("done", "parked", "dropped") and existing.get("gen") == job["gen"]:
                continue  # same evidence — do not reopen
        if open_by_type.get(job_type, 0) >= max_open_per_type:
            continue
        event = {
            "id": job["id"],
            "type": job_type,
            "target": job["target"],
            "state": "queued",
            "attempt": 1,
            "gen": job["gen"],
            "playbook": job["playbook"],
            "evidence": job["evidence"],
            "budget": _job_budget(policy, job_type),
        }
        if job.get("qualifier"):
            event["qualifier"] = job["qualifier"]
        appended.append(append_event(root, event))
        open_by_type[job_type] = open_by_type.get(job_type, 0) + 1

    return {
        "ok": True,
        "mode": "jobs-sync",
        "ledger": str(root / JOBS_RELATIVE),
        "desired": len(desired),
        "events_appended": appended,
        "dropped_stale": dropped_stale,
        "blockers": blockers,
    }


def _desired_jobs(root: Path, wanted_types: list[str], policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    """All jobs the workspace state currently calls for, in launch-priority
    order. Read-only scan; caps and dedupe are applied by the caller."""
    from .campaign_metrics import _ledger_current_state, plateau_status

    jobs: list[dict[str, Any]] = []
    candidates = _ledger_current_state(root)
    plateau: dict[str, dict[str, Any]] = {}
    if any(t in wanted_types for t in ("frontier_seed", "steering", "solver_assist")):
        try:
            plateau = {
                item["target"]: item
                for item in plateau_status(workspace_root=root).get("targets", [])
            }
        except Exception:
            plateau = {}

    if "fleet_plan" in wanted_types:
        jobs.extend(_want_fleet_plan(root))
    if "triage" in wanted_types:
        jobs.extend(_want_triage(root))
    if "allowlist_build" in wanted_types:
        jobs.extend(_want_allowlist_build(root))
    if "harness_author" in wanted_types:
        jobs.extend(_want_harness_author(root, candidates))
    if "frontier_seed" in wanted_types:
        jobs.extend(_want_frontier_seed(root, plateau))
    if "steering" in wanted_types:
        jobs.extend(_want_steering(root, plateau))
    if "solver_assist" in wanted_types:
        jobs.extend(_want_solver_assist(root, plateau))
    if "vuln_hunt" in wanted_types:
        jobs.extend(_want_vuln_hunt(root))
    if "pov_produce" in wanted_types:
        jobs.extend(_want_pov_produce(root))
    return jobs


# Evidence keys that are context for the worker, not part of the trigger:
# excluded from the gen hash so their appearance/refresh never reopens a
# done job (same rule as the hypotheses_exist bug — gen hashes triggers only).
NON_TRIGGER_EVIDENCE_KEYS = {"known_vulns", "grade_run_id"}


def _job(job_type: str, target: str, qualifier: str | None, evidence: dict[str, Any], playbook: str | None = None) -> dict[str, Any]:
    parts = [job_type, target] + ([qualifier] if qualifier else [])
    trigger = {k: v for k, v in evidence.items() if k not in NON_TRIGGER_EVIDENCE_KEYS}
    return {
        "id": ":".join(parts),
        "type": job_type,
        "target": target,
        "qualifier": qualifier,
        "evidence": evidence,
        "gen": _gen_hash(trigger),
        "playbook": playbook or JOB_TYPES[job_type]["playbook"],
    }


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _work_targets(root: Path) -> list[str]:
    work = root / "work"
    if not work.is_dir():
        return []
    return sorted(
        entry.name for entry in work.iterdir()
        if entry.is_dir() and not entry.name.startswith("_")
    )


def _want_fleet_plan(root: Path) -> list[dict[str, Any]]:
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    evidence = {"date": date, "plan_path": str(root / FLEET_PLAN_RELATIVE)}
    return [_job("fleet_plan", FLEET_TARGET, date, evidence)]


def _want_triage(root: Path) -> list[dict[str, Any]]:
    from .known_crashes import load_known

    jobs = []
    for name in _work_targets(root):
        work_dir = root / "work" / name
        for sig, entry in sorted(load_known(work_dir).items()):
            sig12 = sig[:12]
            report_dir = root / "data" / "reports" / name / sig12
            if report_dir.is_dir() and any(report_dir.iterdir()):
                continue
            evidence = {
                "root_signature": sig,
                "crash_type": entry.get("crash_type"),
                "known_crashes": str(work_dir / "known-crashes.json"),
                "report_dir": str(report_dir),
            }
            # Hand the worker the exact finding row so it spends budget on
            # the report, not on rediscovering artifact paths.
            finding = _finding_row_for(root, name, sig12)
            if finding:
                evidence.update({
                    "finding_id": finding.get("finding_id"),
                    "run_id": finding.get("run_id"),
                    "poc_artifact": finding.get("poc_artifact"),
                    "harness": finding.get("harness"),
                    "error_token": finding.get("error_token"),
                    "verified": finding.get("verified"),
                })
            jobs.append(_job("triage", name, sig12, evidence))
    return jobs


def _finding_row_for(root: Path, name: str, sig12: str) -> dict[str, Any] | None:
    runs_dir = root / "data" / "runs"
    if not runs_dir.is_dir():
        return None
    slug = name.replace("/", "_")
    for run_dir in sorted(runs_dir.iterdir(), reverse=True):
        if not run_dir.is_dir() or slug not in run_dir.name:
            continue
        findings = run_dir / "findings.jsonl"
        if not findings.is_file():
            continue
        try:
            with findings.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if str(row.get("root_signature") or "").startswith(sig12):
                        return {
                            "finding_id": row.get("finding_id"),
                            "run_id": run_dir.name,
                            "poc_artifact": row.get("poc_artifact"),
                            "harness": row.get("harness"),
                            "error_token": row.get("error_token"),
                            "verified": row.get("verified"),
                        }
        except OSError:
            continue
    return None


def _want_allowlist_build(root: Path) -> list[dict[str, Any]]:
    from .directed import active_or_queued

    jobs = []
    for name in _work_targets(root):
        try:
            task = active_or_queued(root, name)
        except Exception:
            task = None
        if not task or task.get("binary"):
            continue
        sink = str(task.get("sink") or "")
        method = str(task.get("method") or sink.rsplit(":", 1)[-1])
        evidence = {"task_id": task.get("id"), "sink": sink, "priority": task.get("priority")}
        jobs.append(_job("allowlist_build", name, method, evidence))
    return jobs


def _want_harness_author(root: Path, candidates: Mapping[str, dict[str, Any]]) -> list[dict[str, Any]]:
    jobs = []
    for name, entry in sorted(candidates.items()):
        status = str(entry.get("status"))
        if status not in ("unharnessed", "scaffolded", "awaiting-authoring"):
            continue
        workorder = root / "targets" / "c" / name / "workorder.json"
        evidence = {
            "candidate_status": status,
            "tag": entry.get("tag"),
            "workorder": str(workorder) if workorder.is_file() else None,
        }
        jobs.append(_job("harness_author", name, None, evidence))
    return jobs


def _want_frontier_seed(root: Path, plateau: Mapping[str, dict[str, Any]]) -> list[dict[str, Any]]:
    jobs = []
    for name, item in sorted(plateau.items()):
        if not str(item.get("verdict", "")).startswith("plateaued"):
            continue
        if item.get("next_rung") not in ("frontier", "structured-seeds"):
            continue
        coverage = _read_json(root / "work" / name / "sink-coverage.json")
        uncovered = [
            row for row in coverage.get("uncovered", [])
            if isinstance(row, dict) and row.get("primitive") in ("write", "exec")
        ]
        if not uncovered:
            continue
        top = uncovered[0]
        methods = [str(row.get("method")) for row in uncovered[:5]]
        evidence = {
            "next_rung": item.get("next_rung"),
            "uncovered_methods": methods,
            "sink_coverage": str(root / "work" / name / "sink-coverage.json"),
        }
        jobs.append(_job("frontier_seed", name, str(top.get("method")), evidence))
    return jobs


def _want_steering(root: Path, plateau: Mapping[str, dict[str, Any]]) -> list[dict[str, Any]]:
    jobs = []
    policy = load_policy(root)
    weights_default = bool((policy.get("weights") or {}).get("enabled"))
    for name in _work_targets(root):
        work_dir = root / "work" / name
        target_fuzz = _read_json(root / "targets" / "c" / name / ".localfuzz" / "fuzz.json")
        item = plateau.get(name) or {}

        if str(item.get("verdict", "")).startswith("plateaued") and item.get("next_rung") == "dictionary":
            dict_path = root / "targets" / "c" / name / f"{name}.dict"
            if not dict_path.is_file():
                evidence = {"next_rung": "dictionary", "dict_path": str(dict_path)}
                jobs.append(_job("steering", name, "dict", evidence, STEERING_PLAYBOOKS["dict"]))

        weights_on = target_fuzz.get("weights", {}).get("enabled", weights_default) if isinstance(target_fuzz.get("weights"), dict) else weights_default
        if weights_on and not (work_dir / "bits.json").is_file():
            evidence = {"weights_enabled": True, "bits_path": str(work_dir / "bits.json")}
            jobs.append(_job("steering", name, "bits", evidence, STEERING_PLAYBOOKS["bits"]))

        codec_status = _read_json(work_dir / "codec-status.json")
        sink_status = _read_json(work_dir / "sink-status.json").get("sinks", {})
        reached = [key for key, entry in sink_status.items() if isinstance(entry, dict) and entry.get("status") in ("reached", "exploited")]
        if reached and not codec_status.get("validated"):
            evidence = {
                "reached_sinks": sorted(reached)[:5],
                "codec_status": str(work_dir / "codec-status.json"),
                "codec_validated": bool(codec_status.get("validated")),
            }
            jobs.append(_job("steering", name, "codec", evidence, STEERING_PLAYBOOKS["codec"]))
    return jobs


def _want_solver_assist(root: Path, plateau: Mapping[str, dict[str, Any]]) -> list[dict[str, Any]]:
    jobs = []
    for name, item in sorted(plateau.items()):
        if not str(item.get("verdict", "")).startswith("plateaued"):
            continue
        tried = set(item.get("rungs_tried") or [])
        if not tried & {"symcc-long", "klee-directed"}:
            continue
        effectiveness = _read_json(root / "work" / name / "symx-effectiveness.json")
        if effectiveness.get("surviving", None) != 0:
            continue
        coverage = _read_json(root / "work" / name / "sink-coverage.json")
        uncovered = [
            str(row.get("method")) for row in coverage.get("uncovered", [])
            if isinstance(row, dict) and row.get("primitive") in ("write", "exec")
        ]
        if not uncovered:
            continue
        evidence = {
            "rungs_tried": sorted(tried),
            "symx_surviving": 0,
            "uncovered_methods": uncovered[:5],
        }
        jobs.append(_job("solver_assist", name, uncovered[0], evidence))
    return jobs


def _dangerous_sink_keys(root: Path, name: str) -> list[str]:
    """write/exec sink keys visible to this target: sink-status entries plus
    sink-coverage rows (either file may exist without the other)."""
    work_dir = root / "work" / name
    keys: set[str] = set()
    status = _read_json(work_dir / "sink-status.json").get("sinks", {})
    for key, entry in status.items():
        if isinstance(entry, dict):
            keys.add(str(key))
    coverage = _read_json(work_dir / "sink-coverage.json")
    for bucket in ("covered", "uncovered"):
        for row in coverage.get(bucket, []):
            if isinstance(row, dict) and row.get("primitive") in ("write", "exec"):
                keys.add(f"{row.get('file')}:{row.get('line')}:{row.get('method')}")
    return sorted(keys)


def _want_vuln_hunt(root: Path) -> list[dict[str, Any]]:
    jobs = []
    for name in _work_targets(root):
        keys = _dangerous_sink_keys(root, name)
        if not keys:
            continue
        hypotheses_path = root / "work" / name / "hypotheses.json"
        # gen must hash only the TRIGGER (the sink rows), never state the job
        # itself flips (e.g. whether hypotheses.json exists) — that would
        # reopen the done job on every sync.
        evidence = {
            "sink_keys": keys[:25],
            "hypotheses_path": str(hypotheses_path),
            "known_vulns": str(root / "data" / "known-vulns.jsonl"),
        }
        jobs.append(_job("vuln_hunt", name, None, evidence))
    return jobs


def _latest_run_id(root: Path, name: str) -> str | None:
    """Newest run dir for the target slug — where finding-grade should record."""
    runs_dir = root / "data" / "runs"
    if not runs_dir.is_dir():
        return None
    slug = name.replace("/", "_")
    for run_dir in sorted(runs_dir.iterdir(), reverse=True):
        if run_dir.is_dir() and slug in run_dir.name:
            return run_dir.name
    return None


def _want_pov_produce(root: Path) -> list[dict[str, Any]]:
    jobs = []
    for name in _work_targets(root):
        work_dir = root / "work" / name
        context = {
            "hypotheses_path": str(work_dir / "hypotheses.json"),
            "harness_bin": str(root / "bin" / name / "fuzzer"),
            "seeds_dir": str(work_dir / "seeds"),
            "known_vulns": str(root / "data" / "known-vulns.jsonl"),
            "grade_run_id": _latest_run_id(root, name),
        }
        hypotheses = _read_json(work_dir / "hypotheses.json").get("hypotheses", [])
        for hyp in hypotheses:
            if not isinstance(hyp, dict) or str(hyp.get("status")) != "open":
                continue
            hyp_id = str(hyp.get("id") or "")
            if not hyp_id:
                continue
            evidence = {
                "hypothesis_id": hyp_id,
                "function": hyp.get("function"),
                "file": hyp.get("file"),
                "line": hyp.get("line"),
                "bug_class": hyp.get("bug_class"),
                **context,
            }
            jobs.append(_job("pov_produce", name, hyp_id, evidence))
        # reached-but-unexploited sinks are PoV work even without a hypothesis
        status = _read_json(work_dir / "sink-status.json").get("sinks", {})
        for key, entry in sorted(status.items()):
            if not isinstance(entry, dict) or str(entry.get("status")) != "reached":
                continue
            method = str(entry.get("method") or key.rsplit(":", 1)[-1])
            if method == "LLVMFuzzerTestOneInput" or "/fuzz/" in key:
                continue  # harness entry points are trivially reached, never PoV targets
            evidence = {
                "sink": key,
                "sink_status": "reached",
                "close_seeds": bool(entry.get("close_seeds")),
                **context,
            }
            jobs.append(_job("pov_produce", name, method, evidence))
    return jobs


# ---------------------------------------------------------------------------
# list / update / report


def jobs_list(
    *,
    workspace_root: str | Path | None = None,
    state: str | None = None,
    job_type: str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = resolve_workspace_root(workspace_root, env=env)
    folded = fold_events(load_events(root))
    counts: dict[str, int] = {}
    rows = []
    for job_id, entry in sorted(folded.items()):
        current = str(entry.get("state"))
        counts[current] = counts.get(current, 0) + 1
        if state and current != state:
            continue
        if job_type and str(entry.get("type")) != job_type:
            continue
        rows.append({"id": job_id, **{k: v for k, v in entry.items() if k != "history"}, "events": len(entry["history"])})
    return {
        "ok": True,
        "mode": "jobs-list",
        "ledger": str(root / JOBS_RELATIVE),
        "counts": counts,
        "jobs": rows,
    }


def jobs_update(
    *,
    job_id: str,
    state: str,
    note: str | None = None,
    failure_class: str | None = None,
    fields: Mapping[str, Any] | None = None,
    consume_attempt: bool = True,
    workspace_root: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Append a transition. ``failed`` auto-requeues (attempt+1) below the
    policy attempts cap, else parks; ``infra`` failures never consume the
    attempt (pass consume_attempt=False)."""
    root = resolve_workspace_root(workspace_root, env=env)
    folded = fold_events(load_events(root))
    entry = folded.get(job_id)
    if entry is None:
        return {"ok": False, "blockers": [f"unknown job id: {job_id}"]}
    current = str(entry.get("state"))
    attempt = int(entry.get("attempt") or 1)

    event: dict[str, Any] = {"id": job_id, "state": state}
    if note:
        event["note"] = note
    if failure_class:
        event["failure_class"] = failure_class
    for key, value in (fields or {}).items():
        if key not in ("id", "state"):
            event[key] = value
    appended = [append_event(root, event)]

    if state == "failed":
        max_attempts = int(fleet_policy(root, env=env).get("max_attempts", 3))
        if not consume_attempt:
            appended.append(append_event(root, {"id": job_id, "state": "queued", "attempt": attempt, "note": "infra retry; attempt not consumed"}))
        elif attempt < max_attempts:
            appended.append(append_event(root, {"id": job_id, "state": "queued", "attempt": attempt + 1}))
        else:
            appended.append(append_event(root, {"id": job_id, "state": "parked", "note": f"max attempts ({max_attempts}) exhausted"}))
    return {"ok": True, "mode": "jobs-update", "previous_state": current, "events_appended": appended}


def jobs_report(
    *,
    workspace_root: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = resolve_workspace_root(workspace_root, env=env)
    folded = fold_events(load_events(root))
    by_type_state: dict[str, dict[str, int]] = {}
    cost_total = 0.0
    done, parked, running = [], [], []
    for job_id, entry in sorted(folded.items()):
        job_type = str(entry.get("type"))
        state = str(entry.get("state"))
        by_type_state.setdefault(job_type, {})[state] = by_type_state.setdefault(job_type, {}).get(state, 0) + 1
        worker = entry.get("worker") or {}
        if isinstance(worker, dict) and isinstance(worker.get("cost_usd"), (int, float)):
            cost_total += float(worker["cost_usd"])
        summary = {
            "id": job_id,
            "attempt": entry.get("attempt"),
            "note": entry.get("note"),
            "predicate_ok": (entry.get("predicate") or {}).get("ok") if isinstance(entry.get("predicate"), dict) else None,
        }
        if state == "done":
            done.append(summary)
        elif state == "parked":
            parked.append(summary)
        elif state == "running":
            running.append(summary)
    spend = _read_json(root / SPEND_RELATIVE)
    return {
        "ok": True,
        "mode": "jobs-report",
        "ledger": str(root / JOBS_RELATIVE),
        "by_type_state": by_type_state,
        "worker_cost_usd_total": round(cost_total, 4),
        "spend_ledger": spend,
        "running": running,
        "done": done,
        "parked": parked,
    }

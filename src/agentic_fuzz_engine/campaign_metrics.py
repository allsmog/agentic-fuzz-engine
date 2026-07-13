"""Campaign brain signals: plateau detection and the candidate lifecycle ledger.

Both are deterministic reads/appends over workspace state:

- ``plateau_status`` folds ``work/<target>/rounds.jsonl`` (written by
  ``campaign-round-run``) into a per-target verdict — growing / plateaued /
  insufficient-data — plus the next untried escalation rung from the policy
  ladder. It computes signals only; escalation itself is an operator/session
  decision.

- The candidate ledger (``data/candidates.jsonl``) is an append-only event
  log; a candidate's current state is its last event. Automatic transitions
  come from the round loop (fuzzing / plateaued / confirmed); sync folds in
  ``target-select`` + ``generate.json`` state; escalated:<rung> and dead are
  manual, because reallocating budget is a judgment call.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

from .workspace import load_policy, resolve_workspace_root

LEDGER_RELATIVE = Path("data/candidates.jsonl")
MAX_ROUNDS_READ = 500
MAX_LEDGER_EVENTS = 100_000
BASE_STATUSES = {
    "unharnessed",
    "scaffolded",
    "awaiting-authoring",
    "validated",
    "fuzzing",
    "plateaued",
    "confirmed",
    "dead",
}


# ---------------------------------------------------------------------------
# plateau


def plateau_status(
    *,
    workspace_root: str | Path | None = None,
    target: str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = resolve_workspace_root(workspace_root, env=env)
    policy = load_policy(root, env=env)
    metric = str(policy["plateau"].get("metric", "features"))
    flat_rounds = max(1, int(policy["plateau"].get("flat_rounds", 3)))
    ladder = [str(item) for item in policy.get("ladder", [])]
    ledger = _ledger_current_state(root)

    work_dir = root / "work"
    names = [target.removeprefix("localfuzz/c/")] if target else sorted(
        entry.name for entry in work_dir.iterdir() if entry.is_dir() and (entry / "rounds.jsonl").is_file()
    ) if work_dir.is_dir() else []

    targets = []
    for name in names:
        rounds = _read_rounds(work_dir / name / "rounds.jsonl")
        targets.append(_assess_target(name, rounds, metric=metric, flat_rounds=flat_rounds, ladder=ladder, ledger=ledger))
    return {
        "ok": True,
        "mode": "plateau-status",
        "metric": metric,
        "flat_rounds_threshold": flat_rounds,
        "targets": targets,
        "plateaued": [item["target"] for item in targets if item["verdict"].startswith("plateaued")],
    }


def _assess_target(
    name: str,
    rounds: list[dict[str, Any]],
    *,
    metric: str,
    flat_rounds: int,
    ladder: list[str],
    ledger: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    series = []
    findings_total = 0
    metric_used = metric
    for record in rounds:
        stats = (record.get("fuzz") or {}).get("stats") or {}
        value = stats.get(metric)
        if value is None:
            value = record.get("corpus_size")
            metric_used = "corpus_size"
        series.append(value if isinstance(value, (int, float)) else None)
        findings_total += int((record.get("intake") or {}).get("findings_recorded", 0))

    clean = [value for value in series if value is not None]
    flat = 0
    if clean:
        running_max = clean[0]
        for value in clean[1:]:
            if value > running_max:
                running_max = value
                flat = 0
            else:
                flat += 1
    if len(clean) < flat_rounds + 1:
        verdict = "insufficient-data"
    elif flat >= flat_rounds:
        verdict = f"plateaued({flat} rounds flat)"
    else:
        verdict = "growing"

    tried = _tried_rungs(ledger.get(name, {}))
    next_rung = next((rung for rung in ladder if rung not in tried), None)
    return {
        "target": name,
        "rounds_observed": len(rounds),
        "metric_used": metric_used,
        "series_tail": clean[-(flat_rounds + 2):],
        "flat_rounds": flat,
        "findings_total": findings_total,
        "verdict": verdict,
        "rungs_tried": sorted(tried),
        "next_rung": next_rung if verdict.startswith("plateaued") else None,
        "ledger_status": ledger.get(name, {}).get("status"),
    }


def _read_rounds(path: Path) -> list[dict[str, Any]]:
    rounds = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rounds.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return rounds[-MAX_ROUNDS_READ:]


def _tried_rungs(state: dict[str, Any]) -> set[str]:
    return {
        event.removeprefix("escalated:")
        for event in state.get("history", [])
        if isinstance(event, str) and event.startswith("escalated:")
    }


# ---------------------------------------------------------------------------
# candidate ledger


def ledger_append(
    root: Path,
    *,
    name: str,
    status: str,
    tag: str | None = None,
    note: str | None = None,
    round_index: int | None = None,
) -> dict[str, Any]:
    if status not in BASE_STATUSES and not re.fullmatch(r"escalated:[a-z0-9_-]+", status):
        raise ValueError(f"invalid status {status!r} (allowed: {sorted(BASE_STATUSES)} or escalated:<rung>)")
    path = root / LEDGER_RELATIVE
    path.parent.mkdir(parents=True, exist_ok=True)
    event = {"name": name, "status": status}
    if tag:
        event["tag"] = tag
    if note:
        event["note"] = note
    if round_index is not None:
        event["round"] = int(round_index)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    return event


def _ledger_current_state(root: Path) -> dict[str, dict[str, Any]]:
    path = root / LEDGER_RELATIVE
    state: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return state
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
            name = str(event.get("name") or "")
            if not name:
                continue
            entry = state.setdefault(name, {"history": []})
            entry.update({key: value for key, value in event.items() if key != "name"})
            entry["history"].append(str(event.get("status")))
    return state


def candidates_list(*, workspace_root: str | Path | None = None, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    root = resolve_workspace_root(workspace_root, env=env)
    state = _ledger_current_state(root)
    counts: dict[str, int] = {}
    for entry in state.values():
        counts[str(entry.get("status"))] = counts.get(str(entry.get("status")), 0) + 1
    return {
        "ok": True,
        "mode": "candidates-list",
        "ledger": str(root / LEDGER_RELATIVE),
        "counts": counts,
        "candidates": [
            {"name": name, **{key: value for key, value in entry.items() if key != "history"}, "events": len(entry["history"])}
            for name, entry in sorted(state.items())
        ],
    }


def candidates_update(
    *,
    name: str,
    status: str,
    note: str | None = None,
    workspace_root: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = resolve_workspace_root(workspace_root, env=env)
    event = ledger_append(root, name=name, status=status, note=note)
    return {"ok": True, "mode": "candidates-update", "event": event}


def candidates_sync(
    *,
    sinks_jsonl: str | Path,
    workspace_root: str | Path | None = None,
    top: int = 50,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Fold target-select output + generate.json states into the ledger.

    Appends an event only when a candidate's derived status differs from its
    current ledger state, so repeated syncs are idempotent.
    """
    from .scaffold import TARGETS_RELATIVE, select_targets

    root = resolve_workspace_root(workspace_root, env=env)
    state = _ledger_current_state(root)
    appended = []

    selection = select_targets(sinks_jsonl=sinks_jsonl, workspace_root=root, top=top, env=env)
    for vector in selection["vectors"]:
        name = vector["suggested_name"]
        derived = "unharnessed"
        if vector["harnessed"]:
            manifest_path = root / TARGETS_RELATIVE / name / ".localfuzz" / "generate.json"
            if manifest_path.is_file():
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    manifest = {}
                if manifest.get("validated"):
                    derived = "validated"
                elif manifest.get("status") == "awaiting-authoring":
                    derived = "awaiting-authoring"
                else:
                    derived = "scaffolded"
            else:
                derived = "scaffolded"
        current = state.get(name, {}).get("status")
        # never regress a lifecycle state the rounds have advanced past
        if current in {"fuzzing", "plateaued", "confirmed", "dead"} or (
            current and str(current).startswith("escalated:")
        ):
            continue
        if current != derived:
            appended.append(ledger_append(root, name=name, status=derived, tag=vector["tag"]))

    return {
        "ok": True,
        "mode": "candidates-sync",
        "rows_scanned": selection["rows_scanned"],
        "vectors_considered": len(selection["vectors"]),
        "events_appended": appended,
    }

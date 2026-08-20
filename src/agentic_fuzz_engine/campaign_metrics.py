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
import os
import re
from pathlib import Path
from typing import Any, Mapping

from .managed_persistence import (
    MAX_RECORD_BYTES,
    MAX_TEXT_BYTES,
    append_jsonl,
    iter_jsonl,
    managed_path,
    validate_entry_class,
    validate_target_slug,
)
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
    rotate_after = max(1, int(policy["plateau"].get("rotate_after_known_only_rounds", 5)))
    ladder = [str(item) for item in policy.get("ladder", [])]
    ledger = _ledger_current_state(root)

    work_dir = managed_path(root, "work")
    if target:
        names = [validate_target_slug(target)]
    elif work_dir.is_dir():
        names = []
        with os.scandir(work_dir) as entries:
            for index, entry in enumerate(entries, 1):
                if index > 2000:
                    raise ValueError("campaign target scan exceeds cap")
                if entry.is_symlink():
                    raise ValueError(f"campaign target directory is a symbolic link: {entry.path}")
                if not entry.is_dir(follow_symlinks=False):
                    continue
                try:
                    name = validate_target_slug(entry.name)
                except ValueError:
                    continue
                rounds_path = Path(entry.path) / "rounds.jsonl"
                if rounds_path.is_file():
                    names.append(name)
        names.sort()
    else:
        names = []

    targets = []
    for name in names:
        rounds = _read_rounds(work_dir / name / "rounds.jsonl")
        targets.append(
            _assess_target(
                name, rounds, metric=metric, flat_rounds=flat_rounds, ladder=ladder, ledger=ledger,
                rotate_after=rotate_after, root=root,
            )
        )
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
    rotate_after: int = 5,
    root: Path | None = None,
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

    known_only = _known_only_streak(rounds)
    tried = _tried_rungs(ledger.get(name, {}))
    next_rung = next((rung for rung in ladder if rung not in tried), None)
    recommendation = None
    if verdict.startswith("plateaued") and known_only >= rotate_after:
        # The target keeps producing crashes, but every one maps to a known
        # root signature: escalation rungs deepen the same holes, so the
        # budget should move to another candidate.
        recommendation = "rotate-target"
        next_rung = "rotate-target"

    directed_surface: dict[str, Any] | None = None
    if root is not None and verdict.startswith("plateaued") and "frontier" in tried:
        # Broad fuzzing exhausted and the frontier already ran: if the
        # directed queue holds a task for this target, aiming beats mutating.
        try:
            from .directed import active_or_queued

            task = active_or_queued(root, name)
        except Exception:
            task = None
        if task:
            directed_surface = {
                "active_task": {
                    "id": task.get("id"),
                    "sink": task.get("sink"),
                    "method": task.get("method"),
                    "state": task.get("state"),
                    "priority": task.get("priority"),
                },
                "recommendation": (
                    f"directed: focus sink {task.get('method')} via allowlist build "
                    "(rung directed-allowlist)"
                ),
            }
    stale = None
    if root is not None:
        from .staleness import check_target_staleness

        stale_check = check_target_staleness(root, name)
        stale = stale_check.get("stale")
    return {
        **({"directed": directed_surface} if directed_surface is not None else {}),
        "target": name,
        "rounds_observed": len(rounds),
        "metric_used": metric_used,
        "series_tail": clean[-(flat_rounds + 2):],
        "flat_rounds": flat,
        "findings_total": findings_total,
        "known_only_rounds": known_only,
        "verdict": verdict,
        "recommendation": recommendation,
        "rungs_tried": sorted(tried),
        "next_rung": next_rung if verdict.startswith("plateaued") else None,
        "ledger_status": ledger.get(name, {}).get("status"),
        "stale": stale,
    }


def _known_only_streak(rounds: list[dict[str, Any]]) -> int:
    """Trailing consecutive rounds whose crash activity was all known root
    signatures. Rounds written before the counter existed (missing key) end
    the streak — unknown is not evidence of staleness."""
    streak = 0
    for record in reversed(rounds):
        new_roots = record.get("new_root_signatures")
        if new_roots is None:
            break
        intake = record.get("intake") or {}
        activity = int(intake.get("findings_recorded", 0)) + int(intake.get("known_suppressed", 0))
        if int(new_roots) == 0 and activity > 0:
            streak += 1
        elif int(new_roots) > 0:
            break
        else:
            # Quiet round: no crash activity either way — neutral, streak
            # neither grows nor resets.
            continue
    return streak


def _read_rounds(path: Path) -> list[dict[str, Any]]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            size = os.fstat(descriptor).st_size
            if size > MAX_TEXT_BYTES:
                raise ValueError(f"round metrics exceed {MAX_TEXT_BYTES} bytes: {path}")
            payload = bytearray()
            while len(payload) < size:
                chunk = os.read(descriptor, min(64 * 1024, size - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
        finally:
            os.close(descriptor)
    except OSError:
        return []
    rounds = []
    for raw in bytes(payload).splitlines()[-MAX_ROUNDS_READ:]:
        if not raw.strip() or len(raw) > MAX_RECORD_BYTES:
            continue
        try:
            row = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, OverflowError):
            continue
        if isinstance(row, dict):
            rounds.append(row)
    return rounds


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
    entry_class: str | None = None,
) -> dict[str, Any]:
    name = validate_target_slug(name)
    if status not in BASE_STATUSES and not re.fullmatch(r"escalated:[a-z0-9_-]+", status):
        raise ValueError(f"invalid status {status!r} (allowed: {sorted(BASE_STATUSES)} or escalated:<rung>)")
    event = {"name": name, "status": status}
    if tag:
        event["tag"] = tag
    if note:
        event["note"] = note
    if entry_class is not None:
        event["entry_class"] = validate_entry_class(entry_class)
    if round_index is not None:
        event["round"] = int(round_index)
    append_jsonl(root, LEDGER_RELATIVE, event)
    return event


def ledger_transition(
    root: Path,
    *,
    name: str,
    status: str,
    note: str | None = None,
    round_index: int | None = None,
    skip_if_in: set[str] | None = None,
) -> dict[str, Any] | None:
    """Append a status event only when it changes the candidate's state.

    ``skip_if_in`` guards automatic transitions from clobbering states the
    operator owns (e.g. never drop escalated:<rung>/dead back to fuzzing).
    """
    current = _ledger_current_state(root).get(name, {}).get("status")
    if current == status:
        return None
    if skip_if_in and (current in skip_if_in or (current or "").startswith("escalated:")):
        return None
    return ledger_append(root, name=name, status=status, note=note, round_index=round_index)


def _ledger_current_state(root: Path) -> dict[str, dict[str, Any]]:
    state: dict[str, dict[str, Any]] = {}
    path = managed_path(root, LEDGER_RELATIVE)
    if not path.exists():
        return state
    for _, event in iter_jsonl(root, LEDGER_RELATIVE, max_rows=MAX_LEDGER_EVENTS):
        if event is None:
            continue
        try:
            name = validate_target_slug(str(event.get("name") or ""))
        except ValueError:
            continue
        if "entry_class" in event:
            try:
                validate_entry_class(event["entry_class"])
            except ValueError:
                continue
        entry = state.setdefault(name, {"history": []})
        entry.update({key: value for key, value in event.items() if key != "name"})
        entry["history"].append(str(event.get("status")))
    return state


def candidates_list(
    *,
    workspace_root: str | Path | None = None,
    entry_class: str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = resolve_workspace_root(workspace_root, env=env)
    state = _ledger_current_state(root)
    if entry_class is not None:
        entry_class = validate_entry_class(entry_class)
        state = {name: entry for name, entry in state.items() if entry.get("entry_class") == entry_class}
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
    entry_class: str | None = None,
    workspace_root: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = resolve_workspace_root(workspace_root, env=env)
    event = ledger_append(root, name=name, status=status, note=note, entry_class=entry_class)
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
            entry_classes = vector.get("entry_classes") or {}
            dominant = max(entry_classes, key=entry_classes.get) if entry_classes else None
            appended.append(
                ledger_append(root, name=name, status=derived, tag=vector["tag"], entry_class=dominant)
            )

    return {
        "ok": True,
        "mode": "candidates-sync",
        "rows_scanned": selection["rows_scanned"],
        "vectors_considered": len(selection["vectors"]),
        "events_appended": appended,
    }

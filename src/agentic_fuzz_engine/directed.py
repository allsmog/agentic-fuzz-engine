"""Directed-fuzzing task scheduler: queue, budgets, rotation, recommendation.

When a target plateaus with dangerous sinks still uncovered, the campaign
should *aim* at one sink instead of fuzzing broadly. The engine automates the
scheduling half of that (this module): a workspace-level task queue at
``data/directed-queue.json`` where each task is one uncovered write/exec sink,
with priority ordering, agent preemption, a per-task round budget that rotates
exhausted tasks to the tail with decayed priority, retirement when the sink is
finally reached, and drops when the sink vanishes from the inventory.

The aiming half stays recipe-level on purpose: the operator/agent authors a
``fuzzer-directed`` build step with ``AFL_LLVM_ALLOWLIST`` pointing at the
task's allowlist file and runs it through the ordinary ensemble/intake path.
The queue is mutable planning state, not a findings ledger.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Mapping

QUEUE_RELATIVE = Path("data/directed-queue.json")
DEFAULT_BUDGET_ROUNDS = 6
DEFAULT_MAX_TASKS_PER_TARGET = 4
DEFAULT_MAX_TASKS_TOTAL = 24
DEFAULT_PRIORITY_DECAY = 10
DEFAULT_PRIMITIVES = ("write", "exec")
PRIORITY_AGENT = 100
PRIORITY_FRONTIER = 50
PRIORITY_PRIMITIVE_BONUS = 10
PRIORITY_FLOOR = 10
OPEN_STATES = ("queued", "active")


def load_queue(root: Path) -> dict[str, Any]:
    path = root / QUEUE_RELATIVE
    if not path.is_file():
        return {"version": 1, "tasks": []}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "tasks": []}
    if not isinstance(payload.get("tasks"), list):
        payload["tasks"] = []
    return payload


def save_queue(root: Path, queue: dict[str, Any]) -> None:
    path = root / QUEUE_RELATIVE
    path.parent.mkdir(parents=True, exist_ok=True)
    queue["updated_ts"] = time.time()
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(queue, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def task_id(target: str, sink: str) -> str:
    return f"{target}:{sink}"


def _policy_int(policy: Mapping[str, Any], key: str, default: int) -> int:
    try:
        return int(policy.get(key, default))
    except (TypeError, ValueError):
        return default


def sync_queue(
    *,
    root: Path,
    name: str,
    round_index: int | None = None,
    policy: Mapping[str, Any] | None = None,
    sinks_jsonl: str | Path | None = None,
) -> dict[str, Any]:
    """Reconcile the queue for one target against the sink inventory and the
    sinkpoint lifecycle: enqueue top uncovered write/exec sinks, retire tasks
    whose sink turned reached/exploited, drop tasks whose sink vanished.
    Idempotent — repeated syncs without state changes append nothing."""
    from .seed_weights import resolve_sinks_jsonl
    from .sink_coverage import _load_sink_rows
    from .sink_scan import PRIMITIVE_WEIGHT
    from .sink_status import load_sink_status, sink_key
    from .workspace import load_policy

    directed_policy = dict(policy or {})
    if not directed_policy:
        full = load_policy(root)
        directed_policy = full.get("directed", {}) if isinstance(full.get("directed"), dict) else {}
    primitives = tuple(str(p) for p in (directed_policy.get("primitives") or DEFAULT_PRIMITIVES))
    max_per_target = _policy_int(directed_policy, "max_tasks_per_target", DEFAULT_MAX_TASKS_PER_TARGET)
    max_total = _policy_int(directed_policy, "max_tasks_total", DEFAULT_MAX_TASKS_TOTAL)
    budget_rounds = _policy_int(directed_policy, "budget_rounds", DEFAULT_BUDGET_ROUNDS)

    sinks_path = Path(sinks_jsonl) if sinks_jsonl else resolve_sinks_jsonl(root, name, load_policy(root))
    if not Path(sinks_path).is_file():
        return {"ok": False, "changes": [], "blockers": [f"sinks jsonl not found: {sinks_path}"]}
    rows = _load_sink_rows(Path(sinks_path))
    row_by_key = {sink_key(row): row for row in rows}
    status = load_sink_status(root / "work" / name).get("sinks", {})
    dead_tags = _dead_candidate_tags(root)

    queue = load_queue(root)
    tasks = queue["tasks"]
    tracked = {t["id"] for t in tasks if t.get("target") == name and t.get("state") in OPEN_STATES}
    changes: list[dict[str, Any]] = []

    # Retire / drop existing open tasks for this target.
    for task in tasks:
        if task.get("target") != name or task.get("state") not in OPEN_STATES:
            continue
        sink = str(task.get("sink") or "")
        entry = status.get(sink) or {}
        row = row_by_key.get(sink) or {}
        if str(entry.get("status")) in ("reached", "exploited"):
            task["state"] = "done"
            task["note"] = f"sink {entry.get('status')} at round {round_index}"
            changes.append({"id": task["id"], "transition": "done"})
        elif sink not in row_by_key:
            task["state"] = "dropped"
            task["note"] = "sink no longer in inventory"
            changes.append({"id": task["id"], "transition": "dropped"})
        elif _slug(str(row.get("tag") or "")) in dead_tags:
            # The candidates ledger ruled this surface dead (e.g. a false
            # positive) — a disproven sink must not rotate in the queue.
            task["state"] = "dropped"
            task["note"] = "candidate ruled dead in ledger"
            changes.append({"id": task["id"], "transition": "dropped"})

    # Enqueue uncovered dangerous sinks, most dangerous primitive first.
    open_for_target = sum(1 for t in tasks if t.get("target") == name and t.get("state") in OPEN_STATES)
    open_total = sum(1 for t in tasks if t.get("state") in OPEN_STATES)
    candidates = sorted(
        (
            (key, row)
            for key, row in row_by_key.items()
            if str(row.get("primitive") or "") in primitives
            and str((status.get(key) or {}).get("status") or "unreached") == "unreached"
            and _slug(str(row.get("tag") or "")) not in dead_tags
            and task_id(name, key) not in {t["id"] for t in tasks if t.get("state") in OPEN_STATES}
        ),
        key=lambda item: (-PRIMITIVE_WEIGHT.get(str(item[1].get("primitive") or ""), 1), item[0]),
    )
    for key, row in candidates:
        if open_for_target >= max_per_target or open_total >= max_total:
            break
        priority = PRIORITY_FRONTIER
        if str(row.get("primitive") or "") in ("write", "exec"):
            priority += PRIORITY_PRIMITIVE_BONUS
        tasks.append(
            {
                "id": task_id(name, key),
                "target": name,
                "sink": key,
                "method": row.get("method"),
                "primitive": row.get("primitive"),
                "priority": priority,
                "source": "frontier",
                "state": "queued",
                "budget_rounds": budget_rounds,
                "rounds_used": 0,
                "added_round": round_index,
                "last_round": None,
                "note": None,
            }
        )
        tracked.add(task_id(name, key))
        open_for_target += 1
        open_total += 1
        changes.append({"id": task_id(name, key), "transition": "queued"})

    if changes:
        save_queue(root, queue)
    return {"ok": True, "changes": changes, "open_for_target": open_for_target, "blockers": []}


def tick_budget(
    *,
    root: Path,
    name: str,
    round_index: int,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """One round of scheduler time for a target: the active task burns budget
    (rotating to the queue tail with decayed priority when exhausted), then
    the highest-priority queued task is promoted if nothing is active."""
    directed_policy = dict(policy or {})
    decay = _policy_int(directed_policy, "priority_decay", DEFAULT_PRIORITY_DECAY)

    queue = load_queue(root)
    tasks = queue["tasks"]
    changes: list[dict[str, Any]] = []

    active = [t for t in tasks if t.get("target") == name and t.get("state") == "active"]
    burned = bool(active)
    for task in active:
        task["rounds_used"] = int(task.get("rounds_used") or 0) + 1
        task["last_round"] = round_index
        if task["rounds_used"] >= int(task.get("budget_rounds") or DEFAULT_BUDGET_ROUNDS):
            # Budget exhausted: back to the tail, cheaper — the 1 h analog.
            task["state"] = "queued"
            task["priority"] = max(PRIORITY_FLOOR, int(task.get("priority") or 0) - decay)
            task["rounds_used"] = 0
            task["added_round"] = round_index
            changes.append({"id": task["id"], "transition": "requeued", "priority": task["priority"]})

    if not any(t.get("target") == name and t.get("state") == "active" for t in tasks):
        queued = [t for t in tasks if t.get("target") == name and t.get("state") == "queued"]
        queued.sort(key=lambda t: (-int(t.get("priority") or 0), t.get("added_round") or 0, t["id"]))
        if queued:
            queued[0]["state"] = "active"
            queued[0]["last_round"] = round_index
            changes.append({"id": queued[0]["id"], "transition": "activated"})

    if changes or burned:
        save_queue(root, queue)
    return {"ok": True, "changes": changes, "blockers": []}


def flag_task(
    *,
    root: Path,
    target: str,
    sink: str,
    priority: int = PRIORITY_AGENT,
    note: str | None = None,
) -> dict[str, Any]:
    """Agent preemption: flag a sink as the priority focus. Creates the task
    (source=agent) or raises an existing open task's priority."""
    queue = load_queue(root)
    tasks = queue["tasks"]
    identifier = task_id(target, sink)
    for task in tasks:
        if task["id"] == identifier and task.get("state") in OPEN_STATES:
            task["priority"] = max(int(task.get("priority") or 0), int(priority))
            task["source"] = "agent"
            if note:
                task["note"] = note
            save_queue(root, queue)
            return {"ok": True, "task": task, "created": False}
    method = sink.rsplit(":", 1)[-1] if ":" in sink else sink
    task = {
        "id": identifier,
        "target": target,
        "sink": sink,
        "method": method,
        "primitive": None,
        "priority": int(priority),
        "source": "agent",
        "state": "queued",
        "budget_rounds": DEFAULT_BUDGET_ROUNDS,
        "rounds_used": 0,
        "added_round": None,
        "last_round": None,
        "note": note,
    }
    tasks.append(task)
    save_queue(root, queue)
    return {"ok": True, "task": task, "created": True}


def complete_task(
    *,
    root: Path,
    target: str,
    sink: str,
    state: str = "done",
    note: str | None = None,
) -> dict[str, Any]:
    """Operator/agent closure: mark a task done (goal met) or dropped
    (e.g. the directed build failed and won't be retried)."""
    if state not in ("done", "dropped"):
        return {"ok": False, "blockers": [f"state must be done or dropped, got {state!r}"]}
    queue = load_queue(root)
    identifier = task_id(target, sink)
    for task in queue["tasks"]:
        if task["id"] == identifier and task.get("state") in OPEN_STATES:
            task["state"] = state
            if note:
                task["note"] = note
            save_queue(root, queue)
            return {"ok": True, "task": task}
    return {"ok": False, "blockers": [f"no open task {identifier}"]}


def queue_summary(*, root: Path, target: str | None = None) -> dict[str, Any]:
    queue = load_queue(root)
    tasks = [
        task for task in queue["tasks"]
        if target is None or task.get("target") == target
    ]
    counts: dict[str, int] = {}
    for task in tasks:
        counts[str(task.get("state"))] = counts.get(str(task.get("state")), 0) + 1
    open_tasks = sorted(
        (task for task in tasks if task.get("state") in OPEN_STATES),
        key=lambda t: (0 if t.get("state") == "active" else 1, -int(t.get("priority") or 0), t["id"]),
    )
    return {
        "ok": True,
        "mode": "directed-queue",
        "path": str(root / QUEUE_RELATIVE),
        "counts": counts,
        "tasks": open_tasks,
        "closed": len(tasks) - len(open_tasks),
    }


def active_or_queued(root: Path, target: str) -> dict[str, Any] | None:
    """The task a plateaued target should aim at: active first, else the
    highest-priority queued one."""
    summary = queue_summary(root=root, target=target)
    tasks = summary["tasks"]
    return tasks[0] if tasks else None


def _slug(value: str) -> str:
    return "".join(char if char.isalnum() or char in "_-" else "_" for char in value.lower())


def _dead_candidate_tags(root: Path) -> set[str]:
    from .campaign_metrics import _ledger_current_state

    try:
        state = _ledger_current_state(root)
    except Exception:
        return set()
    return {
        _slug(name)
        for name, entry in state.items()
        if str(entry.get("status")) == "dead"
    }


def directed_build(
    *,
    root: Path,
    name: str,
    sink: str | None = None,
    also_files: list[str] | None = None,
    timeout_seconds: int | float = 900,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build the aiming half of a directed task: rebuild the target's fuzzer
    with clang's ``-fsanitize-coverage-allowlist`` restricted to the sink's
    file, so coverage feedback concentrates there — stock libFuzzer, no
    AFL++ toolchain. The binary lands at ``bin/<t>/fuzzer-directed-<hash>``
    and is recorded on the queue task for the round loop to execute.

    Contract with the build recipe: the modified step is the one whose argv
    carries both a ``-fsanitize`` token and the ``{bin_dir}/fuzzer`` output
    token. Recipes that compile inside a container must mount the target
    dir (the allowlist lives under it) or the compile will fail with a
    clear missing-file error.
    """
    import hashlib
    import json as json_module

    from .container_build import build_target

    task = None
    if sink is None:
        task = active_or_queued(root, name)
        if task is None:
            return {"ok": False, "blockers": [f"no open directed task for {name} (run directed-queue sync)"]}
        sink = str(task.get("sink") or "")
    else:
        queue = load_queue(root)
        for candidate in queue["tasks"]:
            if candidate.get("target") == name and candidate.get("sink") == sink and candidate.get("state") in OPEN_STATES:
                task = candidate
                break
    if not sink:
        return {"ok": False, "blockers": ["directed task has no sink"]}

    sink_file = sink.split(":", 1)[0]
    digest = hashlib.sha256(sink.encode("utf-8")).hexdigest()[:8]
    target_dir = root / "targets" / "c" / name
    build_config_path = target_dir / ".localfuzz" / "build.json"
    if not build_config_path.is_file():
        return {"ok": False, "blockers": [f"build config not found: {build_config_path}"]}
    config = json_module.loads(build_config_path.read_text(encoding="utf-8"))

    allowlist_dir = target_dir / ".localfuzz" / f"directed-{digest}"
    allowlist_dir.mkdir(parents=True, exist_ok=True)
    allowlist = allowlist_dir / "allowlist.txt"
    lines = [f"src:*{sink_file}", "fun:*"]
    for extra in also_files or []:
        lines.insert(-1, f"src:*{extra}")
    allowlist.write_text("\n".join(lines) + "\n", encoding="utf-8")

    binary_token = "{bin_dir}/fuzzer-directed-" + digest
    matched = False
    for step in config.get("steps", []) or []:
        argv = [str(item) for item in step.get("argv", [])]
        has_sanitize = any("-fsanitize" in token for token in argv)
        has_output = any("{bin_dir}/fuzzer" in token for token in argv)
        if not (has_sanitize and has_output):
            continue
        matched = True
        step["argv"] = [
            token.replace("{bin_dir}/fuzzer", binary_token) for token in argv
        ] + [f"-fsanitize-coverage-allowlist={allowlist}"]
    if not matched:
        return {
            "ok": False,
            "blockers": [
                "no build step carries both a -fsanitize token and the {bin_dir}/fuzzer "
                "output token — add a fuzzer compile step to build.json"
            ],
        }

    built = build_target(
        project=f"localfuzz/c/{name}",
        workspace_root=root,
        timeout_seconds=timeout_seconds,
        env=env,
        config_override=config,
    )
    binary = root / "bin" / name / f"fuzzer-directed-{digest}"
    ok = bool(built.get("ok")) and binary.is_file() and os.access(binary, os.X_OK)
    result = {
        "ok": ok,
        "mode": "directed-build",
        "target": name,
        "sink": sink,
        "allowlist": str(allowlist),
        "binary": str(binary),
        "build": {"ok": built.get("ok"), "blockers": built.get("blockers", [])},
        "blockers": [] if ok else (built.get("blockers") or [f"directed binary missing: {binary}"]),
    }
    if ok and task is not None:
        queue = load_queue(root)
        for candidate in queue["tasks"]:
            if candidate.get("id") == task.get("id") and candidate.get("state") in OPEN_STATES:
                candidate["binary"] = str(binary)
                candidate["allowlist"] = str(allowlist)
                save_queue(root, queue)
                break
    return result

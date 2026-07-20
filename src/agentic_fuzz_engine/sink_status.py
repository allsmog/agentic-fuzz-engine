"""Sinkpoint lifecycle: unreached -> reached -> exploited (the frontier loop).

``sink-coverage`` answers *which* dangerous sinks the corpus never executed;
this module turns that report into durable per-sink state
(``work/<target>/sink-status.json``) the input-generator agent and the
plateau ladder can act on:

- ``unreached``: no corpus entry executes the sink's enclosing function —
  a work order for aimed seed construction.
- ``reached``: covered but never crashed — exploration succeeded, so the
  remaining work is crafting the crashing value; the nearest-reaching
  corpus entries are recorded as ``close_seeds`` byte templates.
- ``exploited``: a recorded finding's crash state contains the sink's
  function — stop spending on it.

Transitions never demote (coverage sampling is noisy under symbolization
flags); everything is bounded and failure here must never fail a round.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

MAX_TRACKED_SINKS = 2_000
MAX_CLOSE_SEEDS_PER_SINK = 3
DEFAULT_CLOSE_SEED_MAX_INPUTS = 16
DEFAULT_CLOSE_SEED_MAX_SECONDS = 120.0
DEFAULT_CLOSE_SEED_PER_INPUT_TIMEOUT = 20.0
SINK_STATUS_FILE = "sink-status.json"

_ORDER = {"unreached": 0, "reached": 1, "exploited": 2}


def sink_key(row: Mapping[str, Any]) -> str:
    return f"{row.get('file')}:{row.get('line')}:{row.get('method')}"


def load_sink_status(work_dir: Path) -> dict[str, Any]:
    path = work_dir / SINK_STATUS_FILE
    if not path.is_file():
        return {"version": 1, "sinks": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "sinks": {}}
    if not isinstance(payload.get("sinks"), dict):
        payload["sinks"] = {}
    return payload


def update_sink_status(
    *,
    work_dir: Path,
    coverage_report: Mapping[str, Any],
    findings: list[dict[str, Any]] | None = None,
    round_index: int | None = None,
    close_seed_sampler: Any = None,
) -> dict[str, Any]:
    """Fold a sink-coverage report (+ recorded findings) into the status file.

    ``close_seed_sampler(methods) -> {method: [seed names]}`` is invoked only
    for sinks that transition to ``reached`` this update, so the bounded
    replay cost is paid once per sink, not once per round.
    """
    status = load_sink_status(work_dir)
    sinks: dict[str, dict[str, Any]] = status["sinks"]
    changes: list[dict[str, Any]] = []

    exploited_functions = _exploited_functions(findings or [])

    newly_reached_methods: dict[str, list[str]] = {}
    for row, observed in _iter_report_rows(coverage_report):
        key = sink_key(row)
        entry = sinks.get(key)
        if entry is None:
            if len(sinks) >= MAX_TRACKED_SINKS:
                continue
            entry = {
                "method": row.get("method"),
                "file": row.get("file"),
                "line": row.get("line"),
                "primitive": row.get("primitive"),
                "status": "unreached",
                "first_reached_round": None,
                "close_seeds": [],
                "exploited_by": None,
            }
            sinks[key] = entry

        desired = "unreached"
        if str(row.get("method")) in exploited_functions:
            desired = "exploited"
        elif observed:
            desired = "reached"
        current = str(entry.get("status") or "unreached")
        if _ORDER.get(desired, 0) > _ORDER.get(current, 0):
            entry["status"] = desired
            if desired == "reached":
                entry["first_reached_round"] = round_index
                newly_reached_methods.setdefault(str(row.get("method")), []).append(key)
            if desired == "exploited":
                entry["exploited_by"] = exploited_functions.get(str(row.get("method")))
            changes.append({"sink": key, "from": current, "to": desired, "round": round_index})

    if newly_reached_methods and close_seed_sampler is not None:
        try:
            seed_map = close_seed_sampler(sorted(newly_reached_methods)) or {}
        except Exception:
            seed_map = {}
        for method, keys in newly_reached_methods.items():
            seeds = list(seed_map.get(method) or [])[:MAX_CLOSE_SEEDS_PER_SINK]
            if not seeds:
                continue
            for key in keys:
                sinks[key]["close_seeds"] = seeds

    counts: dict[str, int] = {}
    for entry in sinks.values():
        counts[str(entry.get("status"))] = counts.get(str(entry.get("status")), 0) + 1

    status["sinks"] = sinks
    status["counts"] = counts
    if round_index is not None:
        status["last_round"] = round_index
    path = work_dir / SINK_STATUS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    return {"changes": changes, "counts": counts, "report": str(path)}


def frontier_summary(coverage_report: Mapping[str, Any], *, top: int = 5) -> list[dict[str, Any]]:
    """Top uncovered sinks (already write/exec-ranked by sink-coverage)."""
    uncovered = coverage_report.get("uncovered") or []
    return [
        {
            "sink": sink_key(row),
            "method": row.get("method"),
            "primitive": row.get("primitive"),
            "tag": row.get("tag"),
        }
        for row in uncovered[: max(1, int(top))]
    ]


def sample_close_seeds(
    *,
    fuzzer: Path,
    corpus: Path,
    methods: list[str],
    env: Mapping[str, str] | None = None,
    max_inputs: int = DEFAULT_CLOSE_SEED_MAX_INPUTS,
    max_seconds: float = DEFAULT_CLOSE_SEED_MAX_SECONDS,
    per_input_timeout: float = DEFAULT_CLOSE_SEED_PER_INPUT_TIMEOUT,
) -> dict[str, list[str]]:
    """Which corpus entries execute each method? Bounded per-file
    ``-runs=0 -print_coverage=1`` replays, newest first.

    This is the RoboDuck close-seed analog: a seed proven to *reach* the
    vulnerable function is the byte template the input-generator mutates
    toward the crashing value.
    """
    import time

    from .seed_weights import replay_entry_coverage

    if not methods or not corpus.is_dir():
        return {}
    wanted = {str(method) for method in methods}
    entries = sorted(
        (entry for entry in corpus.iterdir() if entry.is_file()),
        key=lambda entry: entry.stat().st_mtime,
        reverse=True,
    )[: max(1, int(max_inputs))]

    results: dict[str, list[str]] = {}
    deadline = time.monotonic() + max(1.0, float(max_seconds))
    for entry in entries:
        if time.monotonic() >= deadline:
            break
        if all(len(results.get(method, [])) >= MAX_CLOSE_SEEDS_PER_SINK for method in wanted):
            break
        covered = replay_entry_coverage(
            fuzzer=fuzzer, entry=entry, env=env, timeout=per_input_timeout
        )
        if covered is None:
            continue
        for method in wanted:
            if len(results.get(method, [])) >= MAX_CLOSE_SEEDS_PER_SINK:
                continue
            if method in covered:
                results.setdefault(method, []).append(entry.name)
    return results


def _iter_report_rows(coverage_report: Mapping[str, Any]):
    for row in coverage_report.get("covered") or []:
        yield row, True
    for row in coverage_report.get("uncovered") or []:
        yield row, False


def _exploited_functions(findings: list[dict[str, Any]]) -> dict[str, str]:
    """function name -> finding_id for every frame in recorded crash states."""
    exploited: dict[str, str] = {}
    for finding in findings:
        finding_id = str(finding.get("finding_id") or "")
        for frame in finding.get("crash_state") or []:
            exploited.setdefault(str(frame), finding_id)
    return exploited

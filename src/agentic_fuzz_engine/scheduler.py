"""Freshness-aware advisory ranking over measured campaign telemetry.

The scheduler writes recommendations only.  It neither launches work nor
changes job state.  Consumers must use :func:`schedule_ranks`, which returns
no ranks when policy disables scheduling or the artifact is stale.
"""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import asdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .campaign_db import connect, db_status, db_sync
from .managed_persistence import atomic_write_text, read_json, validate_target_slug
from .workspace import resolve_workspace_root

SCHEDULE_RELATIVE = Path("data/schedule.json")
AUTHORABLE_STATES = ("unharnessed", "scaffolded", "awaiting-authoring")
MAX_SCHEDULE_ROWS = 2000
SUPPORTED_LANES = frozenset({"fuzz", "vuln_hunt", "pov_produce", "harness_author", "directed"})
_SCHEDULE_KEYS = {
    "version", "advisory_only", "enabled", "generated_ts", "fresh_until_ts",
    "source_generation", "source_fingerprint", "policy_fingerprint", "lanes",
}
_ROW_KEYS = {
    "rank", "lane", "target", "score", "yield_per_hour", "observed_seconds",
    "observations", "allocation", "reason",
}


@dataclass(frozen=True)
class SchedulerConfig:
    enabled: bool = False
    half_life_hours: float = 24.0
    window_hours: float = 72.0
    exploration_floor: float = 0.2
    ucb_c: float = 0.5
    slots: int = 6
    max_age_seconds: float = 3600.0
    max_experiments: int = 4
    max_experiment_boost: float = 1.0


def _number(section: Mapping[str, Any], key: str, default: float, low: float, high: float) -> float:
    if key not in section:
        return default
    raw = section[key]
    if type(raw) not in (int, float):
        raise ValueError(f"scheduler.{key} must be numeric")
    value = float(raw)
    if not math.isfinite(value) or not low <= value <= high:
        raise ValueError(f"scheduler.{key} is outside its supported finite range")
    return value


def _integer(section: Mapping[str, Any], key: str, default: int, low: int, high: int) -> int:
    if key not in section:
        return default
    value = section[key]
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"scheduler.{key} must be an integer from {low} to {high}")
    return value


def _config(root: Path) -> SchedulerConfig:
    try:
        document = read_json(root, "campaign-policy.json", max_bytes=1024 * 1024)
    except (OSError, ValueError, json.JSONDecodeError, RecursionError, OverflowError) as exc:
        raise ValueError(f"malformed scheduler policy: {exc}") from exc
    if document is None:
        document = {}
    if not isinstance(document, dict):
        raise ValueError("campaign policy must be a JSON object")
    section = document.get("scheduler", {})
    if not isinstance(section, dict):
        raise ValueError("scheduler policy must be a JSON object")
    if "enabled" in section and type(section["enabled"]) is not bool:
        raise ValueError("scheduler.enabled must be a boolean")
    return SchedulerConfig(
        enabled=section.get("enabled", False) is True,
        half_life_hours=_number(section, "half_life_hours", 24.0, 1.0, 24 * 365.0),
        window_hours=_number(section, "window_hours", 72.0, 1.0, 24 * 365.0),
        exploration_floor=_number(section, "exploration_floor", 0.2, 0.0, 0.9),
        ucb_c=_number(section, "ucb_c", 0.5, 0.0, 100.0),
        slots=_integer(section, "slots", 6, 1, 256),
        max_age_seconds=_number(section, "max_age_seconds", 3600.0, 1.0, 7 * 86400.0),
        max_experiments=_integer(section, "max_experiments", 4, 0, 100),
        max_experiment_boost=_number(section, "max_experiment_boost", 1.0, 0.0, 100.0),
    )


def _config_fingerprint(config: SchedulerConfig) -> str:
    return sha256(json.dumps(asdict(config), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class _Lane:
    def __init__(self, lane: str, target: str) -> None:
        self.lane = lane
        self.target = target
        self.reward = 0.0
        self.seconds = 0.0
        self.observations = 0
        self.boost = 0.0
        self.reason: list[str] = []


def _decay(value: float, age_seconds: float, half_life_hours: float) -> float:
    return value * 0.5 ** (max(0.0, age_seconds) / (half_life_hours * 3600.0))


def _lanes(conn: Any, config: SchedulerConfig, now: float) -> dict[tuple[str, str], _Lane]:
    lanes: dict[tuple[str, str], _Lane] = {}

    def get(lane: str, target: str) -> _Lane | None:
        try:
            slug = validate_target_slug(target)
        except ValueError:
            return None
        key = (lane, slug)
        return lanes.setdefault(key, _Lane(*key))

    cutoff = now - config.window_hours * 3600.0
    for row in conn.execute(
        "SELECT target,started_ts,duration_seconds,new_root_signatures,findings_recorded"
        " FROM rounds WHERE started_ts IS NOT NULL AND started_ts>=? ORDER BY target,started_ts,round",
        (cutoff,),
    ):
        lane = get("fuzz", str(row["target"]))
        if lane is None:
            continue
        duration = float(row["duration_seconds"] or 0.0)
        if not math.isfinite(duration) or not 0 < duration <= config.window_hours * 3600.0:
            lane.reason.append("invalid or unmetered round excluded")
            continue
        roots = max(0.0, float(row["new_root_signatures"] or 0.0))
        findings = max(0.0, float(row["findings_recorded"] or 0.0))
        lane.reward += _decay(roots + findings, now - float(row["started_ts"]), config.half_life_hours)
        lane.seconds += duration
        lane.observations += 1

    for row in conn.execute(
        "SELECT type,target,state,predicate_ok,duration_seconds,ended_ts FROM jobs"
        " WHERE type IN ('vuln_hunt','pov_produce','harness_author') ORDER BY type,target,job_id"
    ):
        lane = get(str(row["type"]), str(row["target"] or ""))
        if lane is None:
            continue
        duration = float(row["duration_seconds"] or 0.0)
        if math.isfinite(duration) and 0 < duration <= config.window_hours * 3600.0:
            lane.seconds += duration
            lane.observations += 1
        if row["state"] == "done" and row["predicate_ok"] and row["ended_ts"]:
            lane.reward += _decay(1.0, now - float(row["ended_ts"]), config.half_life_hours)

    placeholders = ",".join("?" for _ in AUTHORABLE_STATES)
    for row in conn.execute(
        f"SELECT name FROM candidates WHERE status IN ({placeholders}) ORDER BY name",
        AUTHORABLE_STATES,
    ):
        lane = get("harness_author", str(row["name"]))
        if lane is None:
            continue
        lane.reward += 0.1
        lane.reason.append("authorable candidate prior")

    for row in conn.execute(
        "SELECT target,budget_rounds,build_seconds FROM directed_tasks"
        " WHERE state IN ('queued','active') ORDER BY target,id"
    ):
        lane = get("directed", str(row["target"] or ""))
        if lane is None:
            continue
        build = max(0.0, float(row["build_seconds"] or 0.0))
        budget = max(1.0, float(row["budget_rounds"] or 1.0))
        lane.seconds += build / budget
        lane.reason.append(f"measured build allocation {build:g}s/{budget:g} rounds")

    applied = 0
    for row in conn.execute("SELECT * FROM experiments ORDER BY id"):
        if applied >= config.max_experiments:
            break
        expires = row["expires"]
        if expires is not None and float(expires) < now:
            continue
        try:
            target = validate_target_slug(str(row["target"] or ""))
        except ValueError:
            continue
        key = (str(row["lane"] or ""), target)
        if key[0] not in SUPPORTED_LANES:
            continue
        lane = lanes.setdefault(key, _Lane(*key))
        boost = min(config.max_experiment_boost, max(0.0, float(row["boost"] or 0.0)))
        lane.boost += boost
        lane.reason.append(f"bounded experiment {row['id']} +{boost:g}")
        applied += 1
    return lanes


def _dark_explore_keys(conn: Any) -> list[tuple[str, str]]:
    candidate_by_tag: dict[str, tuple[str, str]] = {}
    for row in conn.execute("SELECT name,tag,status FROM candidates ORDER BY name"):
        tag = str(row["tag"] or "")
        if tag and tag not in candidate_by_tag:
            lane = "harness_author" if row["status"] in AUTHORABLE_STATES else "vuln_hunt"
            candidate_by_tag[tag] = (lane, str(row["name"]))
    keys: list[tuple[str, str]] = []
    for row in conn.execute(
        "SELECT DISTINCT s.tag FROM sinks s WHERE s.kind='sink'"
        " AND s.primitive IN ('write','exec')"
        " AND NOT EXISTS(SELECT 1 FROM hypothesis_sinks hs WHERE hs.sink_id=s.id)"
        " ORDER BY s.tag"
    ):
        key = candidate_by_tag.get(str(row["tag"] or ""))
        if key and key not in keys:
            keys.append(key)
    return keys


def _allocate(
    lanes: dict[tuple[str, str], _Lane],
    explore_keys: list[tuple[str, str]],
    config: SchedulerConfig,
) -> list[dict[str, Any]]:
    total_hours = sum(lane.seconds for lane in lanes.values()) / 3600.0
    scored: dict[tuple[str, str], tuple[_Lane, float, float]] = {}
    for key, lane in lanes.items():
        hours = lane.seconds / 3600.0
        rate = lane.reward / hours if hours > 0 else lane.reward
        ucb = config.ucb_c * math.sqrt(math.log(total_hours + math.e) / (hours + 1.0))
        scored[key] = (lane, rate, rate + ucb + lane.boost)
    floor = max(1, round(config.exploration_floor * config.slots)) if explore_keys else 0
    order = []
    order.extend((key, "explore") for key in explore_keys[:floor])
    order.extend(
        (key, "exploit")
        for key, _ in sorted(scored.items(), key=lambda item: (-item[1][2], item[0][0], item[0][1]))
    )
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for key, allocation in order:
        if key in seen or len(rows) >= MAX_SCHEDULE_ROWS:
            continue
        seen.add(key)
        lane, rate, score = scored.get(key, (_Lane(*key), 0.0, 0.0))
        rows.append(
            {
                "rank": len(rows) + 1,
                "lane": lane.lane,
                "target": lane.target,
                "score": round(score, 6),
                "yield_per_hour": round(rate, 6),
                "observed_seconds": round(lane.seconds, 6),
                "observations": lane.observations,
                "allocation": allocation,
                "reason": "; ".join(dict.fromkeys(lane.reason)) or "measured reward and exposure",
            }
        )
    return rows


def schedule_sync(
    *,
    workspace_root: str | Path | None = None,
    now: float | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = resolve_workspace_root(workspace_root, env=env)
    if now is not None and type(now) not in (int, float):
        raise ValueError("now must be numeric")
    moment = time.time() if now is None else float(now)
    if not math.isfinite(moment):
        raise ValueError("now must be finite")
    try:
        config = _config(root)
    except ValueError as exc:
        return {"ok": False, "mode": "schedule-sync", "blockers": [str(exc)]}
    sync = db_sync(workspace_root=root, env=env)
    if not sync["ok"]:
        return {"ok": False, "mode": "schedule-sync", "blockers": sync["blockers"]}
    conn = connect(root)
    try:
        lanes = _lanes(conn, config, moment)
        explore = _dark_explore_keys(conn)
    finally:
        conn.close()
    ranked = _allocate(lanes, explore, config)
    payload = {
        "version": 2,
        "advisory_only": True,
        "enabled": config.enabled,
        "generated_ts": moment,
        "fresh_until_ts": moment + config.max_age_seconds,
        "source_generation": sync["generation"],
        "source_fingerprint": sync["source_fingerprint"],
        "policy_fingerprint": _config_fingerprint(config),
        "lanes": ranked,
    }
    validation = _validate_schedule(payload)
    if validation:
        return {"ok": False, "mode": "schedule-sync", "blockers": validation}
    path = atomic_write_text(
        root,
        SCHEDULE_RELATIVE,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        max_bytes=4 * 1024 * 1024,
    )
    return {
        "ok": True,
        "mode": "schedule-sync",
        "schedule": str(path),
        "advisory_only": True,
        "enabled": config.enabled,
        "lanes": len(ranked),
        "top": ranked[: config.slots],
        "warnings": sync.get("warnings", []),
        "blockers": [],
    }


def schedule_list(
    *,
    workspace_root: str | Path | None = None,
    now: float | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = resolve_workspace_root(workspace_root, env=env)
    try:
        payload = read_json(root, SCHEDULE_RELATIVE, max_bytes=4 * 1024 * 1024)
    except (OSError, ValueError, json.JSONDecodeError, RecursionError, OverflowError) as exc:
        return {"ok": False, "mode": "schedule-list", "fresh": False, "blockers": [str(exc)]}
    validation = _validate_schedule(payload)
    if validation:
        return {"ok": False, "mode": "schedule-list", "fresh": False, "blockers": validation}
    status = db_status(root)
    try:
        config = _config(root)
    except ValueError as exc:
        return {"ok": False, "mode": "schedule-list", "fresh": False, "blockers": [str(exc)]}
    if now is not None and type(now) not in (int, float):
        return {"ok": False, "mode": "schedule-list", "fresh": False, "blockers": ["now must be numeric"]}
    moment = time.time() if now is None else float(now)
    if not math.isfinite(moment):
        return {"ok": False, "mode": "schedule-list", "fresh": False, "blockers": ["now must be finite"]}
    reasons: list[str] = []
    if not status.get("ok") or not status.get("fresh"):
        reasons.append("campaign index does not match current sources")
    if payload.get("source_generation") != status.get("generation"):
        reasons.append("schedule was generated from a different campaign index")
    if payload.get("source_fingerprint") != status.get("source_fingerprint"):
        reasons.append("schedule source fingerprint differs from the campaign index")
    if payload.get("source_fingerprint") != status.get("live_source_fingerprint"):
        reasons.append("schedule source fingerprint does not match current sources")
    if payload.get("policy_fingerprint") != _config_fingerprint(config):
        reasons.append("scheduler policy changed after schedule generation")
    if moment > float(payload.get("fresh_until_ts") or 0.0):
        reasons.append("schedule exceeded its configured maximum age")
    return {
        "ok": True,
        "mode": "schedule-list",
        **payload,
        "fresh": not reasons,
        "stale_reasons": reasons,
        "blockers": [],
    }


def schedule_ranks(
    *,
    lane: str,
    workspace_root: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, int]:
    """Safe central-integration API: stale or disabled advice is ignored."""
    if lane not in SUPPORTED_LANES:
        return {}
    try:
        payload = schedule_list(workspace_root=workspace_root, env=env)
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        return {}
    if not payload.get("ok") or not payload.get("fresh") or not payload.get("enabled"):
        return {}
    return {
        str(row["target"]): int(row["rank"])
        for row in payload["lanes"]
        if isinstance(row, dict) and row.get("lane") == lane and isinstance(row.get("rank"), int)
    }


def _exact_finite(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(float(value))


def _validate_schedule(payload: Any) -> list[str]:
    """Validate the complete persisted v2 format without raising."""
    try:
        if not isinstance(payload, dict) or set(payload) != _SCHEDULE_KEYS:
            return ["schedule must be a complete v2 object"]
        if type(payload["version"]) is not int or payload["version"] != 2:
            return ["schedule version must be exact integer 2"]
        if payload["advisory_only"] is not True or type(payload["enabled"]) is not bool:
            return ["schedule advisory_only/enabled flags are invalid"]
        if not _exact_finite(payload["generated_ts"]) or not _exact_finite(payload["fresh_until_ts"]):
            return ["schedule timestamps must be exact finite numbers"]
        generated = float(payload["generated_ts"])
        fresh_until = float(payload["fresh_until_ts"])
        if generated < 0 or fresh_until < generated:
            return ["schedule freshness interval is invalid"]
        for key in ("source_generation", "source_fingerprint", "policy_fingerprint"):
            if type(payload[key]) is not str or not re.fullmatch(r"[0-9a-f]{64}", payload[key]):
                return [f"schedule {key} must be a hexadecimal digest"]
        rows = payload["lanes"]
        if not isinstance(rows, list):
            return ["schedule lanes must be a list"]
        if len(rows) > MAX_SCHEDULE_ROWS:
            return ["schedule row count exceeds cap"]
        ranks: set[int] = set()
        for index, row in enumerate(rows):
            prefix = f"schedule row {index}"
            if not isinstance(row, dict) or set(row) != _ROW_KEYS:
                return [f"{prefix} has an invalid schema"]
            rank = row["rank"]
            if type(rank) is not int or rank <= 0 or rank in ranks:
                return [f"{prefix} rank must be a unique positive integer"]
            ranks.add(rank)
            if type(row["lane"]) is not str or row["lane"] not in SUPPORTED_LANES:
                return [f"{prefix} uses an unsupported lane"]
            try:
                validate_target_slug(row["target"])
            except (TypeError, ValueError):
                return [f"{prefix} target is invalid"]
            for key in ("score", "yield_per_hour", "observed_seconds"):
                if not _exact_finite(row[key]):
                    return [f"{prefix} {key} must be an exact finite number"]
            if float(row["observed_seconds"]) < 0:
                return [f"{prefix} observed_seconds must be non-negative"]
            if type(row["observations"]) is not int or row["observations"] < 0:
                return [f"{prefix} observations must be a non-negative integer"]
            if type(row["allocation"]) is not str or row["allocation"] not in ("explore", "exploit"):
                return [f"{prefix} allocation is invalid"]
            if type(row["reason"]) is not str or len(row["reason"]) > 2000 or any(ord(char) < 32 and char not in "\t" for char in row["reason"]):
                return [f"{prefix} reason is invalid"]
        return []
    except (KeyError, TypeError, ValueError, RecursionError, OverflowError):
        return ["schedule validation failed"]

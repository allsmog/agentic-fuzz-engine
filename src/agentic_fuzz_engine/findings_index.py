"""Global, append-only findings index (``data/findings-index.jsonl``).

Per-run ledgers live inside run dirs, and run dirs are retention-pruned by
campaign-gc — so a burst of new runs can evict the only record of a
completed campaign's findings. This module makes run dirs disposable: every
finding lifecycle event (recorded / classified / graded / deduped) is
mirrored as one normalized line in a single workspace-level JSONL that GC
never touches.

The index is queryable (``findings-index`` verb) and foldable: the fold
view reduces the event stream to latest-state-per-finding, which is what
"what did this campaign find, across all runs, including pruned ones"
means operationally.

Writes are best-effort by contract: a failed index append must never break
finding recording (the per-run ledger stays the write of record for the
run's own lifetime; the index is the durable shadow).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

INDEX_FILE_NAME = "findings-index.jsonl"
CRASH_EXCERPT_CHARS = 240

# event_append types mirrored into the index, and the row "event" they map to.
MIRRORED_EVENT_TYPES = {
    "finding_recorded": "recorded",
    "finding_classified": "classified",
    "finding_graded": "graded",
    "finding_dedupe": "deduped",
    "finding_impact": "impact",
    "finding_reachability": "reachability",
}


def index_path(data_root: str | Path) -> Path:
    return Path(data_root).expanduser() / INDEX_FILE_NAME


def append_index_event(
    data_root: str | Path,
    *,
    run_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    """Normalize one mirrored lifecycle event into an index row and append
    it. Returns the row, or None when the event type is not mirrored or the
    append failed (best-effort contract)."""
    event = MIRRORED_EVENT_TYPES.get(event_type)
    if event is None:
        return None
    try:
        rows = _normalize(data_root, run_id=run_id, event=event, payload=payload)
        if not rows:
            return None
        path = index_path(data_root)
        path.parent.mkdir(parents=True, exist_ok=True)
        blob = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(blob)
        return rows[0] if len(rows) == 1 else {"rows": len(rows)}
    except OSError:
        return None


def _normalize(
    data_root: str | Path,
    *,
    run_id: str,
    event: str,
    payload: dict[str, Any],
) -> list[dict[str, Any]]:
    ts = datetime.now(timezone.utc).isoformat()
    base = {"ts": ts, "run_id": run_id, "event": event}
    if event == "recorded":
        row = {
            **base,
            "finding_id": payload.get("finding_id"),
            "target": payload.get("target"),
            "harness": payload.get("harness"),
            "sanitizer": payload.get("sanitizer"),
            "error_token": payload.get("error_token"),
            "signature": payload.get("signature"),
            "root_signature": payload.get("root_signature"),
            "crash_state": payload.get("crash_state"),
            "primitive": payload.get("primitive"),
            "poc_artifact": payload.get("poc_artifact"),
            "reproductions": payload.get("reproductions"),
            "verified": payload.get("verified"),
            "crash_excerpt": str(payload.get("crash_output") or "")[:CRASH_EXCERPT_CHARS],
        }
        poc = payload.get("poc_artifact")
        if isinstance(poc, str) and poc:
            artifact = Path(data_root) / "runs" / run_id / "artifacts" / poc
            if artifact.is_file():
                row["poc_sha256"] = sha256(artifact.read_bytes()).hexdigest()
                row["poc_size"] = artifact.stat().st_size
        return [row]
    if event == "classified":
        return [
            {
                **base,
                "finding_id": f"finding-{payload.get('signature')}" if payload.get("signature") else None,
                "target": payload.get("target"),
                "harness": payload.get("harness"),
                "signature": payload.get("signature"),
                "poc_artifact": payload.get("poc_artifact"),
                "detail": {"verdict": payload.get("verdict"), "reason": payload.get("reason")},
            }
        ]
    if event == "graded":
        return [
            {
                **base,
                "finding_id": None,
                "target": payload.get("target"),
                "harness": payload.get("harness"),
                "poc_artifact": payload.get("artifact"),
                "detail": {
                    "verdict": payload.get("verdict"),
                    "record_recommended": payload.get("record_recommended"),
                },
            }
        ]
    if event == "reachability":
        return [
            {
                **base,
                "finding_id": payload.get("finding_id"),
                "detail": {
                    "verdict": payload.get("verdict"),
                    "entry_symbol": payload.get("entry_symbol"),
                    "production_callers": len(payload.get("production_callers") or []),
                    "flag_gates": len(payload.get("flag_gates") or []),
                    "bind_surface": payload.get("bind_surface"),
                },
            }
        ]
    if event == "impact":
        return [
            {
                **base,
                "finding_id": payload.get("finding_id"),
                "detail": {
                    "primitive": payload.get("primitive"),
                    "write_evidence": payload.get("write_evidence"),
                    "ubsan_wraps": len(payload.get("ubsan_wraps") or []),
                    "leads": len(payload.get("leads") or []),
                    "flag_matrix": payload.get("flag_matrix"),
                },
            }
        ]
    # deduped: one row per representative so the fold view can mark reps.
    representatives = payload.get("representatives")
    if not isinstance(representatives, list):
        return []
    return [
        {
            **base,
            "finding_id": rep,
            "detail": {"groups": payload.get("groups")},
        }
        for rep in representatives
        if isinstance(rep, str) and rep
    ]


def load_index(
    data_root: str | Path,
    *,
    run_id: str | None = None,
    target: str | None = None,
    finding_id: str | None = None,
    event: str | None = None,
) -> list[dict[str, Any]]:
    path = index_path(data_root)
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if run_id and row.get("run_id") != run_id:
            continue
        if target and row.get("target") != target:
            continue
        if finding_id and row.get("finding_id") != finding_id:
            continue
        if event and row.get("event") != event:
            continue
        rows.append(row)
    return rows


def fold_index(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reduce the event stream to latest-state-per-finding. Rows without a
    finding_id (e.g. graded-by-artifact) are folded by (run_id, poc_artifact)
    onto the recorded finding that references the same artifact when one
    exists; otherwise they are dropped from the fold (still visible raw)."""
    by_artifact: dict[tuple[str, str], str] = {}
    folded: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("event") == "recorded" and row.get("finding_id"):
            poc = row.get("poc_artifact")
            if isinstance(poc, str) and poc:
                by_artifact[(str(row.get("run_id")), poc)] = str(row["finding_id"])
    for row in rows:
        finding_id = row.get("finding_id")
        if not finding_id:
            key = (str(row.get("run_id")), str(row.get("poc_artifact") or ""))
            finding_id = by_artifact.get(key)
            if not finding_id:
                continue
        state = folded.setdefault(
            str(finding_id),
            {
                "finding_id": finding_id,
                "runs": [],
                "events": [],
                "verified": None,
                "classification": None,
                "graded": None,
                "dedupe_representative": False,
            },
        )
        run = str(row.get("run_id"))
        if run not in state["runs"]:
            state["runs"].append(run)
        state["events"].append(row.get("event"))
        state["last_ts"] = row.get("ts")
        if row.get("event") == "recorded":
            for field in (
                "target",
                "harness",
                "sanitizer",
                "error_token",
                "signature",
                "root_signature",
                "crash_state",
                "primitive",
                "poc_artifact",
                "poc_sha256",
                "poc_size",
                "crash_excerpt",
            ):
                if row.get(field) is not None:
                    state[field] = row[field]
            state.setdefault("first_ts", row.get("ts"))
            if row.get("verified") is not None:
                state["verified"] = bool(row["verified"])
            if row.get("reproductions") is not None:
                state["reproductions"] = row["reproductions"]
        elif row.get("event") == "classified":
            state["classification"] = (row.get("detail") or {}).get("verdict")
        elif row.get("event") == "graded":
            state["graded"] = (row.get("detail") or {}).get("verdict")
        elif row.get("event") == "deduped":
            state["dedupe_representative"] = True
        elif row.get("event") == "impact":
            state["impact"] = row.get("detail")
        elif row.get("event") == "reachability":
            state["reachability"] = row.get("detail")
    return sorted(folded.values(), key=lambda item: (str(item.get("target")), str(item["finding_id"])))


def collect_target_findings(data_root: str | Path, target: str) -> list[dict[str, Any]]:
    """Full finding dicts for a target across every surviving source: live
    run dirs plus GC archives. Used by across-runs dedupe, which needs the
    raw crash_output the index deliberately truncates. Deduplicated by
    finding_id keeping the richest row (verified beats unverified)."""
    root = Path(data_root).expanduser()
    ledgers = sorted(root.glob("runs/*/findings.jsonl")) + sorted(root.glob("archive/runs/*/findings.jsonl"))
    best: dict[str, dict[str, Any]] = {}
    for ledger in ledgers:
        try:
            lines = ledger.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line.strip():
                continue
            try:
                finding = json.loads(line)
            except json.JSONDecodeError:
                continue
            if finding.get("target") != target:
                continue
            finding_id = str(finding.get("finding_id") or "")
            if not finding_id:
                continue
            finding["_source_run"] = ledger.parent.name
            current = best.get(finding_id)
            if current is None or _richness(finding) > _richness(current):
                best[finding_id] = finding
    return [
        {key: value for key, value in finding.items() if key != "_source_run"} | {"source_run": finding["_source_run"]}
        for finding in sorted(best.values(), key=lambda item: str(item.get("finding_id")))
    ]


def artifact_sizes_across(data_root: str | Path, findings: list[dict[str, Any]]) -> dict[str, int]:
    """PoV artifact sizes for quality ranking, resolved from whichever root
    (live run or archive) still holds the file."""
    root = Path(data_root).expanduser()
    sizes: dict[str, int] = {}
    for finding in findings:
        name = finding.get("poc_artifact")
        run = finding.get("source_run")
        if not isinstance(name, str) or not name or not isinstance(run, str):
            continue
        for candidate in (
            root / "runs" / run / "artifacts" / name,
            root / "archive" / "runs" / run / "artifacts" / name,
        ):
            if candidate.is_file():
                sizes[name] = candidate.stat().st_size
                break
    return sizes


def _richness(finding: dict[str, Any]) -> tuple[int, int, int]:
    return (
        1 if finding.get("verified") else 0,
        int(finding.get("reproductions") or 0),
        sum(1 for value in finding.values() if value is not None),
    )

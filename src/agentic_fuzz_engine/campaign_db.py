"""Rebuildable, read-only campaign index over workspace state.

JSON and JSONL artifacts remain authoritative.  Synchronization builds a new
SQLite file beside the previous one and promotes it only after a successful
transaction.  Rebuilding on every sync is deliberate: it makes source
deletion, truncation, same-size replacement, and recovery from malformed rows
correct without trusting file metadata or a fragile append cursor.

The public query surface is :func:`db_report`; arbitrary SQL is not accepted.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .managed_persistence import (
    MAX_JSONL_ROWS,
    MAX_RECORD_BYTES,
    managed_path,
    read_json,
    replace_managed_file,
    safe_read_bytes,
    validate_entry_class,
    validate_target_slug,
)
from .workspace import resolve_workspace_root

DB_RELATIVE = Path("data/campaign.db")
SCHEMA_VERSION = 2
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 128 * 1024 * 1024
MAX_SOURCES = 2048
MAX_REPORT_ROWS = 1000

_SCHEMA = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE candidates(
  name TEXT PRIMARY KEY, status TEXT, tag TEXT, entry_class TEXT,
  last_round INTEGER, note TEXT, events INTEGER NOT NULL, history TEXT NOT NULL
);
CREATE TABLE rounds(
  target TEXT NOT NULL, run_id TEXT NOT NULL, round INTEGER NOT NULL,
  started_ts REAL, ended_ts REAL, duration_seconds REAL, lane TEXT,
  fuzz_seconds REAL, new_root_signatures INTEGER, findings_recorded INTEGER,
  raw TEXT NOT NULL, PRIMARY KEY(target, run_id, round)
);
CREATE TABLE jobs(
  job_id TEXT PRIMARY KEY, type TEXT, target TEXT, state TEXT,
  predicate_ok INTEGER, cost_usd REAL, started_ts REAL, ended_ts REAL,
  duration_seconds REAL, events INTEGER NOT NULL, raw TEXT NOT NULL
);
CREATE TABLE findings(
  finding_id TEXT PRIMARY KEY, target TEXT, verified INTEGER,
  error_token TEXT, root_signature TEXT, impact_primitive TEXT,
  write_evidence TEXT, crash_state TEXT, first_ts TEXT, last_ts TEXT,
  raw TEXT NOT NULL
);
CREATE TABLE sinks(
  id INTEGER PRIMARY KEY, source TEXT NOT NULL, tag TEXT, file TEXT,
  line INTEGER, method TEXT, callee TEXT, kind TEXT, primitive TEXT,
  entry_class TEXT, sink_key TEXT, code TEXT, raw TEXT NOT NULL,
  UNIQUE(source, kind, file, line, method, callee)
);
CREATE TABLE hypotheses(
  target TEXT NOT NULL, hyp_id TEXT NOT NULL, function TEXT, file TEXT,
  line INTEGER, bug_class TEXT, status TEXT, confidence REAL, raw TEXT NOT NULL,
  PRIMARY KEY(target, hyp_id)
);
CREATE TABLE hypothesis_sinks(
  target TEXT NOT NULL, hyp_id TEXT NOT NULL, sink_id INTEGER NOT NULL,
  match TEXT NOT NULL, distance INTEGER,
  PRIMARY KEY(target, hyp_id, sink_id)
);
CREATE TABLE sink_coverage(
  target TEXT NOT NULL, bucket TEXT NOT NULL, primitive TEXT, file TEXT,
  line INTEGER, method TEXT, sink_key TEXT,
  PRIMARY KEY(target, bucket, file, line, method)
);
CREATE TABLE known_vulns(
  vuln_id TEXT PRIMARY KEY, target TEXT, bug_class TEXT, functions TEXT,
  status TEXT, raw TEXT NOT NULL
);
CREATE TABLE directed_tasks(
  id TEXT PRIMARY KEY, target TEXT, state TEXT, budget_rounds INTEGER,
  build_seconds REAL, raw TEXT NOT NULL
);
CREATE TABLE experiments(
  id TEXT PRIMARY KEY, lane TEXT, target TEXT, boost REAL,
  expires REAL, rationale TEXT, raw TEXT NOT NULL
);
CREATE INDEX rounds_target_ts ON rounds(target, started_ts);
CREATE INDEX findings_target ON findings(target, verified);
CREATE INDEX sinks_surface ON sinks(kind, primitive, tag);
CREATE INDEX jobs_lane ON jobs(type, target, state);
"""

_FIXED_SOURCES = (
    Path("data/candidates.jsonl"),
    Path("data/jobs.jsonl"),
    Path("data/findings-index.jsonl"),
    Path("data/sink-scan.jsonl"),
    Path("data/entry-scan.jsonl"),
    Path("data/fork-inventory.jsonl"),
    Path("data/known-vulns.jsonl"),
    Path("data/directed-queue.json"),
    Path("data/experiments.json"),
)


def db_path(root: Path) -> Path:
    return Path(root) / DB_RELATIVE


def _work_targets(root: Path) -> list[str]:
    work = managed_path(root, "work")
    if not work.exists():
        return []
    names: list[str] = []
    entries_seen = 0
    with os.scandir(work) as entries:
        for entry in entries:
            entries_seen += 1
            if entries_seen > MAX_SOURCES:
                raise ValueError("workspace work entry count exceeds cap")
            if entry.is_symlink():
                raise ValueError(f"workspace work entry is a symbolic link: {entry.path}")
            if not entry.is_dir(follow_symlinks=False) or entry.name.startswith("_"):
                continue
            try:
                names.append(validate_target_slug(entry.name))
            except ValueError:
                continue
            if len(names) >= MAX_SOURCES // 3:
                raise ValueError("workspace contains too many campaign targets")
    return sorted(names)


def _source_relatives(root: Path) -> list[Path]:
    relatives = list(_FIXED_SOURCES)
    for name in _work_targets(root):
        relatives.extend(
            (
                Path("work") / name / "rounds.jsonl",
                Path("work") / name / "hypotheses.json",
                Path("work") / name / "sink-coverage.json",
            )
        )
    if len(relatives) > MAX_SOURCES:
        raise ValueError("campaign source count exceeds cap")
    return relatives


def source_fingerprint(root: Path) -> str:
    """Digest source names and bytes, including missing fixed sources."""
    digest = hashlib.sha256()
    total_bytes = 0
    for relative in _source_relatives(root):
        digest.update(relative.as_posix().encode("utf-8") + b"\0")
        payload = safe_read_bytes(root, relative, max_bytes=MAX_SOURCE_BYTES)
        if payload is None:
            digest.update(b"MISSING\0")
        else:
            total_bytes += len(payload)
            if total_bytes > MAX_TOTAL_SOURCE_BYTES:
                raise ValueError("campaign sources exceed aggregate byte cap")
            digest.update(str(len(payload)).encode("ascii") + b"\0")
            digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()


def connect(root: Path, *, readonly: bool = True) -> sqlite3.Connection:
    """Open the managed index; writers are reserved for :func:`db_sync`."""
    if not readonly:
        raise ValueError("campaign.db is derived; call db_sync instead of opening a writer")
    root = Path(root)
    path = managed_path(root, DB_RELATIVE)
    if not path.exists():
        raise FileNotFoundError(path)
    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True, timeout=2.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA busy_timeout=2000")
    return conn


def _finite(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _integer(value: Any) -> int | None:
    number = _finite(value)
    return int(number) if number is not None else None


def _timestamp(value: Any) -> float | None:
    return _finite(value)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class _Sources:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.malformed = 0
        self.rows = 0
        self.total_bytes = 0
        self.counts: dict[str, int] = {}

    def _read(self, relative: Path) -> bytes | None:
        payload = safe_read_bytes(self.root, relative, max_bytes=MAX_SOURCE_BYTES)
        if payload is not None:
            self.total_bytes += len(payload)
            if self.total_bytes > MAX_TOTAL_SOURCE_BYTES:
                raise ValueError("campaign sources exceed aggregate byte cap")
        return payload

    def jsonl(self, relative: Path) -> list[dict[str, Any]]:
        payload = self._read(relative)
        if payload is None:
            return []
        # A writer may be between writes.  A non-newline-terminated tail is
        # ignored and becomes visible on the next full rebuild.
        if not payload.endswith(b"\n"):
            payload = payload.rsplit(b"\n", 1)[0] + b"\n" if b"\n" in payload else b""
        rows: list[dict[str, Any]] = []
        for raw in payload.splitlines():
            if not raw.strip():
                continue
            self.rows += 1
            if self.rows > MAX_JSONL_ROWS:
                raise ValueError("campaign JSONL row count exceeds cap")
            if len(raw) > MAX_RECORD_BYTES:
                raise ValueError(f"campaign JSONL row exceeds byte cap: {relative}:{self.rows}")
            try:
                row = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, OverflowError):
                raise ValueError(f"malformed complete JSONL row: {relative}:{self.rows}")
            if not isinstance(row, dict):
                raise ValueError(f"non-object complete JSONL row: {relative}:{self.rows}")
            rows.append(row)
        return rows

    def document(self, relative: Path) -> dict[str, Any]:
        payload = self._read(relative)
        if payload is None:
            return {}
        try:
            value = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, OverflowError):
            raise ValueError(f"malformed JSON document: {relative}")
        if not isinstance(value, dict):
            raise ValueError(f"non-object JSON document: {relative}")
        return value

    def add(self, key: str, amount: int = 1) -> None:
        self.counts[key] = self.counts.get(key, 0) + amount


def _fold_candidates(conn: sqlite3.Connection, sources: _Sources) -> None:
    state: dict[str, dict[str, Any]] = {}
    for event in sources.jsonl(Path("data/candidates.jsonl")):
        try:
            name = validate_target_slug(str(event.get("name") or ""))
        except ValueError:
            sources.malformed += 1
            continue
        if "entry_class" in event:
            try:
                validate_entry_class(event["entry_class"])
            except ValueError:
                sources.malformed += 1
                continue
        current = state.setdefault(name, {"history": []})
        for key in ("status", "tag", "entry_class", "round", "note"):
            if key in event:
                current[key] = event[key]
        current["history"].append(str(event.get("status") or ""))
    for name, row in sorted(state.items()):
        conn.execute(
            "INSERT INTO candidates VALUES(?,?,?,?,?,?,?,?)",
            (
                name,
                row.get("status"),
                row.get("tag"),
                row.get("entry_class"),
                _integer(row.get("round")),
                row.get("note"),
                len(row["history"]),
                _json(row["history"]),
            ),
        )
    sources.add("candidates", len(state))


def _fold_rounds(conn: sqlite3.Connection, sources: _Sources, targets: Iterable[str]) -> None:
    count = 0
    for target in targets:
        for row in sources.jsonl(Path("work") / target / "rounds.jsonl"):
            run_id = str(row.get("run_id") or "")[:160]
            round_index = _integer(row.get("round"))
            if not run_id or round_index is None:
                sources.malformed += 1
                continue
            telemetry = row.get("telemetry") if isinstance(row.get("telemetry"), dict) else {}
            started = _timestamp(telemetry.get("started_ts", row.get("started_ts", row.get("ts"))))
            ended = _timestamp(telemetry.get("ended_ts", row.get("ended_ts")))
            duration = _finite(telemetry.get("duration_seconds", row.get("duration_seconds")))
            if duration is not None and duration < 0:
                duration = None
            intake = row.get("intake") if isinstance(row.get("intake"), dict) else {}
            conn.execute(
                "INSERT OR REPLACE INTO rounds VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    target,
                    run_id,
                    round_index,
                    started,
                    ended,
                    duration,
                    str(telemetry.get("lane") or row.get("lane") or "fuzz"),
                    _finite(telemetry.get("fuzz_budget_seconds", row.get("fuzz_seconds"))),
                    _integer(row.get("new_root_signatures")),
                    _integer(intake.get("findings_recorded")),
                    _json(row),
                ),
            )
            count += 1
    sources.add("rounds", count)


def _fold_jobs(conn: sqlite3.Connection, sources: _Sources) -> None:
    state: dict[str, dict[str, Any]] = {}
    for event in sources.jsonl(Path("data/jobs.jsonl")):
        job_id = str(event.get("id") or "")[:256]
        if not job_id:
            sources.malformed += 1
            continue
        current = state.setdefault(job_id, {"events": 0})
        current.update(event)
        current["events"] += 1
        ts = _timestamp(event.get("ts"))
        if current.get("started_ts") is None and event.get("state") == "running":
            current["started_ts"] = ts
        if event.get("state") in ("done", "failed", "dropped"):
            current["ended_ts"] = ts
    for job_id, row in sorted(state.items()):
        predicate = row.get("predicate") if isinstance(row.get("predicate"), dict) else {}
        worker = row.get("worker") if isinstance(row.get("worker"), dict) else {}
        start = _timestamp(row.get("started_ts"))
        end = _timestamp(row.get("ended_ts"))
        duration = end - start if start is not None and end is not None and end >= start else None
        conn.execute(
            "INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                job_id,
                row.get("type"),
                row.get("target"),
                row.get("state"),
                int(bool(predicate.get("ok"))) if "ok" in predicate else None,
                _finite(worker.get("cost_usd")),
                start,
                end,
                duration,
                row["events"],
                _json(row),
            ),
        )
    sources.add("jobs", len(state))


def _fold_findings(conn: sqlite3.Connection, sources: _Sources) -> None:
    state: dict[str, dict[str, Any]] = {}
    for event in sources.jsonl(Path("data/findings-index.jsonl")):
        finding_id = str(event.get("finding_id") or "")[:200]
        if not finding_id:
            continue
        current = state.setdefault(finding_id, {})
        if event.get("event") == "recorded":
            current.update(event)
            current.setdefault("first_ts", event.get("ts"))
        detail = event.get("detail") if isinstance(event.get("detail"), dict) else {}
        if event.get("event") == "impact":
            current["impact_primitive"] = detail.get("primitive")
            current["write_evidence"] = detail.get("write_evidence")
        current["last_ts"] = event.get("ts", current.get("last_ts"))
    for finding_id, row in sorted(state.items()):
        conn.execute(
            "INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                finding_id,
                row.get("target"),
                int(bool(row.get("verified"))) if "verified" in row else None,
                row.get("error_token"),
                row.get("root_signature"),
                row.get("impact_primitive"),
                row.get("write_evidence"),
                _json(row.get("crash_state") or []),
                row.get("first_ts"),
                row.get("last_ts"),
                _json(row),
            ),
        )
    sources.add("findings", len(state))


def _fold_sinks(conn: sqlite3.Connection, sources: _Sources) -> None:
    count = 0
    for relative in _FIXED_SOURCES[3:6]:
        for row in sources.jsonl(relative):
            file_name = str(row.get("file") or "")[:1000]
            line = _integer(row.get("line"))
            if not file_name or line is None or line < 1:
                sources.malformed += 1
                continue
            conn.execute(
                "INSERT OR IGNORE INTO sinks(source,tag,file,line,method,callee,kind,primitive,entry_class,sink_key,code,raw)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    relative.as_posix(),
                    row.get("tag"),
                    file_name,
                    line,
                    row.get("method"),
                    row.get("callee"),
                    row.get("kind"),
                    row.get("primitive"),
                    row.get("entry_class"),
                    row.get("sink_key"),
                    str(row.get("code") or "")[:2000] or None,
                    _json(row),
                ),
            )
            count += 1
    sources.add("sinks", count)


def _fold_target_docs(conn: sqlite3.Connection, sources: _Sources, targets: Iterable[str]) -> None:
    hypotheses = 0
    coverage = 0
    for target in targets:
        document = sources.document(Path("work") / target / "hypotheses.json")
        rows = document.get("hypotheses") if isinstance(document.get("hypotheses"), list) else []
        for row in rows[:MAX_JSONL_ROWS]:
            if not isinstance(row, dict):
                sources.malformed += 1
                continue
            hyp_id = str(row.get("id") or "")[:160]
            if not hyp_id:
                sources.malformed += 1
                continue
            conn.execute(
                "INSERT OR REPLACE INTO hypotheses VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    target,
                    hyp_id,
                    row.get("function"),
                    row.get("file"),
                    _integer(row.get("line")),
                    row.get("bug_class"),
                    row.get("status"),
                    _finite(row.get("confidence")),
                    _json(row),
                ),
            )
            hypotheses += 1
        document = sources.document(Path("work") / target / "sink-coverage.json")
        for bucket in ("covered", "uncovered"):
            rows = document.get(bucket) if isinstance(document.get(bucket), list) else []
            for row in rows[:MAX_JSONL_ROWS]:
                if not isinstance(row, dict):
                    sources.malformed += 1
                    continue
                conn.execute(
                    "INSERT OR REPLACE INTO sink_coverage VALUES(?,?,?,?,?,?,?)",
                    (
                        target,
                        bucket,
                        row.get("primitive"),
                        row.get("file"),
                        _integer(row.get("line")),
                        row.get("method"),
                        row.get("sink_key"),
                    ),
                )
                coverage += 1
    sources.add("hypotheses", hypotheses)
    sources.add("sink_coverage", coverage)


def _source_parts(value: str) -> tuple[str, ...]:
    text = str(value).replace("\\", "/")
    parts = tuple(part for part in PurePosixPath(text).parts if part not in ("/", "", "."))
    return () if ".." in parts else parts


def path_suffix_match(left: str, right: str) -> bool:
    a = _source_parts(left)
    b = _source_parts(right)
    if not a or not b:
        return False
    common = min(len(a), len(b))
    required = 2
    matches = 0
    for offset in range(1, common + 1):
        if a[-offset] != b[-offset]:
            break
        matches += 1
    return matches >= required


def _bind_hypotheses(conn: sqlite3.Connection, sources: _Sources) -> None:
    sinks = conn.execute("SELECT id,tag,file,line,method FROM sinks ORDER BY id").fetchall()
    candidate_tags = {
        str(row["name"]): str(row["tag"] or row["name"])
        for row in conn.execute("SELECT name,tag FROM candidates")
    }
    tag_counts: dict[str, int] = {}
    for tag in candidate_tags.values():
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
    count = 0
    for hyp in conn.execute("SELECT target,hyp_id,file,line,function FROM hypotheses ORDER BY target,hyp_id"):
        expected_tag = candidate_tags.get(str(hyp["target"]), str(hyp["target"]))
        if tag_counts.get(expected_tag, 0) != 1:
            sources.add("ambiguous_target_tags")
            continue
        matches: list[tuple[tuple[int, int], sqlite3.Row, str, int | None]] = []
        for sink in sinks:
            if str(sink["tag"] or "") != expected_tag:
                continue
            if not path_suffix_match(str(hyp["file"] or ""), str(sink["file"] or "")):
                continue
            hline = _integer(hyp["line"])
            sline = _integer(sink["line"])
            match: str | None = None
            distance: int | None = None
            if hline is not None and sline is not None:
                distance = abs(hline - sline)
                if distance == 0:
                    match = "exact-line"
                elif distance <= 25:
                    match = "line-window"
            if match is None and hyp["function"] and str(hyp["function"]) == str(sink["method"]):
                match = "file-method"
            if match is None:
                continue
            rank = {"exact-line": 0, "line-window": 1, "file-method": 2}[match]
            matches.append(((rank, distance if distance is not None else 1_000_000), sink, match, distance))
        if not matches:
            continue
        best_rank = min(item[0] for item in matches)
        best = [item for item in matches if item[0] == best_rank]
        if len(best) != 1:
            sources.add("ambiguous_hypotheses")
            continue
        _, sink, match, distance = best[0]
        conn.execute(
            "INSERT INTO hypothesis_sinks VALUES(?,?,?,?,?)",
            (hyp["target"], hyp["hyp_id"], sink["id"], match, distance),
        )
        count += 1
    sources.add("hypothesis_bindings", count)


def _fold_auxiliary(conn: sqlite3.Connection, sources: _Sources) -> None:
    for row in sources.jsonl(Path("data/known-vulns.jsonl")):
        vuln_id = str(row.get("id") or row.get("vuln_id") or "")[:160]
        if not vuln_id:
            sources.malformed += 1
            continue
        conn.execute(
            "INSERT OR REPLACE INTO known_vulns VALUES(?,?,?,?,?,?)",
            (
                vuln_id,
                row.get("target"),
                row.get("bug_class"),
                _json(row.get("functions") or []),
                row.get("status"),
                _json(row),
            ),
        )
        sources.add("known_vulns")
    directed = sources.document(Path("data/directed-queue.json"))
    for row in directed.get("tasks", []) if isinstance(directed.get("tasks"), list) else []:
        if not isinstance(row, dict) or not row.get("id"):
            sources.malformed += 1
            continue
        conn.execute(
            "INSERT OR REPLACE INTO directed_tasks VALUES(?,?,?,?,?,?)",
            (
                str(row["id"])[:200],
                row.get("target"),
                row.get("state"),
                _integer(row.get("budget_rounds")),
                _finite(row.get("build_seconds")),
                _json(row),
            ),
        )
        sources.add("directed_tasks")
    experiments = sources.document(Path("data/experiments.json"))
    for row in experiments.get("experiments", []) if isinstance(experiments.get("experiments"), list) else []:
        if not isinstance(row, dict) or not row.get("id"):
            sources.malformed += 1
            continue
        conn.execute(
            "INSERT OR REPLACE INTO experiments VALUES(?,?,?,?,?,?,?)",
            (
                str(row["id"])[:160],
                row.get("lane"),
                row.get("target"),
                _finite(row.get("boost")),
                _finite(row.get("expires")),
                str(row.get("rationale") or "")[:500],
                _json(row),
            ),
        )
        sources.add("experiments")


def db_sync(
    *,
    workspace_root: str | Path | None = None,
    rebuild: bool = False,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build and atomically promote a fresh index.

    ``rebuild`` is retained for API compatibility; every sync already is a
    rebuild, so incremental and explicit rebuild semantics cannot diverge.
    """
    del rebuild
    root = resolve_workspace_root(workspace_root, env=env)
    started = time.monotonic()
    blockers: list[str] = []
    warnings: list[str] = []
    stage: Path | None = None
    try:
        fingerprint = source_fingerprint(root)
        targets = _work_targets(root)
        sources = _Sources(root)
        data_dir = managed_path(root, "data/campaign.db", create_parent=True).parent
        descriptor, raw_stage = tempfile.mkstemp(prefix=".campaign.", suffix=".db", dir=data_dir)
        os.close(descriptor)
        stage = Path(raw_stage)
        conn = sqlite3.connect(stage, timeout=2.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.executescript(_SCHEMA)
            conn.execute("BEGIN IMMEDIATE")
            _fold_candidates(conn, sources)
            _fold_rounds(conn, sources, targets)
            _fold_jobs(conn, sources)
            _fold_findings(conn, sources)
            _fold_sinks(conn, sources)
            _fold_target_docs(conn, sources, targets)
            _bind_hypotheses(conn, sources)
            _fold_auxiliary(conn, sources)
            generated = time.time()
            generation = hashlib.sha256(
                f"{SCHEMA_VERSION}:{fingerprint}".encode("ascii")
            ).hexdigest()
            meta = {
                "schema_version": str(SCHEMA_VERSION),
                "generation": generation,
                "source_fingerprint": fingerprint,
                "generated_ts": repr(generated),
                "malformed_rows": str(sources.malformed),
            }
            conn.executemany("INSERT INTO meta VALUES(?,?)", sorted(meta.items()))
            conn.commit()
        finally:
            conn.close()
        with stage.open("rb") as handle:
            os.fsync(handle.fileno())
        replace_managed_file(root, stage, DB_RELATIVE)
        stage = None
        if sources.malformed:
            warnings.append(f"ignored {sources.malformed} malformed source rows")
        return {
            "ok": True,
            "mode": "campaign-db-sync",
            "database": str(db_path(root)),
            "generation": generation,
            "source_fingerprint": fingerprint,
            "counts": sources.counts,
            "malformed_rows": sources.malformed,
            "warnings": warnings,
            "blockers": [],
            "duration_seconds": round(time.monotonic() - started, 6),
        }
    except (OSError, ValueError, sqlite3.Error, RecursionError, OverflowError) as exc:
        blockers.append(f"campaign index rebuild failed: {exc}")
        return {
            "ok": False,
            "mode": "campaign-db-sync",
            "database": str(db_path(root)),
            "counts": {},
            "warnings": warnings,
            "blockers": blockers,
            "duration_seconds": round(time.monotonic() - started, 6),
        }
    finally:
        if stage is not None:
            try:
                stage.unlink()
            except FileNotFoundError:
                pass


def db_status(root: Path) -> dict[str, Any]:
    try:
        conn = connect(root)
    except (OSError, ValueError, sqlite3.Error) as exc:
        return {"ok": False, "fresh": False, "blockers": [str(exc)]}
    try:
        meta = {row["key"]: row["value"] for row in conn.execute("SELECT key,value FROM meta")}
    finally:
        conn.close()
    try:
        live = source_fingerprint(Path(root))
    except (OSError, ValueError) as exc:
        return {"ok": False, "fresh": False, "meta": meta, "blockers": [str(exc)]}
    fresh = meta.get("source_fingerprint") == live
    return {
        "ok": True,
        "fresh": fresh,
        "generation": meta.get("generation"),
        "source_fingerprint": meta.get("source_fingerprint"),
        "live_source_fingerprint": live,
        "generated_ts": _finite(meta.get("generated_ts")),
        "malformed_rows": _integer(meta.get("malformed_rows")) or 0,
        "blockers": [],
    }


def _limit(value: int) -> int:
    return max(1, min(int(value), MAX_REPORT_ROWS))


def db_report(
    *,
    name: str,
    workspace_root: str | Path | None = None,
    target: str | None = None,
    limit: int = 200,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run a named, parameterized report.  Raw SQL is intentionally absent."""
    root = resolve_workspace_root(workspace_root, env=env)
    synced = db_sync(workspace_root=root, env=env)
    if not synced["ok"]:
        return {"ok": False, "mode": "campaign-db-report", "report": name, "blockers": synced["blockers"]}
    target_slug = validate_target_slug(target) if target is not None else None
    cap = _limit(limit)
    conn = connect(root)
    try:
        if name == "summary":
            tables = ("candidates", "rounds", "jobs", "findings", "sinks", "hypotheses")
            counts = {table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in tables}
            rows: list[dict[str, Any]] = []
            extra: dict[str, Any] = {"counts": counts}
        elif name == "unhypothesized-write-sinks":
            rows = [dict(row) for row in conn.execute(
                "SELECT s.tag,s.file,s.line,s.method,s.callee,s.primitive,s.entry_class"
                " FROM sinks s WHERE s.kind='sink' AND s.primitive IN ('write','exec')"
                " AND NOT EXISTS(SELECT 1 FROM hypothesis_sinks hs WHERE hs.sink_id=s.id)"
                " ORDER BY s.file,s.line,s.method LIMIT ?",
                (cap,),
            )]
            extra = {"total": len(rows)}
        elif name == "hypothesis-coverage":
            params: tuple[Any, ...] = ()
            where = ""
            if target_slug is not None:
                where = " WHERE h.target=?"
                params = (target_slug,)
            rows = [dict(row) for row in conn.execute(
                "SELECT h.target,COUNT(*) AS hypotheses,"
                " SUM(EXISTS(SELECT 1 FROM hypothesis_sinks hs WHERE hs.target=h.target AND hs.hyp_id=h.hyp_id)) AS bound"
                " FROM hypotheses h" + where + " GROUP BY h.target ORDER BY h.target LIMIT ?",
                (*params, cap),
            )]
            extra = {"per_target": rows}
        elif name == "recent-yield":
            params = ()
            where = ""
            if target_slug is not None:
                where = " WHERE target=?"
                params = (target_slug,)
            rows = [dict(row) for row in conn.execute(
                "SELECT target,SUM(COALESCE(new_root_signatures,0)) AS new_roots,"
                " SUM(COALESCE(duration_seconds,0)) AS observed_seconds,COUNT(*) AS rounds"
                " FROM rounds" + where + " GROUP BY target ORDER BY target LIMIT ?",
                (*params, cap),
            )]
            extra = {}
        elif name == "stale":
            status = db_status(root)
            rows = []
            extra = {"stale": [] if status.get("fresh") else ["campaign database sources changed"], "status": status}
        else:
            return {
                "ok": False,
                "mode": "campaign-db-report",
                "report": name,
                "blockers": ["unknown report; choose summary, unhypothesized-write-sinks, hypothesis-coverage, recent-yield, or stale"],
            }
    finally:
        conn.close()
    return {
        "ok": True,
        "mode": "campaign-db-report",
        "report": name,
        "rows": rows,
        **extra,
        "generation": synced["generation"],
        "warnings": synced["warnings"],
        "blockers": [],
    }

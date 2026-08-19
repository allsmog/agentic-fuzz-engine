"""Campaign garbage collection: corpus minimization and run-dir retention.

A long campaign's silent killer on a shared volume is unbounded growth —
corpora, per-run state dirs, and KLEE output trees. This module reclaims
space deterministically and conservatively:

- corpus minimize: ``fuzzer -merge=1`` into a fresh dir, then an atomic swap;
  only when the corpus exceeds policy thresholds, only for targets with a
  working fuzzer binary
- retention: keep the newest N run dirs / KLEE output trees, delete the rest

Every deletion is containment-checked against its expected parent; nothing
outside data-root/runs, klee/klee-ng-out, or the corpus swap dirs is ever
removed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping

from .campaign_rounds import default_asan_options
from .runtime_backends import _run_command
from .workspace import load_policy, resolve_workspace_root

MERGE_TIMEOUT_SECONDS = 900
MAX_PRUNE_DIRS = 500
TARGET_RE = re.compile(r"^(?:localfuzz/c/)?([A-Za-z0-9][A-Za-z0-9_.-]*)$")


def run_campaign_gc(
    *,
    workspace_root: str | Path | None = None,
    target: str | None = None,
    data_root: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    root = resolve_workspace_root(workspace_root, env=environment)
    full_policy = load_policy(root, env=environment)
    policy = full_policy.get("gc", {})
    min_files = int(policy.get("gc_corpus_min_files", 2000))
    max_mb = int(policy.get("gc_corpus_max_mb", 512))
    run_retention = int(policy.get("run_retention", 10))
    klee_retention = int(policy.get("klee_out_retention", 5))
    merge_timeout = float(policy.get("merge_timeout_seconds", MERGE_TIMEOUT_SECONDS))

    environment.setdefault("ASAN_OPTIONS", default_asan_options(root))

    work_dir = root / "work"
    _reject_symlinked_root(work_dir, "work root")
    if target:
        match = TARGET_RE.fullmatch(target)
        if not match:
            raise ValueError("target must be a canonical name or localfuzz/c/<name>")
        names = [match.group(1)]
    else:
        names = (
            sorted(entry.name for entry in work_dir.iterdir() if entry.is_dir() and not entry.is_symlink())
            if work_dir.is_dir() else []
        )
    corpus_results = [
        _minimize_corpus(
            name=name,
            fuzzer=root / "bin" / name / "fuzzer",
            corpus=work_dir / name / "seeds",
            min_files=min_files,
            max_mb=max_mb,
            env=environment,
            merge_timeout=merge_timeout,
        )
        for name in names
    ]

    resolved_data_root = Path(data_root).expanduser().absolute() if data_root else root / "data"
    _reject_symlinked_root(resolved_data_root, "data root")
    runs_root = resolved_data_root / "runs"
    archive_root = resolved_data_root / "archive" / "runs"
    _reject_nested_symlink(resolved_data_root, runs_root, label="runs root")
    _reject_nested_symlink(resolved_data_root, archive_root, label="archive root")
    _reject_symlinked_root(runs_root, "runs root")
    _reject_symlinked_root(archive_root, "archive root")
    runs_pruned = _prune_runs_with_archive(
        runs_root,
        keep=run_retention,
        archive_root=archive_root,
        max_mb=int(policy.get("archive_max_mb", 64)),
        events_tail_kb=int(policy.get("archive_events_tail_kb", 256)),
    )
    archives_pruned = _prune_oldest(archive_root, keep=int(policy.get("archive_retention", 100)))
    klee_root = root / "klee" / "klee-ng-out"
    _reject_nested_symlink(root, klee_root, label="klee output root")
    _reject_symlinked_root(klee_root, "klee output root")
    klee_pruned = _prune_oldest(klee_root, keep=klee_retention)

    # Quarantined known-crash rediscoveries (fuzz-blocker tier) are bounded
    # here too so a manual campaign-gc reclaims them, not just the round loop.
    from .known_crashes import prune_known_inputs

    known_inputs_retention = int(policy.get("known_crash_inputs_retention", 200))
    known_inputs_pruned = {"removed": 0, "kept": 0, "bytes_freed": 0}
    for name in names:
        pruned = prune_known_inputs(work_dir / name, retention=known_inputs_retention)
        for key in known_inputs_pruned:
            known_inputs_pruned[key] += pruned[key]

    # The symcc solution cache is rewritable by contract — bound it here.
    from .symcc_crossover import prune_solutions

    symcc_policy = full_policy.get("symcc", {}) if isinstance(full_policy.get("symcc"), dict) else {}
    solutions_max = int(symcc_policy.get("solutions_max", 512))
    solutions_pruned = {"kept": 0, "removed": 0}
    for name in names:
        pruned = prune_solutions(work_dir / name / "symcc-state", max_entries=solutions_max)
        for key in solutions_pruned:
            solutions_pruned[key] += pruned[key]

    freed = (
        sum(item.get("bytes_freed", 0) for item in corpus_results)
        + runs_pruned["bytes_freed"]
        + klee_pruned["bytes_freed"]
        + known_inputs_pruned["bytes_freed"]
    )
    blockers = [blocker for item in corpus_results for blocker in item.get("blockers", [])]
    return {
        "ok": not blockers,
        "mode": "campaign-gc",
        "corpus": corpus_results,
        "runs_pruned": runs_pruned,
        "archives_pruned": archives_pruned,
        "klee_out_pruned": klee_pruned,
        "known_inputs_pruned": known_inputs_pruned,
        "solutions_pruned": solutions_pruned,
        "bytes_freed": freed,
        "blockers": blockers,
    }


def _minimize_corpus(
    *,
    name: str,
    fuzzer: Path,
    corpus: Path,
    min_files: int,
    max_mb: int,
    env: Mapping[str, str],
    merge_timeout: float = MERGE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    _reject_symlinked_root(corpus, "corpus root")
    _reject_symlinked_root(corpus.parent, "corpus parent")
    if not corpus.is_dir():
        return {"target": name, "action": "skip", "reason": "no corpus dir"}
    fresh = corpus.parent / "seeds.new"
    control = corpus.parent / "merge.ctl"
    meta_path = corpus.parent / "merge.meta"
    _reject_symlinked_root(fresh, "merge staging directory")
    _reject_merge_state_symlinks(control, meta_path)
    in_progress = control.is_file()

    files = [entry for entry in corpus.iterdir() if entry.is_file()]
    size_mb = sum(entry.stat().st_size for entry in files) / 1_048_576
    if not in_progress and len(files) <= min_files and size_mb <= max_mb:
        return {"target": name, "action": "skip", "reason": f"under thresholds ({len(files)} files, {size_mb:.1f} MB)"}
    if not fuzzer.is_file() or not os.access(fuzzer, os.X_OK):
        return {"target": name, "action": "skip", "reason": "no fuzzer binary for merge"}

    if not in_progress:
        # Fresh merge session: record the start stamp so units the fuzz rounds
        # add *during* a multi-pass merge are preserved at swap time.
        if fresh.exists():
            _contained_rmtree(fresh, corpus.parent)
        fresh.mkdir(parents=True)
        _atomic_write_managed(
            meta_path,
            json.dumps({"started_wall": time.time(), "files_at_start": len(files)}).encode("utf-8"),
            parent=corpus.parent,
        )
    fresh.mkdir(parents=True, exist_ok=True)

    # Resumable merge: crashing corpus entries abort a pass; the control file
    # lets the next pass (this GC call or a later one) continue past them.
    run = _run_command(
        [
            str(fuzzer), "-merge=1", str(fresh), str(corpus),
            f"-merge_control_file={control}",
            "-detect_leaks=0", "-rss_limit_mb=2048",
        ],
        cwd=corpus.parent,
        timeout_seconds=merge_timeout,
        env=env,
    )
    _reject_merge_state_symlinks(control, meta_path)
    merged_files = [entry for entry in fresh.iterdir() if entry.is_file()]
    if run["exit_code"] != 0 and not run["timed_out"] and not control.is_file() and not merged_files:
        # No progress and no control file: the binary never ran (e.g. loader
        # failure on a stale import) — a real blocker, not a resumable merge.
        _contained_rmtree(fresh, corpus.parent)
        _unlink_managed(meta_path, parent=corpus.parent)
        return {
            "target": name,
            "action": "failed",
            "blockers": [f"{name}: merge binary failed (exit {run['exit_code']}) — rebuild via target-build"],
            "run_exit": run["exit_code"],
        }
    if run["timed_out"] or run["exit_code"] != 0 or not merged_files:
        # Not complete — keep fresh + control for resumption; never swap a
        # partial merge (that would drop unprocessed corpus units).
        return {
            "target": name,
            "action": "in-progress",
            "files_before": len(files),
            "merged_so_far": len(merged_files),
            "note": "merge resumes next campaign-gc pass",
            "run_exit": run["exit_code"],
            "timed_out": run["timed_out"],
        }

    started_wall = 0.0
    try:
        started_wall = float(json.loads(_read_regular_file(meta_path).decode("utf-8")).get("started_wall", 0.0))
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    preserved = 0
    for entry in files:
        if entry.exists() and entry.stat().st_mtime > started_wall and not (fresh / entry.name).exists():
            shutil.copy2(entry, fresh / entry.name)
            preserved += 1

    before_bytes = sum(entry.stat().st_size for entry in files if entry.exists())
    retired = corpus.parent / "seeds.old"
    if retired.exists():
        _contained_rmtree(retired, corpus.parent)
    corpus.rename(retired)
    fresh.rename(corpus)
    _unlink_managed(control, parent=corpus.parent)
    _unlink_managed(meta_path, parent=corpus.parent)
    # symcc seen-markers reference the old content-hash names; reset so the
    # bounded sync re-walks the minimized corpus over the next rounds.
    seen_dir = corpus.parent / "symcc-state" / "seen"
    if seen_dir.is_dir():
        _contained_rmtree(seen_dir, corpus.parent)
        seen_dir.mkdir(parents=True)
    after_files = [entry for entry in corpus.iterdir() if entry.is_file()]
    freed = before_bytes - sum(entry.stat().st_size for entry in after_files)
    _contained_rmtree(retired, corpus.parent)
    return {
        "target": name,
        "action": "merged",
        "files_before": len(files),
        "files_after": len(after_files),
        "preserved_new_units": preserved,
        "bytes_freed": max(0, freed),
        "merge_exit": run["exit_code"],
    }


LEDGER_FILES = ("campaign.json", "findings.jsonl", "checkpoints.jsonl")


def _prune_runs_with_archive(
    runs_root: Path,
    *,
    keep: int,
    archive_root: Path,
    max_mb: int,
    events_tail_kb: int,
) -> dict[str, Any]:
    """Keep-N-newest pruning for run dirs, but copy each victim's durable
    core (ledgers, PoV artifacts, reports, capped events tail) into
    ``archive/runs/<run_id>/`` with a sha256 manifest before deleting."""
    if not runs_root.is_dir():
        return {
            "parent": str(runs_root), "removed": 0, "kept": 0,
            "bytes_freed": 0, "archived": 0, "archive_failures": [],
        }
    _reject_symlinked_root(runs_root, "runs root")
    _reject_symlinked_root(archive_root, "archive root")
    _reject_nested_symlink(archive_root.parent, archive_root, label="archive root")
    entries = sorted(
        (entry for entry in runs_root.iterdir() if entry.is_dir() and not entry.is_symlink()),
        key=lambda entry: entry.stat().st_mtime,
        reverse=True,
    )
    removed = 0
    freed = 0
    archived = 0
    archive_failures: list[dict[str, str]] = []
    for entry in entries[max(0, keep):MAX_PRUNE_DIRS]:
        try:
            _archive_run(
                entry,
                archive_root / entry.name,
                archive_root=archive_root,
                max_bytes=max_mb * 1_048_576,
                events_tail_bytes=events_tail_kb * 1024,
            )
            archived += 1
        except (OSError, ValueError) as exc:
            # Retention is deliberately fail-closed: source evidence stays in
            # place until a complete archive is installed.
            archive_failures.append({"run": entry.name, "detail": str(exc)})
            continue
        freed += _tree_bytes(entry)
        _contained_rmtree(entry, runs_root)
        removed += 1
    return {
        "parent": str(runs_root),
        "removed": removed,
        "kept": min(len(entries), keep),
        "bytes_freed": freed,
        "archived": archived,
        "archive_failures": archive_failures,
        "archive_root": str(archive_root),
    }


def _archive_run(
    run_dir: Path,
    dest: Path,
    *,
    archive_root: Path,
    max_bytes: int,
    events_tail_bytes: int,
) -> None:
    from hashlib import sha256

    _require_contained_real_path(run_dir, run_dir.parent, label="run candidate")
    _reject_symlinked_root(archive_root, "archive root")
    _require_lexical_child(dest, archive_root, label="archive destination")
    _ensure_archive_root(archive_root)
    if _path_lexists(dest):
        raise ValueError(f"refusing existing archive destination: {dest}")

    # Validate all source inputs before creating output.  A rejected source
    # must leave no partial archive and must not make retention delete it.
    ledger_paths = [run_dir / name for name in LEDGER_FILES]
    for source in ledger_paths:
        _validate_archive_input(source, label="ledger")
    findings_path = run_dir / "findings.jsonl"
    findings_data = _read_regular_file(findings_path) if findings_path.exists() else b""
    poc_names = _poc_names_from_findings(findings_data)
    artifact_dir = run_dir / "artifacts"
    if artifact_dir.is_symlink():
        raise ValueError(f"refusing symlinked artifact directory: {artifact_dir}")
    candidates: list[Path] = []
    if artifact_dir.is_dir():
        for item in sorted(artifact_dir.iterdir()):
            if item.is_symlink():
                raise ValueError(f"refusing symlinked artifact input: {item}")
            if item.is_file() and (item.name in poc_names or "report" in item.name.lower()):
                _validate_archive_input(item, label="artifact")
                candidates.append(item)
    events = run_dir / "events.jsonl"
    _validate_archive_input(events, label="events")

    staging = Path(tempfile.mkdtemp(prefix=f".{dest.name}.staging-", dir=archive_root))
    try:
        manifest: dict[str, Any] = {
            "run_id": run_dir.name,
            "files": {},
            "skipped": [],
            "archived_ts": time.time(),
        }
        budget = max_bytes
        for source in [*ledger_paths, *candidates]:
            if not source.exists():
                continue
            data = _read_regular_file(source)
            size = len(data)
            if size > budget:
                manifest["skipped"].append({"file": source.name, "size": size, "reason": "over archive budget"})
                continue
            relative = Path("artifacts") / source.name if source.parent == artifact_dir else Path(source.name)
            _write_staged_file(staging, relative, data)
            manifest["files"][relative.as_posix()] = {"size": size, "sha256": sha256(data).hexdigest()}
            budget -= size

        if events.exists() and budget > 0:
            data = _read_regular_file(events)
            tail = data[-min(len(data), events_tail_bytes, budget):]
            _write_staged_file(staging, Path("events-tail.jsonl"), tail)
            manifest["files"]["events-tail.jsonl"] = {
                "size": len(tail),
                "sha256": sha256(tail).hexdigest(),
                "truncated": len(tail) < len(data),
            }
        _write_staged_file(
            staging,
            Path("manifest.json"),
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        # ``staging`` is a freshly-created sibling, so the rename makes a
        # complete archive visible in one operation.
        if _path_lexists(dest):
            raise ValueError(f"refusing existing archive destination: {dest}")
        os.replace(staging, dest)
    except BaseException:
        if staging.exists() and not staging.is_symlink():
            _contained_rmtree(staging, archive_root)
        raise


def _path_lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _ensure_archive_root(archive_root: Path) -> None:
    """Create the managed archive root without accepting a link on the way."""
    parent = archive_root.parent
    if parent.is_symlink():
        raise ValueError(f"refusing symlinked archive output component: {parent}")
    archive_root.mkdir(parents=True, exist_ok=True)
    _reject_symlinked_root(archive_root, "archive root")
    _reject_nested_symlink(parent, archive_root, label="archive root")


def _validate_archive_input(source: Path, *, label: str) -> bool:
    if source.is_symlink():
        raise ValueError(f"refusing symlinked {label} input: {source}")
    if not source.exists():
        return False
    mode = source.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise ValueError(f"refusing non-regular {label} input: {source}")
    return True


def _read_regular_file(path: Path) -> bytes:
    """Read one stable regular file without following a final symlink."""
    if path.is_symlink():
        raise ValueError(f"refusing symlinked input: {path}")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"refusing non-regular input: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError(f"refusing changed input: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(descriptor)


def _poc_names_from_findings(data: bytes) -> set[str]:
    names: set[str] = set()
    for line in data.decode("utf-8", errors="replace").splitlines():
        try:
            poc = json.loads(line).get("poc_artifact")
        except (json.JSONDecodeError, AttributeError):
            continue
        if isinstance(poc, str) and poc:
            names.add(poc)
    return names


def _write_staged_file(staging: Path, relative: Path, data: bytes) -> None:
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"invalid archive output path: {relative}")
    target = staging / relative
    _reject_nested_symlink(staging, target.parent, label="archive output component")
    target.parent.mkdir(parents=True, exist_ok=True)
    if _path_lexists(target):
        raise ValueError(f"refusing existing archive output: {target}")
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
    finally:
        os.close(descriptor)


def _prune_oldest(parent: Path, *, keep: int) -> dict[str, Any]:
    _reject_symlinked_root(parent, "prune root")
    if not parent.is_dir():
        return {"parent": str(parent), "removed": 0, "kept": 0, "bytes_freed": 0}
    entries = sorted(
        (entry for entry in parent.iterdir() if entry.is_dir() and not entry.is_symlink()),
        key=lambda entry: entry.stat().st_mtime,
        reverse=True,
    )
    removed = 0
    freed = 0
    for entry in entries[max(0, keep):MAX_PRUNE_DIRS]:
        freed += _tree_bytes(entry)
        _contained_rmtree(entry, parent)
        removed += 1
    return {"parent": str(parent), "removed": removed, "kept": min(len(entries), keep), "bytes_freed": freed}


def _tree_bytes(path: Path) -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for filename in filenames:
            try:
                total += (Path(dirpath) / filename).stat().st_size
            except OSError:
                continue
    return total


def _contained_rmtree(path: Path, parent: Path) -> None:
    resolved = _require_contained_real_path(path, parent, label="delete candidate")
    shutil.rmtree(resolved, ignore_errors=True)


def _reject_merge_state_symlinks(control: Path, meta_path: Path) -> None:
    for path in (control, meta_path):
        if path.is_symlink():
            raise ValueError(f"refusing symlinked merge state: {path}")


def _atomic_write_managed(path: Path, data: bytes, *, parent: Path) -> None:
    _require_lexical_child(path, parent, label="managed state")
    _reject_nested_symlink(parent, path, label="managed state")
    if path.is_symlink():
        raise ValueError(f"refusing symlinked managed state: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if path.is_symlink():
            raise ValueError(f"refusing symlinked managed state: {path}")
        os.replace(temp_path, path)
    except BaseException:
        if temp_path.exists() and not temp_path.is_symlink():
            temp_path.unlink()
        raise


def _unlink_managed(path: Path, *, parent: Path) -> None:
    _require_lexical_child(path, parent, label="managed state")
    _reject_nested_symlink(parent, path, label="managed state")
    if path.is_symlink():
        raise ValueError(f"refusing symlinked managed state: {path}")
    path.unlink(missing_ok=True)


def _reject_symlinked_root(path: Path, label: str) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing symlinked {label}: {path}")


def _require_lexical_child(path: Path, parent: Path, *, label: str) -> None:
    try:
        path.relative_to(parent)
    except ValueError as exc:
        raise ValueError(f"refusing {label} outside managed root: {path}") from exc


def _reject_nested_symlink(parent: Path, path: Path, *, label: str) -> None:
    _require_lexical_child(path, parent, label=label)
    if parent.is_symlink():
        raise ValueError(f"refusing symlinked {label}: {parent}")
    current = parent
    for part in path.relative_to(parent).parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"refusing symlinked {label}: {current}")


def _require_contained_real_path(path: Path, parent: Path, *, label: str) -> Path:
    """Resolve a real deletion candidate and prove it is below ``parent``."""
    _reject_symlinked_root(parent, "managed root")
    if path.is_symlink():
        raise ValueError(f"refusing symlinked {label}: {path}")
    _reject_nested_symlink(parent, path, label=label)
    try:
        resolved = path.resolve(strict=True)
        parent_resolved = parent.resolve(strict=True)
        resolved.relative_to(parent_resolved)
    except (OSError, ValueError) as exc:
        raise ValueError(f"refusing {label} outside managed root: {path}") from exc
    if resolved == parent_resolved:
        raise ValueError(f"refusing to delete managed root itself: {resolved}")
    return resolved

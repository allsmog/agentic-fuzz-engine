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
import shutil
import time
from pathlib import Path
from typing import Any, Mapping

from .campaign_rounds import default_asan_options
from .runtime_backends import _run_command
from .workspace import load_policy, resolve_workspace_root

MERGE_TIMEOUT_SECONDS = 900
MAX_PRUNE_DIRS = 500


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
    names = [target.removeprefix("localfuzz/c/")] if target else (
        sorted(entry.name for entry in work_dir.iterdir() if entry.is_dir()) if work_dir.is_dir() else []
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

    resolved_data_root = Path(data_root).expanduser().resolve() if data_root else root / "data"
    runs_root = resolved_data_root / "runs"
    archive_root = resolved_data_root / "archive" / "runs"
    runs_pruned = _prune_runs_with_archive(
        runs_root,
        keep=run_retention,
        archive_root=archive_root,
        max_mb=int(policy.get("archive_max_mb", 64)),
        events_tail_kb=int(policy.get("archive_events_tail_kb", 256)),
    )
    archives_pruned = _prune_oldest(archive_root, keep=int(policy.get("archive_retention", 100)))
    klee_pruned = _prune_oldest(root / "klee" / "klee-ng-out", keep=klee_retention)

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
    if not corpus.is_dir():
        return {"target": name, "action": "skip", "reason": "no corpus dir"}
    fresh = corpus.parent / "seeds.new"
    control = corpus.parent / "merge.ctl"
    meta_path = corpus.parent / "merge.meta"
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
        meta_path.write_text(json.dumps({"started_wall": time.time(), "files_at_start": len(files)}), encoding="utf-8")
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
    merged_files = [entry for entry in fresh.iterdir() if entry.is_file()]
    if run["exit_code"] != 0 and not run["timed_out"] and not control.is_file() and not merged_files:
        # No progress and no control file: the binary never ran (e.g. loader
        # failure on a stale import) — a real blocker, not a resumable merge.
        _contained_rmtree(fresh, corpus.parent)
        meta_path.unlink(missing_ok=True)
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
        started_wall = float(json.loads(meta_path.read_text(encoding="utf-8")).get("started_wall", 0.0))
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
    control.unlink(missing_ok=True)
    meta_path.unlink(missing_ok=True)
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
        return {"parent": str(runs_root), "removed": 0, "kept": 0, "bytes_freed": 0, "archived": 0}
    entries = sorted(
        (entry for entry in runs_root.iterdir() if entry.is_dir()),
        key=lambda entry: entry.stat().st_mtime,
        reverse=True,
    )
    removed = 0
    freed = 0
    archived = 0
    for entry in entries[max(0, keep):MAX_PRUNE_DIRS]:
        try:
            _archive_run(entry, archive_root / entry.name, max_bytes=max_mb * 1_048_576, events_tail_bytes=events_tail_kb * 1024)
            archived += 1
        except OSError:
            pass  # archive is best-effort; retention must still hold the disk bound
        freed += _tree_bytes(entry)
        _contained_rmtree(entry, runs_root)
        removed += 1
    return {
        "parent": str(runs_root),
        "removed": removed,
        "kept": min(len(entries), keep),
        "bytes_freed": freed,
        "archived": archived,
        "archive_root": str(archive_root),
    }


def _archive_run(run_dir: Path, dest: Path, *, max_bytes: int, events_tail_bytes: int) -> None:
    from hashlib import sha256

    dest.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {"run_id": run_dir.name, "files": {}, "skipped": [], "archived_ts": time.time()}
    budget = max_bytes

    # PoV artifacts referenced by findings, and report artifacts, first —
    # they are the smallest and the least reconstructible.
    poc_names: set[str] = set()
    findings_path = run_dir / "findings.jsonl"
    if findings_path.is_file():
        for line in findings_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                poc = json.loads(line).get("poc_artifact")
            except (json.JSONDecodeError, AttributeError):
                continue
            if isinstance(poc, str) and poc:
                poc_names.add(poc)
    artifact_dir = run_dir / "artifacts"
    candidates: list[Path] = []
    if artifact_dir.is_dir():
        for item in sorted(artifact_dir.iterdir()):
            if not item.is_file() or item.is_symlink():
                continue
            if item.name in poc_names or "report" in item.name.lower():
                candidates.append(item)
    for source in [run_dir / name for name in LEDGER_FILES] + candidates:
        if not source.is_file() or source.is_symlink():
            continue
        size = source.stat().st_size
        if size > budget:
            manifest["skipped"].append({"file": source.name, "size": size, "reason": "over archive budget"})
            continue
        target = dest / ("artifacts/" + source.name if source.parent == artifact_dir else source.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        manifest["files"][str(target.relative_to(dest))] = {
            "size": size,
            "sha256": sha256(source.read_bytes()).hexdigest(),
        }
        budget -= size

    events = run_dir / "events.jsonl"
    if events.is_file() and budget > 0:
        data = events.read_bytes()
        tail = data[-min(len(data), events_tail_bytes, budget):]
        (dest / "events-tail.jsonl").write_bytes(tail)
        manifest["files"]["events-tail.jsonl"] = {
            "size": len(tail),
            "sha256": sha256(tail).hexdigest(),
            "truncated": len(tail) < len(data),
        }
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _prune_oldest(parent: Path, *, keep: int) -> dict[str, Any]:
    if not parent.is_dir():
        return {"parent": str(parent), "removed": 0, "kept": 0, "bytes_freed": 0}
    entries = sorted(
        (entry for entry in parent.iterdir() if entry.is_dir()),
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
    resolved = path.resolve()
    parent_resolved = parent.resolve()
    if not str(resolved).startswith(str(parent_resolved) + os.sep):
        raise ValueError(f"refusing to delete {resolved}: outside {parent_resolved}")
    shutil.rmtree(resolved, ignore_errors=True)

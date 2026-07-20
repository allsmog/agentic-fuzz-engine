"""Per-seed weighted corpus scheduling (the FuzzDB/BIT tier).

The round loop's fuzzer picks mutation bases uniformly from whatever the
corpus holds; nothing concentrates energy on the seeds that already execute
dangerous code. This module closes that gap with three bounded pieces:

- a **per-seed coverage index** (``work/<t>/seed-cov.jsonl``): each corpus
  entry replayed once through ``-runs=0 -print_coverage=1``, its covered
  functions intersected with a small *function universe* (sink methods,
  agent-authored bits, known crash frames) so rows stay tiny;
- **BIT scoring**: every sink row is an implicit bug hypothesis (weight
  scaled by its primitive), agents may add explicit hypotheses in
  ``work/<t>/bits.json``; a seed's weight sums the hypotheses it covers.
  Exploited hypotheses are *deprioritized, never removed* — their
  contribution collapses to +1 (deprioritize-on-PoV);
- a **focus corpus split**: a slice of round fuzz time runs with the top-K
  weighted seeds as the write-corpus (libFuzzer writes new units into the
  first dir argument), then new units are linked back into the main corpus
  preserving their content-hash names.

Everything is policy-gated (``weights.enabled``, default off), strictly
budgeted, and advisory: an un-indexed seed scores neutral, a failed step
becomes a blocker note, and the round proceeds exactly as before.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .sink_scan import PRIMITIVE_WEIGHT

SEED_COV_FILE = "seed-cov.jsonl"
SEED_COV_STATE_FILE = "seed-cov-state.json"
SEED_WEIGHTS_FILE = "seed-weights.json"
BITS_FILE = "bits.json"
FOCUS_DIR = "focus-seeds"
DEFAULT_REPLAY_TIMEOUT = 20.0
MAX_REBIND_HASH_BYTES = 256 * 1024 * 1024
MAX_TOP_ENTRIES = 256

_COVERED_LINE_RE = re.compile(r"^COVERED_FUNC\b.*$", re.MULTILINE)
_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*")
_LINE_NOISE_TOKENS = {"COVERED_FUNC", "hits", "edges", "PCs", "in"}


def covered_function_names(output: str) -> set[str]:
    """Identifier tokens from COVERED_FUNC lines (robust to demangling layout)."""
    names: set[str] = set()
    for match in _COVERED_LINE_RE.finditer(output):
        for token in _IDENTIFIER_RE.findall(match.group(0)):
            if token not in _LINE_NOISE_TOKENS and not token.isdigit():
                names.add(token)
    return names


def replay_entry_coverage(
    *,
    fuzzer: Path,
    entry: Path,
    env: Mapping[str, str] | None = None,
    timeout: float = DEFAULT_REPLAY_TIMEOUT,
) -> set[str] | None:
    """One bounded ``-runs=0 -print_coverage=1`` replay of a single input.

    The entry is staged into a one-file temporary directory: libFuzzer's
    single-file path ("Running 1 inputs") executes without collecting
    features, so ``-print_coverage=1`` would report every function
    uncovered. The corpus-directory load path does collect features.

    Returns the covered-function token set, or None when the replay timed
    out / failed to launch (callers must treat None as "unknown", never as
    "covers nothing").
    """
    environment = dict(env) if env is not None else dict(os.environ)
    # COVERED_FUNC names resolve through the sanitizer symbolizer; the
    # campaign default symbolize=0 would leave the dump empty.
    environment["ASAN_OPTIONS"] = re.sub(
        r"symbolize=0", "symbolize=1", environment.get("ASAN_OPTIONS", "symbolize=1")
    )
    # Distro llvm-symbolizer builds may query remote debuginfod servers per
    # PC; without that egress every lookup stalls until the TCP timeout and
    # the bounded replay dies. Local debug info is all we need.
    environment.setdefault("DEBUGINFOD_URLS", "")
    try:
        with tempfile.TemporaryDirectory(prefix="afe-replay-") as staging:
            staged = Path(staging) / entry.name
            try:
                os.link(entry, staged)
            except OSError:
                shutil.copyfile(entry, staged)
            completed = subprocess.run(
                [str(fuzzer), "-runs=0", "-print_coverage=1", staging],
                capture_output=True,
                timeout=max(1.0, float(timeout)),
                env=environment,
            )
    except (subprocess.TimeoutExpired, OSError):
        return None
    output = ((completed.stderr or b"") + b"\n" + (completed.stdout or b"")).decode(
        "utf-8", errors="replace"
    )
    return covered_function_names(output)


def resolve_sinks_jsonl(root: Path, name: str, policy: Mapping[str, Any]) -> Path:
    """Sinks JSONL resolution shared with the frontier: per-target fuzz.json
    override first, then policy ``frontier.sinks_jsonl``, then the default."""
    fuzz_json = root / "targets" / "c" / name / ".localfuzz" / "fuzz.json"
    if fuzz_json.is_file():
        try:
            configured = json.loads(fuzz_json.read_text(encoding="utf-8")).get("sinks_jsonl")
        except (OSError, json.JSONDecodeError):
            configured = None
        if isinstance(configured, str) and configured:
            return Path(configured) if configured.startswith("/") else root / configured
    frontier_policy = policy.get("frontier", {}) if isinstance(policy.get("frontier"), dict) else {}
    configured = frontier_policy.get("sinks_jsonl")
    if isinstance(configured, str) and configured:
        return Path(configured) if configured.startswith("/") else root / configured
    return root / "data" / "sink-scan.jsonl"


def weights_policy(policy: Mapping[str, Any], fuzz_cfg: Mapping[str, Any]) -> dict[str, Any]:
    """Effective weights knobs: policy section overlaid with the per-target
    ``fuzz.json {"weights": {...}}`` block."""
    merged = dict(policy.get("weights", {})) if isinstance(policy.get("weights"), dict) else {}
    override = fuzz_cfg.get("weights")
    if isinstance(override, dict):
        merged.update(override)
    return merged


def load_bits(work_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Agent-authored bug hypotheses from ``bits.json`` (schema-tolerant)."""
    path = work_dir / BITS_FILE
    if not path.is_file():
        return [], []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], [f"unreadable bits.json ignored: {exc}"]
    rows = payload.get("bits") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return [], ["bits.json has no 'bits' list; ignored"]
    bits: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or not row.get("func_name"):
            continue
        bits.append(
            {
                "id": str(row.get("id") or row.get("func_name")),
                "func_name": str(row["func_name"]),
                "weight": float(row.get("weight") or 8),
                "key_conditions": [str(f) for f in row.get("key_conditions") or [] if f],
                "should_be_taken": [str(f) for f in row.get("should_be_taken") or [] if f],
                "deprioritized": bool(row.get("deprioritized")),
            }
        )
    return bits, []


def build_function_universe(
    *,
    root: Path,
    name: str,
    work_dir: Path,
    policy: Mapping[str, Any],
) -> tuple[set[str], str, list[dict[str, Any]], list[str]]:
    """(universe, universe_sha, sink_rows, blockers).

    The universe is the only vocabulary the per-seed index stores — sink
    methods, bits functions, and known crash-state frames — so index rows
    stay a few hundred bytes even for image-sized corpora.
    """
    from .known_crashes import load_known
    from .sink_coverage import _load_sink_rows

    blockers: list[str] = []
    sinks_path = resolve_sinks_jsonl(root, name, policy)
    sink_rows: list[dict[str, Any]] = []
    if sinks_path.is_file():
        sink_rows = _load_sink_rows(sinks_path)
    else:
        blockers.append(f"missing sinks JSONL for weights universe: {sinks_path}")

    universe: set[str] = {str(row["method"]) for row in sink_rows if row.get("method")}
    bits, bits_blockers = load_bits(work_dir)
    blockers.extend(bits_blockers)
    for bit in bits:
        universe.add(bit["func_name"])
        universe.update(bit["key_conditions"])
        universe.update(bit["should_be_taken"])
    for entry in load_known(work_dir).values():
        for frame in entry.get("crash_state") or []:
            universe.add(str(frame))

    digest = sha256("\n".join(sorted(universe)).encode("utf-8")).hexdigest()[:16]
    return universe, digest, sink_rows, blockers


# ---------------------------------------------------------------------------
# Per-seed coverage index


def _load_index_state(work_dir: Path) -> dict[str, Any]:
    path = work_dir / SEED_COV_STATE_FILE
    if not path.is_file():
        return {"version": 1, "universe_sha": None, "last_round": None, "indexed": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "universe_sha": None, "last_round": None, "indexed": {}}
    if not isinstance(payload.get("indexed"), dict):
        payload["indexed"] = {}
    return payload


def _save_index_state(work_dir: Path, state: dict[str, Any]) -> None:
    path = work_dir / SEED_COV_STATE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_seed_cov_rows(work_dir: Path) -> dict[str, dict[str, Any]]:
    """name -> row for every index line (later lines win on duplicates)."""
    path = work_dir / SEED_COV_FILE
    rows: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return rows
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict) and row.get("name"):
                    rows[str(row["name"])] = row
    except OSError:
        return rows
    return rows


def _append_index_rows(work_dir: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    path = work_dir / SEED_COV_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _compact_index(work_dir: Path, live_rows: dict[str, dict[str, Any]]) -> None:
    """seed-cov.jsonl is a cache, not a findings ledger: when most rows are
    dead (post GC-merge renames) it is atomically rewritten compacted."""
    path = work_dir / SEED_COV_FILE
    tmp = path.with_suffix(".jsonl.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        for name in sorted(live_rows):
            handle.write(json.dumps(live_rows[name], sort_keys=True) + "\n")
    tmp.replace(path)


def _content_sha(path: Path) -> str | None:
    try:
        return sha256(path.read_bytes()).hexdigest()[:20]
    except OSError:
        return None


def update_seed_cov_index(
    *,
    work_dir: Path,
    fuzzer: Path,
    corpus: Path,
    universe: set[str],
    universe_sha: str,
    round_index: int | None = None,
    max_new: int = 48,
    max_seconds: float = 180.0,
    per_input_timeout: float = 20.0,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Index un-indexed corpus entries (newest first, triple-budgeted) and
    rebind rows whose entries were renamed by the GC ``-merge=1`` swap."""
    state = _load_index_state(work_dir)
    if state.get("universe_sha") != universe_sha:
        # Vocabulary changed (new bits/sinks): old rows would under-report
        # coverage of the new functions. Invalidate and rebuild incrementally.
        state = {"version": 1, "universe_sha": universe_sha, "last_round": None, "indexed": {}}
        if (work_dir / SEED_COV_FILE).is_file():
            _compact_index(work_dir, {})
    indexed: dict[str, str] = dict(state.get("indexed") or {})
    rows = load_seed_cov_rows(work_dir)

    corpus_files = [entry for entry in corpus.iterdir() if entry.is_file()] if corpus.is_dir() else []
    corpus_names = {entry.name for entry in corpus_files}

    # Rebind pass: GC merge renames surviving units to fresh content hashes;
    # match orphaned rows to unknown corpus files by (size, content sha) so
    # their replay cost is not paid twice. Size prefilter keeps hashing cheap.
    rebound = 0
    orphan_by_size: dict[int, list[str]] = {}
    for name in list(indexed):
        if name not in corpus_names:
            row = rows.get(name)
            if row and row.get("sha") and isinstance(row.get("size"), int):
                orphan_by_size.setdefault(int(row["size"]), []).append(name)
            del indexed[name]
    new_rows: list[dict[str, Any]] = []
    if orphan_by_size:
        orphan_sha_to_name = {
            str(rows[name]["sha"]): name for names in orphan_by_size.values() for name in names
        }
        hashed_bytes = 0
        for entry in corpus_files:
            if entry.name in indexed:
                continue
            size = entry.stat().st_size
            if size not in orphan_by_size or hashed_bytes > MAX_REBIND_HASH_BYTES:
                continue
            hashed_bytes += size
            digest = _content_sha(entry)
            old_name = orphan_sha_to_name.get(digest or "")
            if digest and old_name:
                old_row = rows[old_name]
                row = {"name": entry.name, "sha": digest, "size": size, "funcs": old_row.get("funcs") or []}
                if old_row.get("error"):
                    row["error"] = old_row["error"]
                rows[entry.name] = row
                new_rows.append(row)
                indexed[entry.name] = digest
                rebound += 1

    # Index pass: newest first so the highest-signal units index first.
    candidates = sorted(
        (entry for entry in corpus_files if entry.name not in indexed),
        key=lambda entry: entry.stat().st_mtime,
        reverse=True,
    )
    deadline = time.monotonic() + max(1.0, float(max_seconds))
    new_indexed = 0
    timeouts = 0
    for entry in candidates:
        if new_indexed >= max(0, int(max_new)) or time.monotonic() >= deadline:
            break
        digest = _content_sha(entry)
        if digest is None:
            continue
        covered = replay_entry_coverage(fuzzer=fuzzer, entry=entry, env=env, timeout=per_input_timeout)
        row: dict[str, Any] = {"name": entry.name, "sha": digest, "size": entry.stat().st_size}
        if covered is None:
            # Record the failure so a pathological entry is not re-replayed
            # every round; it scores neutral (funcs=[]) forever.
            row["funcs"] = []
            row["error"] = "replay-timeout"
            timeouts += 1
        else:
            row["funcs"] = sorted(covered & universe)
        rows[entry.name] = row
        new_rows.append(row)
        indexed[entry.name] = digest
        new_indexed += 1

    _append_index_rows(work_dir, new_rows)
    live_rows = {name: rows[name] for name in rows if name in corpus_names and name in indexed}
    total_lines = _count_index_lines(work_dir)
    if total_lines and len(live_rows) < total_lines / 2:
        _compact_index(work_dir, live_rows)

    state["universe_sha"] = universe_sha
    state["indexed"] = indexed
    if round_index is not None:
        state["last_round"] = round_index
    _save_index_state(work_dir, state)
    return {
        "indexed_total": len(indexed),
        "new_indexed": new_indexed,
        "rebound": rebound,
        "timeouts": timeouts,
        "unindexed_remaining": max(0, len(corpus_names) - len(indexed)),
    }


def _count_index_lines(work_dir: Path) -> int:
    path = work_dir / SEED_COV_FILE
    if not path.is_file():
        return 0
    try:
        with path.open("r", encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


# ---------------------------------------------------------------------------
# BIT scoring


def compute_seed_weights(
    *,
    work_dir: Path,
    sink_rows: list[dict[str, Any]],
    bits: list[dict[str, Any]],
    universe_sha: str,
    round_index: int | None = None,
    bit_weight_default: float = 8.0,
    top_k: int = 64,
) -> dict[str, Any]:
    """Score every indexed seed against the hypothesis set and persist the
    ranked report (``seed-weights.json``). Pure function of on-disk state."""
    from .known_crashes import load_known
    from .sink_status import load_sink_status

    # Deprioritized functions: already exploited (sink lifecycle), already
    # crashed (known root signatures), or explicitly marked by an agent.
    # Reads existing ledgers; never writes them.
    deprioritized: set[str] = set()
    for entry in load_sink_status(work_dir).get("sinks", {}).values():
        if entry.get("status") == "exploited" and entry.get("method"):
            deprioritized.add(str(entry["method"]))
    for entry in load_known(work_dir).values():
        for frame in entry.get("crash_state") or []:
            deprioritized.add(str(frame))

    # Implicit hypotheses: unique sink methods at their strongest primitive.
    max_primitive = max(PRIMITIVE_WEIGHT.values()) if PRIMITIVE_WEIGHT else 1
    implicit: dict[str, float] = {}
    for row in sink_rows:
        method = str(row.get("method") or "")
        if not method:
            continue
        weight = bit_weight_default * PRIMITIVE_WEIGHT.get(str(row.get("primitive") or ""), 1) / max_primitive
        implicit[method] = max(implicit.get(method, 0.0), weight)

    # Collapse everything into per-function additive contributions so scoring
    # is one pass over each seed's (tiny) function list.
    func_weight: dict[str, float] = {}
    bits_deprioritized = 0
    for method, weight in implicit.items():
        if method in deprioritized:
            bits_deprioritized += 1
            func_weight[method] = func_weight.get(method, 0.0) + 1.0
        else:
            func_weight[method] = func_weight.get(method, 0.0) + weight
    for bit in bits:
        if bit["deprioritized"] or bit["func_name"] in deprioritized:
            bits_deprioritized += 1
            func_weight[bit["func_name"]] = func_weight.get(bit["func_name"], 0.0) + 1.0
            continue
        weight = float(bit["weight"])
        func_weight[bit["func_name"]] = func_weight.get(bit["func_name"], 0.0) + weight
        for func in bit["key_conditions"]:
            func_weight[func] = func_weight.get(func, 0.0) + weight / 2.0
        for func in bit["should_be_taken"]:
            func_weight[func] = func_weight.get(func, 0.0) + weight / 4.0

    rows = load_seed_cov_rows(work_dir)
    weights: dict[str, float] = {}
    for name, row in rows.items():
        score = 1.0
        for func in row.get("funcs") or []:
            score += func_weight.get(str(func), 0.0)
        weights[name] = round(score, 3)

    ranked = sorted(weights.items(), key=lambda item: (-item[1], item[0]))
    top = [{"name": name, "score": score} for name, score in ranked[: min(int(top_k), MAX_TOP_ENTRIES)]]
    scores = [score for _, score in ranked]
    report = {
        "version": 1,
        "updated_round": round_index,
        "universe_sha": universe_sha,
        "indexed_total": len(weights),
        "bits_total": len(implicit) + len(bits),
        "bits_deprioritized": bits_deprioritized,
        "score_min": min(scores) if scores else None,
        "score_max": max(scores) if scores else None,
        "score_mean": round(sum(scores) / len(scores), 3) if scores else None,
        "top": top,
    }
    path = work_dir / SEED_WEIGHTS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    report["weights"] = weights
    return report


def load_seed_weights(work_dir: Path) -> dict[str, Any]:
    path = work_dir / SEED_WEIGHTS_FILE
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


# ---------------------------------------------------------------------------
# Focus corpus split


def build_focus_dir(
    *,
    work_dir: Path,
    corpus: Path,
    top: list[dict[str, Any]],
    top_k: int = 64,
) -> dict[str, Any]:
    """Rebuild ``work/<t>/focus-seeds`` from the current ranked top-K.

    Rebuilt from scratch every weighted round so it never holds links into a
    retired GC swap dir while in use.
    """
    focus = work_dir / FOCUS_DIR
    if focus.exists():
        shutil.rmtree(focus, ignore_errors=True)
    focus.mkdir(parents=True, exist_ok=True)
    baseline: list[str] = []
    for item in top[: max(1, int(top_k))]:
        name = str(item.get("name") or "")
        source = corpus / name
        if not name or not source.is_file():
            continue
        destination = focus / name
        try:
            os.link(source, destination)
        except OSError:
            try:
                shutil.copy2(source, destination)
            except OSError:
                continue
        baseline.append(name)
    return {"focus_dir": str(focus), "baseline": baseline, "size": len(baseline)}


def merge_back_focus(*, focus_dir: Path, corpus: Path, baseline: set[str]) -> dict[str, Any]:
    """Link every non-baseline unit back into the main corpus, preserving
    libFuzzer's content-hash names (name == identity; fresh names mean the
    SymCC seen-markers pick the units up next sync)."""
    merged = 0
    if not focus_dir.is_dir():
        return {"merged_new": 0}
    for entry in focus_dir.iterdir():
        if not entry.is_file() or entry.name in baseline:
            continue
        destination = corpus / entry.name
        if destination.exists():
            continue
        try:
            os.link(entry, destination)
        except OSError:
            try:
                shutil.copy2(entry, destination)
            except OSError:
                continue
        merged += 1
    return {"merged_new": merged}


def prepare_focus_round(
    *,
    work_dir: Path,
    corpus: Path,
    policy_weights: Mapping[str, Any],
) -> dict[str, Any]:
    """Round-head decision: build the focus set from the *previous* round's
    weights (Atlantis rebalances asynchronously too). Returns
    ``{"ready": False, "reason": ...}`` until the index has enough entries."""
    report = load_seed_weights(work_dir)
    min_indexed = int(policy_weights.get("focus_min_indexed", 32))
    indexed_total = int(report.get("indexed_total") or 0)
    if indexed_total < min_indexed:
        return {"ready": False, "reason": f"indexed {indexed_total} < focus_min_indexed {min_indexed}"}
    top = report.get("top") or []
    if not top:
        return {"ready": False, "reason": "no ranked seeds yet"}
    built = build_focus_dir(
        work_dir=work_dir,
        corpus=corpus,
        top=top,
        top_k=int(policy_weights.get("focus_top_k", 64)),
    )
    if not built["size"]:
        return {"ready": False, "reason": "ranked seeds absent from corpus (post-GC rename?)"}
    return {"ready": True, **built}


def update_weights_after_round(
    *,
    engine_state: Any,
    run_id: str,
    root: Path,
    name: str,
    work_dir: Path,
    fuzzer: Path,
    corpus: Path,
    round_index: int,
    policy: Mapping[str, Any],
    policy_weights: Mapping[str, Any],
    new_root_sigs: int,
    sink_changes: int,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Round-tail bookkeeping: incremental index update, then a rebalance
    when a trigger fired (new root cause, sink transition, bits.json edit,
    or the periodic schedule). Never raises."""
    blockers: list[str] = []
    universe, universe_sha, sink_rows, universe_blockers = build_function_universe(
        root=root, name=name, work_dir=work_dir, policy=policy
    )
    blockers.extend(universe_blockers)
    index = update_seed_cov_index(
        work_dir=work_dir,
        fuzzer=fuzzer,
        corpus=corpus,
        universe=universe,
        universe_sha=universe_sha,
        round_index=round_index,
        max_new=int(policy_weights.get("cov_max_new_per_round", 48)),
        max_seconds=float(policy_weights.get("cov_max_seconds", 180)),
        per_input_timeout=float(policy_weights.get("cov_per_input_timeout", 20)),
        env=env,
    )

    bits, bits_blockers = load_bits(work_dir)
    blockers.extend(bits_blockers)
    state = _load_index_state(work_dir)
    bits_path = work_dir / BITS_FILE
    bits_mtime = bits_path.stat().st_mtime if bits_path.is_file() else None
    rebalance_every = max(1, int(policy_weights.get("rebalance_every", 1)))
    previous = load_seed_weights(work_dir)
    triggers = []
    if new_root_sigs:
        triggers.append("new-root-signatures")
    if sink_changes:
        triggers.append("sink-status-changed")
    if bits_mtime is not None and bits_mtime != state.get("bits_mtime"):
        triggers.append("bits-changed")
    if round_index % rebalance_every == 0 or not previous:
        triggers.append("schedule")
    if index["new_indexed"] or index["rebound"]:
        triggers.append("index-grew")

    rebalanced = False
    report: dict[str, Any] = previous
    if triggers:
        report = compute_seed_weights(
            work_dir=work_dir,
            sink_rows=sink_rows,
            bits=bits,
            universe_sha=universe_sha,
            round_index=round_index,
            bit_weight_default=float(policy_weights.get("bit_weight_default", 8)),
            top_k=int(policy_weights.get("focus_top_k", 64)),
        )
        rebalanced = True
        if bits_mtime is not None:
            state = _load_index_state(work_dir)
            state["bits_mtime"] = bits_mtime
            _save_index_state(work_dir, state)
        if engine_state is not None:
            try:
                engine_state.event_append(
                    run_id,
                    "seed_weights_rebalanced",
                    {
                        "round": round_index,
                        "indexed_total": index["indexed_total"],
                        "new_indexed": index["new_indexed"],
                        "bits_total": report.get("bits_total"),
                        "bits_deprioritized": report.get("bits_deprioritized"),
                        "top": (report.get("top") or [])[:10],
                        "triggers": triggers,
                    },
                )
            except Exception:
                pass
    return {
        "index": index,
        "rebalanced": rebalanced,
        "triggers": triggers,
        "bits_total": report.get("bits_total"),
        "bits_deprioritized": report.get("bits_deprioritized"),
        "blockers": blockers,
    }

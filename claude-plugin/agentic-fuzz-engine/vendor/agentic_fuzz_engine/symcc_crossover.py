"""SymCC solution crossover: re-apply learned byte patches as cheap mutations.

The concolic lane solves branch constraints into concrete inputs, but each
solution is spent on the one corpus entry it was derived from. The byte-level
difference between a SymCC child and its parent *is* the solved constraint —
"offset 17 must be 0xFF", "the header length field must grow by 4" — and that
knowledge transfers: applied to *other* corpus entries it flips the same
branch without another concolic execution.

This module records those solution deltas (``work/<t>/symcc-state/
solutions.jsonl``, a bounded rewritable cache), applies random cached
solutions to the newest corpus entries each round as a pure-python mutation
lane (``symx-<sha20>`` offspring, Atlantis-style sequential application with
every intermediate emitted), and harvests multi-byte patch runs into the
target dictionary. Deterministic per (target, round); disk-guarded; never
required for a round to succeed.
"""

from __future__ import annotations

import base64
import binascii
import json
import random
import time
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .runtime_backends import MIN_FREE_DISK_GB, check_disk_headroom

SOLUTIONS_FILE = "solutions.jsonl"
CROSSOVER_STATS_FILE = "crossover-stats.json"
EFFECTIVENESS_FILE = "symx-effectiveness.json"
DEFAULT_MAX_PATCHES = 16
DEFAULT_MAX_TAIL_BYTES = 64
DEFAULT_SOLUTIONS_MAX = 512
DEFAULT_MAX_BLOB_BYTES = 1_048_576
MIN_DICT_RUN_BYTES = 4
DICT_TOKEN_MAX_BYTES = 64


def extract_solution(
    parent: bytes,
    child: bytes,
    *,
    max_patches: int = DEFAULT_MAX_PATCHES,
    max_tail_bytes: int = DEFAULT_MAX_TAIL_BYTES,
) -> dict[str, Any] | None:
    """Byte-delta between a concolic child and its parent, or None when the
    child is too restructured to be reusable crossover material."""
    len_delta = len(child) - len(parent)
    if abs(len_delta) > max(0, int(max_tail_bytes)):
        return None
    prefix = min(len(parent), len(child))
    patches = [[index, child[index]] for index in range(prefix) if parent[index] != child[index]]
    if len(patches) > max(0, int(max_patches)):
        return None
    tail_b64 = None
    if len_delta > 0:
        tail_b64 = base64.b64encode(child[len(parent):]).decode("ascii")
    if not patches and len_delta == 0:
        return None
    return {
        "parent_sha": sha256(parent).hexdigest()[:20],
        "len_delta": len_delta,
        "patches": patches,
        "tail_b64": tail_b64,
    }


def record_solutions(state_dir: Path, records: list[dict[str, Any]]) -> int:
    if not records:
        return 0
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / SOLUTIONS_FILE
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    return len(records)


def load_solutions(state_dir: Path, *, max_entries: int = DEFAULT_SOLUTIONS_MAX) -> list[dict[str, Any]]:
    """Newest ``max_entries`` solution records (corrupt lines tolerated)."""
    path = state_dir / SOLUTIONS_FILE
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict) and isinstance(record.get("patches"), list):
                    records.append(record)
    except OSError:
        return []
    return records[-max(1, int(max_entries)):]


def prune_solutions(state_dir: Path, *, max_entries: int = DEFAULT_SOLUTIONS_MAX) -> dict[str, Any]:
    """GC hook: rewrite the cache to its newest ``max_entries`` lines.

    solutions.jsonl is a rewritable cache, not a findings ledger.
    """
    path = state_dir / SOLUTIONS_FILE
    if not path.is_file():
        return {"kept": 0, "removed": 0}
    try:
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError:
        return {"kept": 0, "removed": 0}
    keep = max(1, int(max_entries))
    if len(lines) <= keep:
        return {"kept": len(lines), "removed": 0}
    tmp = path.with_suffix(".jsonl.tmp")
    tmp.write_text("\n".join(lines[-keep:]) + "\n", encoding="utf-8")
    tmp.replace(path)
    return {"kept": keep, "removed": len(lines) - keep}


def apply_solution(
    data: bytes,
    record: Mapping[str, Any],
    *,
    max_blob_bytes: int = DEFAULT_MAX_BLOB_BYTES,
) -> bytes | None:
    """Apply one solution's patches (+ length change) to arbitrary input
    bytes; offsets past the end are skipped, no-ops return None."""
    out = bytearray(data)
    for patch in record.get("patches") or []:
        try:
            offset, value = int(patch[0]), int(patch[1]) & 0xFF
        except (TypeError, ValueError, IndexError):
            continue
        if 0 <= offset < len(out):
            out[offset] = value
    len_delta = int(record.get("len_delta") or 0)
    if len_delta > 0 and record.get("tail_b64"):
        try:
            out.extend(base64.b64decode(str(record["tail_b64"])))
        except (ValueError, binascii.Error):
            pass
    elif len_delta < 0:
        del out[max(0, len(out) + len_delta):]
    result = bytes(out)
    if not result or result == data or len(result) > max(1, int(max_blob_bytes)):
        return None
    return result


def run_crossover(
    *,
    work_dir: Path,
    corpus: Path,
    round_index: int,
    target_name: str,
    policy: Mapping[str, Any],
    min_free_gb: float = MIN_FREE_DISK_GB,
) -> dict[str, Any]:
    """One bounded crossover pass: cached solutions applied sequentially to
    the newest corpus entries, every intermediate merged as ``symx-<sha>``.
    Pure python, deterministic per (target, round). Never raises."""
    state_dir = work_dir / "symcc-state"
    solutions = load_solutions(state_dir, max_entries=int(policy.get("solutions_max", DEFAULT_SOLUTIONS_MAX)))
    if not solutions:
        return {"skipped": "no cached solutions", "new_seeds": 0, "applied": 0}
    if not corpus.is_dir():
        return {"skipped": "no corpus dir", "new_seeds": 0, "applied": 0}

    max_blob = int(policy.get("max_parent_bytes", DEFAULT_MAX_BLOB_BYTES))
    inputs_budget = max(1, int(policy.get("crossover_inputs", 16)))
    apply_budget = max(1, int(policy.get("crossover_apply", 3)))
    new_max = max(1, int(policy.get("crossover_new_max", 64)))

    entries = sorted(
        (entry for entry in corpus.iterdir() if entry.is_file()),
        key=lambda entry: entry.stat().st_mtime,
        reverse=True,
    )
    rng = random.Random(f"{target_name}:{round_index}")
    applied = 0
    new_seeds = 0
    inputs_used = 0
    blockers: list[str] = []
    for entry in entries:
        if inputs_used >= inputs_budget or new_seeds >= new_max or blockers:
            break
        try:
            if entry.stat().st_size > max_blob:
                continue
            base = entry.read_bytes()
        except OSError:
            continue
        inputs_used += 1
        for _ in range(apply_budget):
            if new_seeds >= new_max or blockers:
                break
            record = rng.choice(solutions)
            mutated = apply_solution(base, record, max_blob_bytes=max_blob)
            if mutated is None:
                continue
            applied += 1
            # Sequential semantics: the intermediate becomes the next base
            # AND is emitted as its own corpus candidate.
            base = mutated
            digest = sha256(mutated).hexdigest()[:20]
            destination = corpus / f"symx-{digest}"
            if destination.exists():
                continue
            headroom = check_disk_headroom(corpus, min_free_gb=min_free_gb)
            if not headroom["ok"]:
                blockers.append(headroom["blocker"])
                break
            try:
                destination.write_bytes(mutated)
            except OSError as exc:
                blockers.append(f"crossover write failed: {exc}")
                break
            new_seeds += 1

    _bump_stats(state_dir, applied=applied, new_seeds=new_seeds)
    return {
        "solutions_available": len(solutions),
        "inputs_used": inputs_used,
        "applied": applied,
        "new_seeds": new_seeds,
        "blockers": blockers,
    }


def harvest_dictionary_tokens(
    *,
    records: list[dict[str, Any]],
    dict_path: Path,
    max_new: int = 16,
    total_cap: int = 256,
) -> dict[str, Any]:
    """Multi-byte patch runs and extension tails become dictionary tokens —
    solved magic values transfer to the coverage fuzzer's own mutator.

    Tokens land in an engine-owned ``# symcc-harvest`` section appended to
    the target dictionary; existing lines (agent-authored or harvested) are
    never touched and duplicates are skipped, so the pass is idempotent.
    """
    tokens: list[bytes] = []
    seen_tokens: set[bytes] = set()
    for record in records:
        for run in _patch_runs(record.get("patches") or []):
            if MIN_DICT_RUN_BYTES <= len(run) <= DICT_TOKEN_MAX_BYTES and run not in seen_tokens:
                seen_tokens.add(run)
                tokens.append(run)
        tail_b64 = record.get("tail_b64")
        if tail_b64:
            try:
                tail = base64.b64decode(str(tail_b64))
            except (ValueError, binascii.Error):
                continue
            if MIN_DICT_RUN_BYTES <= len(tail) <= DICT_TOKEN_MAX_BYTES and tail not in seen_tokens:
                seen_tokens.add(tail)
                tokens.append(tail)
    if not tokens:
        return {"tokens_added": 0, "harvested_total": _harvested_count(dict_path)}

    existing_lines = set()
    harvested = 0
    if dict_path.is_file():
        try:
            for line in dict_path.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if stripped:
                    existing_lines.add(stripped)
                if stripped.startswith("symx_"):
                    harvested += 1
        except OSError:
            pass

    added_lines: list[str] = []
    for token in tokens:
        if len(added_lines) >= max(0, int(max_new)) or harvested + len(added_lines) >= max(0, int(total_cap)):
            break
        quoted = _quote_bytes(token)
        if any(quoted in line for line in existing_lines):
            continue
        added_lines.append(f"symx_{harvested + len(added_lines):03d}={quoted}")

    if added_lines:
        dict_path.parent.mkdir(parents=True, exist_ok=True)
        header_needed = "# symcc-harvest" not in existing_lines
        with dict_path.open("a", encoding="utf-8") as handle:
            if header_needed:
                handle.write("\n# symcc-harvest\n")
            for line in added_lines:
                handle.write(line + "\n")
    return {"tokens_added": len(added_lines), "harvested_total": harvested + len(added_lines)}


def measure_crossover_effectiveness(*, work_dir: Path, corpus: Path) -> dict[str, Any]:
    """Post-GC corpus residency of the crossover lane (mirrors
    seedgen-effectiveness): did the symx- offspring earn their keep?"""
    stats = _load_stats(work_dir / "symcc-state")
    surviving = 0
    if corpus.is_dir():
        surviving = sum(1 for entry in corpus.iterdir() if entry.name.startswith("symx-") and entry.is_file())
    report = {
        "applied_total": stats.get("applied", 0),
        "generated_total": stats.get("new_seeds", 0),
        "surviving": surviving,
    }
    path = work_dir / EFFECTIVENESS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    return report


def _harvested_count(dict_path: Path) -> int:
    if not dict_path.is_file():
        return 0
    try:
        return sum(
            1
            for line in dict_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip().startswith("symx_")
        )
    except OSError:
        return 0


def _patch_runs(patches: list[Any]) -> list[bytes]:
    """Consecutive-offset patch values as byte runs (solved magic values)."""
    normalized: list[tuple[int, int]] = []
    for patch in patches:
        try:
            normalized.append((int(patch[0]), int(patch[1]) & 0xFF))
        except (TypeError, ValueError, IndexError):
            continue
    normalized.sort()
    runs: list[bytes] = []
    current: list[int] = []
    previous_offset: int | None = None
    for offset, value in normalized:
        if previous_offset is not None and offset == previous_offset + 1:
            current.append(value)
        else:
            if current:
                runs.append(bytes(current))
            current = [value]
        previous_offset = offset
    if current:
        runs.append(bytes(current))
    return runs


def _quote_bytes(token: bytes) -> str:
    body = []
    for byte in token:
        char = chr(byte)
        if char == "\\":
            body.append("\\\\")
        elif char == '"':
            body.append('\\"')
        elif 32 <= byte <= 126:
            body.append(char)
        else:
            body.append(f"\\x{byte:02x}")
    return '"' + "".join(body) + '"'


def _load_stats(state_dir: Path) -> dict[str, Any]:
    path = state_dir / CROSSOVER_STATS_FILE
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _bump_stats(state_dir: Path, *, applied: int, new_seeds: int) -> None:
    stats = _load_stats(state_dir)
    stats["applied"] = int(stats.get("applied") or 0) + applied
    stats["new_seeds"] = int(stats.get("new_seeds") or 0) + new_seeds
    stats["updated_ts"] = time.time()
    state_dir.mkdir(parents=True, exist_ok=True)
    tmp = (state_dir / CROSSOVER_STATS_FILE).with_suffix(".json.tmp")
    tmp.write_text(json.dumps(stats, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(state_dir / CROSSOVER_STATS_FILE)

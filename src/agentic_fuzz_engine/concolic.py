from __future__ import annotations

import base64
import json
import os
import re
from hashlib import sha256
from pathlib import Path
from typing import Any

from .dictionary import (
    MAX_DICTIONARY_FILE_BYTES,
    MAX_DICTIONARY_SOURCE_FILES,
    SOURCE_SUFFIXES,
    generate_dictionary_from_source,
)


MAX_CONCOLIC_TOKENS = 32
MAX_CONCOLIC_SEEDS = 32
MAX_SEED_BYTES = 4096
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".pytest_cache", "node_modules", "target", "build", "out"}
BRANCH_LINE_RE = re.compile(r"\b(?:if|while|switch)\s*\(")
SIZE_GUARD_RE = re.compile(
    r"\b(?P<var>size|len|length|n)\b\s*(?P<op>>=|>|==|<=|<)\s*(?P<value>\d{1,6})"
    r"|(?P<left>\d{1,6})\s*(?P<left_op><=|<|==|>=|>)\s*\b(?P<left_var>size|len|length|n)\b"
)
BYTE_CMP_RE = re.compile(
    r"\b(?P<name>data|buf|bytes|input)\s*\[\s*(?P<offset>\d{1,5})\s*\]\s*"
    r"(?P<op>==|!=)\s*(?P<value>0x[0-9a-fA-F]{1,2}|\d{1,3}|'(?:\\.|[^\\'])')"
)


def plan_concolic_branches(
    source_dir: str,
    *,
    target: str,
    harness: str,
    artifact_prefix: str = "concolic",
    max_files: int = MAX_DICTIONARY_SOURCE_FILES,
    max_file_bytes: int = MAX_DICTIONARY_FILE_BYTES,
    max_tokens: int = MAX_CONCOLIC_TOKENS,
    max_seeds: int = MAX_CONCOLIC_SEEDS,
) -> dict[str, Any]:
    source = Path(source_dir).expanduser().resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"source_dir is not a directory: {source_dir}")
    max_files = _bounded_int(max_files, "max_files", MAX_DICTIONARY_SOURCE_FILES)
    max_file_bytes = _bounded_int(max_file_bytes, "max_file_bytes", MAX_DICTIONARY_FILE_BYTES)
    max_tokens = _bounded_int(max_tokens, "max_tokens", MAX_CONCOLIC_TOKENS)
    max_seeds = _bounded_int(max_seeds, "max_seeds", MAX_CONCOLIC_SEEDS)

    dictionary = generate_dictionary_from_source(
        str(source),
        artifact_name=f"{artifact_prefix}/derived.dict",
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        max_tokens=max_tokens,
    )
    files, source_truncated = _source_files(source, max_files=max_files)
    branches = _token_branches(dictionary["token_entries"])
    skipped = list(dictionary["skipped"])
    for path in files:
        rel = path.relative_to(source).as_posix()
        size = path.stat().st_size
        if size > max_file_bytes:
            if not any(item.get("path") == rel for item in skipped):
                skipped.append({"path": rel, "reason": "file too large", "size": size})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        branches.extend(_predicate_branches(text, path=path, source=source, start_index=len(branches)))

    branches = _dedupe_branches(branches)
    seeds = _seed_candidates(
        [str(token) for token in dictionary["dictionary_tokens"]],
        branches,
        artifact_prefix=artifact_prefix,
        max_seeds=max_seeds,
    )
    plan = {
        "target": target,
        "harness": harness,
        "source_dir": str(source),
        "mode": "static-concolic-plan",
        "solver_executed": False,
        "solver_note": "No solver or external concolic service was invoked; constraints are source-derived branch targets.",
        "branches": branches,
        "dictionary_tokens": dictionary["dictionary_tokens"],
        "seed_families": [
            {
                "name": seed["family"],
                "mutation": seed["mutation"],
                "branch_ids": seed["branch_ids"],
                "source_tokens": seed["source_tokens"],
                "size": seed["size"],
                "sha256": seed["sha256"],
            }
            for seed in seeds
        ],
        "blockers": [] if branches else ["no branch predicates, comparison literals, or byte guards found"],
    }
    plan_bytes = json.dumps(plan, indent=2, sort_keys=True).encode("utf-8")
    return {
        "target": target,
        "harness": harness,
        "source_dir": str(source),
        "artifact_prefix": artifact_prefix,
        "branch_plan_artifact_name": f"{artifact_prefix}/branch_plan.json",
        "branch_plan_content_b64": base64.b64encode(plan_bytes).decode("ascii"),
        "dictionary_tokens": dictionary["dictionary_tokens"],
        "token_entries": dictionary["token_entries"],
        "branches": branches,
        "seed_artifacts": seeds,
        "source_files_scanned": dictionary["source_files_scanned"],
        "skipped": skipped,
        "truncated": bool(dictionary["truncated"] or source_truncated),
        "blockers": plan["blockers"],
    }


def _token_branches(token_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    branches = []
    for index, entry in enumerate(token_entries):
        token = str(entry["token"])
        branches.append(
            {
                "branch_id": f"B{index:03d}",
                "source_rel": entry["source_rel"],
                "line": entry["line"],
                "predicate": f"input satisfies comparison literal {_display_token(token)}",
                "controlling_bytes": {"contains": token},
                "suggested_seed_transform": f"insert {_display_token(token)} at the parser-controlled field or offset 0",
                "expected_next_state": "literal comparison branch is reachable",
                "risk_class": "parser-state-gate",
                "source_token": token,
                "reason": entry["reason"],
                "score": entry["score"],
            }
        )
    return branches


def _predicate_branches(text: str, *, path: Path, source: Path, start_index: int) -> list[dict[str, Any]]:
    branches = []
    rel = path.relative_to(source).as_posix()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not BRANCH_LINE_RE.search(line):
            continue
        for match in SIZE_GUARD_RE.finditer(line):
            value = int(match.group("value") or match.group("left") or 0)
            op = match.group("op") or match.group("left_op") or "?"
            branch_id = f"B{start_index + len(branches):03d}"
            branches.append(
                {
                    "branch_id": branch_id,
                    "source_rel": rel,
                    "line": line_number,
                    "predicate": f"input length {op} {value}",
                    "controlling_bytes": {"min_length": value if op in {">=", ">"} else None, "length_value": value},
                    "suggested_seed_transform": f"resize seed near length {value}",
                    "expected_next_state": "length-gated branch is reachable",
                    "risk_class": "length-allocation-or-copy-gate",
                    "source_token": None,
                    "reason": "length predicate",
                    "score": 85,
                }
            )
        for match in BYTE_CMP_RE.finditer(line):
            offset = int(match.group("offset"))
            value = _parse_byte_value(match.group("value"))
            branch_id = f"B{start_index + len(branches):03d}"
            branches.append(
                {
                    "branch_id": branch_id,
                    "source_rel": rel,
                    "line": line_number,
                    "predicate": f"{match.group('name')}[{offset}] {match.group('op')} 0x{value:02x}",
                    "controlling_bytes": {"offset": offset, "value": value, "operator": match.group("op")},
                    "suggested_seed_transform": f"set byte {offset} to 0x{value:02x}",
                    "expected_next_state": "byte-guarded branch is reachable",
                    "risk_class": "byte-dispatch-gate",
                    "source_token": None,
                    "reason": "byte predicate",
                    "score": 90,
                }
            )
    return branches


def _seed_candidates(
    tokens: list[str],
    branches: list[dict[str, Any]],
    *,
    artifact_prefix: str,
    max_seeds: int,
) -> list[dict[str, Any]]:
    candidates: list[tuple[str, str, bytes, list[str], list[str]]] = []
    token_branches = [branch for branch in branches if branch.get("source_token")]
    if len(tokens) >= 2:
        branch_ids = [str(branch["branch_id"]) for branch in token_branches[:2]]
        candidates.append(("branch-chain", "concat-first-two-literals", (tokens[0] + tokens[1]).encode("utf-8"), branch_ids, tokens[:2]))
    for branch in token_branches:
        token = str(branch["source_token"])
        data = token.encode("utf-8")
        candidates.append(("literal-branch", f"reach-{branch['branch_id']}", data, [str(branch["branch_id"])], [token]))
        candidates.append(("literal-branch", f"reach-{branch['branch_id']}-with-boundary", data + b"\x00" + b"A" * 8, [str(branch["branch_id"])], [token]))
    for branch in branches:
        control = branch.get("controlling_bytes") if isinstance(branch.get("controlling_bytes"), dict) else {}
        if isinstance(control.get("offset"), int) and isinstance(control.get("value"), int):
            offset = int(control["offset"])
            value = int(control["value"])
            data = bytearray(b"\x00" * min(MAX_SEED_BYTES, max(offset + 1, 1)))
            data[offset] = value & 0xFF
            candidates.append(("byte-constraint", f"set-{branch['branch_id']}", bytes(data), [str(branch["branch_id"])], []))
        length_value = control.get("length_value")
        if isinstance(length_value, int) and 0 < length_value <= MAX_SEED_BYTES:
            size = max(1, length_value)
            candidates.append(("length-constraint", f"size-{branch['branch_id']}", b"A" * size, [str(branch["branch_id"])], []))

    emitted: set[str] = set()
    seeds = []
    for family, mutation, data, branch_ids, source_tokens in candidates:
        if len(seeds) >= max_seeds:
            break
        if len(data) > MAX_SEED_BYTES:
            continue
        digest = sha256(data).hexdigest()
        if digest in emitted:
            continue
        emitted.add(digest)
        index = len(seeds)
        artifact_name = f"{artifact_prefix}/seed_{index:02d}_{_safe_label(family)}_{_safe_label(mutation)}.bin"
        seeds.append(
            {
                "artifact_name": artifact_name,
                "content_b64": base64.b64encode(data).decode("ascii"),
                "family": family,
                "mutation": mutation,
                "branch_ids": branch_ids,
                "source_tokens": source_tokens,
                "sha256": digest,
                "size": len(data),
            }
        )
    return seeds


def _dedupe_branches(branches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped = []
    seen = set()
    for branch in sorted(branches, key=lambda item: (-int(item.get("score", 0)), str(item.get("source_rel")), int(item.get("line", 0)))):
        key = (
            branch.get("source_rel"),
            branch.get("line"),
            branch.get("predicate"),
            json.dumps(branch.get("controlling_bytes", {}), sort_keys=True),
        )
        if key in seen:
            continue
        seen.add(key)
        branch = dict(branch)
        branch["branch_id"] = f"B{len(deduped):03d}"
        deduped.append(branch)
    return deduped


def _source_files(source: Path, *, max_files: int) -> tuple[list[Path], bool]:
    files = []
    for root, dirs, names in os.walk(source):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS and not name.startswith(".cache")]
        for name in sorted(names):
            path = Path(root) / name
            if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
                continue
            if len(files) >= max_files:
                return files, True
            files.append(path.resolve())
    return files, False


def _parse_byte_value(value: str) -> int:
    if value.startswith("0x"):
        return int(value, 16) & 0xFF
    if value.startswith("'") and value.endswith("'"):
        inner = value[1:-1]
        if inner.startswith("\\x") and len(inner) >= 4:
            return int(inner[2:4], 16) & 0xFF
        if inner.startswith("\\") and len(inner) >= 2:
            escapes = {"0": 0, "n": 10, "r": 13, "t": 9}
            return escapes.get(inner[1], ord(inner[1])) & 0xFF
        return ord(inner[:1] or "\x00") & 0xFF
    return int(value) & 0xFF


def _display_token(token: str) -> str:
    escaped = "".join(char if 32 <= ord(char) <= 126 and char not in {'"', "\\"} else f"\\x{ord(char):02x}" for char in token)
    return f'"{escaped}"'


def _safe_label(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value)[:48] or "seed"


def _bounded_int(value: int, name: str, limit: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed <= 0 or parsed > limit:
        raise ValueError(f"{name} must be between 1 and {limit}")
    return parsed

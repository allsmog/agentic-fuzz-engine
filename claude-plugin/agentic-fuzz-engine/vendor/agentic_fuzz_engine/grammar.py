from __future__ import annotations

import base64
import json
from hashlib import sha256
from typing import Any

from .dictionary import MAX_DICTIONARY_FILE_BYTES, MAX_DICTIONARY_SOURCE_FILES, generate_dictionary_from_source


MAX_GRAMMAR_TOKENS = 32
MAX_GRAMMAR_SEEDS = 32
MAX_SEED_BYTES = 4096


def infer_grammar_from_source(
    source_dir: str,
    *,
    target: str,
    harness: str,
    artifact_prefix: str = "grammar",
    max_files: int = MAX_DICTIONARY_SOURCE_FILES,
    max_file_bytes: int = MAX_DICTIONARY_FILE_BYTES,
    max_tokens: int = MAX_GRAMMAR_TOKENS,
    max_seeds: int = MAX_GRAMMAR_SEEDS,
) -> dict[str, Any]:
    max_tokens = _bounded_int(max_tokens, "max_tokens", MAX_GRAMMAR_TOKENS)
    max_seeds = _bounded_int(max_seeds, "max_seeds", MAX_GRAMMAR_SEEDS)
    generated_dictionary = generate_dictionary_from_source(
        source_dir,
        artifact_name=f"{artifact_prefix}/derived.dict",
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        max_tokens=max_tokens,
    )
    token_entries = list(generated_dictionary["token_entries"])
    tokens = [str(entry["token"]) for entry in token_entries]
    seeds = _seed_candidates(tokens, artifact_prefix=artifact_prefix, max_seeds=max_seeds)
    grammar = {
        "target": target,
        "harness": harness,
        "source_dir": generated_dictionary["source_dir"],
        "format_hypothesis": _format_hypothesis(tokens),
        "start": "input",
        "productions": _productions(tokens),
        "negative_families": [
            "truncated-token",
            "oversized-repetition",
            "length-prefix-mismatch",
            "duplicate-section",
        ],
        "dictionary_tokens": tokens,
        "source_token_entries": token_entries,
        "seed_families": [
            {
                "name": seed["family"],
                "mutation": seed["mutation"],
                "source_tokens": seed["source_tokens"],
                "size": seed["size"],
                "sha256": seed["sha256"],
            }
            for seed in seeds
        ],
        "blockers": [] if tokens else ["no source literals or byte patterns suitable for grammar inference"],
    }
    grammar_bytes = json.dumps(grammar, indent=2, sort_keys=True).encode("utf-8")
    return {
        "target": target,
        "harness": harness,
        "source_dir": generated_dictionary["source_dir"],
        "artifact_prefix": artifact_prefix,
        "grammar_artifact_name": f"{artifact_prefix}/grammar.json",
        "grammar_content_b64": base64.b64encode(grammar_bytes).decode("ascii"),
        "dictionary_tokens": tokens,
        "token_entries": token_entries,
        "seed_artifacts": seeds,
        "source_files_scanned": generated_dictionary["source_files_scanned"],
        "skipped": generated_dictionary["skipped"],
        "truncated": generated_dictionary["truncated"],
        "blockers": grammar["blockers"],
    }


def _productions(tokens: list[str]) -> list[dict[str, Any]]:
    productions = [
        {
            "name": "input",
            "alternatives": ["token", "token payload", "length_prefix token payload", "token token"],
        },
        {"name": "payload", "alternatives": ["", "A", "A*8", "A*64", "\\x00", "\\xff"]},
        {"name": "length_prefix", "encoding": "u32le", "controls": "following token+payload byte length"},
    ]
    for index, token in enumerate(tokens[:MAX_GRAMMAR_TOKENS]):
        productions.append({"name": f"token_{index:02d}", "literal": _escaped(token), "source": "source comparison"})
    return productions


def _seed_candidates(tokens: list[str], *, artifact_prefix: str, max_seeds: int) -> list[dict[str, Any]]:
    candidates: list[tuple[str, str, bytes, list[str]]] = []
    token_bytes = [(token, token.encode("utf-8")) for token in tokens if token.encode("utf-8")]
    for token, data in token_bytes:
        candidates.append(("token", "literal", data, [token]))
    if len(token_bytes) >= 2:
        left_token, left = token_bytes[0]
        right_token, right = token_bytes[1]
        candidates.append(("token-pair", "concat-first-two", left + right, [left_token, right_token]))
        candidates.append(("token-pair", "nul-separated-first-two", left + b"\x00" + right, [left_token, right_token]))
    for token, data in token_bytes:
        candidates.extend(
            [
                ("token-payload", "append-short-payload", data + b"A" * 8, [token]),
                ("token-payload", "append-nul", data + b"\x00", [token]),
                ("length-prefix", "u32le-token-length", len(data).to_bytes(4, "little") + data, [token]),
                ("negative", "truncated-token", data[: max(1, len(data) // 2)], [token]),
                ("negative", "oversized-repetition", (data * 8)[:MAX_SEED_BYTES], [token]),
            ]
        )
    if not candidates:
        candidates.extend(
            [
                ("fallback", "empty", b"", []),
                ("fallback", "nul", b"\x00", []),
                ("fallback", "ascii-boundary", b"A" * 64, []),
            ]
        )

    emitted: set[str] = set()
    seeds = []
    for family, mutation, data, source_tokens in candidates:
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
                "source_tokens": source_tokens,
                "sha256": digest,
                "size": len(data),
            }
        )
    return seeds


def _format_hypothesis(tokens: list[str]) -> str:
    if not tokens:
        return "unknown"
    if any(any(ord(char) < 32 or ord(char) > 126 for char in token) for token in tokens):
        return "binary"
    if any(token.isupper() and token.isalpha() and len(token) <= 12 for token in tokens):
        return "text-or-command-protocol"
    return "structured-bytes"


def _escaped(token: str) -> str:
    return "".join(char if 32 <= ord(char) <= 126 and char not in {'"', "\\"} else f"\\x{ord(char):02x}" for char in token)


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

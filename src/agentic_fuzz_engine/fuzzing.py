from __future__ import annotations

import base64
import re
from hashlib import sha256
from typing import Any


MAX_FUZZ_ITERATIONS = 100
MAX_SEED_BYTES = 1_048_576
MAX_DICTIONARY_TOKENS = 64
MAX_TOKEN_BYTES = 1024

_FEATURE_RE = re.compile(r"^\s*(?:COVERAGE|EDGE|NEW_EDGE|FEATURE)\s*[:=]\s*([A-Za-z0-9_.:/+-]{1,160})\s*$", re.MULTILINE)


def build_fuzz_candidates(
    seed_artifacts: list[dict[str, str]],
    *,
    dictionary_tokens: list[str] | None = None,
    max_iterations: int = 25,
    exclude_sha256: set[str] | None = None,
) -> list[dict[str, Any]]:
    if max_iterations <= 0 or max_iterations > MAX_FUZZ_ITERATIONS:
        raise ValueError(f"max_iterations must be between 1 and {MAX_FUZZ_ITERATIONS}")

    seeds = _decode_seeds(seed_artifacts)
    tokens = _dictionary_bytes(dictionary_tokens or [])
    excluded = exclude_sha256 or set()
    emitted: set[str] = set()
    candidates: list[dict[str, Any]] = []

    def emit(family: str, mutation: str, data: bytes, parents: list[str]) -> None:
        if len(candidates) >= max_iterations or len(data) > MAX_SEED_BYTES:
            return
        digest = sha256(data).hexdigest()
        if digest in emitted or digest in excluded:
            return
        emitted.add(digest)
        candidates.append(
            {
                "family": family,
                "mutation": mutation,
                "parent_artifacts": parents,
                "content_b64": base64.b64encode(data).decode("ascii"),
                "sha256": digest,
                "size": len(data),
            }
        )

    for seed in seeds:
        name = seed["name"]
        data = seed["data"]
        emit("seed", "original", data, [name])
        for token in tokens:
            label = _token_label(token)
            emit("dictionary", f"append:{label}", data + token, [name])
            emit("dictionary", f"prepend:{label}", token + data, [name])
            emit("dictionary", f"replace:{label}", token, [name])
        if data:
            emit("structure", "duplicate", data + data, [name])
            emit("structure", "truncate-half", data[: max(1, len(data) // 2)], [name])
            emit("structure", "little-endian-length-prefix", len(data).to_bytes(4, "little") + data, [name])
            for offset in _interesting_offsets(len(data)):
                mutated = bytearray(data)
                mutated[offset] ^= 0xFF
                emit("bitflip", f"xor-ff-at-{offset}", bytes(mutated), [name])
            for suffix in (b"\x00", b"\xff", b"\x7f\xff\xff\xff", b"A" * 64):
                emit("boundary", f"append-{_token_label(suffix)}", data + suffix, [name])

    for left in seeds:
        for right in seeds:
            if left["name"] == right["name"]:
                continue
            left_data = left["data"]
            right_data = right["data"]
            pivot_left = len(left_data) // 2
            pivot_right = len(right_data) // 2
            emit(
                "splice",
                "half-and-half",
                left_data[:pivot_left] + right_data[pivot_right:],
                [left["name"], right["name"]],
            )

    return candidates


def extract_coverage_features(harness_result: dict[str, Any]) -> list[str]:
    features: set[str] = set()
    for run in harness_result.get("runs", []):
        if not isinstance(run, dict):
            continue
        for field in ("stdout", "stderr", "combined_output"):
            value = run.get(field)
            if isinstance(value, str):
                features.update(_FEATURE_RE.findall(value))
    return sorted(features)


def summarize_harness_run(harness_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "verified": bool(harness_result.get("verified")),
        "crashes": int(harness_result.get("crashes") or 0),
        "matches_expected": int(harness_result.get("matches_expected") or 0),
        "observed_error_token": harness_result.get("observed_error_token"),
        "expected_error_token": harness_result.get("expected_error_token"),
        "repetitions": harness_result.get("repetitions"),
        "timeout_seconds": harness_result.get("timeout_seconds"),
        "exit_codes": [
            run.get("exit_code")
            for run in harness_result.get("runs", [])
            if isinstance(run, dict) and "exit_code" in run
        ],
    }


def _decode_seeds(seed_artifacts: list[dict[str, str]]) -> list[dict[str, Any]]:
    if not seed_artifacts:
        seed_artifacts = [{"name": "empty-seed", "content_b64": ""}]
    seeds = []
    for artifact in seed_artifacts:
        name = artifact.get("name")
        content_b64 = artifact.get("content_b64")
        if not isinstance(name, str) or not isinstance(content_b64, str):
            raise ValueError("seed artifacts must include string name and content_b64")
        data = base64.b64decode(content_b64.encode("ascii"))
        if len(data) > MAX_SEED_BYTES:
            raise ValueError(f"seed artifact is too large: {name}")
        seeds.append({"name": name, "data": data})
    return seeds


def _dictionary_bytes(tokens: list[str]) -> list[bytes]:
    if len(tokens) > MAX_DICTIONARY_TOKENS:
        raise ValueError(f"dictionary may contain at most {MAX_DICTIONARY_TOKENS} tokens")
    result = []
    for token in tokens:
        if not isinstance(token, str):
            raise ValueError("dictionary tokens must be strings")
        data = token.encode("utf-8")
        if not data or len(data) > MAX_TOKEN_BYTES:
            raise ValueError(f"dictionary token must be between 1 and {MAX_TOKEN_BYTES} bytes")
        result.append(data)
    return result


def _interesting_offsets(size: int) -> list[int]:
    offsets = {0, size // 2, size - 1}
    return sorted(offset for offset in offsets if 0 <= offset < size)


def _token_label(value: bytes) -> str:
    printable = "".join(chr(byte) if 32 <= byte <= 126 and chr(byte).isalnum() else "_" for byte in value[:16])
    return printable or "bytes"

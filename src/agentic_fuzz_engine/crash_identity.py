"""Crash identity v2: normalized crash states and cross-harness root signatures.

The v1 signature (``asan.asan_signature``) hashes the raw top-4 frames, so
sanitizer interceptor frames (``__interceptor_memcpy``) and inlining flap
fragment one root cause into many signatures, and libFuzzer ``DEDUP_TOKEN``
lines are ignored entirely. This module ports the battle-tested identity
rules from ClusterFuzz (via Buttercup's vendored parser):

- ``crash_state``: the top 3 stack frames after dropping sanitizer-runtime,
  libc, allocator, and harness-driver frames — the stable "where" of a crash.
- ``dedup_tokens``: sorted libFuzzer ``DEDUP_TOKEN:`` values; when present
  they take priority over frames as the identity key.
- ``root_signature``: hash of tokens (or crash_type + crash_state) with NO
  target/harness/error-token material, so the same root cause reached from
  two harnesses shares one key.
- ``crash_states_similar``: ClusterFuzz's fuzzy tier — LCS >= 2 shared
  frames, or average per-frame similarity ratio > 0.8 — used by dedupe to
  consolidate groups whose top frame flaps between inlined callees.

Everything is stdlib-only and pure; parsing reuses the frame grammar from
``asan.py`` (which stays unchanged for its existing callers).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from .asan import ASAN_ACCESS_RE, AsanFrame, iter_asan_frames

DEDUP_TOKEN_RE = re.compile(r"^DEDUP_TOKEN:\s*(.+?)\s*$", re.MULTILINE)
SANITIZER_HEADER_RE = re.compile(
    r"(?:ERROR:\s*)?"
    r"(AddressSanitizer|LeakSanitizer|MemorySanitizer|ThreadSanitizer|UndefinedBehaviorSanitizer)"
    r":\s*([A-Za-z0-9_-]+(?:\s+on\s+unknown\s+address)?)"
)
UBSAN_RUNTIME_ERROR_RE = re.compile(
    r"^(?P<file>[^\s:]+):(?P<line>\d+)(?::\d+)?:\s*runtime error:\s*(?P<message>.+)$",
    re.MULTILINE,
)
LIBFUZZER_ERROR_RE = re.compile(r"ERROR:\s*libFuzzer:\s*(deadly signal|timeout|out-of-memory)")

_SANITIZER_FAMILY = {
    "AddressSanitizer": "address",
    "LeakSanitizer": "leak",
    "MemorySanitizer": "memory",
    "ThreadSanitizer": "thread",
    "UndefinedBehaviorSanitizer": "ubsan",
}

CRASH_STATE_DEPTH = 3
LCS_THRESHOLD = 2
SIMILARITY_RATIO_THRESHOLD = 0.8

# Frames that describe the sanitizer/allocator/harness machinery, not the
# bug. ClusterFuzz strips these before computing crash state; keeping the
# harness-driver frames out also prevents fuzzy consolidation from merging
# unrelated shallow crashes on generic driver frames.
_FRAME_EXACT_BLACKLIST = frozenset(
    {
        "main",
        "_start",
        "LLVMFuzzerTestOneInput",
        "__libc_start_main",
        "__libc_start_call_main",
    }
)
_FRAME_PREFIX_BLACKLIST = (
    "__interceptor_",
    "__asan_",
    "__asan::",
    "__sanitizer_",
    "__sanitizer::",
    "__ubsan_",
    "__ubsan::",
    "__lsan_",
    "__lsan::",
    "__msan_",
    "__msan::",
    "__tsan_",
    "__tsan::",
    "__libc_",
    "operator new",
    "operator delete",
    "std::__1::allocator",
    "std::allocator",
    "__gnu_cxx::",
    "fuzzer::",
)
_FILE_SUBSTRING_BLACKLIST = (
    "sanitizer_common",
    "asan_interceptors",
    "asan_allocator",
    "compiler-rt",
    "libsanitizer",
    "/usr/include/",
    "libc-start",
    "FuzzerDriver",
    "FuzzerLoop",
    "FuzzerMain",
)


@dataclass(frozen=True, slots=True)
class CrashSignal:
    crash_type: str
    sanitizer_family: str
    frames: tuple[AsanFrame, ...]
    crash_state: tuple[str, ...]
    dedup_tokens: tuple[str, ...]
    top_function: str | None = None
    top_file: str | None = None
    access: str | None = None
    access_size: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "crash_type": self.crash_type,
            "sanitizer_family": self.sanitizer_family,
            "crash_state": list(self.crash_state),
            "dedup_tokens": list(self.dedup_tokens),
            "top_function": self.top_function,
            "top_file": self.top_file,
            "access": self.access,
            "access_size": self.access_size,
            "root_signature": root_signature(self),
        }


def extract_dedup_tokens(output: str) -> tuple[str, ...]:
    """Return sorted unique libFuzzer ``DEDUP_TOKEN`` values."""
    return tuple(sorted({match.group(1) for match in DEDUP_TOKEN_RE.finditer(output)}))


def frame_blacklisted(frame: AsanFrame) -> bool:
    function = frame.function or ""
    if function in _FRAME_EXACT_BLACKLIST:
        return True
    if any(function.startswith(prefix) for prefix in _FRAME_PREFIX_BLACKLIST):
        return True
    if frame.file and any(token in frame.file for token in _FILE_SUBSTRING_BLACKLIST):
        return True
    return False


def compute_crash_state(frames: tuple[AsanFrame, ...]) -> tuple[str, ...]:
    """Top CRASH_STATE_DEPTH non-blacklisted function names.

    Falls back to the raw top frames when everything is blacklisted so a
    crash entirely inside runtime frames still has a non-empty identity.
    """
    survivors = [frame.function for frame in frames if not frame_blacklisted(frame)]
    if not survivors:
        survivors = [frame.function for frame in frames]
    return tuple(survivors[:CRASH_STATE_DEPTH])


def parse_crash_output(output: str) -> CrashSignal | None:
    if not output:
        return None
    frames = iter_asan_frames(output)
    tokens = extract_dedup_tokens(output)

    crash_type: str | None = None
    family = "unknown"
    access = None
    access_size = None

    header = SANITIZER_HEADER_RE.search(output)
    if header:
        family = _SANITIZER_FAMILY.get(header.group(1), "unknown")
        crash_type = header.group(2).strip()
        access_match = ASAN_ACCESS_RE.search(output, header.end())
        if access_match:
            access = access_match.group(1)
            access_size = int(access_match.group(2))
    else:
        ubsan = UBSAN_RUNTIME_ERROR_RE.search(output)
        if ubsan:
            family = "ubsan"
            crash_type = _slug(ubsan.group("message"))
            if not frames:
                frames = (
                    AsanFrame(index=0, function=_slug(ubsan.group("message")), file=ubsan.group("file"), line=int(ubsan.group("line"))),
                )
        else:
            libfuzzer = LIBFUZZER_ERROR_RE.search(output)
            if libfuzzer:
                family = "libfuzzer"
                crash_type = libfuzzer.group(1).replace(" ", "-")
    if crash_type is None:
        return None

    crash_state = compute_crash_state(frames)
    top = next((frame for frame in frames if not frame_blacklisted(frame)), frames[0] if frames else None)
    return CrashSignal(
        crash_type=crash_type,
        sanitizer_family=family,
        frames=frames,
        crash_state=crash_state,
        dedup_tokens=tokens,
        top_function=top.function if top else None,
        top_file=top.file if top else None,
        access=access,
        access_size=access_size,
    )


def root_signature(signal: CrashSignal) -> str:
    """Cross-harness root-cause key: DEDUP_TOKENs when present, else
    crash_type + crash_state. Deliberately excludes target/harness/token."""
    if signal.dedup_tokens:
        material = "dedup:" + "\n".join(signal.dedup_tokens)
    else:
        material = signal.crash_type + "|" + ";".join(signal.crash_state)
    return sha256(material.encode("utf-8")).hexdigest()[:24]


def crash_states_similar(
    first: tuple[str, ...] | list[str],
    second: tuple[str, ...] | list[str],
    *,
    lcs_threshold: int = LCS_THRESHOLD,
    ratio_threshold: float = SIMILARITY_RATIO_THRESHOLD,
) -> bool:
    """ClusterFuzz CrashComparer port: equal, LCS >= threshold shared frames,
    or average positional similarity ratio above threshold."""
    first = list(first)
    second = list(second)
    if not first or not second:
        return False
    if first == second:
        return True
    if _longest_common_subsequence(first, second) >= lcs_threshold:
        return True
    compared = 0
    ratio_sum = 0.0
    for index in range(min(len(first), len(second))):
        ratio_sum += _similarity_ratio(first[index], second[index])
        compared += 1
    return compared > 0 and (ratio_sum / compared) > ratio_threshold


def consolidate_signature_groups(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fuzzy second dedupe tier: merge exact-signature groups whose
    representatives share crash_type and a similar crash_state.

    Input/output rows keep the ``state.finding_dedupe`` group shape; a merged
    group additionally carries ``members`` (absorbed signatures),
    ``consolidated: true``, and the representative's ``root_signature``.
    """
    consolidated: list[dict[str, Any]] = []
    for group in groups:
        identity = _group_identity(group)
        merged = False
        if identity is not None:
            for existing in consolidated:
                existing_identity = existing.get("_identity")
                if existing_identity is None:
                    continue
                if existing_identity[0] != identity[0]:
                    continue
                if not crash_states_similar(existing_identity[1], identity[1]):
                    continue
                _merge_groups(existing, group, incoming_identity=identity)
                merged = True
                break
        if not merged:
            entry = dict(group)
            entry["_identity"] = identity
            entry.setdefault("members", [group.get("signature")])
            entry["root_signature"] = identity[2] if identity else None
            entry.setdefault("consolidated", False)
            consolidated.append(entry)
    for entry in consolidated:
        entry.pop("_identity", None)
    return consolidated


def _group_identity(group: dict[str, Any]) -> tuple[str, tuple[str, ...], str] | None:
    representative = group.get("representative")
    if not isinstance(representative, dict):
        return None
    signal = parse_crash_output(str(representative.get("crash_output") or ""))
    if signal is None:
        return None
    return (signal.crash_type, signal.crash_state, root_signature(signal))


def _merge_groups(existing: dict[str, Any], incoming: dict[str, Any], *, incoming_identity: tuple) -> None:
    existing["consolidated"] = True
    existing.setdefault("members", [existing.get("signature")])
    existing["members"].append(incoming.get("signature"))
    existing["count"] = int(existing.get("count") or 0) + int(incoming.get("count") or 0)
    incoming_quality = incoming.get("representative_quality") or {}
    existing_quality = existing.get("representative_quality") or {}
    incoming_score = int(incoming_quality.get("score") or 0)
    existing_score = int(existing_quality.get("score") or 0)
    if incoming_score > existing_score:
        demoted = existing.get("representative")
        demoted_quality = existing.get("representative_quality")
        existing["representative"] = incoming.get("representative")
        existing["representative_quality"] = incoming_quality
        existing["_identity"] = incoming_identity
        existing["root_signature"] = incoming_identity[2]
        extra_duplicates = [demoted] if demoted else []
        extra_qualities = [demoted_quality] if demoted_quality else []
    else:
        extra_duplicates = [incoming.get("representative")] if incoming.get("representative") else []
        extra_qualities = [incoming_quality] if incoming_quality else []
    existing["duplicates"] = list(existing.get("duplicates") or []) + extra_duplicates + list(incoming.get("duplicates") or [])
    existing["duplicate_qualities"] = (
        list(existing.get("duplicate_qualities") or []) + extra_qualities + list(incoming.get("duplicate_qualities") or [])
    )


def _longest_common_subsequence(first: list[str], second: list[str]) -> int:
    rows = len(first)
    cols = len(second)
    table = [[0] * (cols + 1) for _ in range(rows + 1)]
    for i in range(1, rows + 1):
        for j in range(1, cols + 1):
            if first[i - 1] == second[j - 1]:
                table[i][j] = table[i - 1][j - 1] + 1
            else:
                table[i][j] = max(table[i - 1][j], table[i][j - 1])
    return table[rows][cols]


def _levenshtein_distance(first: str, second: str) -> int:
    if first == second:
        return 0
    if not first:
        return len(second)
    if not second:
        return len(first)
    previous = list(range(len(second) + 1))
    current = [0] * (len(second) + 1)
    for i, char_1 in enumerate(first):
        current[0] = i + 1
        for j, char_2 in enumerate(second):
            cost = 0 if char_1 == char_2 else 1
            current[j + 1] = min(current[j] + 1, previous[j + 1] + 1, previous[j] + cost)
        previous, current = current, previous
    return previous[len(second)]


def _similarity_ratio(first: str, second: str) -> float:
    length_sum = len(first) + len(second)
    if length_sum == 0:
        return 1.0
    return (length_sum - _levenshtein_distance(first, second)) / float(length_sum)


def _slug(value: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9]+", value.lower())
    return "-".join(tokens[:6]) or "runtime-error"

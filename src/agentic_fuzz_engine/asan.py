from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any


ASAN_ERROR_RE = re.compile(
    r"(?:ERROR:\s*)?AddressSanitizer:\s*([A-Za-z0-9_-]+(?:\s+on\s+unknown\s+address)?)"
)
ASAN_FRAME_RE = re.compile(
    r"^\s*#(?P<index>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<rest>.+?)\s*$",
    re.MULTILINE,
)
ASAN_ACCESS_RE = re.compile(r"\b(READ|WRITE) of size (\d+)")
# Trailing "path:line[:col]" tail of a symbolized frame. Kept free of "(" and
# ")" so module-offset forms like "(binary+0x1234)" never match as a file.
_FRAME_FILE_TAIL_RE = re.compile(r"\s+(?P<file>[^\s():]+):(?P<line>\d+)(?::\d+)?$")
_FRAME_BUILDID_TAIL_RE = re.compile(r"\s*\(BuildId:\s*[0-9a-fA-F]+\)\s*$")
_FRAME_MODULE_TAIL_RE = re.compile(r"\s*\([^()]*\+0x[0-9a-fA-F]+\)\s*$")


def split_frame_rest(rest: str) -> tuple[str, str | None, int | None]:
    """Split the text after ``in`` into (function, file, line).

    C++ symbols carry parameter lists with spaces — ``ns::F(char const*, int)
    /path/f.cpp:10:3`` — so the function can NOT be parsed as a single
    non-space token (that truncates at the first comma and swallows the
    file:line, hiding the project frame from grading and dedupe). Parse the
    tail instead, then strip the parameter list from the function name.
    """
    rest = _FRAME_BUILDID_TAIL_RE.sub("", rest)
    file: str | None = None
    line: int | None = None
    tail = _FRAME_FILE_TAIL_RE.search(rest)
    if tail:
        file = tail.group("file")
        line = int(tail.group("line"))
        rest = rest[: tail.start()]
    else:
        rest = _FRAME_MODULE_TAIL_RE.sub("", rest)
    function = rest.strip()
    paren = function.find("(")
    if paren > 0:
        function = function[:paren].rstrip()
    return function or rest.strip(), file, line


def iter_asan_frames(output: str) -> tuple[AsanFrame, ...]:
    frames = []
    for match in ASAN_FRAME_RE.finditer(output):
        function, file, line = split_frame_rest(match.group("rest"))
        frames.append(AsanFrame(index=int(match.group("index")), function=function, file=file, line=line))
    return tuple(frames)


@dataclass(frozen=True, slots=True)
class AsanFrame:
    index: int
    function: str
    file: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AsanSignal:
    crash_type: str
    top_function: str | None
    top_file: str | None
    frames: tuple[AsanFrame, ...]
    raw_excerpt: str
    access: str | None = None
    access_size: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "crash_type": self.crash_type,
            "top_function": self.top_function,
            "top_file": self.top_file,
            "frames": [frame.to_dict() for frame in self.frames],
            "raw_excerpt": self.raw_excerpt,
            "access": self.access,
            "access_size": self.access_size,
            "signature": asan_signature(self),
        }


def parse_asan_signal(output: str) -> AsanSignal | None:
    match = ASAN_ERROR_RE.search(output)
    if not match:
        return None
    frames = iter_asan_frames(output)
    top = _first_project_frame(frames) or (frames[0] if frames else None)
    excerpt_start = max(match.start() - 120, 0)
    excerpt_end = min(match.end() + 2000, len(output))
    # The access line follows the error header; searching from the header
    # avoids picking up shadow-byte legend noise earlier in the stream.
    access_match = ASAN_ACCESS_RE.search(output, match.end())
    return AsanSignal(
        crash_type=match.group(1).strip(),
        top_function=top.function if top else None,
        top_file=top.file if top else None,
        frames=frames,
        raw_excerpt=output[excerpt_start:excerpt_end],
        access=access_match.group(1) if access_match else None,
        access_size=int(access_match.group(2)) if access_match else None,
    )


def asan_signature(signal: AsanSignal) -> str:
    material = "|".join(
        [
            signal.crash_type,
            signal.top_function or "",
            signal.top_file or "",
            ";".join(frame.function for frame in signal.frames[:4]),
        ]
    )
    return sha256(material.encode("utf-8")).hexdigest()[:24]


# Sanitizer verdicts that mean "resources ran out", not "memory corrupted".
# Campaign policy: alloc-size-only / OOM / timeout / slow-unit events are
# resource-class noise (LOW/DoS) and must never be recorded as promotable
# findings. A report that ALSO carries a corruption verdict stays a finding.
_RESOURCE_TOKENS = (
    "out of memory: allocator is trying to allocate",
    "out-of-memory",
    "allocation-size-too-big",
    "requested allocation size",
    "exceeds maximum supported size",
    "libFuzzer: timeout",
    "libFuzzer: out-of-memory",
)
_CORRUPTION_TOKENS = (
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "container-overflow",
    "heap-use-after-free",
    "use-after-poison",
    "stack-use-after",
    "double-free",
    "bad-free",
    "invalid-free",
    "SEGV on unknown address",
    "FPE on unknown address",
    "negative-size-param",
    "memcpy-param-overlap",
    "dynamic-stack-buffer-overflow",
)


def is_resource_class(output: str) -> bool:
    """True when the crash output is resource exhaustion with no corruption verdict."""
    if not any(token in output for token in _RESOURCE_TOKENS):
        return False
    return not any(token in output for token in _CORRUPTION_TOKENS)


def _first_project_frame(frames: tuple[AsanFrame, ...]) -> AsanFrame | None:
    for frame in frames:
        if not frame.file:
            continue
        if "/src/" in frame.file or "/work/" in frame.file or frame.file.endswith((".c", ".cc", ".cpp", ".h", ".hpp")):
            return frame
    return None

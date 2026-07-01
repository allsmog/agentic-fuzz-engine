from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any


ASAN_ERROR_RE = re.compile(
    r"(?:ERROR:\s*)?AddressSanitizer:\s*([A-Za-z0-9_-]+(?:\s+on\s+unknown\s+address)?)"
)
ASAN_FRAME_RE = re.compile(
    r"^\s*#(?P<index>\d+)\s+0x[0-9a-fA-F]+\s+in\s+"
    r"(?P<function>[^\s]+)(?:\s+(?P<file>[^:\s]+):(?P<line>\d+))?",
    re.MULTILINE,
)


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "crash_type": self.crash_type,
            "top_function": self.top_function,
            "top_file": self.top_file,
            "frames": [frame.to_dict() for frame in self.frames],
            "raw_excerpt": self.raw_excerpt,
            "signature": asan_signature(self),
        }


def parse_asan_signal(output: str) -> AsanSignal | None:
    match = ASAN_ERROR_RE.search(output)
    if not match:
        return None
    frames = tuple(
        AsanFrame(
            index=int(frame.group("index")),
            function=frame.group("function"),
            file=frame.group("file"),
            line=int(frame.group("line")) if frame.group("line") else None,
        )
        for frame in ASAN_FRAME_RE.finditer(output)
    )
    top = _first_project_frame(frames) or (frames[0] if frames else None)
    excerpt_start = max(match.start() - 120, 0)
    excerpt_end = min(match.end() + 2000, len(output))
    return AsanSignal(
        crash_type=match.group(1).strip(),
        top_function=top.function if top else None,
        top_file=top.file if top else None,
        frames=frames,
        raw_excerpt=output[excerpt_start:excerpt_end],
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


def _first_project_frame(frames: tuple[AsanFrame, ...]) -> AsanFrame | None:
    for frame in frames:
        if not frame.file:
            continue
        if "/src/" in frame.file or "/work/" in frame.file or frame.file.endswith((".c", ".cc", ".cpp", ".h", ".hpp")):
            return frame
    return None

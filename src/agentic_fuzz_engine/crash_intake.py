from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from .asan import parse_asan_signal


MAX_CRASH_IMPORT_FILES = 100
MAX_CRASH_FILE_BYTES = 1_048_576
SIDECAR_SUFFIXES = {".log", ".stderr", ".stdout", ".txt", ".json"}
CRASH_SUFFIXES = {".bin", ".pov", ".testcase", ".crash"}
CRASH_DIR_NAMES = {"crashes", "crashers", "findings", "povs", "queue"}


def collect_crash_import(
    source_path: str,
    *,
    artifact_prefix: str = "crashes",
    max_files: int = MAX_CRASH_IMPORT_FILES,
    max_file_bytes: int = MAX_CRASH_FILE_BYTES,
) -> dict[str, Any]:
    source = Path(source_path).expanduser().resolve()
    if not source.exists():
        raise FileNotFoundError(f"source_path does not exist: {source_path}")
    if max_files <= 0 or max_files > MAX_CRASH_IMPORT_FILES:
        raise ValueError(f"max_files must be between 1 and {MAX_CRASH_IMPORT_FILES}")
    if max_file_bytes <= 0 or max_file_bytes > MAX_CRASH_FILE_BYTES:
        raise ValueError(f"max_file_bytes must be between 1 and {MAX_CRASH_FILE_BYTES}")

    files = _candidate_files(source)
    artifacts = []
    skipped = []
    truncated = len(files) > max_files
    for path in files[:max_files]:
        size = path.stat().st_size
        rel = _relative(path, source)
        if size > max_file_bytes:
            skipped.append({"source_rel": rel, "reason": "too_large", "size": size})
            continue
        if size == 0:
            skipped.append({"source_rel": rel, "reason": "empty", "size": 0})
            continue
        sidecar_text = _sidecar_text(path)
        signal = parse_asan_signal(sidecar_text) if sidecar_text else None
        artifacts.append(
            {
                "artifact_name": _artifact_name(artifact_prefix, rel),
                "source_path": str(path),
                "source_rel": rel,
                "size": size,
                "content_b64": base64.b64encode(path.read_bytes()).decode("ascii"),
                "sidecar_signal": signal.to_dict() if signal else None,
                "sidecar_excerpt": sidecar_text[:12000] if sidecar_text else "",
            }
        )

    blockers = [] if artifacts else ["no crash artifacts discovered"]
    return {
        "source_path": str(source),
        "artifact_prefix": artifact_prefix,
        "artifacts": artifacts,
        "skipped": skipped,
        "truncated": truncated,
        "blockers": blockers,
    }


def _candidate_files(source: Path) -> list[Path]:
    if source.is_file():
        return [] if _is_sidecar(source) else [source]
    files = sorted(path for path in source.rglob("*") if path.is_file() and not _is_sidecar(path))
    return [path for path in files if _looks_like_crash(path, source)]


def _looks_like_crash(path: Path, root: Path) -> bool:
    name = path.name.lower()
    rel_parts = {part.lower() for part in path.relative_to(root).parts[:-1]}
    if path.suffix.lower() in CRASH_SUFFIXES:
        return True
    if name.startswith(("crash", "poc", "proof", "oom-", "timeout-", "slow-unit-")):
        return True
    if name.startswith("id:") and rel_parts.intersection(CRASH_DIR_NAMES):
        return True
    return False


def _is_sidecar(path: Path) -> bool:
    return path.suffix.lower() in SIDECAR_SUFFIXES


def _sidecar_text(path: Path) -> str:
    candidates = [
        path.with_name(path.name + ".log"),
        path.with_name(path.name + ".stderr"),
        path.with_suffix(path.suffix + ".log") if path.suffix else path.with_name(path.name + ".log"),
        path.with_suffix(".log"),
        path.with_suffix(".stderr"),
        path.with_suffix(".txt"),
    ]
    chunks = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        try:
            chunks.append(candidate.read_text(encoding="utf-8", errors="replace")[:12000])
        except OSError:
            continue
    return "\n".join(chunks)


def _artifact_name(prefix: str, rel: str) -> str:
    clean_prefix = prefix.strip("/") or "crashes"
    return f"{clean_prefix}/{rel}"


def _relative(path: Path, source: Path) -> str:
    if source.is_file():
        return path.name
    return path.relative_to(source).as_posix()

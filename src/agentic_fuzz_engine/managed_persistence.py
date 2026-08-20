"""Small, fail-closed persistence primitives for workspace-owned state.

The helpers in this module are intentionally narrower than a general file API:
callers supply a workspace root and a lexical relative path, every existing
component is checked with ``lstat``, symbolic links are rejected, reads are
bounded, and replacements are made from a unique file in the destination
directory.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from pathlib import Path, PurePath
from typing import Any, Iterator

MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_JSONL_ROWS = 100_000
MAX_RECORD_BYTES = 256 * 1024
_TARGET_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,95}\Z")
_ENTRY_CLASS_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")


def validate_target_slug(value: str) -> str:
    """Return the canonical bare target slug or raise ``ValueError``."""
    if not isinstance(value, str):
        raise ValueError("target must be a string")
    text = value.removeprefix("localfuzz/c/")
    if not _TARGET_RE.fullmatch(text):
        raise ValueError("target must be a lowercase slug (letters, digits, '_' or '-')")
    return text


def validate_entry_class(value: str) -> str:
    """Return a bounded, control-free entry-class slug or raise ``ValueError``."""
    if type(value) is not str or not _ENTRY_CLASS_RE.fullmatch(value):
        raise ValueError("entry_class must be a lowercase slug of at most 64 characters")
    return value


def _relative_parts(relative: str | Path) -> tuple[str, ...]:
    candidate = PurePath(relative)
    if candidate.is_absolute() or not candidate.parts:
        raise ValueError("managed path must be non-empty and relative")
    if any(part in ("", ".", "..") for part in candidate.parts):
        raise ValueError("managed path contains a forbidden component")
    return tuple(candidate.parts)


def _check_existing(path: Path, *, allow_directory: bool = True) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"managed path contains a symbolic link: {path}")
    if not allow_directory and not stat.S_ISREG(info.st_mode):
        raise ValueError(f"managed path is not a regular file: {path}")


def managed_path(root: Path, relative: str | Path, *, create_parent: bool = False) -> Path:
    """Resolve a lexical child of ``root`` while rejecting link components."""
    root = Path(root)
    parts = _relative_parts(relative)
    if root.exists():
        _check_existing(root)
        if not root.is_dir():
            raise ValueError(f"workspace root is not a directory: {root}")
    elif create_parent:
        root.mkdir(parents=True, exist_ok=True)
        _check_existing(root)
    current = root
    for index, part in enumerate(parts):
        current = current / part
        final = index == len(parts) - 1
        if current.exists() or current.is_symlink():
            _check_existing(current)
            if not final and not current.is_dir():
                raise ValueError(f"managed path parent is not a directory: {current}")
        elif create_parent and not final:
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            _check_existing(current)
            if not current.is_dir():
                raise ValueError(f"managed path parent is not a directory: {current}")
    return current


def safe_read_bytes(
    root: Path,
    relative: str | Path,
    *,
    max_bytes: int = MAX_TEXT_BYTES,
    missing_ok: bool = True,
) -> bytes | None:
    path = managed_path(root, relative)
    if not path.exists():
        if missing_ok:
            return None
        raise FileNotFoundError(path)
    _check_existing(path, allow_directory=False)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        size = os.fstat(descriptor).st_size
        if size > max_bytes:
            raise ValueError(f"managed input exceeds {max_bytes} bytes: {path}")
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > max_bytes:
            raise ValueError(f"managed input exceeds {max_bytes} bytes: {path}")
        return bytes(data)
    finally:
        os.close(descriptor)


def safe_read_text(
    root: Path,
    relative: str | Path,
    *,
    max_bytes: int = MAX_TEXT_BYTES,
    missing_ok: bool = True,
) -> str | None:
    payload = safe_read_bytes(root, relative, max_bytes=max_bytes, missing_ok=missing_ok)
    return None if payload is None else payload.decode("utf-8")


def read_json(
    root: Path,
    relative: str | Path,
    *,
    max_bytes: int = MAX_TEXT_BYTES,
) -> Any | None:
    text = safe_read_text(root, relative, max_bytes=max_bytes)
    return None if text is None else json.loads(text)


def iter_jsonl(
    root: Path,
    relative: str | Path,
    *,
    max_bytes: int = MAX_TEXT_BYTES,
    max_rows: int = MAX_JSONL_ROWS,
) -> Iterator[tuple[int, dict[str, Any] | None]]:
    """Yield complete JSONL records; malformed rows are returned as ``None``."""
    payload = safe_read_bytes(root, relative, max_bytes=max_bytes)
    if payload is None:
        return
    complete = payload if payload.endswith(b"\n") else payload.rsplit(b"\n", 1)[0] + b"\n" if b"\n" in payload else b""
    for number, raw in enumerate(complete.splitlines(), 1):
        if number > max_rows:
            raise ValueError(f"managed JSONL exceeds {max_rows} rows: {relative}")
        if not raw.strip():
            continue
        if len(raw) > MAX_RECORD_BYTES:
            yield number, None
            continue
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            yield number, None
            continue
        yield number, value if isinstance(value, dict) else None


def atomic_write_bytes(
    root: Path,
    relative: str | Path,
    payload: bytes,
    *,
    max_bytes: int = MAX_TEXT_BYTES,
) -> Path:
    if len(payload) > max_bytes:
        raise ValueError(f"managed output exceeds {max_bytes} bytes")
    destination = managed_path(root, relative, create_parent=True)
    if destination.exists() or destination.is_symlink():
        _check_existing(destination, allow_directory=False)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, destination)
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    return destination


def atomic_write_text(
    root: Path,
    relative: str | Path,
    text: str,
    *,
    max_bytes: int = MAX_TEXT_BYTES,
) -> Path:
    return atomic_write_bytes(root, relative, text.encode("utf-8"), max_bytes=max_bytes)


def append_jsonl(root: Path, relative: str | Path, record: dict[str, Any]) -> Path:
    payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(payload) > MAX_RECORD_BYTES:
        raise ValueError("managed JSONL record exceeds size cap")
    path = managed_path(root, relative, create_parent=True)
    if path.exists() or path.is_symlink():
        _check_existing(path, allow_directory=False)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise OSError("short JSONL append")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def replace_managed_file(root: Path, source: Path, relative: str | Path) -> Path:
    """Atomically promote a regular, same-directory staging file."""
    destination = managed_path(root, relative, create_parent=True)
    _check_existing(source, allow_directory=False)
    if source.parent != destination.parent:
        raise ValueError("staging file must share the destination directory")
    if destination.exists() or destination.is_symlink():
        _check_existing(destination, allow_directory=False)
    os.replace(source, destination)
    directory_fd = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return destination

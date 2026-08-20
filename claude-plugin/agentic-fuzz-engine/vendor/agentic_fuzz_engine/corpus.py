from __future__ import annotations

import ast
import base64
from hashlib import sha256
from pathlib import Path
from typing import Any


MAX_CORPUS_IMPORT_FILES = 100
MAX_CORPUS_FILE_BYTES = 262_144
MAX_DICTIONARY_TOKENS = 256
MAX_DICTIONARY_TOKEN_BYTES = 1024


def collect_corpus_import(
    source_path: str,
    *,
    kind: str = "auto",
    artifact_prefix: str = "corpus",
    max_files: int = MAX_CORPUS_IMPORT_FILES,
    max_file_bytes: int = MAX_CORPUS_FILE_BYTES,
) -> dict[str, Any]:
    source = Path(source_path).expanduser().resolve()
    if not source.exists():
        raise FileNotFoundError(f"corpus source path does not exist: {source_path}")
    max_files = _bounded_int(max_files, "max_files", MAX_CORPUS_IMPORT_FILES)
    max_file_bytes = _bounded_int(max_file_bytes, "max_file_bytes", MAX_CORPUS_FILE_BYTES)
    if kind not in {"auto", "seed", "dictionary"}:
        raise ValueError("kind must be auto, seed, or dictionary")

    files, truncated = _source_files(source, max_files=max_files)
    artifacts = []
    dictionary_tokens: list[str] = []
    skipped = []
    for path in files:
        size = path.stat().st_size
        rel = path.name if source.is_file() else path.relative_to(source).as_posix()
        if size > max_file_bytes:
            skipped.append({"path": rel, "reason": "file too large", "size": size})
            continue
        if kind in {"auto", "dictionary"} and path.suffix == ".dict":
            tokens = parse_dictionary_file(path)
            dictionary_tokens.extend(tokens)
        if kind == "dictionary" and path.suffix != ".dict":
            skipped.append({"path": rel, "reason": "not a dictionary file", "size": size})
            continue
        data = path.read_bytes()
        artifacts.append(
            {
                "artifact_name": _artifact_name(artifact_prefix, rel),
                "source_path": str(path),
                "source_rel": rel,
                "content_b64": base64.b64encode(data).decode("ascii"),
                "sha256": sha256(data).hexdigest(),
                "size": len(data),
                "kind": "dictionary" if path.suffix == ".dict" else "seed",
            }
        )
    return {
        "source_path": str(source),
        "kind": kind,
        "artifact_prefix": artifact_prefix,
        "artifacts": artifacts,
        "dictionary_tokens": dictionary_tokens[:MAX_DICTIONARY_TOKENS],
        "skipped": skipped,
        "truncated": truncated,
    }


def parse_dictionary_file(path: Path) -> list[str]:
    tokens = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line and not line.startswith(('"', "'")):
            line = line.split("=", 1)[1].strip()
        token = _parse_token(line)
        if token and len(token.encode("utf-8")) <= MAX_DICTIONARY_TOKEN_BYTES:
            tokens.append(token)
        if len(tokens) >= MAX_DICTIONARY_TOKENS:
            break
    return tokens


def _parse_token(value: str) -> str:
    try:
        parsed = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return value.strip().strip('"').strip("'")
    if isinstance(parsed, bytes):
        return parsed.decode("latin1", errors="replace")
    if isinstance(parsed, str):
        return parsed
    return str(parsed)


def _source_files(source: Path, *, max_files: int) -> tuple[list[Path], bool]:
    if source.is_file():
        return [source], False
    files = []
    for path in sorted(item for item in source.rglob("*") if item.is_file()):
        resolved = path.resolve()
        try:
            resolved.relative_to(source)
        except ValueError:
            continue
        if len(files) >= max_files:
            return files, True
        files.append(resolved)
    return files, False


def _artifact_name(prefix: str, rel: str) -> str:
    raw = f"{prefix}/{rel}" if prefix else rel
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in raw)[:180] or "seed.bin"


def _bounded_int(value: int, name: str, limit: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed <= 0 or parsed > limit:
        raise ValueError(f"{name} must be between 1 and {limit}")
    return parsed

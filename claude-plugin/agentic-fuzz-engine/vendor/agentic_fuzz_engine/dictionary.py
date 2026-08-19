from __future__ import annotations

import ast
import base64
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_DICTIONARY_SOURCE_FILES = 500
MAX_DICTIONARY_FILE_BYTES = 262_144
MAX_GENERATED_DICTIONARY_TOKENS = 64
MAX_TOKEN_BYTES = 1024
SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".inc",
    ".inl",
    ".ipp",
}
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".pytest_cache", "node_modules", "target", "build", "out"}
STRING_RE = re.compile(r"""(?P<prefix>[rubfRUBF]{0,3})(?P<quote>["'])(?P<body>(?:\\.|(?!\2)[^\\\n]){1,512})(?P=quote)""")
HEX_BYTE_RE = re.compile(r"0x([0-9a-fA-F]{2})")
SECRET_HINTS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer ",
    "password",
    "private_key",
    "secret",
    "session_key",
)


@dataclass(frozen=True, slots=True)
class DictionaryToken:
    token: str
    source_path: str
    source_rel: str
    line: int
    reason: str
    score: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "source_path": self.source_path,
            "source_rel": self.source_rel,
            "line": self.line,
            "reason": self.reason,
            "score": self.score,
        }


def generate_dictionary_from_source(
    source_dir: str,
    *,
    artifact_name: str = "generated.dict",
    max_files: int = MAX_DICTIONARY_SOURCE_FILES,
    max_file_bytes: int = MAX_DICTIONARY_FILE_BYTES,
    max_tokens: int = MAX_GENERATED_DICTIONARY_TOKENS,
) -> dict[str, Any]:
    source = Path(source_dir).expanduser().resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"source_dir is not a directory: {source_dir}")
    max_files = _bounded_int(max_files, "max_files", MAX_DICTIONARY_SOURCE_FILES)
    max_file_bytes = _bounded_int(max_file_bytes, "max_file_bytes", MAX_DICTIONARY_FILE_BYTES)
    max_tokens = _bounded_int(max_tokens, "max_tokens", MAX_GENERATED_DICTIONARY_TOKENS)

    files, truncated = _source_files(source, max_files=max_files)
    candidates: list[DictionaryToken] = []
    skipped = []
    for path in files:
        rel = path.relative_to(source).as_posix()
        size = path.stat().st_size
        if size > max_file_bytes:
            skipped.append({"path": rel, "reason": "file too large", "size": size})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        candidates.extend(_tokens_from_text(text, path=path, source=source))

    selected = _select_tokens(candidates, max_tokens=max_tokens)
    content = "\n".join(
        f"tok_{index:03d}={_libfuzzer_quote(item.token)}" for index, item in enumerate(selected)
    )
    if content:
        content += "\n"
    return {
        "source_dir": str(source),
        "artifact_name": artifact_name,
        "artifact_content_b64": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "dictionary_tokens": [item.token for item in selected],
        "token_entries": [item.to_dict() for item in selected],
        "source_files_scanned": len(files) - len(skipped),
        "skipped": skipped,
        "truncated": truncated,
    }


def _tokens_from_text(text: str, *, path: Path, source: Path) -> list[DictionaryToken]:
    tokens = []
    rel = path.relative_to(source).as_posix()
    lines = text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        context = _context(lines, line_number)
        for match in STRING_RE.finditer(line):
            token = _parse_literal(match.group(0))
            if _is_useful_token(token, context=context):
                tokens.append(
                    DictionaryToken(
                        token=token,
                        source_path=str(path),
                        source_rel=rel,
                        line=line_number,
                        reason=_reason_for_context(context, token),
                        score=_score_token(token, context, rel),
                    )
                )
        hex_token = _hex_byte_token(line)
        if hex_token and _is_useful_token(hex_token, context=context):
            tokens.append(
                DictionaryToken(
                    token=hex_token,
                    source_path=str(path),
                    source_rel=rel,
                    line=line_number,
                    reason="hex byte sequence",
                    score=_score_token(hex_token, context, rel) + 20,
                )
            )
    return tokens


def _select_tokens(candidates: list[DictionaryToken], *, max_tokens: int) -> list[DictionaryToken]:
    by_token: dict[str, DictionaryToken] = {}
    for item in candidates:
        current = by_token.get(item.token)
        if current is None or (item.score, -item.line) > (current.score, -current.line):
            by_token[item.token] = item
    return sorted(by_token.values(), key=lambda item: (-item.score, item.source_rel, item.line, item.token))[:max_tokens]


def _parse_literal(raw: str) -> str:
    prefix = ""
    while raw and raw[0] in "rubfRUBF":
        prefix += raw[0]
        raw = raw[1:]
    clean_prefix = "".join(char for char in prefix if char.lower() != "f")
    try:
        parsed = ast.literal_eval(clean_prefix + raw)
    except (SyntaxError, ValueError):
        parsed = raw[1:-1]
    if isinstance(parsed, bytes):
        return parsed.decode("latin1", errors="replace")
    return str(parsed)


def _is_useful_token(token: str, *, context: str) -> bool:
    if not token:
        return False
    data = token.encode("utf-8")
    if not (1 <= len(data) <= MAX_TOKEN_BYTES):
        return False
    lowered = token.lower()
    context_lower = context.lower()
    if any(hint in lowered or hint in context_lower for hint in SECRET_HINTS):
        return False
    if token.startswith(("/", "~/")) or "/Users/" in token or "\\Users\\" in token:
        return False
    if "://" in token:
        return False
    if len(token) == 1 and not any(marker in context_lower for marker in ("case", "switch", "magic", "tag")):
        return False
    if len(token) > 160 and not _has_binary_bytes(token):
        return False
    if lowered in {"error", "failed", "failure", "invalid", "usage", "unknown"}:
        return False
    return True


def _score_token(token: str, context: str, source_rel: str) -> int:
    context_lower = context.lower()
    score = 0
    if any(name in context_lower for name in ("memcmp", "strcmp", "strncmp", "strcasecmp", "strstr", "memmem")):
        score += 100
    if any(name in context_lower for name in ("magic", "signature", "header", "token", "verb", "opcode", "tag")):
        score += 70
    if any(name in context_lower for name in ("case ", "switch", "state", "parse", "decode", "validate")):
        score += 35
    if "fuzz" in source_rel.lower() or "harness" in source_rel.lower():
        score += 15
    if _has_binary_bytes(token):
        score += 50
    if token.isupper() and len(token) >= 3:
        score += 30
    if 3 <= len(token.encode("utf-8")) <= 32:
        score += 20
    return score


def _reason_for_context(context: str, token: str) -> str:
    lowered = context.lower()
    if any(name in lowered for name in ("memcmp", "strcmp", "strncmp", "strcasecmp", "strstr", "memmem")):
        return "literal in comparison"
    if any(name in lowered for name in ("magic", "signature", "header")):
        return "magic/header literal"
    if any(name in lowered for name in ("case ", "switch")) or len(token) == 1:
        return "branch selector literal"
    return "source literal"


def _hex_byte_token(line: str) -> str | None:
    values = [int(item, 16) for item in HEX_BYTE_RE.findall(line)]
    if len(values) < 2 or len(values) > 32:
        return None
    return bytes(values).decode("latin1", errors="replace")


def _context(lines: list[str], line_number: int) -> str:
    start = max(0, line_number - 2)
    end = min(len(lines), line_number + 1)
    return "\n".join(lines[start:end])


def _has_binary_bytes(token: str) -> bool:
    return any(ord(char) < 32 or ord(char) > 126 for char in token)


def _libfuzzer_quote(token: str) -> str:
    body = []
    for byte in token.encode("utf-8"):
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


def _bounded_int(value: int, name: str, limit: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed <= 0 or parsed > limit:
        raise ValueError(f"{name} must be between 1 and {limit}")
    return parsed

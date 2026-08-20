"""Find candidate first-party input boundaries in C and C++ sources.

Rows are evidence for harness selection.  A matching handler, program entry,
or library call does not by itself prove that attacker-controlled bytes reach
the candidate.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from .fork_inventory import MAX_TREE_DIRECTORIES, MAX_TREE_ENTRIES, _BoundedTree, _atomic_jsonl, _validate_output
from .harness_gen import MAX_SOURCE_BYTES, _CPP_LANGUAGE, _innermost_function_declarator
from .workspace import load_policy, load_workspace, resolve_workspace_root

try:  # pragma: no cover - availability is exercised through result metadata
    import tree_sitter
except Exception:  # pragma: no cover
    tree_sitter = None  # type: ignore[assignment]

MAX_FILES_SCANNED = 20_000
MAX_ROWS_TOTAL = 8_000
MAX_ROWS_PER_FILE = 30
MAX_LIB_PREFIXES = 64
SOURCE_SUFFIXES = {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hh"}
EXCLUDED_DIR_NAMES = {
    "test", "tests", "testing", "example", "examples", "benchmark", "benchmarks",
    "third_party", "third-party", "external", "vendor", ".git", "build", "out",
}
EXCLUDED_FILE_MARKERS = ("_test", "_tests", "_bench", "_benchmark", "_mock", "_fake")
_PREFIX_RE = re.compile(r"[A-Za-z_]\w{0,63}_?")
_HANDLER_RE = re.compile(
    r"\b(?:class|struct)\s+(\w+)\s*(?:final\s*)?:\s*[^\{;]*?\b(?:public|protected|private)\s+([\w:<>]+)"
)
_MAIN_RE = re.compile(r"^\s*(?:int|auto)\s+main\s*\(", re.MULTILINE)


def run_entry_scan(
    *, source_root: str | Path | None = None, out_path: str | Path | None = None,
    workspace_root: str | Path | None = None, lib_prefixes: Sequence[str] | None = None,
    service_base_suffixes: Sequence[str] | None = None,
    max_files: int = MAX_FILES_SCANNED, env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    root: Path | None = None
    workspace: dict[str, Any] = {}
    try:
        root = resolve_workspace_root(workspace_root, env=environment)
        workspace = load_workspace(root, env=environment)
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        root = None
    policy: Mapping[str, Any] = {}
    if root is not None:
        candidate = load_policy(root, env=environment).get("entry_scan") or {}
        if isinstance(candidate, Mapping):
            policy = candidate
    try:
        prefixes = _validate_prefixes(lib_prefixes if lib_prefixes is not None else policy.get("lib_prefixes", []))
        base_suffixes = _validate_suffixes(
            service_base_suffixes if service_base_suffixes is not None else policy.get("service_base_suffixes", [])
        )
        file_limit = min(max(int(max_files), 1), MAX_FILES_SCANNED)
    except (TypeError, ValueError) as exc:
        return _blocked(str(exc))

    source_value = source_root or workspace.get("source_dir")
    if not source_value:
        return _blocked("source_root required (no workspace source_dir)")
    scan_root = Path(str(source_value)).expanduser().resolve()
    if not scan_root.is_dir():
        return _blocked(f"source_root is not a directory: {scan_root}")
    if out_path is None:
        if root is None:
            return _blocked("out_path required when no initialized workspace is available")
        out = root / "data" / "entry-scan.jsonl"
    else:
        out = Path(out_path).expanduser()
    try:
        out = _validate_output(out, root)
    except ValueError as exc:
        return _blocked(str(exc))

    from .boundaries import classify_path, load_boundaries

    boundaries = load_boundaries(root)
    rows: list[dict[str, Any]] = []
    counts = {"service-handler": 0, "program-main": 0, "library-call": 0}
    files_scanned = files_skipped = 0
    seen: set[tuple[str, int, str, str]] = set()
    parser_available = _CPP_LANGUAGE is not None and tree_sitter is not None

    try:
        with _BoundedTree(scan_root) as tree:
            for source in tree.regular_files(
                max_entries=MAX_TREE_ENTRIES, max_directories=MAX_TREE_DIRECTORIES
            ):
                if len(rows) >= MAX_ROWS_TOTAL or files_scanned >= file_limit:
                    break
                path = source.path
                if path.suffix.lower() not in SOURCE_SUFFIXES:
                    continue
                rel = source.relative
                if any(part.lower() in EXCLUDED_DIR_NAMES for part in rel.parts[:-1]) or any(
                    marker in path.stem.lower() for marker in EXCLUDED_FILE_MARKERS
                ):
                    continue
                if source.expected.st_size > MAX_SOURCE_BYTES:
                    files_skipped += 1
                    continue
                text = tree.read_text(source, max_bytes=MAX_SOURCE_BYTES)
                files_scanned += 1
                found = _scan_tree(text, prefixes, base_suffixes) if parser_available else _scan_fallback(text, base_suffixes)
                rel_text = rel.as_posix()
                module = rel.parts[0].lower() if len(rel.parts) > 1 else "root"
                entry_class, _weight = classify_path(rel_text, boundaries)
                file_rows = 0
                for item in found:
                    if file_rows >= MAX_ROWS_PER_FILE or len(rows) >= MAX_ROWS_TOTAL:
                        break
                    key = (rel_text, item["line"], item["method"], item["callee"])
                    if key in seen:
                        continue
                    seen.add(key)
                    kind = item["entry_kind"]
                    rows.append({
                        "tag": module, "file": rel_text, "line": item["line"],
                        "method": item["method"], "callee": item["callee"],
                        "code": item["code"][:200], "kind": "entry", "primitive": None,
                        "entry_kind": kind, "entry_class": entry_class, "via": "entry-scan",
                        "candidate_evidence": item["candidate_evidence"],
                        **item.get("extra", {}),
                    })
                    counts[kind] += 1
                    file_rows += 1
    except ValueError as exc:
        return _blocked(f"unable to scan source tree safely: {exc}")
    try:
        _atomic_jsonl(out, rows)
    except (OSError, ValueError) as exc:
        return _blocked(f"unable to write entry inventory: {exc}")
    return {
        "ok": True, "mode": "entry-scan", "source_root": str(scan_root), "out": str(out),
        "files_scanned": files_scanned, "files_skipped": files_skipped,
        "rows_written": len(rows), "lib_prefixes": prefixes,
        "service_base_suffixes": base_suffixes, "counts": counts,
        "extractor": "tree-sitter" if parser_available else "conservative-regex",
        "blockers": [],
    }


def _blocked(message: str) -> dict[str, Any]:
    return {"ok": False, "mode": "entry-scan", "rows_written": 0, "blockers": [message]}


def _validate_prefixes(values: Any) -> list[str]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ValueError("lib_prefixes must be a list")
    if len(values) > MAX_LIB_PREFIXES:
        raise ValueError(f"lib_prefixes exceeds {MAX_LIB_PREFIXES} entries")
    prefixes: set[str] = set()
    for value in values:
        prefix = str(value)
        if not _PREFIX_RE.fullmatch(prefix):
            raise ValueError(f"invalid library prefix: {value!r}")
        prefixes.add(prefix)
    return sorted(prefixes)


def _validate_suffixes(values: Any) -> list[str]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ValueError("service_base_suffixes must be a list")
    if len(values) > 32:
        raise ValueError("service_base_suffixes exceeds 32 entries")
    result: set[str] = set()
    for value in values:
        suffix = str(value)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", suffix):
            raise ValueError(f"invalid service base suffix: {value!r}")
        result.add(suffix.lower())
    return sorted(result)


def _function_name(node: Any) -> str | None:
    declarator = _innermost_function_declarator(node.child_by_field_name("declarator"))
    if declarator is None:
        return None
    name_node = declarator.child_by_field_name("declarator")
    if name_node is None:
        return None
    text = name_node.text.decode("utf-8", errors="replace")
    return re.split(r"::|\.|->", text)[-1].strip() or None


def _node_line(text_lines: list[str], node: Any) -> tuple[int, str]:
    line = node.start_point[0] + 1
    code = text_lines[line - 1].strip() if line <= len(text_lines) else ""
    return line, code


def _scan_tree(text: str, prefixes: Sequence[str], base_suffixes: Sequence[str]) -> list[dict[str, Any]]:
    parser = tree_sitter.Parser(_CPP_LANGUAGE)
    tree = parser.parse(text.encode("utf-8"))
    lines = text.splitlines()
    result: list[dict[str, Any]] = []
    functions: list[Any] = []
    classes: list[Any] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            functions.append(node)
        elif node.type in {"class_specifier", "struct_specifier"}:
            classes.append(node)
        stack.extend(reversed(node.children))

    for node in sorted(classes, key=lambda item: item.start_point):
        header = node.text.decode("utf-8", errors="replace").split("{", 1)[0]
        match = _HANDLER_RE.search(header)
        if not match:
            continue
        handler_match, confidence = _looks_like_service_handler(match.group(1), match.group(2), base_suffixes)
        if not handler_match:
            continue
        line, code = _node_line(lines, node)
        result.append({
            "line": line, "method": match.group(1), "callee": "service-handler",
            "code": code, "entry_kind": "service-handler",
            "candidate_evidence": "class-derives-service-interface",
            "extra": {"service_interface": match.group(2), "heuristic_confidence": confidence},
        })

    for node in sorted(functions, key=lambda item: item.start_point):
        name = _function_name(node)
        if not name:
            continue
        if name == "main":
            line, code = _node_line(lines, node)
            result.append({"line": line, "method": "main", "callee": "program-main",
                "code": code, "entry_kind": "program-main", "candidate_evidence": "main-definition"})
        body = node.child_by_field_name("body")
        if body is None or not prefixes:
            continue
        pending = [body]
        while pending:
            current = pending.pop()
            if current.type == "call_expression":
                called_node = current.child_by_field_name("function")
                called = called_node.text.decode("utf-8", errors="replace") if called_node is not None else ""
                bare = re.split(r"::|\.|->", called)[-1].strip()
                if bare and any(bare.startswith(prefix) for prefix in prefixes):
                    line, code = _node_line(lines, current)
                    result.append({"line": line, "method": name, "callee": bare,
                        "code": code, "entry_kind": "library-call",
                        "candidate_evidence": "first-party-call-to-prefixed-library-symbol",
                        "extra": {"lib_call": True, "heuristic_confidence": "configured-symbol-prefix"}})
            pending.extend(reversed(current.children))
    return result


def _looks_like_service_handler(
    class_name: str, base_name: str, base_suffixes: Sequence[str]
) -> tuple[bool, str | None]:
    bare_base = re.sub(r"<.*", "", base_name.split("::")[-1]).lower()
    if any(bare_base.endswith(suffix) for suffix in base_suffixes):
        return True, "configured-base-suffix"
    return False, None


def _scan_fallback(text: str, base_suffixes: Sequence[str]) -> list[dict[str, Any]]:
    """Fallback emits only definitions it can attribute without guessing call ownership."""
    lines = text.splitlines()
    result: list[dict[str, Any]] = []
    for match in _HANDLER_RE.finditer(text):
        handler_match, confidence = _looks_like_service_handler(match.group(1), match.group(2), base_suffixes)
        if not handler_match:
            continue
        line = text[:match.start()].count("\n") + 1
        result.append({"line": line, "method": match.group(1), "callee": "service-handler",
            "code": lines[line - 1].strip(), "entry_kind": "service-handler",
            "candidate_evidence": "class-derives-service-interface",
            "extra": {"service_interface": match.group(2), "heuristic_confidence": confidence}})
    for match in _MAIN_RE.finditer(text):
        line = text[:match.start()].count("\n") + 1
        result.append({"line": line, "method": "main", "callee": "program-main",
            "code": lines[line - 1].strip(), "entry_kind": "program-main",
            "candidate_evidence": "main-definition"})
    return result

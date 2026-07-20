"""Deterministic sink/entry-point inventory (``sink-scan``).

Produces the sinks JSONL that ``candidates sync`` / ``target-select`` /
``target-generate`` consume, from nothing but a source tree — no Joern, no
external tooling, no prior knowledge of the codebase.

Two row kinds, both attributed to a concrete function definition so the
direct_call generator can extract the signature at that site:

- ``entry``: a function whose parameters have a fuzzable shape (single
  string-ish parameter, or byte-pointer + length) AND whose name looks like
  an input boundary (Parse/Decode/Deserialize/From*/Load/Read/...) or whose
  body contains a dangerous callee.
- ``sink``: a call site of a dangerous callee (memcpy/strcpy/exec*/...),
  recorded against the enclosing function.

Rows are tagged with the module name (first path component under the scan
root), so each module becomes one rankable attack vector and one generated
target. Everything is bounded: files scanned, bytes per file, rows per
module, rows total.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

from .harness_gen import (
    MAX_SOURCE_BYTES,
    _CPP_LANGUAGE,
    _innermost_function_declarator,
    _is_byteptr,
    _is_integral,
    _is_stringish,
    _parse_params,
)
from .workspace import load_workspace, resolve_workspace_root

try:  # pragma: no cover - exercised implicitly
    import tree_sitter
except Exception:  # pragma: no cover
    tree_sitter = None  # type: ignore[assignment]

MAX_FILES_SCANNED = 20000
MAX_ROWS_PER_MODULE = 400
MAX_ROWS_TOTAL = 20000
MAX_SINK_ROWS_PER_FILE = 40

SOURCE_SUFFIXES = {".cpp", ".cc", ".cxx", ".c"}

EXCLUDED_DIR_NAMES = {
    "test", "tests", "testing", "example", "examples", "benchmark",
    "benchmarks", "third_party", "third-party", "external", "vendor",
    ".git", "build", "out",
}

EXCLUDED_FILE_MARKERS = ("_test", "_tests", "_bench", "_benchmark", "_mock", "_fake")

# Each dangerous callee is classified by the primitive an attacker gets when
# its arguments go wrong: ``write`` (memory corruption), ``exec`` (command /
# code loading), ``alloc`` (attacker-sized stack growth). Write/exec sinks
# rank first because they are the exploitable-primitive candidates.
SINK_PRIMITIVES = {
    "memcpy": "write", "memmove": "write", "strcpy": "write", "strncpy": "write",
    "strcat": "write", "strncat": "write", "sprintf": "write", "vsprintf": "write",
    "sscanf": "write", "gets": "write",
    "alloca": "alloc",
    "system": "exec", "popen": "exec",
    "execl": "exec", "execlp": "exec", "execle": "exec",
    "execv": "exec", "execvp": "exec", "execvpe": "exec",
    "dlopen": "exec",
}

DANGEROUS_CALLEES = set(SINK_PRIMITIVES)

PRIMITIVE_WEIGHT = {"write": 3, "exec": 3, "alloc": 2}

ENTRY_NAME_RE = re.compile(
    r"(?i)(parse|decode|deserial|unmarshal|unpack|from_?(json|string|bytes|buffer|blob)"
    r"|ingest|import|extract|load|read|convert)"
)

_ENTRY_FALLBACK_RE = re.compile(
    r"^[ \t]*[\w:<>&,\*\s]+?\b([A-Za-z_]\w*)\s*\(([^;{)]*)\)\s*(const\s*)?(noexcept\s*)?\{",
    re.MULTILINE,
)


def run_sink_scan(
    *,
    source_root: str | Path | None = None,
    out_path: str | Path | None = None,
    workspace_root: str | Path | None = None,
    max_files: int = MAX_FILES_SCANNED,
    max_rows_per_module: int = MAX_ROWS_PER_MODULE,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(env) if env is not None else dict(os.environ)
    root: Path | None = None
    workspace: dict[str, Any] = {}
    try:
        root = resolve_workspace_root(workspace_root, env=environment)
        workspace = load_workspace(root, env=environment)
    except (FileNotFoundError, ValueError):
        root = None

    if source_root is None:
        source_root = workspace.get("source_dir")
    if not source_root:
        return {"ok": False, "blockers": ["source_root required (no workspace source_dir)"], "rows_written": 0}
    scan_root = Path(source_root).expanduser().resolve()
    if not scan_root.is_dir():
        return {"ok": False, "blockers": [f"source_root is not a directory: {scan_root}"], "rows_written": 0}

    if out_path is None:
        if root is None:
            return {"ok": False, "blockers": ["out_path required (no workspace for default)"], "rows_written": 0}
        out = root / "data" / "sink-scan.jsonl"
    else:
        out = Path(out_path).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    max_files = max(1, int(max_files))
    max_rows_per_module = max(1, int(max_rows_per_module))

    from .boundaries import classify_path, load_boundaries

    boundaries = load_boundaries(root)

    files_scanned = 0
    files_skipped = 0
    rows: list[dict[str, Any]] = []
    per_module: dict[str, dict[str, int]] = {}
    seen: set[tuple[str, str, str, str]] = set()

    for path in sorted(scan_root.rglob("*")):
        if len(rows) >= MAX_ROWS_TOTAL:
            break
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        rel = path.relative_to(scan_root)
        if any(part in EXCLUDED_DIR_NAMES for part in rel.parts[:-1]):
            continue
        stem = path.stem.lower()
        if any(marker in stem for marker in EXCLUDED_FILE_MARKERS):
            continue
        if files_scanned >= max_files:
            files_skipped += 1
            continue
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                files_skipped += 1
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            files_skipped += 1
            continue
        files_scanned += 1

        module = rel.parts[0] if len(rel.parts) > 1 else "root"
        tag = module.lower()
        entry_class, class_weight = classify_path(str(rel), boundaries)
        stats = per_module.setdefault(
            tag,
            {"entries": 0, "sinks": 0, "write_sinks": 0, "exec_sinks": 0, "files": 0, "weight": 0, "boundary_weight": 0},
        )
        stats["files"] += 1
        module_rows = stats["entries"] + stats["sinks"]
        if module_rows >= max_rows_per_module:
            continue

        if _CPP_LANGUAGE is not None and tree_sitter is not None:
            found = _scan_with_tree_sitter(text)
        else:
            found = _scan_with_regex(text)

        for item in found:
            if stats["entries"] + stats["sinks"] >= max_rows_per_module or len(rows) >= MAX_ROWS_TOTAL:
                break
            key = (str(rel), item["method"], item["callee"], item["kind"])
            if key in seen:
                continue
            seen.add(key)
            primitive = SINK_PRIMITIVES.get(item["callee"]) if item["kind"] == "sink" else None
            rows.append(
                {
                    "tag": tag,
                    "file": str(rel),
                    "line": item["line"],
                    "method": item["method"],
                    "callee": item["callee"],
                    "code": item["code"][:200],
                    "kind": item["kind"],
                    "primitive": primitive,
                    "entry_class": entry_class,
                    "via": "sink-scan",
                }
            )
            stats["entries" if item["kind"] == "entry" else "sinks"] += 1
            if primitive == "write":
                stats["write_sinks"] += 1
            elif primitive == "exec":
                stats["exec_sinks"] += 1
            stats["weight"] += PRIMITIVE_WEIGHT.get(primitive or "", 1)
            stats["boundary_weight"] += PRIMITIVE_WEIGHT.get(primitive or "", 1) * class_weight

    with out.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    modules_ranked = sorted(
        (
            {"tag": tag, **stats, "rows": stats["entries"] + stats["sinks"]}
            for tag, stats in per_module.items()
            if stats["entries"] + stats["sinks"] > 0
        ),
        # boundary_weight == weight when no boundaries map exists, so the
        # ordering is unchanged for workspaces that never author one.
        key=lambda item: (-item.get("boundary_weight", item["weight"]), -item["weight"], -item["rows"], item["tag"]),
    )
    return {
        "ok": True,
        "mode": "sink-scan",
        "source_root": str(scan_root),
        "out": str(out),
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "rows_written": len(rows),
        "modules": modules_ranked,
        "extractor": "tree-sitter" if (_CPP_LANGUAGE is not None and tree_sitter is not None) else "regex",
        "blockers": [],
    }


def _scan_with_tree_sitter(text: str) -> list[dict[str, Any]]:
    parser = tree_sitter.Parser(_CPP_LANGUAGE)
    tree = parser.parse(text.encode("utf-8"))
    found: list[dict[str, Any]] = []

    stack = [tree.root_node]
    functions = []
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            functions.append(node)
        stack.extend(node.children)

    for node in sorted(functions, key=lambda n: n.start_point[0]):
        fn = _innermost_function_declarator(node.child_by_field_name("declarator"))
        if fn is None:
            continue
        name_node = fn.child_by_field_name("declarator")
        name_text = name_node.text.decode("utf-8", errors="replace") if name_node else ""
        bare = name_text.split("::")[-1]
        if not bare or not re.fullmatch(r"[A-Za-z_]\w*", bare) or bare == "main":
            continue
        params_node = fn.child_by_field_name("parameters")
        params_text = params_node.text.decode("utf-8", errors="replace") if params_node else "()"
        params = _parse_params(params_text)
        line = node.start_point[0] + 1
        first_line = text.splitlines()[line - 1].strip() if line - 1 < len(text.splitlines()) else bare

        dangerous_calls = _dangerous_calls_in(node, text)
        for callee, call_line, call_code in dangerous_calls[:MAX_SINK_ROWS_PER_FILE]:
            found.append(
                {"method": bare, "callee": callee, "line": call_line, "code": call_code, "kind": "sink"}
            )
        if _fuzzable_shape(params) and (ENTRY_NAME_RE.search(bare) or dangerous_calls):
            found.append(
                {"method": bare, "callee": "entry-point", "line": line, "code": first_line, "kind": "entry"}
            )
    return found


def _dangerous_calls_in(node: Any, text: str) -> list[tuple[str, int, str]]:
    body = node.child_by_field_name("body")
    if body is None:
        return []
    calls: list[tuple[str, int, str]] = []
    lines = text.splitlines()
    stack = [body]
    while stack:
        current = stack.pop()
        if current.type == "call_expression":
            fn_node = current.child_by_field_name("function")
            if fn_node is not None:
                callee_text = fn_node.text.decode("utf-8", errors="replace")
                callee = re.split(r"::|\.|->", callee_text)[-1].strip()
                if callee in DANGEROUS_CALLEES:
                    call_line = current.start_point[0] + 1
                    code = lines[call_line - 1].strip() if call_line - 1 < len(lines) else callee
                    calls.append((callee, call_line, code))
        stack.extend(current.children)
    calls.sort(key=lambda item: item[1])
    return calls


def _scan_with_regex(text: str) -> list[dict[str, Any]]:
    # Fallback without tree-sitter: entry-shaped definitions only (dangerous
    # call sites cannot be reliably attributed to an enclosing function).
    found: list[dict[str, Any]] = []
    for match in _ENTRY_FALLBACK_RE.finditer(text):
        name = match.group(1)
        if name == "main" or not ENTRY_NAME_RE.search(name):
            continue
        params = _parse_params(f"({match.group(2)})")
        if not _fuzzable_shape(params):
            continue
        line = text[: match.start()].count("\n") + 1
        found.append(
            {
                "method": name,
                "callee": "entry-point",
                "line": line,
                "code": match.group(0).split("{")[0].strip(),
                "kind": "entry",
            }
        )
    return found


def _fuzzable_shape(params: list[dict[str, str]]) -> bool:
    if len(params) == 1 and _is_stringish(params[0]["type"]):
        return True
    if len(params) == 2 and _is_byteptr(params[0]["type"]) and _is_integral(params[1]["type"]):
        return True
    return False


def merge_sink_jsonl(
    *,
    inputs: list[str | Path],
    out_path: str | Path,
) -> dict[str, Any]:
    """Union several sink inventories (auto-scan, Joern export, curated) into
    one JSONL. Dedupe key is ``file:line:callee``; when two sources carry the
    same key, the richer provenance wins (joern > manual > sink-scan) so
    curated attribution survives repeated merges. Later inputs never clobber
    an earlier row of higher provenance rank.
    """
    rank = {"joern": 3, "manual": 2, "sink-scan": 1}

    def row_rank(row: Mapping[str, Any]) -> int:
        via = str(row.get("via") or "").lower()
        for token, value in rank.items():
            if token in via:
                return value
        return 0

    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    read = {"files": 0, "rows": 0, "bad_lines": 0, "missing": []}
    for item in inputs:
        path = Path(item).expanduser()
        if not path.is_file():
            read["missing"].append(str(path))
            continue
        read["files"] += 1
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    read["bad_lines"] += 1
                    continue
                if not isinstance(row, dict) or not row.get("file"):
                    read["bad_lines"] += 1
                    continue
                read["rows"] += 1
                key = (str(row.get("file")), str(row.get("line")), str(row.get("callee")))
                current = merged.get(key)
                if current is None or row_rank(row) > row_rank(current):
                    merged[key] = row

    out = Path(out_path).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        for key in sorted(merged):
            handle.write(json.dumps(merged[key], sort_keys=True) + "\n")
    tmp.replace(out)

    by_via: dict[str, int] = {}
    for row in merged.values():
        via = str(row.get("via") or "unknown")
        by_via[via] = by_via.get(via, 0) + 1
    return {
        "ok": read["files"] > 0,
        "mode": "sink-merge",
        "out": str(out),
        "inputs_read": read["files"],
        "rows_read": read["rows"],
        "rows_written": len(merged),
        "bad_lines": read["bad_lines"],
        "missing_inputs": read["missing"],
        "by_via": by_via,
        "blockers": [] if read["files"] > 0 else ["no readable inputs"],
    }

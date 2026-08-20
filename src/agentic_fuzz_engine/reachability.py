"""Reachability evidence for findings: who can hit this in production?

A verified crash says nothing about who can trigger it. The severity
over-claims this module prevents are always the same three facts, all
statically checkable before a report ships:

- the crashing entry has **no production caller**;
- the vulnerable path is **gated by a runtime flag** whose shipped default
  routes around it;
- the service only binds **localhost** (declared fact, never guessed).

``finding-reachability`` assembles a ``reachability`` block from three
bounded evidence sources and attaches it to the finding (event + durable
index). The *verdict* stays a judgment: the verb defaults it to
``unknown`` and the operator/agent sets it from the gathered evidence
(``--verdict``). ``campaign-report`` then enforces the block's *presence*
per policy ``report.require_reachability`` (off | warn | block).

Evidence sources:

1. **Caller scan** — bounded text search for call sites of the entry
   symbol over the source tree (rg when available, pure-python fallback),
   tagged ``via: rg``. Heavier CPG queries stay on the existing
   ``sarif-reachability-run`` verb; attach their artifact via ``--note``.
2. **Flag-gate scan** — lexical: flag definitions (gflags/absl) and
   ``FLAGS_*`` references in guard context near the crash frames, with
   their literal defaults. Candidates for the reviewer, not verdicts.
3. **Declared service facts** — ``work/services.json``, authored once per
   codebase: bind addresses and pinned flags per service. The engine
   never discovers runtime topology; it applies declared facts
   (``via: declared``).
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Mapping

from .crash_identity import parse_crash_output
from .runtime_backends import _run_command

SOURCE_SUFFIXES = (".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".scala", ".java")
MAX_CALLERS = 50
MAX_FLAG_GATES = 20
FLAG_WINDOW_LINES = 40
FLAG_DEFINE_RES = (
    re.compile(r"DEFINE_(?:bool|int32|int64|uint64|double|string)\s*\(\s*(?P<name>\w+)\s*,\s*(?P<default>[^,\n]+)"),
    re.compile(r"ABSL_FLAG\s*\(\s*[\w:<>]+\s*,\s*(?P<name>\w+)\s*,\s*(?P<default>[^,\n]+)"),
)
FLAG_REF_RE = re.compile(r"FLAGS_(?P<name>\w+)")
VERDICTS = ("reachable", "flag-gated", "no-production-caller", "local-only", "demonstrative", "unknown")


def finding_reachability(
    *,
    state: Any,
    run_id: str,
    finding_id: str,
    entry_symbol: str,
    workspace_root: Path,
    source_dir: str | Path | None = None,
    verdict: str | None = None,
    note: str | None = None,
    max_files: int = 20000,
    timeout_seconds: float = 120.0,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    if verdict is not None and verdict not in VERDICTS:
        return {"ok": False, "blockers": [f"verdict must be one of {VERDICTS}, got {verdict!r}"]}

    finding = next(
        (item for item in state.finding_list(run_id) if item.get("finding_id") == finding_id),
        None,
    )
    if finding is None:
        return {"ok": False, "blockers": [f"finding not found in run {run_id}: {finding_id}"]}

    notes: list[str] = []
    if note:
        notes.append(note)
    source = Path(source_dir).expanduser() if source_dir else None
    if source is not None and not source.is_dir():
        notes.append(f"source_dir not a directory, caller/flag scans skipped: {source}")
        source = None

    callers = _caller_scan(
        source, entry_symbol, max_files=max_files, timeout_seconds=timeout_seconds, env=environment
    ) if source else []
    flag_gates = _flag_gate_scan(source, finding) if source else []
    declared = _declared_service_facts(workspace_root, str(finding.get("target") or ""))

    resolved_verdict = verdict or "unknown"
    if verdict is None:
        if source and not callers:
            # No text-level caller anywhere in the tree is strong evidence,
            # but stays advisory: the reviewer confirms before re-tiering.
            notes.append(f"caller scan found no call sites of {entry_symbol!r} — review for no-production-caller")

    block = {
        "finding_id": finding_id,
        "verdict": resolved_verdict,
        "entry_symbol": entry_symbol,
        "production_callers": callers,
        "flag_gates": flag_gates,
        "bind_surface": declared.get("bind_surface", "unknown"),
        "declared_services": declared.get("services", []),
        "notes": notes,
    }
    state.event_append(
        run_id,
        "finding_reachability",
        {"finding_id": finding_id, **{key: value for key, value in block.items() if key != "finding_id"}},
    )
    return {"ok": True, "mode": "finding-reachability", "run_id": run_id, "reachability": block}


def _caller_scan(
    source: Path,
    symbol: str,
    *,
    max_files: int,
    timeout_seconds: float,
    env: Mapping[str, str],
) -> list[dict[str, Any]]:
    tail = symbol.rsplit("::", 1)[-1]
    pattern = re.escape(tail) + r"\s*\("
    callers: list[dict[str, Any]] = []
    rg = shutil.which("rg")
    if rg:
        run = _run_command(
            [rg, "-n", "--no-heading", "-e", pattern, "-g", "*.{cpp,cc,cxx,c,h,hpp,scala,java}", str(source)],
            cwd=source,
            timeout_seconds=timeout_seconds,
            env=dict(env),
        )
        lines = str(run.get("stdout") or "").splitlines()
    else:
        lines = _python_grep(source, re.compile(pattern), max_files=max_files)
    compiled = re.compile(pattern)
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        file_part, line_part, text = parts[0], parts[1], parts[2]
        if not line_part.isdigit() or not compiled.search(text):
            continue
        if _looks_like_definition(text, tail):
            continue  # definitions and declarations are not callers
        try:
            rel = str(Path(file_part).relative_to(source))
        except ValueError:
            rel = file_part
        callers.append({"file": rel, "line": int(line_part), "code": text.strip()[:160], "via": "rg"})
        if len(callers) >= MAX_CALLERS:
            break
    return callers


_DEFINITION_PRE_KEYWORDS = {"return", "new", "throw", "delete", "co_return", "co_await", "else", "case", "await"}


def _looks_like_definition(text: str, tail: str) -> bool:
    """A definition/declaration has a type word (not a control keyword)
    immediately before the symbol; a bare call site does not."""
    match = re.match(
        r"^\s*(?P<pre>[A-Za-z_][\w:<>&\*]*(?:\s+[\w:<>&\*]+)*)\s+(?:\w+::)*" + re.escape(tail) + r"\s*\(",
        text,
    )
    if not match:
        return False
    first_word = match.group("pre").split()[0].rstrip("*&")
    return first_word not in _DEFINITION_PRE_KEYWORDS


def _python_grep(source: Path, pattern: re.Pattern[str], *, max_files: int) -> list[str]:
    lines: list[str] = []
    scanned = 0
    for path in sorted(source.rglob("*")):
        if scanned >= max_files or len(lines) >= MAX_CALLERS * 4:
            break
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for index, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                lines.append(f"{path}:{index}:{line}")
    return lines


def _flag_gate_scan(source: Path, finding: dict[str, Any]) -> list[dict[str, Any]]:
    signal = parse_crash_output(str(finding.get("crash_output") or ""))
    if signal is None:
        return []
    gates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for frame in signal.frames:
        if not frame.file or not frame.line:
            continue
        path = Path(frame.file)
        if not path.is_file():
            path = source / frame.file
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        # Flag definitions anywhere in the frame's file carry the default.
        defaults: dict[str, str] = {}
        for line in lines:
            for pattern in FLAG_DEFINE_RES:
                match = pattern.search(line)
                if match:
                    defaults[match.group("name")] = match.group("default").strip()
                    break
        center = int(frame.line) - 1
        lower = max(0, center - FLAG_WINDOW_LINES)
        upper = min(len(lines), center + FLAG_WINDOW_LINES + 1)
        for index in range(lower, upper):
            for match in FLAG_REF_RE.finditer(lines[index]):
                name = match.group("name")
                key = (str(path), name)
                if key in seen:
                    continue
                seen.add(key)
                gates.append(
                    {
                        "flag": name,
                        "default": defaults.get(name),
                        "file": frame.file,
                        "line": index + 1,
                        "near_frame": f"{frame.function or '?'} @ {frame.file}:{frame.line}",
                    }
                )
                if len(gates) >= MAX_FLAG_GATES:
                    return gates
    return gates


def _declared_service_facts(workspace_root: Path, target: str) -> dict[str, Any]:
    path = workspace_root / "work" / "services.json"
    if not path.is_file():
        return {"bind_surface": "unknown", "services": []}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"bind_surface": "unknown", "services": []}
    services = [item for item in payload.get("services", []) if isinstance(item, dict)]
    name = target.removeprefix("localfuzz/c/")
    matched = [
        {**item, "via": "declared"}
        for item in services
        if name and (name in str(item.get("name") or "") or str(item.get("name") or "") in name
                     or name in [str(t) for t in (item.get("targets") or [])])
    ]
    bind = "unknown"
    if matched:
        binds = {str(item.get("binds") or "unknown") for item in matched}
        bind = sorted(binds)[0] if len(binds) == 1 else "mixed"
    return {"bind_surface": bind, "services": matched or services[:10]}

"""Valgrind memcheck replay sweep (``valgrind-sweep``).

The write-class oracle for UNINSTRUMENTED binaries. Closed-source vendor
libraries (a fork ``.a`` with no source) cannot be rebuilt under ASAN, so
campaign crashes found on an instrumented sibling must be confirmed — and
new write-class evidence hunted — by replaying inputs through a replay
driver linked against the real binary under valgrind. This verb makes that
loop engine-native: bounded sequential replay of a corpus (or a single
artifact) with memcheck records parsed into the same access vocabulary as
``asan.py`` (WRITE beats READ), ranked write-first, and reported durably.

Everything is bounded: inputs replayed, per-input timeout, total wall
clock. No detached processes; one input at a time.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any, Mapping

from .workspace import resolve_workspace_root
from .process_safety import bounded_run, tool_env

MAX_INPUTS = 4096
MAX_PER_INPUT_TIMEOUT = 120.0
MAX_WALL_SECONDS = 3600.0
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
ERROR_EXITCODE = 97

# Memcheck error headers, ordered by the primitive they hand an attacker.
# ``access`` mirrors AsanSignal.access so dedupe's WRITE bonus applies to
# valgrind-sourced findings unchanged.
_ERROR_KINDS: tuple[tuple[re.Pattern[str], str, str | None], ...] = (
    (re.compile(r"Invalid write of size (\d+)"), "invalid-write", "WRITE"),
    (re.compile(r"Invalid free\(\)|Mismatched free\(\)"), "invalid-free", "WRITE"),
    (re.compile(r"Jump to the invalid address"), "invalid-jump", "EXEC"),
    (re.compile(r"Process terminating with default action of signal (\d+)"), "fatal-signal", None),
    (re.compile(r"Invalid read of size (\d+)"), "invalid-read", "READ"),
    (re.compile(r"Use of uninitialised value of size (\d+)"), "uninitialised", None),
    (re.compile(r"Conditional jump or move depends on uninitialised"), "uninitialised-cond", None),
)

KIND_SEVERITY = {
    "invalid-write": 0,
    "invalid-free": 1,
    "invalid-jump": 2,
    "fatal-signal": 3,
    "invalid-read": 4,
    "uninitialised": 5,
    "uninitialised-cond": 6,
}

_FRAME_RE = re.compile(r"(?:at|by) 0x[0-9A-Fa-f]+: ([^\s(]+) \(([^)]*)\)")
_NOISE_MODULE_RE = re.compile(r"vgpreload|/valgrind/|ld-linux|libc(?:\.|-)")


def parse_valgrind_errors(text: str, *, max_errors: int = 64) -> list[dict[str, Any]]:
    """Parse ``valgrind -q`` memcheck stderr into structured error records."""
    errors: list[dict[str, Any]] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if len(errors) >= max_errors:
            break
        for pattern, kind, access in _ERROR_KINDS:
            match = pattern.search(line)
            if match is None:
                continue
            size: int | None = None
            if match.groups() and match.group(1) and match.group(1).isdigit():
                size = int(match.group(1))
            frames: list[str] = []
            signature_frame: str | None = None
            for follow in lines[index + 1 : index + 12]:
                frame = _FRAME_RE.search(follow)
                if frame is None:
                    if frames:
                        break
                    continue
                function, module = frame.group(1), frame.group(2)
                frames.append(function)
                if signature_frame is None and not _NOISE_MODULE_RE.search(module):
                    signature_frame = function
                if len(frames) >= 6:
                    break
            errors.append(
                {
                    "kind": kind,
                    "access": access,
                    "size": size,
                    "frames": frames,
                    "signature_frame": signature_frame or (frames[0] if frames else None),
                }
            )
            break
    return errors


def worst_error(errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not errors:
        return None
    return min(errors, key=lambda err: KIND_SEVERITY.get(err["kind"], 99))


def valgrind_sweep(
    *,
    target: str,
    command: list[str] | None = None,
    corpus_dir: str | Path | None = None,
    max_inputs: int = 2000,
    per_input_timeout: float = 10.0,
    max_seconds: float = 900.0,
    top: int = 50,
    workspace_root: str | Path | None = None,
    valgrind_path: str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(env) if env is not None else dict(os.environ)
    blockers: list[str] = []
    try:
        root = resolve_workspace_root(workspace_root, env=environment)
    except (FileNotFoundError, ValueError) as exc:
        return {"ok": False, "mode": "valgrind-sweep", "blockers": [str(exc)]}

    name = target.removeprefix("localfuzz/c/")
    valgrind = valgrind_path or shutil.which("valgrind")
    if not valgrind or not Path(valgrind).exists():
        blockers.append("valgrind binary not found (install valgrind)")

    if not command:
        blockers.append("command required: replay driver argv (use {input} placeholder or input path is appended)")

    corpus = Path(corpus_dir).expanduser().resolve() if corpus_dir else root / "work" / name / "seeds"
    inputs: list[Path] = []
    if corpus.is_file():
        inputs = [corpus]
    elif corpus.is_dir():
        inputs = sorted(entry for entry in corpus.iterdir() if entry.is_file())
    if not inputs:
        blockers.append(f"no inputs to replay under {corpus}")

    result_base: dict[str, Any] = {
        "ok": False,
        "mode": "valgrind-sweep",
        "target": target,
        "corpus": str(corpus),
        "blockers": blockers,
    }
    if blockers:
        return result_base

    max_inputs = min(max(int(max_inputs), 1), MAX_INPUTS)
    per_timeout = min(max(float(per_input_timeout), 1.0), MAX_PER_INPUT_TIMEOUT)
    wall_budget = min(max(float(max_seconds), 1.0), MAX_WALL_SECONDS)

    started = time.monotonic()
    scanned = 0
    budget_exhausted = False
    hits: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for entry in inputs[:max_inputs]:
        if time.monotonic() - started > wall_budget:
            budget_exhausted = True
            break
        argv = list(command or [])
        if any("{input}" in arg for arg in argv):
            argv = [arg.replace("{input}", str(entry)) for arg in argv]
        else:
            argv.append(str(entry))
        scanned += 1
        completed = bounded_run([valgrind, "-q", f"--error-exitcode={ERROR_EXITCODE}", *argv], cwd=root, env=tool_env(environment), timeout_seconds=per_timeout, max_output_chars=MAX_OUTPUT_BYTES)
        if completed.timed_out:
            continue
        if completed.exit_code not in {0, ERROR_EXITCODE} and completed.exit_code >= 0:
            context = (completed.stderr or completed.stdout).strip().splitlines()[-1:] or ["no diagnostic output"]
            return {**result_base, "inputs_scanned": scanned, "blockers": [f"valgrind replay command failed (exit {completed.exit_code}): {context[0][:500]}"]}
        output = completed.stderr[:MAX_OUTPUT_BYTES]
        errors = parse_valgrind_errors(output)
        crashed = completed.exit_code == ERROR_EXITCODE or completed.exit_code < 0
        if not errors and not crashed:
            continue
        if not errors and crashed:
            errors = [{"kind": "fatal-signal", "access": None, "size": None,
                       "frames": [], "signature_frame": None}]
        worst = worst_error(errors)
        for err in errors:
            counts[err["kind"]] = counts.get(err["kind"], 0) + 1
        hits.append(
            {
                "input": str(entry),
                "returncode": completed.exit_code,
                "worst_kind": worst["kind"] if worst else None,
                "worst_access": worst.get("access") if worst else None,
                "worst_size": worst.get("size") if worst else None,
                "signature_frame": worst.get("signature_frame") if worst else None,
                "errors": errors[:8],
            }
        )

    hits.sort(key=lambda hit: KIND_SEVERITY.get(hit["worst_kind"] or "", 99))
    report = {
        "mode": "valgrind-sweep",
        "target": target,
        "corpus": str(corpus),
        "command": command,
        "inputs_scanned": scanned,
        "inputs_total": len(inputs),
        "budget_exhausted": budget_exhausted,
        "flagged": len(hits),
        "counts_by_kind": counts,
        "write_class_hits": sum(1 for hit in hits if hit["worst_access"] == "WRITE"),
        "hits": hits[: max(int(top), 1)],
    }
    report_dir = root / "work" / name
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "valgrind-sweep.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return {
        **result_base,
        "ok": True,
        "blockers": [],
        "inputs_scanned": scanned,
        "inputs_total": len(inputs),
        "budget_exhausted": budget_exhausted,
        "flagged": len(hits),
        "counts_by_kind": counts,
        "write_class_hits": report["write_class_hits"],
        "hits": report["hits"],
        "report": str(report_path),
    }

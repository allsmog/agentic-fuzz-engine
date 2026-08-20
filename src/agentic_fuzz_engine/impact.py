"""Per-finding impact pass: read→write escalation evidence as a verb.

The engine records sanitizer crashes; whether a crash is *worth escalating*
was previously manual analysis. This module mechanizes the evidence
gathering that produced past write-class escalations:

- **primitive**: the ASAN READ/WRITE access token, exposed as a field.
- **UBSan replay**: the same PoV through ``bin/<t>/fuzzer-ubsan`` (optional
  build step); integer wraps / implicit conversions reported on the crash
  path are the #1 signal that a guard upstream is vacuous.
- **valgrind replay**: the PoV through the uninstrumented ``bin/<t>/replay``
  binary under memcheck — the oracle that catches "sanitizer said read but
  the real libc writes first" (wrapped-size memcpy class).
- **adjacency leads**: dangerous write callees near the crash site that
  share identifiers with the crashing line. Advisory only — leads are for
  the analyst, never auto-promoted.

The result is an ``impact`` block appended as a ``finding_impact`` event
(mirrored into the durable findings index) and returned to the caller.
Everything is bounded; missing binaries degrade to notes, never errors.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Mapping

from .crash_identity import frame_blacklisted, parse_crash_output
from .runtime_backends import _run_command
from .sink_scan import SINK_PRIMITIVES

UBSAN_LINE_RE = re.compile(r"(?P<file>[^\s:]+):(?P<line>\d+)(?::\d+)?: runtime error: (?P<error>.+)")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
IDENT_STOPWORDS = {
    "const", "size_t", "uint32_t", "uint64_t", "int32_t", "int64_t", "char",
    "unsigned", "return", "static_cast", "reinterpret_cast", "sizeof", "auto",
    "void", "bool", "true", "false", "nullptr", "int",
}
WRITE_CALLEES = tuple(name for name, primitive in SINK_PRIMITIVES.items() if primitive == "write")
MAX_UBSAN_LINES = 20
MAX_LEADS = 10


def crash_primitive(crash_output: str) -> str:
    """read | write | abort | fpe | oom | unknown from a sanitizer report."""
    signal = parse_crash_output(crash_output)
    if signal is not None and signal.access:
        return str(signal.access).lower()
    text = crash_output or ""
    if "FPE" in text or "floating-point-exception" in text:
        return "fpe"
    if "out-of-memory" in text or "allocation size" in text.lower():
        return "oom"
    if "CHECK failed" in text or "abort" in text.lower():
        return "abort"
    return "unknown"


def finding_impact(
    *,
    state: Any,
    run_id: str,
    finding_id: str,
    workspace_root: Path,
    source_dir: str | Path | None = None,
    replay_timeout_seconds: float = 60.0,
    lead_window: int = 60,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    environment.setdefault("ASAN_OPTIONS", "detect_leaks=0:allocator_may_return_null=1:symbolize=0")
    environment.setdefault("UBSAN_OPTIONS", "print_stacktrace=0:halt_on_error=0")
    environment.setdefault("DEBUGINFOD_URLS", "")
    replay_controls = {key: environment[key] for key in ("ASAN_OPTIONS", "UBSAN_OPTIONS", "DEBUGINFOD_URLS")}

    finding = next(
        (item for item in state.finding_list(run_id) if item.get("finding_id") == finding_id),
        None,
    )
    if finding is None:
        return {"ok": False, "blockers": [f"finding not found in run {run_id}: {finding_id}"]}
    name = str(finding.get("target") or "").removeprefix("localfuzz/c/")
    crash_output = str(finding.get("crash_output") or "")
    notes: list[str] = []

    pov: Path | None = None
    poc_artifact = finding.get("poc_artifact")
    if isinstance(poc_artifact, str) and poc_artifact:
        candidate = Path(state.data_root) / "runs" / run_id / "artifacts" / poc_artifact
        if candidate.is_file():
            pov = candidate
    if pov is None:
        notes.append("no PoV artifact on disk — replay lanes skipped")

    block: dict[str, Any] = {
        "finding_id": finding_id,
        "primitive": crash_primitive(crash_output),
        "write_evidence": "none",
        "ubsan_wraps": [],
        "leads": [],
        "notes": notes,
    }
    if block["primitive"] == "write":
        block["write_evidence"] = "asan-write"

    signal = parse_crash_output(crash_output)
    crash_files = {
        Path(frame.file).name for frame in (signal.frames if signal else ()) if frame.file
    }

    # UBSan lane: wraps on the crash path make downstream guards vacuous.
    ubsan_bin = workspace_root / "bin" / name / "fuzzer-ubsan"
    if pov is not None and ubsan_bin.is_file() and os.access(ubsan_bin, os.X_OK):
        run = _run_command([str(ubsan_bin), str(pov)], cwd=workspace_root, timeout_seconds=replay_timeout_seconds, env=environment, declared_env=replay_controls)
        text = str(run.get("stdout") or "") + "\n" + str(run.get("stderr") or "")
        for match in list(UBSAN_LINE_RE.finditer(text))[:MAX_UBSAN_LINES]:
            block["ubsan_wraps"].append(
                {
                    "file": match.group("file"),
                    "line": int(match.group("line")),
                    "error": match.group("error").strip()[:160],
                    "on_crash_path": Path(match.group("file")).name in crash_files,
                }
            )
    elif pov is not None:
        notes.append(f"no UBSan binary at {ubsan_bin} (add a fuzzer-ubsan build step)")

    # Valgrind lane: real-libc write oracle over the uninstrumented replay.
    replay_bin = workspace_root / "bin" / name / "replay"
    if pov is not None and replay_bin.is_file() and os.access(replay_bin, os.X_OK):
        from shutil import which

        valgrind = which("valgrind")
        if valgrind:
            from .valgrind_replay import parse_valgrind_errors, worst_error

            run = _run_command(
                [valgrind, "--error-exitcode=99", str(replay_bin), str(pov)],
                cwd=workspace_root,
                timeout_seconds=replay_timeout_seconds,
                env=environment,
                declared_env=replay_controls,
            )
            errors = parse_valgrind_errors(str(run.get("stderr") or ""))
            worst = worst_error(errors)
            block["valgrind"] = {"errors": len(errors), "worst": worst}
            if worst and "write" in str(worst.get("kind") or "").lower():
                block["write_evidence"] = "valgrind-invalid-write"
        else:
            notes.append("valgrind not installed — write oracle skipped")
    elif pov is not None:
        notes.append(f"no uninstrumented replay binary at {replay_bin} — valgrind lane skipped")

    # Flag matrix: one bounded replay per authored profile; a crash that
    # only reproduces under a non-default profile is config-gated.
    fuzzer_bin = workspace_root / "bin" / name / "fuzzer"
    from .flag_profiles import load_flag_profiles

    profiles_payload = load_flag_profiles(workspace_root / "targets" / "c" / name)
    if pov is not None and profiles_payload and fuzzer_bin.is_file() and os.access(fuzzer_bin, os.X_OK):
        matrix: dict[str, str] = {}
        for profile_name in sorted(profiles_payload["profiles"]):
            profile_env = {**replay_controls, "FUZZ_FLAG_PROFILE": profile_name}
            run = _run_command(
                [str(fuzzer_bin), str(pov)],
                cwd=workspace_root,
                timeout_seconds=replay_timeout_seconds,
                env=environment,
                declared_env=profile_env,
            )
            text_out = str(run.get("stdout") or "") + str(run.get("stderr") or "")
            if run.get("timed_out"):
                matrix[profile_name] = "error"
            elif "ERROR:" in text_out or int(run.get("exit_code") or 0) != 0:
                matrix[profile_name] = "reproduces"
            else:
                matrix[profile_name] = "no-repro"
        block["flag_matrix"] = matrix
        default_profile = str(profiles_payload.get("default_profile") or "")
        if default_profile and matrix.get(default_profile) == "no-repro":
            notes.append(
                f"crash does NOT reproduce under default profile {default_profile!r} — config-gated finding"
            )

    # Adjacency leads: write sinks near the crash line sharing identifiers.
    block["leads"] = _adjacency_leads(signal, source_dir=source_dir, window=lead_window)

    state.event_append(run_id, "finding_impact", {"finding_id": finding_id, **{k: v for k, v in block.items() if k != "finding_id"}})
    return {"ok": True, "mode": "finding-impact", "run_id": run_id, "impact": block}


def _adjacency_leads(
    signal: Any,
    *,
    source_dir: str | Path | None,
    window: int,
) -> list[dict[str, Any]]:
    if signal is None:
        return []
    frame = next(
        (item for item in signal.frames if item.file and item.line and not frame_blacklisted(item)),
        None,
    )
    if frame is None:
        return []
    path = Path(frame.file)
    if not path.is_file() and source_dir:
        path = Path(source_dir) / frame.file
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    crash_index = int(frame.line) - 1
    if not (0 <= crash_index < len(lines)):
        return []
    crash_idents = {
        ident for ident in IDENT_RE.findall(lines[crash_index]) if ident not in IDENT_STOPWORDS
    }
    leads: list[dict[str, Any]] = []
    lower = max(0, crash_index - window)
    upper = min(len(lines), crash_index + window + 1)
    for index in range(lower, upper):
        if index == crash_index:
            continue
        line = lines[index]
        callee = next((name for name in WRITE_CALLEES if f"{name}(" in line), None)
        if callee is None:
            continue
        shared = sorted(
            ident for ident in IDENT_RE.findall(line)
            if ident in crash_idents and ident != callee
        )
        if not shared:
            continue
        leads.append(
            {
                "file": frame.file,
                "line": index + 1,
                "callee": callee,
                "shared_idents": shared[:8],
                "advisory": True,
            }
        )
        if len(leads) >= MAX_LEADS:
            break
    return leads

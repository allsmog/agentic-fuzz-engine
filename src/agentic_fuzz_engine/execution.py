from __future__ import annotations

import base64
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from time import monotonic
from typing import Any

from .asan import parse_asan_signal


MAX_TIMEOUT_SECONDS = 60.0
MAX_REPETITIONS = 5
MAX_OUTPUT_CHARS = 12000
FORBIDDEN_EXECUTABLES = {
    "docker",
    "docker-compose",
    "kubectl",
    "redis-cli",
    "kafka-console-consumer",
    "kafka-console-producer",
}
FORBIDDEN_ARG_FRAGMENTS = (
    "fuzz-" + "userspace/docker-" + "run.py",
    "fuzz-" + "multilang/run.py",
)


def run_harness_artifact(
    *,
    artifact_name: str,
    content_b64: str,
    command: list[str] | str,
    timeout_seconds: int | float = 10,
    repetitions: int = 3,
    workdir: str | None = None,
    expected_error_token: str | None = None,
) -> dict[str, Any]:
    timeout = _bounded_timeout(timeout_seconds)
    repeat_count = _bounded_repetitions(repetitions)
    command_argv = _normalize_command(command)
    expected = _normalize_asan_token(expected_error_token) if expected_error_token else None

    with tempfile.TemporaryDirectory(prefix="agentic-fuzz-harness-") as tmp:
        poc_path = Path(tmp) / _safe_artifact_filename(artifact_name)
        poc_path.write_bytes(base64.b64decode(content_b64.encode("ascii")))
        materialized = _materialize_command(command_argv, str(poc_path))
        _validate_command(materialized)

        # In-process symbolization is forced OFF: on EDR-protected hosts the
        # llvm-symbolizer child blocks at spawn with zero CPU, wedging every
        # replay until the timeout. Frames are symbolized offline (addr2line)
        # in _run_once instead, so dedupe signatures still carry real frames.
        env = _replay_asan_env()

        runs = [
            _run_once(materialized, timeout_seconds=timeout, workdir=workdir, expected_error_token=expected, env=env)
            for _ in range(repeat_count)
        ]

    matching = [run for run in runs if run["matched_expected"]]
    crashing = [run for run in runs if run["crashed"]]
    first_crash = next((run for run in runs if run["asan_signal"]), None)
    observed = first_crash["observed_error_token"] if first_crash else None
    verified = len(matching if expected else crashing) == repeat_count
    crash_output = str(first_crash["combined_output"]) if first_crash else ""
    return {
        "ok": True,
        "verified": verified,
        "artifact": artifact_name,
        "command": materialized,
        "timeout_seconds": timeout,
        "repetitions": repeat_count,
        "crashes": len(crashing),
        "matches_expected": len(matching),
        "expected_error_token": expected_error_token,
        "observed_error_token": observed,
        "crash_output": crash_output,
        "runs": runs,
    }


def _replay_asan_env() -> dict[str, str]:
    env = dict(os.environ)
    options = [
        option
        for option in env.get("ASAN_OPTIONS", "").split(":")
        if option and not option.startswith(("symbolize=", "external_symbolizer_path="))
    ]
    options.append("symbolize=0")
    env["ASAN_OPTIONS"] = ":".join(options)
    return env


# Unsymbolized sanitizer frame: `#N 0xPC  (/path/to/module+0xOFFSET)`.
_UNSYM_FRAME_RE = re.compile(
    r"^(?P<head>\s*#\d+\s+0x[0-9a-fA-F]+)\s+\((?P<module>/[^)+]+)\+0x(?P<offset>[0-9a-fA-F]+)\)",
    re.MULTILINE,
)
_MAX_SYMBOLIZE_ADDRS = 64


def _offline_symbolize(output: str) -> str:
    """Rewrite unsymbolized frames to `... in FUNC FILE:LINE` via addr2line.

    addr2line is used instead of llvm-symbolizer because EDR holds the latter
    at spawn indefinitely on protected hosts. Bounded: one addr2line call per
    referenced module, capped address count, short timeout; on any failure the
    original output is returned unchanged.
    """
    matches = list(_UNSYM_FRAME_RE.finditer(output))
    if not matches:
        return output
    by_module: dict[str, list[str]] = {}
    for match in matches:
        offsets = by_module.setdefault(match.group("module"), [])
        if match.group("offset") not in offsets and len(offsets) < _MAX_SYMBOLIZE_ADDRS:
            offsets.append(match.group("offset"))
    addr2line = shutil.which("addr2line")
    if addr2line is None:
        return output
    resolved: dict[tuple[str, str], tuple[str, str]] = {}
    for module, offsets in by_module.items():
        if not os.access(module, os.R_OK):
            continue
        try:
            proc = subprocess.run(
                [addr2line, "-f", "-C", "-e", module, *(f"0x{offset}" for offset in offsets)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        lines = proc.stdout.splitlines()
        for index, offset in enumerate(offsets):
            if 2 * index + 1 >= len(lines):
                break
            function, file_line = lines[2 * index].strip(), lines[2 * index + 1].strip()
            if function and function != "??":
                resolved[(module, offset)] = (function, file_line)

    def _rewrite(match: re.Match[str]) -> str:
        entry = resolved.get((match.group("module"), match.group("offset")))
        if entry is None:
            return match.group(0)
        function, file_line = entry
        rewritten = f"{match.group('head')} in {function}"
        if file_line and not file_line.startswith("??"):
            rewritten += f" {file_line.split(' ')[0]}"
        return rewritten

    return _UNSYM_FRAME_RE.sub(_rewrite, output)


def _run_once(
    command: list[str],
    *,
    timeout_seconds: float,
    workdir: str | None,
    expected_error_token: str | None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    started = monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=workdir or None,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        timed_out = False
        returncode = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = 124
        stdout = _coerce_output(exc.stdout)
        stderr = _coerce_output(exc.stderr) + "\nTIMEOUT"

    elapsed_ms = int((monotonic() - started) * 1000)
    combined = _clip(stdout + stderr)
    if "ERROR: " in combined:
        combined = _offline_symbolize(combined)
    signal = parse_asan_signal(combined)
    observed = f"AddressSanitizer: {signal.crash_type}" if signal else None
    normalized_output = _normalize_asan_token(combined)
    matched_expected = bool(expected_error_token and expected_error_token in normalized_output)
    return {
        "exit_code": returncode,
        "timed_out": timed_out,
        "elapsed_ms": elapsed_ms,
        "crashed": returncode != 0 and signal is not None,
        "matched_expected": matched_expected if expected_error_token else signal is not None,
        "observed_error_token": observed,
        "asan_signal": signal.to_dict() if signal else None,
        "stdout": _clip(stdout),
        "stderr": _clip(stderr),
        "combined_output": combined,
    }


def _normalize_command(command: list[str] | str) -> list[str]:
    if isinstance(command, str):
        command = shlex.split(command)
    if not isinstance(command, list) or not command:
        raise ValueError("harness command must be a non-empty argv list")
    argv = []
    for arg in command:
        if not isinstance(arg, str) or not arg:
            raise ValueError("harness command arguments must be non-empty strings")
        if "\x00" in arg or "\n" in arg or "\r" in arg:
            raise ValueError("harness command arguments may not contain control characters")
        argv.append(arg)
    return argv


def _materialize_command(command: list[str], poc_path: str) -> list[str]:
    replaced = [arg.replace("{poc}", poc_path) for arg in command]
    if all("{poc}" not in arg for arg in command) and poc_path not in replaced:
        replaced.append(poc_path)
    return replaced


def _validate_command(command: list[str]) -> None:
    executable = Path(command[0]).name
    if executable in FORBIDDEN_EXECUTABLES:
        raise ValueError(f"harness command executable is not allowed: {executable}")
    if executable in {"bash", "sh", "zsh"} and "-c" in command[1:]:
        raise ValueError("harness command may not use shell -c")
    joined = " ".join(command)
    for fragment in FORBIDDEN_ARG_FRAGMENTS:
        if fragment in joined:
            raise ValueError("harness command references a forbidden external runtime path")


def _bounded_timeout(value: int | float) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("timeout_seconds must be numeric") from exc
    if timeout <= 0 or timeout > MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout_seconds must be between 0 and {MAX_TIMEOUT_SECONDS:g}")
    return timeout


def _bounded_repetitions(value: int) -> int:
    try:
        repetitions = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("repetitions must be an integer") from exc
    if repetitions <= 0 or repetitions > MAX_REPETITIONS:
        raise ValueError(f"repetitions must be between 1 and {MAX_REPETITIONS}")
    return repetitions


def _normalize_asan_token(value: str) -> str:
    return value.replace("ERROR:", "").strip()


def _safe_artifact_filename(value: str) -> str:
    name = Path(value).name
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in name)[:120] or "poc.bin"


def _clip(value: str) -> str:
    if len(value) <= MAX_OUTPUT_CHARS:
        return value
    return value[:MAX_OUTPUT_CHARS] + "\n[truncated]"


def _coerce_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value

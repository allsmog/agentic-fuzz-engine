from __future__ import annotations

import base64
import shlex
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

        runs = [
            _run_once(materialized, timeout_seconds=timeout, workdir=workdir, expected_error_token=expected)
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


def _run_once(
    command: list[str],
    *,
    timeout_seconds: float,
    workdir: str | None,
    expected_error_token: str | None,
) -> dict[str, Any]:
    started = monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=workdir or None,
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

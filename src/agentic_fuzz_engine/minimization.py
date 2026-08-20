from __future__ import annotations

import base64
from typing import Any

from .execution import run_harness_artifact


MAX_MINIMIZE_BYTES = 1_048_576
MAX_MINIMIZE_ATTEMPTS = 200


def minimize_pov_artifact(
    *,
    artifact_name: str,
    content_b64: str,
    command: list[str] | str,
    expected_error_token: str | None = None,
    timeout_seconds: int | float = 10,
    repetitions: int = 3,
    workdir: str | None = None,
    max_attempts: int = 80,
    preserve_signal: bool = True,
) -> dict[str, Any]:
    data = base64.b64decode(content_b64.encode("ascii"))
    if len(data) > MAX_MINIMIZE_BYTES:
        raise ValueError(f"PoV artifact must be at most {MAX_MINIMIZE_BYTES} bytes")
    attempt_limit = _bounded_attempts(max_attempts)
    original_run = run_harness_artifact(
        artifact_name=artifact_name,
        content_b64=content_b64,
        command=command,
        timeout_seconds=timeout_seconds,
        repetitions=repetitions,
        workdir=workdir,
        expected_error_token=expected_error_token,
    )
    if not original_run["verified"]:
        return {
            "ok": False,
            "verdict": "ORIGINAL_NOT_VERIFIED",
            "artifact": artifact_name,
            "original_size": len(data),
            "minimized_size": len(data),
            "attempts": 0,
            "accepted_reductions": 0,
            "original_run": original_run,
        }
    baseline_signal = _first_signal(original_run)
    if preserve_signal and baseline_signal is None:
        return {
            "ok": False,
            "verdict": "MISSING_BASELINE_SIGNAL",
            "artifact": artifact_name,
            "original_size": len(data),
            "minimized_size": len(data),
            "attempts": 0,
            "accepted_reductions": 0,
            "original_run": original_run,
        }

    current = data
    attempts = 0
    accepted: list[dict[str, Any]] = []
    block = max(1, len(current) // 2)
    while block >= 1 and attempts < attempt_limit and len(current) > 1:
        changed = False
        offset = 0
        while offset < len(current) and attempts < attempt_limit and len(current) > 1:
            end = min(offset + block, len(current))
            candidate = current[:offset] + current[end:]
            if not candidate:
                offset += block
                continue
            attempts += 1
            candidate_run = run_harness_artifact(
                artifact_name=f"{artifact_name}.min-attempt-{attempts}",
                content_b64=base64.b64encode(candidate).decode("ascii"),
                command=command,
                timeout_seconds=timeout_seconds,
                repetitions=repetitions,
                workdir=workdir,
                expected_error_token=expected_error_token,
            )
            if _preserves_crash(candidate_run, baseline_signal, preserve_signal=preserve_signal):
                accepted.append(
                    {
                        "attempt": attempts,
                        "removed_offset": offset,
                        "removed_bytes": end - offset,
                        "size": len(candidate),
                        "signal": _first_signal(candidate_run),
                    }
                )
                current = candidate
                changed = True
                offset = max(0, offset - block)
                continue
            offset += block
        if not changed:
            block //= 2

    final_run = run_harness_artifact(
        artifact_name=f"{artifact_name}.minimized",
        content_b64=base64.b64encode(current).decode("ascii"),
        command=command,
        timeout_seconds=timeout_seconds,
        repetitions=repetitions,
        workdir=workdir,
        expected_error_token=expected_error_token,
    )
    return {
        "ok": True,
        "verdict": "MINIMIZED" if len(current) < len(data) else "UNCHANGED",
        "artifact": artifact_name,
        "original_size": len(data),
        "minimized_size": len(current),
        "reduction_bytes": len(data) - len(current),
        "reduction_ratio": (len(data) - len(current)) / len(data) if data else 0.0,
        "attempts": attempts,
        "accepted_reductions": len(accepted),
        "preserved_signal": _preserves_crash(final_run, baseline_signal, preserve_signal=preserve_signal),
        "baseline_signal": baseline_signal,
        "final_signal": _first_signal(final_run),
        "original_run": _summarize_run(original_run),
        "final_run": _summarize_run(final_run),
        "accepted": accepted,
        "content_b64": base64.b64encode(current).decode("ascii"),
    }


def _preserves_crash(run: dict[str, Any], baseline_signal: dict[str, Any] | None, *, preserve_signal: bool) -> bool:
    if not run.get("verified"):
        return False
    if not preserve_signal:
        return True
    signal = _first_signal(run)
    if signal is None or baseline_signal is None:
        return False
    for key in ("crash_type", "top_function", "top_file"):
        expected = baseline_signal.get(key)
        if expected and signal.get(key) != expected:
            return False
    return True


def _first_signal(run: dict[str, Any]) -> dict[str, Any] | None:
    for attempt in run.get("runs", []):
        if isinstance(attempt, dict) and isinstance(attempt.get("asan_signal"), dict):
            return attempt["asan_signal"]
    return None


def _summarize_run(run: dict[str, Any]) -> dict[str, Any]:
    return {
        "verified": run.get("verified"),
        "crashes": run.get("crashes"),
        "matches_expected": run.get("matches_expected"),
        "observed_error_token": run.get("observed_error_token"),
        "repetitions": run.get("repetitions"),
    }


def _bounded_attempts(value: int) -> int:
    try:
        attempts = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("max_attempts must be an integer") from exc
    if attempts <= 0 or attempts > MAX_MINIMIZE_ATTEMPTS:
        raise ValueError(f"max_attempts must be between 1 and {MAX_MINIMIZE_ATTEMPTS}")
    return attempts

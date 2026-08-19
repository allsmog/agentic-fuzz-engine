from __future__ import annotations

from typing import Any

from .execution import run_harness_artifact
from .fidelity import FixtureBenchmark


def grade_finding_artifact(
    *,
    artifact_name: str,
    content_b64: str,
    artifact_size: int,
    target: str,
    harness: str,
    sanitizer: str,
    command: list[str] | str,
    expected_error_token: str | None,
    benchmarks: tuple[FixtureBenchmark, ...],
    timeout_seconds: int | float = 10,
    repetitions: int = 3,
    workdir: str | None = None,
) -> dict[str, Any]:
    run = run_harness_artifact(
        artifact_name=artifact_name,
        content_b64=content_b64,
        command=command,
        timeout_seconds=timeout_seconds,
        repetitions=repetitions,
        workdir=workdir,
        expected_error_token=expected_error_token,
    )
    signal = _first_signal(run)
    matching = int(run["matches_expected"] if expected_error_token else run["crashes"])
    criteria = {
        "artifact_present": artifact_size > 0,
        "scope_declared": bool(target and harness and sanitizer),
        "reproduces_at_least_2_of_3": matching >= min(2, int(run["repetitions"])),
        "reproduces_3_of_3": matching == int(run["repetitions"]),
        "sanitizer_signal": signal is not None and (not expected_error_token or matching > 0),
        "top_project_frame": _has_project_frame(signal),
    }
    fidelity = _fidelity_alignment(
        benchmarks=benchmarks,
        target=target,
        harness=harness,
        sanitizer=sanitizer,
        expected_error_token=expected_error_token,
    )
    fail_reasons = [name for name, passed in criteria.items() if name not in {"reproduces_3_of_3"} and not passed]
    if fail_reasons:
        verdict = "FAIL"
    elif criteria["reproduces_3_of_3"]:
        verdict = "PASS"
    else:
        verdict = "WEAK_PASS"
    return {
        "verdict": verdict,
        "record_recommended": verdict == "PASS",
        "artifact": artifact_name,
        "artifact_size": artifact_size,
        "target": target,
        "harness": harness,
        "sanitizer": sanitizer,
        "expected_error_token": expected_error_token,
        "criteria": criteria,
        "fail_reasons": fail_reasons,
        "reproduction": {
            "attempts": run["repetitions"],
            "matching": matching,
            "crashes": run["crashes"],
            "matches_expected": run["matches_expected"],
            "observed_error_token": run["observed_error_token"],
            "exit_codes": [attempt.get("exit_code") for attempt in run["runs"]],
        },
        "signal": signal,
        "fidelity": fidelity,
        "run": run,
    }


def _first_signal(run: dict[str, Any]) -> dict[str, Any] | None:
    for attempt in run.get("runs", []):
        if isinstance(attempt, dict) and isinstance(attempt.get("asan_signal"), dict):
            return attempt["asan_signal"]
    return None


def _has_project_frame(signal: dict[str, Any] | None) -> bool:
    if not signal:
        return False
    top_function = signal.get("top_function")
    top_file = signal.get("top_file")
    if not top_function or top_function in {"LLVMFuzzerTestOneInput", "main"}:
        return False
    return isinstance(top_file, str) and (
        "/src/" in top_file
        or "/work/" in top_file
        or top_file.endswith((".c", ".cc", ".cpp", ".h", ".hpp"))
    )


def _fidelity_alignment(
    *,
    benchmarks: tuple[FixtureBenchmark, ...],
    target: str,
    harness: str,
    sanitizer: str,
    expected_error_token: str | None,
) -> dict[str, Any]:
    matches = [
        benchmark
        for benchmark in benchmarks
        if benchmark.target == target
        and benchmark.harness == harness
        and benchmark.sanitizer == sanitizer
        and (expected_error_token is None or benchmark.error_token == expected_error_token)
    ]
    return {
        "aligned": bool(matches),
        "disabled_only": bool(matches) and all(match.disabled_project for match in matches),
        "matches": [
            {
                "project": match.project,
                "fixture": match.fixture,
                "target": match.target,
                "harness": match.harness,
                "sanitizer": match.sanitizer,
                "error_token": match.error_token,
                "proof_sha256": match.proof_sha256,
                "disabled_project": match.disabled_project,
            }
            for match in matches
        ],
    }

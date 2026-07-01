from __future__ import annotations

import base64
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from hashlib import sha256
from time import monotonic
from typing import Any

from .execution import _bounded_timeout, _clip, _normalize_command, _validate_command, run_harness_artifact


MAX_PATCH_BYTES = 512_000


def prepare_patch_candidate(
    *,
    patch_content_b64: str,
    artifact_name: str,
    finding_id: str | None = None,
    rationale: str | None = None,
    variants_checked: list[str] | None = None,
) -> dict[str, Any]:
    patch_bytes = base64.b64decode(patch_content_b64.encode("ascii"))
    if not patch_bytes or len(patch_bytes) > MAX_PATCH_BYTES:
        raise ValueError(f"patch artifact must be between 1 and {MAX_PATCH_BYTES} bytes")
    patch_text = patch_bytes.decode("utf-8", errors="replace")
    changed_paths = validate_unified_diff(patch_text)
    metadata = {
        "finding_id": finding_id,
        "patch_artifact": artifact_name,
        "patch_sha256": sha256(patch_bytes).hexdigest(),
        "patch_size": len(patch_bytes),
        "changed_paths": changed_paths,
        "rationale": rationale or "",
        "variants_checked": variants_checked or [],
        "validation": {
            "unified_diff": True,
            "path_safe": True,
            "hunks_present": True,
        },
    }
    metadata_content = json.dumps(metadata, indent=2, sort_keys=True).encode("utf-8")
    return {
        "artifact_name": artifact_name,
        "content_b64": patch_content_b64,
        "metadata": metadata,
        "metadata_artifact_name": f"{artifact_name}.metadata.json",
        "metadata_content_b64": base64.b64encode(metadata_content).decode("ascii"),
    }


def grade_patch_artifact(
    *,
    patch_name: str,
    patch_content_b64: str,
    source_dir: str,
    pov_name: str,
    pov_content_b64: str,
    harness_command: list[str] | str,
    expected_error_token: str,
    build_command: list[str] | str | None = None,
    test_command: list[str] | str | None = None,
    reattack_artifacts: list[dict[str, str]] | None = None,
    reattack_command: list[str] | str | None = None,
    timeout_seconds: int | float = 10,
    repetitions: int = 3,
) -> dict[str, Any]:
    timeout = _bounded_timeout(timeout_seconds)
    source = Path(source_dir).expanduser().resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"source_dir is not a directory: {source_dir}")

    patch_bytes = base64.b64decode(patch_content_b64.encode("ascii"))
    if not patch_bytes or len(patch_bytes) > MAX_PATCH_BYTES:
        raise ValueError(f"patch artifact must be between 1 and {MAX_PATCH_BYTES} bytes")

    with tempfile.TemporaryDirectory(prefix="agentic-fuzz-patch-grade-") as tmp:
        work_source = Path(tmp) / "source"
        _copy_source(source, work_source)
        patch_path = Path(tmp) / _safe_name(patch_name)
        patch_path.write_bytes(patch_bytes)

        apply_check = _run_command(["git", "apply", "--check", str(patch_path)], cwd=work_source, timeout_seconds=timeout)
        if apply_check["exit_code"] != 0:
            return _verdict(False, "APPLY_FAIL", work_source, patch_name, apply_check=apply_check)

        apply_run = _run_command(["git", "apply", str(patch_path)], cwd=work_source, timeout_seconds=timeout)
        if apply_run["exit_code"] != 0:
            return _verdict(False, "APPLY_FAIL", work_source, patch_name, apply_check=apply_check, apply=apply_run)

        build_run = None
        if build_command is not None:
            build_run = _run_command(_materialize_src_command(build_command, work_source), cwd=work_source, timeout_seconds=timeout)
            if build_run["exit_code"] != 0:
                return _verdict(False, "BUILD_FAIL", work_source, patch_name, apply_check=apply_check, apply=apply_run, build=build_run)

        pov_command = _materialize_src_command(harness_command, work_source)
        pov_run = run_harness_artifact(
            artifact_name=pov_name,
            content_b64=pov_content_b64,
            command=pov_command,
            timeout_seconds=timeout,
            repetitions=repetitions,
            workdir=str(work_source),
            expected_error_token=expected_error_token,
        )
        if pov_run["matches_expected"] > 0 or pov_run["crashes"] > 0:
            return _verdict(
                False,
                "POV_STILL_CRASHES",
                work_source,
                patch_name,
                apply_check=apply_check,
                apply=apply_run,
                build=build_run,
                pov=pov_run,
            )

        tests_run = None
        if test_command is not None:
            tests_run = _run_command(_materialize_src_command(test_command, work_source), cwd=work_source, timeout_seconds=timeout)
            if tests_run["exit_code"] != 0:
                return _verdict(
                    False,
                    "TEST_FAIL",
                    work_source,
                    patch_name,
                    apply_check=apply_check,
                    apply=apply_run,
                    build=build_run,
                    pov=pov_run,
                    tests=tests_run,
                )

        reattack_runs = []
        for artifact in reattack_artifacts or []:
            reattack_run = run_harness_artifact(
                artifact_name=artifact["name"],
                content_b64=artifact["content_b64"],
                command=_materialize_src_command(reattack_command or harness_command, work_source),
                timeout_seconds=timeout,
                repetitions=repetitions,
                workdir=str(work_source),
                expected_error_token=expected_error_token,
            )
            reattack_runs.append({"artifact": artifact["name"], "run": reattack_run})
            if reattack_run["matches_expected"] > 0 or reattack_run["crashes"] > 0:
                return _verdict(
                    False,
                    "REATTACK_FAIL",
                    work_source,
                    patch_name,
                    apply_check=apply_check,
                    apply=apply_run,
                    build=build_run,
                    pov=pov_run,
                    tests=tests_run,
                    reattack=reattack_runs,
                )

        return _verdict(
            True,
            "PASS",
            work_source,
            patch_name,
            apply_check=apply_check,
            apply=apply_run,
            build=build_run,
            pov=pov_run,
            tests=tests_run,
            reattack=reattack_runs,
        )


def _copy_source(source: Path, destination: Path) -> None:
    def ignore(_dir: str, names: list[str]) -> set[str]:
        return {name for name in names if name in {".git", "__pycache__", ".pytest_cache"}}

    shutil.copytree(source, destination, ignore=ignore)


def _run_command(command: list[str], *, cwd: Path, timeout_seconds: float) -> dict[str, Any]:
    argv = _normalize_command(command)
    _validate_command(argv)
    started = monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        return {
            "command": argv,
            "exit_code": proc.returncode,
            "timed_out": False,
            "elapsed_ms": int((monotonic() - started) * 1000),
            "stdout": _clip(proc.stdout or ""),
            "stderr": _clip(proc.stderr or ""),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": argv,
            "exit_code": 124,
            "timed_out": True,
            "elapsed_ms": int((monotonic() - started) * 1000),
            "stdout": _clip(_coerce_output(exc.stdout)),
            "stderr": _clip(_coerce_output(exc.stderr) + "\nTIMEOUT"),
        }


def _materialize_src_command(command: list[str] | str, source: Path) -> list[str]:
    return [arg.replace("{src}", str(source)) for arg in _normalize_command(command)]


def validate_unified_diff(patch_text: str) -> list[str]:
    lines = patch_text.splitlines()
    if not any(line.startswith("@@ ") for line in lines):
        raise ValueError("patch candidate must contain at least one unified-diff hunk")
    changed_paths: set[str] = set()
    for line in lines:
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                changed_paths.add(_normalize_diff_path(parts[2]))
                changed_paths.add(_normalize_diff_path(parts[3]))
        elif line.startswith("--- ") or line.startswith("+++ "):
            path = line[4:].split("\t", 1)[0].strip()
            if path != "/dev/null":
                changed_paths.add(_normalize_diff_path(path))
    changed_paths.discard("")
    if not changed_paths:
        raise ValueError("patch candidate must name at least one changed source path")
    return sorted(changed_paths)


def _validate_unified_diff(patch_text: str) -> list[str]:
    return validate_unified_diff(patch_text)


def _normalize_diff_path(value: str) -> str:
    path = value.strip()
    if path in {"", "/dev/null"}:
        return ""
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"patch candidate path is unsafe: {value}")
    if "\x00" in path or path.startswith("-"):
        raise ValueError(f"patch candidate path is unsafe: {value}")
    return candidate.as_posix()


def _verdict(passed: bool, tier: str, source: Path, patch_name: str, **evidence: Any) -> dict[str, Any]:
    return {
        "passed": passed,
        "tier": tier,
        "patch_artifact": patch_name,
        "work_source": str(source),
        "evidence": {key: value for key, value in evidence.items() if value is not None},
    }


def _safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in Path(value).name)[:120] or "patch.diff"


def _coerce_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value

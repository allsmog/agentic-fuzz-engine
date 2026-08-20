"""Bounded per-target builds driven by the target's declared build steps.

``target-build`` reads ``targets/c/<name>/.localfuzz/build.json`` from the
workspace and runs each declared step in order. The engine stays generic: any
container/toolchain specifics (e.g. ``docker exec`` into a build container for
generated headers) live in the declared argv, not in this module.

Placeholders substituted into argv and env values:
``{target_dir}`` ``{bin_dir}`` ``{workspace_root}`` ``{source_dir}``
``{build_container}``.
"""

from __future__ import annotations

import json
import math
import os
import time
from pathlib import Path
from typing import Any, Mapping

from .runtime_backends import MAX_RUNTIME_TIMEOUT_SECONDS, _run_command
from .process_safety import validate_declared_env
from .scaffold import TARGETS_RELATIVE
from .workspace import load_workspace, resolve_workspace_root

BUILD_CONFIG_RELATIVE = Path(".localfuzz/build.json")
MAX_BUILD_STEPS = 32


def build_target(
    *,
    project: str,
    workspace_root: str | Path | None = None,
    only_steps: list[str] | None = None,
    timeout_seconds: int | float = 900,
    total_timeout_seconds: int | float | None = None,
    env: Mapping[str, str] | None = None,
    build_env: Mapping[str, str] | None = None,
    config_override: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    # Validate caller/target declarations before filesystem setup or selected
    # steps can make a skipped build look successful.
    declared_build_env = validate_declared_env(build_env)
    environment = dict(os.environ if env is None else env)
    timeout = min(float(timeout_seconds), MAX_RUNTIME_TIMEOUT_SECONDS)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout_seconds must be finite and positive")
    deadline: float | None = None
    if total_timeout_seconds is not None:
        total_timeout = min(float(total_timeout_seconds), MAX_RUNTIME_TIMEOUT_SECONDS)
        if not math.isfinite(total_timeout) or total_timeout <= 0:
            raise ValueError("total_timeout_seconds must be finite and positive")
        deadline = time.monotonic() + total_timeout

    root = resolve_workspace_root(workspace_root, env=environment)
    try:
        workspace = load_workspace(root, env=environment)
    except FileNotFoundError:
        workspace = {"root": str(root)}

    name = project.removeprefix("localfuzz/c/")
    target_dir = root / TARGETS_RELATIVE / name
    build_config_path = target_dir / BUILD_CONFIG_RELATIVE
    if not target_dir.is_dir():
        raise FileNotFoundError(f"target dir not found (run target-scaffold first): {target_dir}")
    if config_override is None and not build_config_path.is_file():
        raise FileNotFoundError(f"build config not found: {build_config_path}")

    config = dict(config_override) if config_override is not None else json.loads(
        build_config_path.read_text(encoding="utf-8")
    )
    steps = config.get("steps", [])
    if not isinstance(steps, list) or not steps:
        raise ValueError(f"build config has no steps: {build_config_path}")
    if len(steps) > MAX_BUILD_STEPS:
        raise ValueError(f"build config exceeds {MAX_BUILD_STEPS} steps")
    validated_step_envs: list[dict[str, str]] = []
    for step in steps:
        if not isinstance(step, Mapping):
            raise ValueError("build config steps must be objects")
        raw_step_env = step.get("env") or {}
        if not isinstance(raw_step_env, Mapping):
            raise ValueError("build step env must be an object")
        validated_step_envs.append(validate_declared_env(raw_step_env))

    bin_dir = root / "bin" / name
    bin_dir.mkdir(parents=True, exist_ok=True)
    placeholders = {
        "target_dir": str(target_dir),
        "bin_dir": str(bin_dir),
        "workspace_root": str(root),
        "source_dir": str(workspace.get("source_dir") or ""),
        "build_container": str((workspace.get("docker") or {}).get("build_container") or ""),
    }

    selected = {step_name.strip() for step_name in (only_steps or []) if step_name.strip()}
    step_results = []
    blockers = []
    failed = False
    for step, step_env in zip(steps, validated_step_envs):
        step_name = str(step.get("name") or f"step-{len(step_results)}")
        if selected and step_name not in selected:
            step_results.append({"name": step_name, "skipped": True, "reason": "not selected"})
            continue
        if failed:
            step_results.append({"name": step_name, "skipped": True, "reason": "previous step failed"})
            continue
        argv = [_substitute(str(item), placeholders) for item in step.get("argv", [])]
        if not argv:
            blockers.append(f"{step_name}: empty argv")
            failed = True
            step_results.append({"name": step_name, "skipped": True, "reason": "empty argv"})
            continue
        step_timeout = timeout
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                blockers.append(f"{step_name}: total build budget exhausted")
                failed = True
                step_results.append({
                    "name": step_name, "skipped": True,
                    "reason": "total build budget exhausted",
                })
                continue
            step_timeout = min(step_timeout, remaining)
        declared_env = dict(declared_build_env)
        for key, value in step_env.items():
            declared_env[key] = _substitute(value, placeholders)
        try:
            run = _run_command(
                argv,
                cwd=target_dir,
                timeout_seconds=step_timeout,
                env=environment,
                declared_env=declared_env or None,
            )
        except ValueError as exc:
            run = {"exit_code": 127, "timed_out": False, "elapsed_ms": 0, "stdout": "", "stderr": str(exc), "command": argv}
        ok = run["exit_code"] == 0 and not run["timed_out"]
        step_results.append({"name": step_name, "skipped": False, "ok": ok, "run": run})
        if not ok:
            failed = True
            reason = "timeout" if run["timed_out"] else (str(run.get("stderr") or "") if run["exit_code"] == 127 and "declared environment" in str(run.get("stderr") or "") else f"exit {run['exit_code']}")
            blockers.append(f"{step_name}: {reason}")

    artifacts = [
        {
            "path": str(entry),
            "size": entry.stat().st_size,
            "executable": os.access(entry, os.X_OK),
        }
        for entry in sorted(bin_dir.iterdir())
        if entry.is_file()
    ]
    manifest: dict[str, Any] | None = None
    if not blockers and config_override is None:
        # Successful build: record the input-closure hash manifest so the
        # round loop can detect staleness proactively (see staleness.py).
        from .staleness import write_manifest

        manifest = write_manifest(
            root=root,
            name=name,
            target_dir=target_dir,
            build_config=config,
            placeholders=placeholders,
        )
    return {
        "ok": not blockers,
        "build_manifest": manifest,
        "mode": "target-build",
        "project": f"localfuzz/c/{name}",
        "target_dir": str(target_dir),
        "bin_dir": str(bin_dir),
        "build_config": str(build_config_path),
        "steps": step_results,
        "artifacts": artifacts,
        "blockers": blockers,
    }


def _substitute(text: str, placeholders: Mapping[str, str]) -> str:
    for key, value in placeholders.items():
        text = text.replace("{" + key + "}", value)
    return text

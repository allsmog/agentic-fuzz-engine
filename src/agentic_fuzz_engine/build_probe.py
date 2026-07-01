from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from time import monotonic
from typing import Any

from .discovery import discover_local_target
from .execution import _bounded_timeout, _clip, _coerce_output, _normalize_command, _validate_command


DEFAULT_BUILD_ID = "build-probe"


def probe_target_build(
    *,
    source_dir: str,
    worktree_dir: str | Path,
    project: str | None = None,
    build_commands: list[list[str]] | None = None,
    timeout_seconds: int | float = 30,
) -> dict[str, Any]:
    source = Path(source_dir).expanduser().resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"source_dir is not a directory: {source_dir}")
    timeout = _bounded_timeout(timeout_seconds)
    worktree = Path(worktree_dir).expanduser().resolve()
    if worktree.exists():
        shutil.rmtree(worktree)
    _copy_source(source, worktree)

    before = discover_local_target(str(worktree), project=project)
    commands = build_commands or _first_probe_commands(before)
    runs = []
    ok = bool(commands)
    blocker = None if commands else "no runnable build probe commands discovered"
    for command in commands:
        run = _run_build_command(_materialize_src_command(command, worktree), cwd=worktree, timeout_seconds=timeout)
        runs.append(run)
        if run["exit_code"] != 0:
            ok = False
            blocker = "build command failed"
            break
    after = discover_local_target(str(worktree), project=project)
    runnable_harnesses = [harness for harness in after["harnesses"] if harness.get("runnable")]
    if ok and not runnable_harnesses:
        ok = False
        blocker = "build completed but no runnable harness command was discovered"

    return {
        "ok": ok,
        "project": project,
        "source_dir": str(source),
        "worktree_dir": str(worktree),
        "build_commands": commands,
        "runs": runs,
        "before": _discovery_summary(before),
        "after": after,
        "command_map": after["command_map"],
        "runnable_harnesses": runnable_harnesses,
        "blocker": blocker,
    }


def _first_probe_commands(discovery: dict[str, Any]) -> list[list[str]]:
    for build_system in discovery.get("build_systems", []):
        commands = build_system.get("recommended_probe_commands")
        if commands:
            return commands
    return []


def _run_build_command(command: list[str], *, cwd: Path, timeout_seconds: float) -> dict[str, Any]:
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


def _copy_source(source: Path, destination: Path) -> None:
    def ignore(_dir: str, names: list[str]) -> set[str]:
        return {name for name in names if name in {".git", "__pycache__", ".pytest_cache"}}

    shutil.copytree(source, destination, ignore=ignore)


def _materialize_src_command(command: list[str], source: Path) -> list[str]:
    return [arg.replace("{src}", str(source)) for arg in command]


def _discovery_summary(discovery: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": discovery["ok"],
        "build_systems": discovery["build_systems"],
        "command_map": discovery["command_map"],
        "harnesses": [
            {
                "name": harness["name"],
                "runnable": harness["runnable"],
                "blockers": harness["blockers"],
            }
            for harness in discovery["harnesses"]
        ],
        "blockers": discovery["blockers"],
    }

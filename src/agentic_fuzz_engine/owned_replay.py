from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .fidelity import REFERENCE_PROJECTS_RELATIVE, FixtureBenchmark, discover_reference_benchmarks, load_target_profile, resolve_reference_root


MAX_COMPILE_TIMEOUT_SECONDS = 120.0
MAX_OUTPUT_CHARS = 12000

_WRAPPER_C = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 3;
  if (fseek(f, 0, SEEK_END) != 0) return 4;
  long n = ftell(f);
  if (n < 0) return 5;
  rewind(f);
  uint8_t *buf = malloc((size_t)n ? (size_t)n : 1);
  if (!buf) return 6;
  if (n && fread(buf, 1, (size_t)n, f) != (size_t)n) return 7;
  fclose(f);
  int rc = LLVMFuzzerTestOneInput(buf, (size_t)n);
  free(buf);
  return rc;
}
"""

_WRAPPER_CC = r"""
#include <cstdint>
#include <cstdio>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 3;
  if (fseek(f, 0, SEEK_END) != 0) return 4;
  long n = ftell(f);
  if (n < 0) return 5;
  rewind(f);
  uint8_t *buf = static_cast<uint8_t *>(malloc((size_t)n ? (size_t)n : 1));
  if (!buf) return 6;
  if (n && fread(buf, 1, (size_t)n, f) != (size_t)n) return 7;
  fclose(f);
  int rc = LLVMFuzzerTestOneInput(buf, (size_t)n);
  free(buf);
  return rc;
}
"""


def run_owned_direct_asan_replay(
    engine: Any,
    *,
    run_id: str | None = None,
    project: str | None = None,
    include_disabled: bool = False,
    max_cases: int | None = None,
    compile_timeout_seconds: int | float = 30,
    replay_timeout_seconds: int | float = 10,
    repetitions: int = 1,
) -> dict[str, Any]:
    target_filter = _normalize_target(project)
    selected = list(discover_reference_benchmarks(engine.reference_root, include_disabled=include_disabled))
    if target_filter:
        project_name = target_filter.removeprefix("localfuzz/c/")
        selected = [benchmark for benchmark in selected if benchmark.project == project_name]
    if max_cases is not None:
        selected = selected[:max_cases]

    active_run_id = run_id or "owned-direct-asan-replay"
    target = target_filter or "localfuzz/c/all"
    engine.call_tool(
        "campaign_start",
        {
            "target": target,
            "name": active_run_id,
            "metadata": {
                "mode": "owned-direct-asan-replay",
                "runtime_authority": "agentic_fuzz_engine",
                "include_disabled": include_disabled,
                "max_cases": max_cases,
            },
        },
    )

    build_cache: dict[tuple[str, str, str], dict[str, Any]] = {}
    command_maps: dict[str, dict[str, list[str]]] = {}
    build_results: list[dict[str, Any]] = []
    for benchmark in selected:
        key = (benchmark.target, benchmark.harness, benchmark.base_commit)
        if key not in build_cache:
            build_cache[key] = _build_direct_replay_binary(
                engine,
                run_id=active_run_id,
                benchmark=benchmark,
                timeout_seconds=compile_timeout_seconds,
            )
        build = build_cache[key]
        build_results.append(
            {
                "project": benchmark.project,
                "target": benchmark.target,
                "fixture": benchmark.fixture,
                "harness": benchmark.harness,
                "status": "compiled" if build.get("ok") else "blocked",
                "binary": build.get("binary"),
                "blocker": build.get("blocker"),
            }
        )
        if build.get("ok") and isinstance(build.get("binary"), str):
            command_maps.setdefault(benchmark.target, {})[benchmark.harness] = [str(build["binary"]), "{poc}"]

    replay_results: list[dict[str, Any]] = []
    for replay_target, command_map in sorted(command_maps.items()):
        replay = engine.call_tool(
            "fidelity_replay_campaign",
            {
                "run_id": active_run_id,
                "project": replay_target,
                "command_map": command_map,
                "timeout_seconds": replay_timeout_seconds,
                "repetitions": repetitions,
                "record_findings": True,
                "include_disabled": include_disabled,
            },
        )
        replay_results.append(replay)

    audit = engine.call_tool(
        "campaign_fidelity_audit",
        {"run_id": active_run_id, "project": target_filter, "include_disabled": include_disabled},
    )
    summary = _summary(selected=selected, build_results=build_results, replay_results=replay_results, audit=audit)
    engine.state.event_append(active_run_id, "owned_direct_asan_replay", summary)
    return {
        "ok": summary["represented_fixtures"] > 0 and summary["verified_proofs"] == summary["represented_fixtures"],
        "mode": "owned-direct-asan-replay",
        "runtime_authority": "agentic_fuzz_engine",
        "run_id": active_run_id,
        "target": target,
        "summary": summary,
        "builds": list(build_cache.values()),
        "fixture_builds": build_results,
        "replays": replay_results,
        "audit": audit,
        "blockers": _blockers(build_results=build_results, audit=audit),
    }


def _build_direct_replay_binary(
    engine: Any,
    *,
    run_id: str,
    benchmark: FixtureBenchmark,
    timeout_seconds: int | float,
) -> dict[str, Any]:
    root = resolve_reference_root(engine.reference_root)
    project_dir = root / REFERENCE_PROJECTS_RELATIVE / benchmark.project
    try:
        profile = load_target_profile(benchmark.target, root)
    except Exception as exc:  # pragma: no cover - defensive for malformed external fixture trees
        return _blocked_build(benchmark, f"target profile failed to load: {exc}")

    harness_source = _find_harness_source(project_dir=project_dir, profile=profile.to_dict(), benchmark=benchmark)
    if harness_source is None:
        return _blocked_build(benchmark, "harness source not found in benchmark source snapshot or userspace project")

    source_root = project_dir / "sources" / benchmark.base_commit / "src"
    project_source_dir = _project_source_dir(source_root)
    is_cxx = harness_source.suffix.lower() in {".cc", ".cpp", ".cxx"}
    compiler = _compiler(is_cxx)
    if compiler is None:
        return _blocked_build(benchmark, "clang++ not found" if is_cxx else "clang not found")

    build_dir = engine.state.worktree_dir(run_id, f"direct-asan-{benchmark.project}-{benchmark.harness}-{benchmark.base_commit}")
    build_dir.mkdir(parents=True, exist_ok=True)
    wrapper = build_dir / ("fuzzer_replay_main.cc" if is_cxx else "fuzzer_replay_main.c")
    wrapper.write_text(_WRAPPER_CC if is_cxx else _WRAPPER_C, encoding="utf-8")
    binary = build_dir / f"{benchmark.project}_{benchmark.harness}_replay"
    include_dirs = _include_dirs(project_source_dir=project_source_dir, source_root=source_root, harness_source=harness_source, profile=profile.to_dict())
    command = [
        compiler,
        "-g",
        "-O1",
        "-fsanitize=address",
        *[f"-I{path}" for path in include_dirs],
        str(harness_source),
        str(wrapper),
        "-o",
        str(binary),
    ]
    if is_cxx:
        command.insert(1, "-std=c++17")

    timeout = _bounded_timeout(timeout_seconds)
    try:
        proc = subprocess.run(
            command,
            cwd=str(project_source_dir) if project_source_dir.exists() else None,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
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

    ok = returncode == 0 and binary.exists()
    return {
        "ok": ok,
        "project": benchmark.project,
        "target": benchmark.target,
        "harness": benchmark.harness,
        "base_commit": benchmark.base_commit,
        "harness_source": str(harness_source),
        "project_source_dir": str(project_source_dir),
        "binary": str(binary) if ok else None,
        "command": command,
        "exit_code": returncode,
        "timed_out": timed_out,
        "stdout": _clip(stdout),
        "stderr": _clip(stderr),
        "blocker": None if ok else "direct ASAN compile failed",
    }


def _find_harness_source(*, project_dir: Path, profile: dict[str, Any], benchmark: FixtureBenchmark) -> Path | None:
    userspace_project_dir = Path(str(profile.get("userspace_project_dir"))).expanduser() if profile.get("userspace_project_dir") else None
    source_root = project_dir / "sources" / benchmark.base_commit / "src"
    for harness in profile.get("harnesses", []):
        if not isinstance(harness, dict) or harness.get("name") != benchmark.harness:
            continue
        raw_path = harness.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            continue
        for base in (project_dir, userspace_project_dir, source_root):
            if base is None:
                continue
            candidate = (base / raw_path).resolve()
            if candidate.exists() and candidate.is_file():
                return candidate
    for base in (source_root, userspace_project_dir, project_dir):
        if base is None or not base.exists():
            continue
        for name in _candidate_harness_names(benchmark):
            for extension in (".c", ".cc", ".cpp", ".cxx"):
                matches = sorted(base.glob(f"**/{name}{extension}"))
                if matches:
                    return matches[0].resolve()
    return None


def _candidate_harness_names(benchmark: FixtureBenchmark) -> tuple[str, ...]:
    names = [benchmark.harness]
    if benchmark.project == "php" and benchmark.harness.startswith("php-fuzz-"):
        names.append("fuzzer-" + benchmark.harness.removeprefix("php-fuzz-"))
    if benchmark.project == "sleuthkit" and benchmark.harness.startswith("sleuthkit_fls_"):
        names.append("sleuthkit_fls_fuzzer")
    if benchmark.project == "wireshark" and benchmark.harness.startswith("fuzzshark_"):
        names.append("fuzzshark")
    return tuple(dict.fromkeys(names))


def _project_source_dir(source_root: Path) -> Path:
    if not source_root.exists():
        return source_root
    children = [path for path in source_root.iterdir() if path.is_dir()]
    if len(children) == 1:
        return children[0].resolve()
    return source_root.resolve()


def _include_dirs(*, project_source_dir: Path, source_root: Path, harness_source: Path, profile: dict[str, Any]) -> list[Path]:
    dirs = [project_source_dir.resolve(), source_root.resolve(), harness_source.parent.resolve()]
    userspace_project_dir = profile.get("userspace_project_dir")
    if isinstance(userspace_project_dir, str) and userspace_project_dir:
        dirs.append(Path(userspace_project_dir).expanduser().resolve())
    deduped: list[Path] = []
    for path in dirs:
        if path.exists() and path not in deduped:
            deduped.append(path)
    return deduped


def _compiler(is_cxx: bool) -> str | None:
    env_key = "CXX" if is_cxx else "CC"
    configured = os.environ.get(env_key)
    if configured and shutil.which(configured):
        return configured
    return shutil.which("clang++" if is_cxx else "clang")


def _summary(
    *,
    selected: list[FixtureBenchmark],
    build_results: list[dict[str, Any]],
    replay_results: list[dict[str, Any]],
    audit: dict[str, Any],
) -> dict[str, Any]:
    verified = sum(int(replay.get("verified") or 0) for replay in replay_results)
    executed = sum(int(replay.get("executed") or 0) for replay in replay_results)
    score = audit.get("score") if isinstance(audit.get("score"), dict) else {}
    represented = int(score.get("represented_fixtures") or 0)
    enabled = int(score.get("enabled_fixtures") or len([item for item in selected if not item.disabled_project]))
    return {
        "selected_fixtures": len(selected),
        "enabled_fixtures": enabled,
        "disabled_fixtures": int(score.get("disabled_fixtures") or len([item for item in selected if item.disabled_project])),
        "compiled_harnesses": len({(item["target"], item["harness"]) for item in build_results if item.get("status") == "compiled"}),
        "blocked_harnesses": len({(item["target"], item["harness"]) for item in build_results if item.get("status") != "compiled"}),
        "executed_proofs": executed,
        "verified_proofs": verified,
        "represented_fixtures": represented,
        "missing_fixtures": int(score.get("missing_fixtures") or 0),
        "coverage_ratio": score.get("coverage_ratio", represented / enabled if enabled else 0.0),
    }


def _blockers(*, build_results: list[dict[str, Any]], audit: dict[str, Any]) -> list[str]:
    blockers = []
    for item in build_results:
        if item.get("status") != "compiled":
            blockers.append(f"{item.get('project')}:{item.get('fixture')}:{item.get('harness')}: {item.get('blocker')}")
    blockers.extend(str(item) for item in audit.get("blockers", []) if item)
    return list(dict.fromkeys(blockers))


def _blocked_build(benchmark: FixtureBenchmark, blocker: str) -> dict[str, Any]:
    return {
        "ok": False,
        "project": benchmark.project,
        "target": benchmark.target,
        "harness": benchmark.harness,
        "base_commit": benchmark.base_commit,
        "binary": None,
        "command": [],
        "exit_code": None,
        "timed_out": False,
        "stdout": "",
        "stderr": "",
        "blocker": blocker,
    }


def _normalize_target(project: str | None) -> str | None:
    if not project:
        return None
    return project if project.startswith("localfuzz/") else f"localfuzz/c/{project}"


def _bounded_timeout(value: int | float) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        timeout = 30.0
    if timeout <= 0:
        return 30.0
    return min(timeout, MAX_COMPILE_TIMEOUT_SECONDS)


def _clip(value: str) -> str:
    if len(value) <= MAX_OUTPUT_CHARS:
        return value
    return value[: MAX_OUTPUT_CHARS // 2] + "\n...[truncated]...\n" + value[-MAX_OUTPUT_CHARS // 2 :]


def _coerce_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value

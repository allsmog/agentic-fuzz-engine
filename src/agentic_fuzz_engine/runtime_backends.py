from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import shutil
import stat
import sys
from hashlib import sha256
from pathlib import Path
from time import monotonic, time as wall_time
from typing import Any, Mapping

from .execution import FORBIDDEN_ARG_FRAGMENTS, _clip, _normalize_command
from .patching import validate_unified_diff
from .process_safety import bounded_run, docker_client_env, sanitized_env, tool_env, validate_command_shape, validate_declared_env
from .workspace import KLEE_IMAGE_ENV, load_workspace, translate_host_path


MAX_RUNTIME_TIMEOUT_SECONDS = 3600.0
MAX_COLLECTED_FILE_BYTES = 1_048_576
MAX_COLLECTED_FILES = 100
MAX_Z3_CONSTRAINT_BYTES = 1_048_576
MAX_Z3_ENCODED_BYTES = ((MAX_Z3_CONSTRAINT_BYTES + 2) // 3) * 4
MAX_Z3_TIMEOUT_SECONDS = 60.0
SKIP_SOURCE_DIRS = {".git", "__pycache__", ".pytest_cache", ".cache"}


def runtime_backend_status(*, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    environment = env if env is not None else os.environ
    groups = {
        "fuzz_ensemble": {
            "title": "AFL++/LibAFL/libFuzzer ensemble",
            "checks": {
                "clang": _binary_check("clang", environment),
                "llvm-symbolizer": _binary_check("llvm-symbolizer", environment),
                "afl-fuzz": _binary_check("afl-fuzz", environment),
                "cargo": _binary_check("cargo", environment),
            },
        },
        "symbolic_stack": {
            "title": "SymCC/SymQEMU/KLEE/Z3 symbolic execution",
            "checks": {
                "symcc": _binary_check("symcc", environment),
                "symqemu": _binary_any_check(("symqemu", "symqemu-x86_64"), environment),
                "klee_ng": _klee_image_check(environment),
                "z3": _python_module_check("z3"),
            },
        },
        "sarif_reachability": {
            "title": "CodeQL/Joern/SootUp SARIF reachability",
            "checks": {
                "codeql": _binary_check("codeql", environment),
                "joern": _binary_check("joern", environment),
                "java": _binary_check("java", environment),
                "sootup": _sootup_check(environment),
            },
        },
        "cached_patch_pool": {
            "title": "cached patch environment pool/cache",
            "checks": {
                "docker": _binary_check("docker", environment),
                "git": _binary_check("git", environment),
                "uv": _binary_check("uv", environment),
                "model_credentials": _env_any_check(
                    ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY", "GROK_API_KEY"),
                    environment,
                ),
            },
        },
    }
    for group in groups.values():
        checks = group["checks"]
        group["ready"] = all(bool(check["ok"]) for check in checks.values())
        group["missing"] = [name for name, check in checks.items() if not check["ok"]]
    blockers = [f"{name}: {missing}" for name, group in groups.items() for missing in group["missing"]]
    return {
        "ok": not blockers,
        "mode": "real-runtime-backend-status",
        "groups": groups,
        "ready_groups": sum(1 for group in groups.values() if group["ready"]),
        "blockers": blockers,
    }


def run_fuzz_ensemble(
    *,
    work_dir: str | Path,
    target: str,
    harness: str,
    harness_command: list[str] | str | None = None,
    seed_artifacts: list[dict[str, str]] | None = None,
    workers: list[str] | None = None,
    libafl_command: list[str] | str | None = None,
    runs: int = 128,
    timeout_seconds: int | float = 60,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    timeout = _bounded_runtime_timeout(timeout_seconds)
    run_count = _bounded_runs(runs)
    selected = workers or ["libfuzzer", "afl", "libafl"]
    if not all(worker in {"libfuzzer", "afl", "libafl"} for worker in selected):
        raise ValueError("workers must be selected from libfuzzer, afl, libafl")

    work = Path(work_dir).expanduser().resolve()
    seed_dir = work / "seeds"
    crash_root = work / "crashes"
    work.mkdir(parents=True, exist_ok=True)
    seed_dir.mkdir(parents=True, exist_ok=True)
    crash_root.mkdir(parents=True, exist_ok=True)
    seeds = _materialize_seed_artifacts(seed_artifacts or [], seed_dir)

    statuses = runtime_backend_status(env=environment)["groups"]["fuzz_ensemble"]["checks"]
    worker_results = []
    for worker in selected:
        if worker == "libfuzzer":
            worker_results.append(
                _run_libfuzzer(
                    command=harness_command,
                    seed_dir=seed_dir,
                    crash_dir=crash_root / "libfuzzer",
                    run_count=run_count,
                    timeout_seconds=timeout,
                    status=statuses,
                    env=environment,
                )
            )
        elif worker == "afl":
            worker_results.append(
                _run_afl(
                    command=harness_command,
                    seed_dir=seed_dir,
                    crash_dir=crash_root / "afl",
                    timeout_seconds=timeout,
                    status=statuses,
                    env=environment,
                )
            )
        elif worker == "libafl":
            worker_results.append(
                _run_libafl(
                    command=libafl_command,
                    seed_dir=seed_dir,
                    crash_dir=crash_root / "libafl",
                    timeout_seconds=timeout,
                    status=statuses,
                    env=environment,
                )
            )

    crash_files = []
    for worker_result in worker_results:
        for path in _collect_files(Path(worker_result.get("crash_dir") or ""), max_files=MAX_COLLECTED_FILES):
            crash_files.append({"worker": worker_result["worker"], **path})
    blockers = [
        f"{result['worker']}: {blocker}"
        for result in worker_results
        for blocker in result.get("blockers", [])
    ]
    executed = sum(1 for result in worker_results if result.get("executed"))
    return {
        "ok": executed > 0 and not blockers,
        "mode": "real-fuzz-ensemble",
        "target": target,
        "harness": harness,
        "work_dir": str(work),
        "seed_dir": str(seed_dir),
        "seed_count": len(seeds),
        "workers_requested": selected,
        "workers_executed": executed,
        "worker_results": worker_results,
        "crash_files": crash_files,
        "blockers": blockers,
    }


def run_symbolic_worker(
    *,
    work_dir: str | Path,
    mode: str,
    command: list[str] | str | None = None,
    constraints_smt2_b64: str | None = None,
    output_dir: str | Path | None = None,
    klee_config: str | None = None,
    workspace_root: str | Path | None = None,
    timeout_seconds: int | float = 60,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    timeout = _bounded_runtime_timeout(timeout_seconds)
    selected_mode = mode.lower().strip()
    if selected_mode not in {"symcc", "symqemu", "z3", "klee"}:
        raise ValueError("mode must be one of symcc, symqemu, z3, klee")

    work = Path(work_dir).expanduser().resolve()
    out = Path(output_dir).expanduser().resolve() if output_dir else work / selected_mode / "outputs"
    work.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    status = runtime_backend_status(env=environment)["groups"]["symbolic_stack"]["checks"]

    if selected_mode == "z3":
        result = _run_z3_solver(constraints_smt2_b64=constraints_smt2_b64, status=status, timeout_seconds=timeout)
    elif selected_mode == "symcc":
        result = _run_symcc(command=command, work=work, output_dir=out, timeout_seconds=timeout, status=status, env=environment)
    elif selected_mode == "klee":
        result = _run_klee_ng(
            klee_config=klee_config,
            command=command,
            output_dir=out,
            timeout_seconds=timeout,
            status=status,
            env=environment,
            workspace_root=workspace_root,
        )
    else:
        result = _run_symqemu(command=command, work=work, output_dir=out, timeout_seconds=timeout, status=status, env=environment)

    output_files = _collect_files(out, max_files=MAX_COLLECTED_FILES)
    blockers = result.get("blockers", [])
    return {
        "ok": bool(result.get("ok")) and not blockers,
        "mode": f"real-symbolic-{selected_mode}",
        "worker": selected_mode,
        "work_dir": str(work),
        "output_dir": str(out),
        "result": result,
        "output_files": output_files,
        "blockers": blockers,
    }


def run_sarif_reachability(
    *,
    work_dir: str | Path,
    source_dir: str | Path,
    sarif_file: str | Path,
    language: str = "c-cpp",
    database_dir: str | Path | None = None,
    create_database: bool = False,
    codeql_query_suite: str | None = None,
    joern_command: list[str] | str | None = None,
    sootup_command: list[str] | str | None = None,
    run_codeql: bool = True,
    run_joern: bool = True,
    run_sootup: bool = True,
    timeout_seconds: int | float = 300,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    timeout = _bounded_runtime_timeout(timeout_seconds)
    work = Path(work_dir).expanduser().resolve()
    source = Path(source_dir).expanduser().resolve()
    sarif = Path(sarif_file).expanduser().resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"source_dir is not a directory: {source_dir}")
    if not sarif.is_file():
        raise FileNotFoundError(f"sarif_file is not a file: {sarif_file}")
    work.mkdir(parents=True, exist_ok=True)

    summary = _summarize_sarif(sarif, source)
    status = runtime_backend_status(env=environment)["groups"]["sarif_reachability"]["checks"]
    stages = []
    blockers = []

    if run_codeql:
        codeql_stage = _run_codeql(
            work=work,
            source=source,
            language=language,
            database_dir=Path(database_dir).expanduser().resolve() if database_dir else work / "codeql-db",
            create_database=create_database,
            query_suite=codeql_query_suite,
            timeout_seconds=timeout,
            status=status,
            env=environment,
        )
        stages.append(codeql_stage)
        blockers.extend(f"codeql: {blocker}" for blocker in codeql_stage.get("blockers", []))

    if run_joern:
        joern_stage = _run_optional_analyzer(
            name="joern",
            command=joern_command,
            work=work,
            timeout_seconds=timeout,
            status=status["joern"],
            env=environment,
            placeholders={"source_dir": str(source), "sarif_file": str(sarif), "work_dir": str(work)},
        )
        stages.append(joern_stage)
        blockers.extend(f"joern: {blocker}" for blocker in joern_stage.get("blockers", []))

    if run_sootup:
        sootup_stage = _run_optional_analyzer(
            name="sootup",
            command=sootup_command,
            work=work,
            timeout_seconds=timeout,
            status=status["java"],
            env=environment,
            placeholders={"source_dir": str(source), "sarif_file": str(sarif), "work_dir": str(work)},
            extra_blocker=None if (sootup_command not in (None, "", []) or status["sootup"]["ok"]) else "missing SOOTUP_JAR or explicit SootUp command",
        )
        stages.append(sootup_stage)
        blockers.extend(f"sootup: {blocker}" for blocker in sootup_stage.get("blockers", []))

    completed = [stage for stage in stages if stage.get("executed") and stage.get("run", {}).get("exit_code") == 0]
    verdict = "analyzed" if completed else "blocked" if blockers else "unknown"
    outputs = _collect_files(work, max_files=MAX_COLLECTED_FILES)
    return {
        "ok": bool(completed) and not blockers,
        "mode": "real-sarif-reachability",
        "source_dir": str(source),
        "sarif_file": str(sarif),
        "language": language,
        "input_sarif": summary,
        "stages": stages,
        "verdict": verdict,
        "output_files": outputs,
        "blockers": blockers,
    }


def prepare_patch_environment(
    *,
    source_dir: str | Path,
    pool_root: str | Path,
    env_name: str = "patch-env",
    patch_name: str | None = None,
    patch_content_b64: str | None = None,
    build_command: list[str] | str | None = None,
    test_command: list[str] | str | None = None,
    timeout_seconds: int | float = 300,
    env: Mapping[str, str] | None = None,
    declared_env: Mapping[str, str] | None = None,
    build_env: Mapping[str, str] | None = None,
    test_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    # These are caller declarations, not ambient environment. Validate them
    # before creating/copying an environment so a no-op call cannot bypass the
    # control policy.
    common_declared_env = validate_declared_env(declared_env)
    validated_build_env = validate_declared_env(build_env)
    validated_test_env = validate_declared_env(test_env)
    environment = dict(os.environ if env is None else env)
    timeout = _bounded_runtime_timeout(timeout_seconds)
    source = Path(source_dir).expanduser().resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"source_dir is not a directory: {source_dir}")
    pool = Path(pool_root).expanduser().resolve()
    cache_root = pool / "cache"
    env_root = pool / "envs"
    cache_root.mkdir(parents=True, exist_ok=True)
    env_root.mkdir(parents=True, exist_ok=True)

    source_fingerprint = _source_fingerprint(source)
    patch_bytes = base64.b64decode(patch_content_b64.encode("ascii")) if patch_content_b64 else b""
    patch_sha = sha256(patch_bytes).hexdigest() if patch_bytes else None
    cache_key = source_fingerprint["sha256"]
    cache_dir = cache_root / cache_key
    cache_hit = cache_dir.is_dir()
    if not cache_hit:
        _copy_source_tree(source, cache_dir)
        _write_json(cache_dir / ".agentic-fuzz-cache.json", {"source": source_fingerprint})

    safe_env_name = _safe_name(f"{env_name}-{cache_key[:12]}-{patch_sha[:12] if patch_sha else 'nopatch'}")
    env_dir = env_root / safe_env_name
    if env_dir.exists():
        shutil.rmtree(env_dir)
    shutil.copytree(cache_dir, env_dir, symlinks=True)

    blockers = []
    commands = []
    patch_record = None
    if patch_bytes:
        git_check = _binary_check("git", environment)
        if not git_check["ok"]:
            blockers.append("missing git for patch application")
        else:
            patch_text = patch_bytes.decode("utf-8", errors="replace")
            changed_paths = validate_unified_diff(patch_text)
            patch_path = env_dir / _safe_name(patch_name or "candidate.patch")
            patch_path.write_bytes(patch_bytes)
            apply_check = _run_command(["git", "apply", "--check", str(patch_path)], cwd=env_dir, timeout_seconds=timeout, env=environment, declared_env=common_declared_env or None)
            commands.append({"stage": "apply-check", **apply_check})
            if apply_check["exit_code"] != 0:
                blockers.append(f"patch apply check failed (exit {apply_check['exit_code']})")
            else:
                apply_run = _run_command(["git", "apply", str(patch_path)], cwd=env_dir, timeout_seconds=timeout, env=environment, declared_env=common_declared_env or None)
                commands.append({"stage": "apply", **apply_run})
                if apply_run["exit_code"] != 0:
                    blockers.append(f"patch application failed (exit {apply_run['exit_code']})")
            patch_record = {
                "patch_name": patch_name or patch_path.name,
                "patch_sha256": patch_sha,
                "patch_path": str(patch_path),
                "changed_paths": changed_paths,
            }

    for stage, command, stage_env in (("build", build_command, validated_build_env), ("test", test_command, validated_test_env)):
        if command is None:
            continue
        effective_env = {**common_declared_env, **stage_env}
        run = _run_command(
            _replace_placeholders(_runtime_command(command), {"src": str(env_dir), "env_dir": str(env_dir)}),
            cwd=env_dir,
            timeout_seconds=timeout,
            env=environment,
            declared_env=effective_env or None,
        )
        commands.append({"stage": stage, **run})
        if run["exit_code"] != 0:
            blockers.append(f"{stage} command failed (exit {run['exit_code']})")

    manifest = {
        "mode": "real-cached-patch-environment",
        "source": source_fingerprint,
        "cache_hit": cache_hit,
        "cache_dir": str(cache_dir),
        "env_dir": str(env_dir),
        "patch": patch_record,
        "commands": [{"stage": command["stage"], "exit_code": command["exit_code"]} for command in commands],
        "blockers": blockers,
    }
    manifest_path = env_dir / ".agentic-fuzz-env.json"
    _write_json(manifest_path, manifest)
    return {
        "ok": not blockers,
        **manifest,
        "manifest_path": str(manifest_path),
        "commands": commands,
    }


def _run_libfuzzer(
    *,
    command: list[str] | str | None,
    seed_dir: Path,
    crash_dir: Path,
    run_count: int,
    timeout_seconds: float,
    status: dict[str, Any],
    env: Mapping[str, str],
) -> dict[str, Any]:
    crash_dir.mkdir(parents=True, exist_ok=True)
    if not status["clang"]["ok"]:
        return _blocked_worker("libfuzzer", crash_dir, "missing clang/libFuzzer toolchain")
    if command in (None, "", []):
        return _blocked_worker("libfuzzer", crash_dir, "missing libFuzzer harness command")
    argv = _runtime_command(command)
    if any("{poc}" in arg for arg in argv):
        return _blocked_worker("libfuzzer", crash_dir, "libFuzzer command must use corpus placeholders, not {poc}")
    materialized = _replace_placeholders(
        argv,
        {"seed_corpus": str(seed_dir), "corpus": str(seed_dir), "crash_dir": str(crash_dir), "artifact_prefix": str(crash_dir) + os.sep},
    )
    if not any(str(seed_dir) == arg for arg in materialized):
        materialized.append(str(seed_dir))
    if not any(arg.startswith("-runs=") for arg in materialized):
        materialized.append(f"-runs={run_count}")
    if not any(arg.startswith("-artifact_prefix=") for arg in materialized):
        materialized.append(f"-artifact_prefix={crash_dir}{os.sep}")
    run = _run_command(
        materialized,
        cwd=crash_dir.parent,
        timeout_seconds=timeout_seconds,
        env=env,
        raw_output_parser=parse_libfuzzer_stats,
    )
    return {"worker": "libfuzzer", "executed": True, "crash_dir": str(crash_dir), "run": run, "blockers": [] if not run["timed_out"] else ["timeout"]}


def _run_afl(
    *,
    command: list[str] | str | None,
    seed_dir: Path,
    crash_dir: Path,
    timeout_seconds: float,
    status: dict[str, Any],
    env: Mapping[str, str],
) -> dict[str, Any]:
    crash_dir.mkdir(parents=True, exist_ok=True)
    if not status["afl-fuzz"]["ok"]:
        return _blocked_worker("afl", crash_dir, "missing afl-fuzz")
    if command in (None, "", []):
        return _blocked_worker("afl", crash_dir, "missing AFL++ harness command")
    harness_argv = _runtime_command(command)
    harness_argv = _replace_placeholders(harness_argv, {"poc": "@@", "seed_corpus": str(seed_dir), "crash_dir": str(crash_dir)})
    if not any("@@" in arg for arg in harness_argv):
        harness_argv.append("@@")
    afl_env = dict(env)
    afl_env.setdefault("AFL_NO_UI", "1")
    afl_env.setdefault("AFL_SKIP_CPUFREQ", "1")
    afl_env.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
    afl_env.setdefault("AFL_AUTORESUME", "1")
    afl_timeout = max(1, int(timeout_seconds))
    argv = [
        status["afl-fuzz"]["path"] or "afl-fuzz",
        "-V",
        str(afl_timeout),
        "-i",
        str(seed_dir),
        "-o",
        str(crash_dir),
        "--",
        *harness_argv,
    ]
    run = _run_command(argv, cwd=crash_dir.parent, timeout_seconds=timeout_seconds + 15, env=env, declared_env={name: value for name, value in afl_env.items() if name.startswith("AFL_")})
    return {"worker": "afl", "executed": True, "crash_dir": str(crash_dir), "run": run, "blockers": [] if not run["timed_out"] else ["timeout"]}


def _run_libafl(
    *,
    command: list[str] | str | None,
    seed_dir: Path,
    crash_dir: Path,
    timeout_seconds: float,
    status: dict[str, Any],
    env: Mapping[str, str],
) -> dict[str, Any]:
    crash_dir.mkdir(parents=True, exist_ok=True)
    if not status["cargo"]["ok"]:
        return _blocked_worker("libafl", crash_dir, "missing cargo/LibAFL Rust toolchain")
    if command in (None, "", []):
        return _blocked_worker("libafl", crash_dir, "missing explicit LibAFL runner command")
    argv = _replace_placeholders(
        _runtime_command(command),
        {"seed_corpus": str(seed_dir), "corpus": str(seed_dir), "crash_dir": str(crash_dir), "work_dir": str(crash_dir.parent)},
    )
    run = _run_command(argv, cwd=crash_dir.parent, timeout_seconds=timeout_seconds, env=env)
    return {"worker": "libafl", "executed": True, "crash_dir": str(crash_dir), "run": run, "blockers": [] if not run["timed_out"] else ["timeout"]}


MAX_KLEE_EXTRACTED_TESTS = 2000
MAX_KLEE_TEST_JSON_BYTES = 4 * 1024 * 1024
MAX_KLEE_TOTAL_TEST_JSON_BYTES = 32 * 1024 * 1024
MAX_KLEE_SEED_BYTES = 1 * 1024 * 1024
MAX_KLEE_TOTAL_SEED_BYTES = 16 * 1024 * 1024
MAX_KLEE_ERROR_REPORT_BYTES = 1 * 1024 * 1024
MAX_KLEE_TOTAL_ERROR_REPORT_BYTES = 8 * 1024 * 1024
MIN_FREE_DISK_GB = 10.0
DEFAULT_KLEE_MEMORY_GB = 16
DEFAULT_KLEE_PIDS_LIMIT = 1024
DEFAULT_KLEE_CPUS = 8
MAX_KLEE_MEMORY_GB = 64
MAX_KLEE_PIDS_LIMIT = 4096
MAX_KLEE_CPUS = 32


def check_disk_headroom(path: str | Path, *, min_free_gb: float = MIN_FREE_DISK_GB) -> dict[str, Any]:
    """Refuse to start disk-hungry work when the volume is nearly full.

    A fuzz/symbolic campaign that fills the volume takes down every other
    consumer of it (build caches, container state), so this is a hard guard,
    not a warning.
    """
    target = Path(path).expanduser()
    probe = target if target.exists() else target.parent
    usage = shutil.disk_usage(probe)
    free_gb = usage.free / 1_073_741_824
    ok = free_gb >= min_free_gb
    return {
        "ok": ok,
        "path": str(probe),
        "free_gb": round(free_gb, 2),
        "min_free_gb": min_free_gb,
        "blocker": None if ok else f"only {free_gb:.1f} GiB free on {probe} (need >= {min_free_gb:g} GiB); free space before fuzzing",
    }


def _klee_image_check(environment: Mapping[str, str]) -> dict[str, Any]:
    image = environment.get(KLEE_IMAGE_ENV)
    if not image:
        return {"ok": False, "path": None, "detail": f"set {KLEE_IMAGE_ENV} to an immutable sha256 image digest"}
    docker = shutil.which("docker", path=environment.get("PATH"))
    if not docker:
        return {"ok": False, "path": None, "detail": f"docker not on PATH (image {image})"}
    try:
        proc = bounded_run([docker, "image", "inspect", image, "--format", "{{.Id}}"], env=docker_client_env(environment), timeout_seconds=15)
    except OSError as exc:
        return {"ok": False, "path": None, "detail": f"docker image inspect failed: {exc}"}
    if proc.exit_code != 0:
        return {"ok": False, "path": None, "detail": f"image not present: {image}"}
    if not _is_immutable_image(image):
        return {"ok": False, "path": None, "detail": f"image must be pinned by a sha256 digest: {image}"}
    return {"ok": True, "path": image, "detail": None}


def _run_klee_ng(
    *,
    klee_config: str | None,
    command: list[str] | str | None,
    output_dir: Path,
    timeout_seconds: float,
    status: dict[str, Any],
    env: Mapping[str, str],
    workspace_root: str | Path | None,
) -> dict[str, Any]:
    if not klee_config:
        return {"ok": False, "executed": False, "blockers": ["missing klee_config (ci JSON under the workspace klee dir)"]}
    try:
        workspace = load_workspace(workspace_root, env=env)
    except FileNotFoundError as exc:
        return {"ok": False, "executed": False, "blockers": [str(exc)]}

    root = Path(workspace["root"])
    klee_dir = (root / "klee").resolve()
    if not klee_dir.is_dir():
        return {"ok": False, "executed": False, "blockers": [f"workspace klee dir missing: {klee_dir}"]}

    config_path = Path(klee_config)
    config_path = (config_path if config_path.is_absolute() else klee_dir / config_path).resolve()
    if not config_path.is_file():
        return {"ok": False, "executed": False, "blockers": [f"klee ci config not found: {config_path}"]}
    try:
        config_rel = config_path.relative_to(klee_dir)
    except ValueError:
        return {"ok": False, "executed": False, "blockers": [f"klee ci config must live under {klee_dir}"]}

    if not status["klee_ng"]["ok"]:
        return {"ok": False, "executed": False, "blockers": [f"missing klee-ng backend: {status['klee_ng'].get('detail')}"]}

    headroom = check_disk_headroom(klee_dir)
    if not headroom["ok"]:
        return {"ok": False, "executed": False, "disk": headroom, "blockers": [headroom["blocker"]]}

    image = str(status["klee_ng"]["path"] or "")
    if not _is_immutable_image(image):
        return {"ok": False, "executed": False, "blockers": [f"klee image must be pinned by digest: {image}"]}
    docker_config = workspace.get("docker") or {}
    memory_gb = min(MAX_KLEE_MEMORY_GB, max(1, int(docker_config.get("klee_memory_gb") or DEFAULT_KLEE_MEMORY_GB)))
    pids_limit = min(MAX_KLEE_PIDS_LIMIT, max(16, int(docker_config.get("klee_pids_limit") or DEFAULT_KLEE_PIDS_LIMIT)))
    cpus = min(MAX_KLEE_CPUS, max(1, int(docker_config.get("klee_cpus") or DEFAULT_KLEE_CPUS)))
    mount_args = ["-v", f"{translate_host_path(klee_dir, workspace)}:/work"]
    scripts_dir = klee_dir / "scripts"
    if scripts_dir.is_dir():
        mount_args += ["-v", f"{translate_host_path(scripts_dir, workspace)}:/opt/klee-ng/src/scripts:ro"]
    source_dir = workspace.get("source_dir")
    if source_dir:
        mount_args += ["-v", f"{translate_host_path(source_dir, workspace)}:{source_dir}:ro"]
    for mount in workspace.get("extra_mounts", []):
        host = mount.get("host")
        container = mount.get("container")
        if not host or not container:
            continue
        mode = "ro" if str(mount.get("mode", "rw")) == "ro" else "rw"
        mount_args += ["-v", f"{translate_host_path(host, workspace)}:{container}:{mode}"]

    container_name = f"agentic-fuzz-klee-{os.getpid()}-{int(monotonic() * 1_000_000)}"
    argv = [
        "docker", "run", "--name", container_name,
        f"--memory={memory_gb}g",
        f"--memory-swap={memory_gb}g",
        f"--pids-limit={pids_limit}",
        f"--cpus={cpus}",
        "--network=none",
        *mount_args,
        image,
        "/opt/klee-ng/src/scripts/klee-ng-ci",
        f"/work/{config_rel}",
        *(_runtime_command(command) if command else []),
    ]
    wall_started = wall_time()
    cleanup = None
    try:
        run = _run_command(argv, cwd=klee_dir, timeout_seconds=timeout_seconds, env=env)
    finally:
        # Force removal owns the lifecycle after a client timeout or daemon
        # error. A unique name avoids touching another run.
        cleanup = bounded_run(["docker", "rm", "-f", container_name], env=docker_client_env(env), timeout_seconds=30)

    extraction = _extract_klee_tests(klee_dir / "klee-ng-out", output_dir, newer_than=wall_started - 5.0)
    run_ok = run["exit_code"] == 0 and not run["timed_out"]
    if run_ok:
        blockers: list[str] = []
    else:
        detail = (str(run.get("stderr") or run.get("stdout") or "").strip().splitlines()[-1:] or ["no diagnostic output"])[0]
        state = "timed out" if run["timed_out"] else f"failed (exit {run['exit_code']})"
        blockers = [f"klee-ng ci {state}: {detail[:500]}"]
    if cleanup is not None and cleanup.exit_code != 0:
        context = (cleanup.stderr or cleanup.stdout).strip().splitlines()[-1:] or ["no diagnostic output"]
        blockers.append(f"klee container cleanup failed (exit {cleanup.exit_code}): {context[0][:500]}")
    return {
        "ok": not blockers,
        "executed": True,
        "image": image,
        "config": str(config_rel),
        "container": container_name,
        "limits": {"memory_gb": memory_gb, "pids_limit": pids_limit, "cpus": cpus, "network": "none"},
        "disk": headroom,
        "run": run,
        "cleanup": {"exit_code": cleanup.exit_code, "timed_out": cleanup.timed_out, "stdout": _clip(cleanup.stdout), "stderr": _clip(cleanup.stderr)} if cleanup is not None else None,
        "extraction": extraction,
        "blockers": blockers,
    }


def _extract_klee_tests(out_root: Path, output_dir: Path, *, newer_than: float | None = None) -> dict[str, Any]:
    """Convert klee-ng JSON test files into raw seed bytes + error reports.

    Seeds land in ``output_dir/seeds`` (one file per symbolic input) so the
    corpus-import path picks them up; failing tests are copied verbatim into
    ``output_dir/errors`` for crash intake.
    """
    seeds_dir = output_dir / "seeds"
    errors_dir = output_dir / "errors"
    if not _ensure_nofollow_directory(seeds_dir) or not _ensure_nofollow_directory(errors_dir):
        return {
            "scanned": 0,
            "seeds_written": 0,
            "errors_written": 0,
            "out_root": str(out_root),
            "rejected_tests": 0,
            "rejected_inputs": 0,
            "rejected_errors": 0,
            "blockers": ["KLEE extraction output directory is not a regular directory"],
        }
    root_fd = _open_nofollow_directory(out_root)
    seed_fd = _open_nofollow_directory(seeds_dir)
    error_fd = _open_nofollow_directory(errors_dir)
    if root_fd is None or seed_fd is None or error_fd is None:
        for descriptor in (root_fd, seed_fd, error_fd):
            if descriptor is not None:
                os.close(descriptor)
        return {
            "scanned": 0, "seeds_written": 0, "errors_written": 0,
            "out_root": str(out_root), "rejected_tests": 0,
            "rejected_inputs": 0, "rejected_errors": 0,
            "blockers": ["KLEE extraction directory changed or is a symlink"],
        }
    seeds = 0
    errors = 0
    scanned = 0
    seed_bytes = 0
    error_bytes = 0
    rejected_inputs = 0
    rejected_tests = 0
    rejected_errors = 0
    test_json_bytes = 0
    test_json_bytes_read = 0
    candidates: list[Path] = []
    try:
        for candidate in out_root.glob("*/*/test*.json"):
            if len(candidates) >= MAX_KLEE_EXTRACTED_TESTS:
                break
            candidates.append(candidate)
        for test_path in sorted(candidates):
            # Physical reads, including discarded race/malformed candidates,
            # own this budget. Accepted JSON size is reporting only.
            remaining_test_bytes = MAX_KLEE_TOTAL_TEST_JSON_BYTES - test_json_bytes_read
            if remaining_test_bytes <= 0:
                break
            scanned += 1
            try:
                rel_parts = test_path.relative_to(out_root).parts
            except ValueError:
                rejected_tests += 1
                continue
            loaded, bytes_read = _read_nofollow_bounded_at_with_count(
                root_fd,
                rel_parts,
                min(MAX_KLEE_TEST_JSON_BYTES, remaining_test_bytes),
            )
            test_json_bytes_read += bytes_read
            if loaded is None:
                rejected_tests += 1
                continue
            raw_test, test_stat = loaded
            test_json_bytes += len(raw_test)
            if newer_than is not None and test_stat.st_mtime < newer_than:
                continue
            test_size = len(raw_test)
            try:
                payload = json.loads(raw_test.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                rejected_tests += 1
                continue
            if not isinstance(payload, dict) or "inputs" not in payload or not isinstance(payload["inputs"], list):
                rejected_tests += 1
                continue
            inputs = payload["inputs"]
            source_tag = sha256("/".join(rel_parts).encode("utf-8", errors="replace")).hexdigest()[:12]
            label = _safe_klee_name(f"{test_path.parent.parent.name}-{test_path.parent.name}-{test_path.stem}")
            for index, input_obj in enumerate(inputs):
                if not isinstance(input_obj, dict):
                    rejected_inputs += 1
                    continue
                data = input_obj.get("data")
                if not isinstance(data, list):
                    rejected_inputs += 1
                    continue
                if any(not isinstance(item, int) or isinstance(item, bool) or item < 0 or item > 255 for item in data):
                    rejected_inputs += 1
                    continue
                blob = bytes(data)
                if type(input_obj.get("size")) is not int or input_obj["size"] != len(blob):
                    rejected_inputs += 1
                    continue
                if len(blob) > MAX_KLEE_SEED_BYTES or seed_bytes + len(blob) > MAX_KLEE_TOTAL_SEED_BYTES:
                    rejected_inputs += 1
                    continue
                output_name = f"{label}-{_safe_klee_name(str(input_obj.get('name', 'input')))}-{index}-{source_tag}-{sha256(blob).hexdigest()[:12]}.bin"
                if not _write_nofollow_at(seed_fd, output_name, blob):
                    rejected_inputs += 1
                    continue
                seeds += 1
                seed_bytes += len(blob)
            if payload.get("error"):
                if test_size <= MAX_KLEE_ERROR_REPORT_BYTES and error_bytes + test_size <= MAX_KLEE_TOTAL_ERROR_REPORT_BYTES:
                    if _write_nofollow_at(error_fd, f"{label}-{source_tag}-{sha256(raw_test).hexdigest()[:12]}.json", raw_test):
                        errors += 1
                        error_bytes += test_size
                    else:
                        rejected_errors += 1
                else:
                    rejected_errors += 1
        return {
            "scanned": scanned,
            "seeds_written": seeds,
            "errors_written": errors,
            "seeds_dir": str(seeds_dir),
            "errors_dir": str(errors_dir),
            "out_root": str(out_root),
            "test_json_bytes": test_json_bytes,
            "test_json_bytes_read": test_json_bytes_read,
            "seed_bytes": seed_bytes,
            "error_report_bytes": error_bytes,
            "rejected_tests": rejected_tests,
            "rejected_inputs": rejected_inputs,
            "rejected_errors": rejected_errors,
        }
    finally:
        os.close(root_fd)
        os.close(seed_fd)
        os.close(error_fd)


def _safe_klee_name(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "_" for char in value)
    cleaned = cleaned.lstrip(".")
    return cleaned[:120] or "input"


def _ensure_nofollow_directory(path: Path) -> bool:
    # ``output_dir`` is managed output, not an input escape hatch. Check the
    # managed parent and the requested child with lstat; do not reject an OS
    # supplied ancestor such as macOS's /private -> /var compatibility link.
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        parent = path.parent.lstat()
        if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
            return False
        path.mkdir(parents=True, exist_ok=True)
        current = path.lstat()
        return not stat.S_ISLNK(current.st_mode) and stat.S_ISDIR(current.st_mode)
    except OSError:
        return False


def _open_nofollow_directory(path: Path) -> int | None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        current = os.fstat(descriptor)
        if not stat.S_ISDIR(current.st_mode):
            os.close(descriptor)
            return None
        return descriptor
    except OSError:
        os.close(descriptor)
        return None


def _read_nofollow_bounded(path: Path, limit: int) -> tuple[bytes, os.stat_result] | None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        return _read_open_file_bounded(descriptor, limit)
    except OSError:
        return None
    finally:
        os.close(descriptor)


def _read_nofollow_bounded_at(root_fd: int, parts: tuple[str, ...], limit: int) -> tuple[bytes, os.stat_result] | None:
    """Read a held path without exposing physical-read accounting to callers."""
    loaded, _bytes_read = _read_nofollow_bounded_at_with_count(root_fd, parts, limit)
    return loaded


def _read_nofollow_bounded_at_with_count(
    root_fd: int, parts: tuple[str, ...], limit: int,
) -> tuple[tuple[bytes, os.stat_result] | None, int]:
    """Read a no-follow path and return bytes physically read even on reject."""
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return None, 0
    directory_fd = os.dup(root_fd)
    file_fd: int | None = None
    bytes_read = 0
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        for part in parts[:-1]:
            next_fd = os.open(part, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
            if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
                return None, bytes_read
        file_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        file_fd = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        loaded, bytes_read = _read_open_file_bounded_with_count(file_fd, limit)
        if loaded is None:
            return None, bytes_read
        _data, held_stat = loaded
        verify_fd = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        try:
            current = os.fstat(verify_fd)
            if (current.st_dev, current.st_ino, current.st_size) != (held_stat.st_dev, held_stat.st_ino, held_stat.st_size):
                return None, bytes_read
        finally:
            os.close(verify_fd)
        return loaded, bytes_read
    except OSError:
        return None, bytes_read
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)


def _read_open_file_bounded(descriptor: int, limit: int) -> tuple[bytes, os.stat_result] | None:
    loaded, _bytes_read = _read_open_file_bounded_with_count(descriptor, limit)
    return loaded


def _read_open_file_bounded_with_count(
    descriptor: int, limit: int,
) -> tuple[tuple[bytes, os.stat_result] | None, int]:
    bytes_read = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            return None, bytes_read
        expected_size = before.st_size
        pieces: list[bytes] = []
        # Do not reserve an extra sentinel byte: callers may pass the
        # remaining aggregate budget, so an expected-size-plus-one read would
        # physically consume bytes beyond that budget during a growth race.
        # The before/after identity and metadata checks below detect growth or
        # same-size replacement without issuing an over-budget read.
        remaining = expected_size
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            bytes_read += len(chunk)
            if not chunk:
                break
            pieces.append(chunk)
            remaining -= len(chunk)
        data = b"".join(pieces)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            getattr(before, "st_mtime_ns", int(before.st_mtime * 1_000_000_000)),
            getattr(before, "st_ctime_ns", int(before.st_ctime * 1_000_000_000)),
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            getattr(after, "st_mtime_ns", int(after.st_mtime * 1_000_000_000)),
            getattr(after, "st_ctime_ns", int(after.st_ctime * 1_000_000_000)),
        )
        if (not stat.S_ISREG(after.st_mode)
                or after_identity != before_identity
                or len(data) != expected_size):
            return None, bytes_read
        return (data, after), bytes_read
    except OSError:
        return None, bytes_read


def _write_nofollow_at(directory_fd: int, name: str, data: bytes) -> bool:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except OSError:
        return False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return True
    except OSError:
        try:
            os.unlink(name, dir_fd=directory_fd)
        except OSError:
            pass
        return False


def _run_z3_solver(*, constraints_smt2_b64: str | None, status: dict[str, Any], timeout_seconds: float = 10.0) -> dict[str, Any]:
    if not status["z3"]["ok"]:
        return {"ok": False, "executed": False, "blockers": ["missing z3 Python bindings"]}
    if not constraints_smt2_b64:
        return {"ok": False, "executed": False, "blockers": ["missing SMT-LIB constraints"]}
    if len(constraints_smt2_b64) > MAX_Z3_ENCODED_BYTES:
        return {"ok": False, "executed": False, "blockers": [f"encoded SMT-LIB constraints exceed {MAX_Z3_ENCODED_BYTES} byte cap"]}
    try:
        raw = base64.b64decode(constraints_smt2_b64.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        return {"ok": False, "executed": False, "blockers": [f"invalid SMT-LIB base64: {exc}"]}
    if len(raw) > MAX_Z3_CONSTRAINT_BYTES:
        return {"ok": False, "executed": False, "blockers": [f"SMT-LIB constraints exceed {MAX_Z3_CONSTRAINT_BYTES} byte cap"]}
    wall_timeout = min(MAX_Z3_TIMEOUT_SECONDS, max(0.001, float(timeout_seconds)))
    bootstrap = (
        "import base64,json,sys,z3; s=z3.Solver(); s.set(timeout=int(sys.argv[2])); "
        "s.from_string(base64.b64decode(sys.argv[1]).decode('utf-8')); r=s.check(); "
        "print(json.dumps({'check':str(r),'model':str(s.model()) if r==z3.sat else None}))"
    )
    run = bounded_run([sys.executable, "-c", bootstrap, constraints_smt2_b64, str(max(1, int(wall_timeout * 1000)))], env=sanitized_env(), timeout_seconds=wall_timeout)
    if run.timed_out:
        return {"ok": False, "executed": True, "solver": "z3", "check": "unknown", "reason": "wall-time timeout", "elapsed_ms": run.elapsed_ms, "blockers": ["z3 solver timed out"]}
    if run.exit_code != 0:
        return {"ok": False, "executed": True, "solver": "z3", "check": "unknown", "reason": run.stderr[-500:] or "solver failed", "elapsed_ms": run.elapsed_ms, "blockers": ["z3 solver failed"]}
    try:
        payload = json.loads(run.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return {"ok": False, "executed": True, "solver": "z3", "check": "unknown", "reason": "solver returned no parseable result", "elapsed_ms": run.elapsed_ms, "blockers": ["z3 solver returned invalid output"]}
    check = str(payload.get("check", "unknown"))
    return {
        "ok": check in {"sat", "unsat"},
        "executed": True,
        "solver": "z3",
        "check": check,
        "model": payload.get("model"),
        "reason": None if check in {"sat", "unsat"} else "solver returned unknown",
        "elapsed_ms": run.elapsed_ms,
        "blockers": [] if check in {"sat", "unsat"} else ["z3 solver returned unknown"],
    }


def _run_symcc(
    *,
    command: list[str] | str | None,
    work: Path,
    output_dir: Path,
    timeout_seconds: float,
    status: dict[str, Any],
    env: Mapping[str, str],
) -> dict[str, Any]:
    if not status["symcc"]["ok"]:
        return {"ok": False, "executed": False, "blockers": ["missing symcc"]}
    if command in (None, "", []):
        return {"ok": False, "executed": False, "blockers": ["missing SymCC command"]}
    if status.get("docker_wrapper") and not _is_immutable_image(str(status.get("image") or "")):
        return {"ok": False, "executed": False, "blockers": ["SymCC wrapper image must be pinned by digest"]}
    sym_env = {"SYMCC_OUTPUT_DIR": str(output_dir)}
    argv = _replace_placeholders(_runtime_command(command), {"output_dir": str(output_dir), "work_dir": str(work), "symcc": status["symcc"]["path"] or "symcc"})
    run = _run_command(argv, cwd=work, timeout_seconds=timeout_seconds, env=env, declared_env={"SYMCC_OUTPUT_DIR": sym_env["SYMCC_OUTPUT_DIR"]})
    return {"ok": run["exit_code"] == 0, "executed": True, "run": run, "blockers": [] if run["exit_code"] == 0 else ["SymCC command failed"]}


def _run_symqemu(
    *,
    command: list[str] | str | None,
    work: Path,
    output_dir: Path,
    timeout_seconds: float,
    status: dict[str, Any],
    env: Mapping[str, str],
) -> dict[str, Any]:
    if not status["symqemu"]["ok"]:
        return {"ok": False, "executed": False, "blockers": ["missing symqemu"]}
    if command in (None, "", []):
        return {"ok": False, "executed": False, "blockers": ["missing SymQEMU command"]}
    if status.get("docker_wrapper") and not _is_immutable_image(str(status.get("image") or "")):
        return {"ok": False, "executed": False, "blockers": ["SymQEMU wrapper image must be pinned by digest"]}
    symqemu = status["symqemu"]["path"] or "symqemu"
    argv = _replace_placeholders(_runtime_command(command), {"output_dir": str(output_dir), "work_dir": str(work), "symqemu": symqemu})
    if Path(argv[0]).name not in {"symqemu", "symqemu-x86_64"}:
        argv = [symqemu, *argv]
    sym_env = {"SYMCC_OUTPUT_DIR": str(output_dir)}
    run = _run_command(argv, cwd=work, timeout_seconds=timeout_seconds, env=env, declared_env={"SYMCC_OUTPUT_DIR": sym_env["SYMCC_OUTPUT_DIR"]})
    return {"ok": run["exit_code"] == 0, "executed": True, "run": run, "blockers": [] if run["exit_code"] == 0 else ["SymQEMU command failed"]}


def _run_codeql(
    *,
    work: Path,
    source: Path,
    language: str,
    database_dir: Path,
    create_database: bool,
    query_suite: str | None,
    timeout_seconds: float,
    status: dict[str, Any],
    env: Mapping[str, str],
) -> dict[str, Any]:
    if not status["codeql"]["ok"]:
        return {"analyzer": "codeql", "executed": False, "blockers": ["missing codeql"]}
    codeql = status["codeql"]["path"] or "codeql"
    runs = []
    blockers = []
    db_exists = database_dir.exists()
    if create_database and not db_exists:
        database_dir.parent.mkdir(parents=True, exist_ok=True)
        create = _run_command(
            [
                codeql,
                "database",
                "create",
                str(database_dir),
                f"--language={_codeql_language(language)}",
                f"--source-root={source}",
                "--overwrite",
            ],
            cwd=work,
            timeout_seconds=timeout_seconds,
            env=env,
        )
        runs.append({"stage": "database-create", **create})
        db_exists = create["exit_code"] == 0
        if not db_exists:
            blockers.append("database creation failed")
    if not db_exists:
        blockers.append("missing CodeQL database; pass --create-database or --database-dir")
    if not query_suite:
        blockers.append("missing CodeQL query suite")
    if db_exists and query_suite:
        output = work / "codeql-results.sarif"
        analyze = _run_command(
            [
                codeql,
                "database",
                "analyze",
                str(database_dir),
                query_suite,
                "--format=sarifv2.1.0",
                f"--output={output}",
            ],
            cwd=work,
            timeout_seconds=timeout_seconds,
            env=env,
        )
        runs.append({"stage": "database-analyze", "output": str(output), **analyze})
        if analyze["exit_code"] != 0:
            blockers.append("database analysis failed")
    return {
        "analyzer": "codeql",
        "executed": bool(runs),
        "database_dir": str(database_dir),
        "runs": runs,
        "run": runs[-1] if runs else None,
        "blockers": blockers,
    }


def _run_optional_analyzer(
    *,
    name: str,
    command: list[str] | str | None,
    work: Path,
    timeout_seconds: float,
    status: dict[str, Any],
    env: Mapping[str, str],
    placeholders: dict[str, str],
    extra_blocker: str | None = None,
) -> dict[str, Any]:
    blockers = []
    if not status["ok"]:
        blockers.append(f"missing {name}")
    if extra_blocker:
        blockers.append(extra_blocker)
    if command in (None, "", []):
        blockers.append(f"missing explicit {name} command")
    if blockers:
        return {"analyzer": name, "executed": False, "blockers": blockers}
    argv = _replace_placeholders(_runtime_command(command), placeholders)
    run = _run_command(argv, cwd=work, timeout_seconds=timeout_seconds, env=env)
    return {
        "analyzer": name,
        "executed": True,
        "run": run,
        "blockers": [] if run["exit_code"] == 0 else [f"{name} command failed"],
    }


def _materialize_seed_artifacts(seed_artifacts: list[dict[str, str]], seed_dir: Path) -> list[dict[str, Any]]:
    seed_dir.mkdir(parents=True, exist_ok=True)
    if not seed_artifacts:
        path = seed_dir / "seed-empty"
        path.write_bytes(b"")
        return [{"name": path.name, "path": str(path), "size": 0, "sha256": sha256(b"").hexdigest()}]
    records = []
    for index, artifact in enumerate(seed_artifacts):
        name = _safe_name(str(artifact.get("name") or f"seed-{index}"))
        content = artifact.get("content_b64")
        if not isinstance(content, str):
            raise ValueError("seed artifacts must include content_b64")
        data = base64.b64decode(content.encode("ascii"))
        path = seed_dir / name
        path.write_bytes(data)
        records.append({"name": name, "path": str(path), "size": len(data), "sha256": sha256(data).hexdigest()})
    return records


def _runtime_command(command: list[str] | str) -> list[str]:
    argv = _normalize_command(command)
    validate_command_shape(argv, context="runtime")
    executable = Path(argv[0]).name
    joined = " ".join(argv)
    for fragment in FORBIDDEN_ARG_FRAGMENTS:
        if fragment in joined:
            raise ValueError("runtime command references a forbidden runtime path")
    return argv


def _replace_placeholders(argv: list[str], values: dict[str, str]) -> list[str]:
    replaced = []
    for arg in argv:
        value = arg
        for key, replacement in values.items():
            value = value.replace("{" + key + "}", replacement)
        replaced.append(value)
    return replaced


def parse_libfuzzer_stats(output: str) -> dict[str, Any] | None:
    """Extract coverage stats from raw libFuzzer output (pre-clipping).

    Uses the last status/DONE line (``#N ... cov: X ft: Y ... corp: Z``) and
    the ``stat::`` block from ``-print_final_stats=1`` when present.
    """
    stats: dict[str, Any] = {}
    status_line = re.compile(r"#(\d+)\s+\S+\s+cov: (\d+) ft: (\d+) corp: (\d+)")
    for match in status_line.finditer(output):
        stats["execs"] = int(match.group(1))
        stats["covered_pcs"] = int(match.group(2))
        stats["features"] = int(match.group(3))
        stats["corpus_units"] = int(match.group(4))
    for match in re.finditer(r"stat::([a-z_]+):\s+(\d+)", output):
        stats[f"stat_{match.group(1)}"] = int(match.group(2))
    return stats or None


def _run_command(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    env: Mapping[str, str],
    raw_output_parser: Any = None,
    declared_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    argv = _runtime_command(command)
    # Keep enough bounded raw output for libFuzzer final stats while exposing
    # only the normal clipped transcript to callers.
    proc = bounded_run(argv, cwd=cwd, env=tool_env(env, declared=declared_env), timeout_seconds=timeout_seconds, max_output_chars=1_048_576)
    try:
        parsed = None
        if raw_output_parser is not None:
            try:
                parsed = raw_output_parser(f"{proc.stdout}\n{proc.stderr}")
            except Exception:  # noqa: BLE001 - parser failures must not mask the run
                parsed = None
        return {
            "command": argv,
            "parsed": parsed,
            "exit_code": proc.exit_code,
            "timed_out": proc.timed_out,
            "elapsed_ms": proc.elapsed_ms,
            "stdout": _clip(proc.stdout),
            "stderr": _clip(proc.stderr),
        }
    except OSError as exc:
        return {"command": argv, "exit_code": 127, "timed_out": False, "elapsed_ms": 0, "stdout": "", "stderr": _clip(str(exc))}


def _collect_files(root: Path, *, max_files: int) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    records = []
    paths = [root] if root.is_file() else sorted(path for path in root.rglob("*") if path.is_file())
    for path in paths:
        if len(records) >= max_files:
            break
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > MAX_COLLECTED_FILE_BYTES:
            continue
        data = path.read_bytes()
        records.append(
            {
                "path": str(path),
                "relative_path": path.relative_to(root).as_posix() if root.is_dir() else path.name,
                "size": len(data),
                "sha256": sha256(data).hexdigest(),
            }
        )
    return records


def _summarize_sarif(path: Path, source: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    runs = payload.get("runs") if isinstance(payload.get("runs"), list) else []
    result_count = 0
    source_hits = 0
    rules = set()
    for run in runs:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
        driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
        for rule in driver.get("rules", []) if isinstance(driver.get("rules"), list) else []:
            if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                rules.add(rule["id"])
        results = run.get("results") if isinstance(run.get("results"), list) else []
        result_count += len(results)
        for result in results:
            if _sarif_result_has_source_hit(result, source):
                source_hits += 1
    return {
        "runs": len(runs),
        "results": result_count,
        "rule_count": len(rules),
        "source_location_hits": source_hits,
        "valid_json": True,
    }


def _sarif_result_has_source_hit(result: Any, source: Path) -> bool:
    if not isinstance(result, dict):
        return False
    for location in result.get("locations", []) if isinstance(result.get("locations"), list) else []:
        if not isinstance(location, dict):
            continue
        physical = location.get("physicalLocation") if isinstance(location.get("physicalLocation"), dict) else {}
        artifact = physical.get("artifactLocation") if isinstance(physical.get("artifactLocation"), dict) else {}
        uri = artifact.get("uri")
        if isinstance(uri, str) and (source / uri).exists():
            return True
    return False


def _source_fingerprint(source: Path) -> dict[str, Any]:
    digest = sha256()
    files = 0
    total_bytes = 0
    for path in sorted(item for item in source.rglob("*") if item.is_file()):
        if SKIP_SOURCE_DIRS.intersection(path.relative_to(source).parts):
            continue
        rel = path.relative_to(source).as_posix()
        stat = path.stat()
        digest.update(rel.encode("utf-8"))
        digest.update(str(stat.st_size).encode("ascii"))
        digest.update(str(stat.st_mtime_ns).encode("ascii"))
        files += 1
        total_bytes += stat.st_size
    return {"path": str(source), "sha256": digest.hexdigest(), "files": files, "bytes": total_bytes}


def _copy_source_tree(source: Path, destination: Path) -> None:
    def ignore(_dir: str, names: list[str]) -> set[str]:
        return {name for name in names if name in SKIP_SOURCE_DIRS}

    shutil.copytree(source, destination, ignore=ignore, symlinks=True)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _binary_check(name: str, env: Mapping[str, str]) -> dict[str, Any]:
    path = _which(name, env)
    if path and name in {"symcc", "sym++"}:
        wrapper = _docker_wrapper_image_check(
            path,
            env,
            env_name="AGENTIC_FUZZ_SYMCC_IMAGE",
            fallback_env_name="AGENTIC_FUZZ_SYMCC_IMAGE",
        )
        if wrapper is not None:
            return {"ok": wrapper["ok"], "path": path, "alternatives": [name], **wrapper}
    if path and name in {"symqemu", "symqemu-x86_64"}:
        wrapper = _docker_wrapper_image_check(
            path,
            env,
            env_name="AGENTIC_FUZZ_SYMQEMU_IMAGE",
            fallback_env_name="AGENTIC_FUZZ_SYMQEMU_IMAGE",
        )
        if wrapper is not None:
            return {"ok": wrapper["ok"], "path": path, "alternatives": [name], **wrapper}
    return {"ok": bool(path), "path": path, "alternatives": [name]}


def _binary_any_check(names: tuple[str, ...], env: Mapping[str, str]) -> dict[str, Any]:
    last_wrapper: dict[str, Any] | None = None
    for name in names:
        check = _binary_check(name, env)
        if check["ok"]:
            return {"ok": True, "path": check.get("path"), "alternatives": list(names), **{key: value for key, value in check.items() if key not in {"ok", "path", "alternatives"}}}
        if check.get("docker_wrapper"):
            last_wrapper = check
    if last_wrapper is not None:
        return {"ok": False, "path": last_wrapper.get("path"), "alternatives": list(names), **{key: value for key, value in last_wrapper.items() if key not in {"ok", "path", "alternatives"}}}
    return {"ok": False, "path": None, "alternatives": list(names)}


def _python_module_check(name: str) -> dict[str, Any]:
    return {"ok": importlib.util.find_spec(name) is not None, "module": name, "alternatives": [name]}


def _env_any_check(names: tuple[str, ...], env: Mapping[str, str]) -> dict[str, Any]:
    present = [name for name in names if env.get(name)]
    if (env.get("AGENTIC_FUZZ_CLAUDE_CODE_MODEL") == "1" or env.get("AGENTIC_FUZZ_CLAUDE_CODE_MODEL") == "1") and _which("claude", env):
        present.append("CLAUDE_CODE_MODEL_RUNTIME")
    return {"ok": bool(present), "present": present, "alternatives": [*names, "CLAUDE_CODE_MODEL_RUNTIME"]}


def _sootup_check(env: Mapping[str, str]) -> dict[str, Any]:
    jar = env.get("SOOTUP_JAR")
    if jar and Path(jar).expanduser().is_file():
        return {"ok": True, "path": str(Path(jar).expanduser()), "alternatives": ["SOOTUP_JAR"]}
    path = _which("sootup", env)
    return {"ok": bool(path), "path": path, "alternatives": ["SOOTUP_JAR", "sootup"]}


def _which(name: str, env: Mapping[str, str]) -> str | None:
    path = shutil.which(name, path=env.get("PATH"))
    if path:
        return path
    for directory in _tool_search_dirs():
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _tool_search_dirs() -> tuple[Path, ...]:
    repo_root = Path(__file__).resolve().parents[2]
    custom_home = os.environ.get("AGENTIC_FUZZ_TOOL_HOME") or os.environ.get("AGENTIC_FUZZ_TOOL_HOME")
    custom_dirs = (Path(custom_home).expanduser() / "bin",) if custom_home else ()
    return (
        *custom_dirs,
        repo_root / "tools" / "bin",
        Path("/opt/homebrew/opt/llvm/bin"),
        Path("/usr/local/opt/llvm/bin"),
        Path("/opt/homebrew/bin"),
        Path("/usr/local/bin"),
    )


def _docker_wrapper_image_check(
    path: str,
    env: Mapping[str, str],
    *,
    env_name: str,
    fallback_env_name: str | None = None,
) -> dict[str, Any] | None:
    try:
        resolved = Path(path).resolve()
    except OSError:
        return None
    repo_tools = Path(__file__).resolve().parents[2] / "tools" / "bin"
    try:
        resolved.relative_to(repo_tools.resolve())
    except ValueError:
        return None

    image = env.get(env_name) or (env.get(fallback_env_name) if fallback_env_name else None)
    if not image:
        return {
            "ok": False,
            "docker_wrapper": True,
            "image": None,
            "image_ok": False,
            "reason": f"set {env_name} to an immutable sha256 image digest",
        }
    if not _is_immutable_image(image):
        return {"ok": False, "docker_wrapper": True, "image": image, "image_ok": False, "reason": "Docker image must be pinned by a sha256 digest"}
    docker = _which("docker", env)
    if not docker:
        return {
            "ok": False,
            "docker_wrapper": True,
            "image": image,
            "image_ok": False,
            "reason": "repo-local Docker wrapper requires docker",
        }
    try:
        proc = bounded_run([docker, "image", "inspect", image], env=docker_client_env(env), timeout_seconds=10)
    except OSError as exc:
        return {
            "ok": False,
            "docker_wrapper": True,
            "image": image,
            "image_ok": False,
            "reason": f"could not inspect Docker image: {str(exc)[:240]}",
        }
    if proc.exit_code != 0:
        return {
            "ok": False,
            "docker_wrapper": True,
            "image": image,
            "image_ok": False,
            "reason": f"Docker image is not present: {proc.stderr[:240]}",
        }
    return {"ok": True, "docker_wrapper": True, "image": image, "image_ok": True}


def _is_immutable_image(image: str) -> bool:
    digest = image.rsplit("@sha256:", 1)
    return len(digest) == 2 and len(digest[1]) == 64 and all(char in "0123456789abcdef" for char in digest[1].lower())


def _codeql_language(language: str) -> str:
    normalized = language.lower().replace("_", "-")
    if normalized in {"c", "cpp", "c-cpp", "c++"}:
        return "cpp"
    if normalized in {"java", "jvm"}:
        return "java"
    return normalized


def _bounded_runtime_timeout(value: int | float) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("timeout_seconds must be numeric") from exc
    if timeout <= 0 or timeout > MAX_RUNTIME_TIMEOUT_SECONDS:
        raise ValueError(f"timeout_seconds must be between 0 and {MAX_RUNTIME_TIMEOUT_SECONDS:g}")
    return timeout


def _bounded_runs(value: int) -> int:
    try:
        runs = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("runs must be an integer") from exc
    if runs <= 0 or runs > 1_000_000:
        raise ValueError("runs must be between 1 and 1000000")
    return runs


def _blocked_worker(worker: str, crash_dir: Path, blocker: str) -> dict[str, Any]:
    return {"worker": worker, "executed": False, "crash_dir": str(crash_dir), "blockers": [blocker]}


def _safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in Path(value).name)[:160] or "item"


def _coerce_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value

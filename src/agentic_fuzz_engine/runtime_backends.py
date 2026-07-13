from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import subprocess
from hashlib import sha256
from pathlib import Path
from time import monotonic
from typing import Any, Mapping

from .execution import FORBIDDEN_ARG_FRAGMENTS, _clip, _normalize_command
from .patching import validate_unified_diff


MAX_RUNTIME_TIMEOUT_SECONDS = 3600.0
MAX_COLLECTED_FILE_BYTES = 1_048_576
MAX_COLLECTED_FILES = 100
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
            "title": "SymCC/SymQEMU/Z3 symbolic execution",
            "checks": {
                "symcc": _binary_check("symcc", environment),
                "symqemu": _binary_any_check(("symqemu", "symqemu-x86_64"), environment),
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
    timeout_seconds: int | float = 60,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    timeout = _bounded_runtime_timeout(timeout_seconds)
    selected_mode = mode.lower().strip()
    if selected_mode not in {"symcc", "symqemu", "z3"}:
        raise ValueError("mode must be one of symcc, symqemu, z3")

    work = Path(work_dir).expanduser().resolve()
    out = Path(output_dir).expanduser().resolve() if output_dir else work / selected_mode / "outputs"
    work.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    status = runtime_backend_status(env=environment)["groups"]["symbolic_stack"]["checks"]

    if selected_mode == "z3":
        result = _run_z3_solver(constraints_smt2_b64=constraints_smt2_b64, status=status)
    elif selected_mode == "symcc":
        result = _run_symcc(command=command, work=work, output_dir=out, timeout_seconds=timeout, status=status, env=environment)
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
) -> dict[str, Any]:
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
            apply_check = _run_command(["git", "apply", "--check", str(patch_path)], cwd=env_dir, timeout_seconds=timeout, env=environment)
            commands.append({"stage": "apply-check", **apply_check})
            if apply_check["exit_code"] != 0:
                blockers.append("patch apply check failed")
            else:
                apply_run = _run_command(["git", "apply", str(patch_path)], cwd=env_dir, timeout_seconds=timeout, env=environment)
                commands.append({"stage": "apply", **apply_run})
                if apply_run["exit_code"] != 0:
                    blockers.append("patch application failed")
            patch_record = {
                "patch_name": patch_name or patch_path.name,
                "patch_sha256": patch_sha,
                "patch_path": str(patch_path),
                "changed_paths": changed_paths,
            }

    for stage, command in (("build", build_command), ("test", test_command)):
        if command is None:
            continue
        run = _run_command(
            _replace_placeholders(_runtime_command(command), {"src": str(env_dir), "env_dir": str(env_dir)}),
            cwd=env_dir,
            timeout_seconds=timeout,
            env=environment,
        )
        commands.append({"stage": stage, **run})
        if run["exit_code"] != 0:
            blockers.append(f"{stage} command failed")

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
    run = _run_command(materialized, cwd=crash_dir.parent, timeout_seconds=timeout_seconds, env=env)
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
    run = _run_command(argv, cwd=crash_dir.parent, timeout_seconds=timeout_seconds + 15, env=afl_env)
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


def _run_z3_solver(*, constraints_smt2_b64: str | None, status: dict[str, Any]) -> dict[str, Any]:
    if not status["z3"]["ok"]:
        return {"ok": False, "executed": False, "blockers": ["missing z3 Python bindings"]}
    if not constraints_smt2_b64:
        return {"ok": False, "executed": False, "blockers": ["missing SMT-LIB constraints"]}
    import z3  # type: ignore[import-not-found]

    constraints = base64.b64decode(constraints_smt2_b64.encode("ascii")).decode("utf-8", errors="replace")
    solver = z3.Solver()
    solver.from_string(constraints)
    started = monotonic()
    check = solver.check()
    model = solver.model() if check == z3.sat else None
    return {
        "ok": True,
        "executed": True,
        "solver": "z3",
        "check": str(check),
        "model": str(model) if model is not None else None,
        "elapsed_ms": int((monotonic() - started) * 1000),
        "blockers": [],
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
    sym_env = dict(env)
    sym_env.setdefault("SYMCC_OUTPUT_DIR", str(output_dir))
    argv = _replace_placeholders(_runtime_command(command), {"output_dir": str(output_dir), "work_dir": str(work), "symcc": status["symcc"]["path"] or "symcc"})
    run = _run_command(argv, cwd=work, timeout_seconds=timeout_seconds, env=sym_env)
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
    symqemu = status["symqemu"]["path"] or "symqemu"
    argv = _replace_placeholders(_runtime_command(command), {"output_dir": str(output_dir), "work_dir": str(work), "symqemu": symqemu})
    if Path(argv[0]).name not in {"symqemu", "symqemu-x86_64"}:
        argv = [symqemu, *argv]
    sym_env = dict(env)
    sym_env.setdefault("SYMCC_OUTPUT_DIR", str(output_dir))
    run = _run_command(argv, cwd=work, timeout_seconds=timeout_seconds, env=sym_env)
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
    executable = Path(argv[0]).name
    if executable in {"bash", "sh", "zsh"} and "-c" in argv[1:]:
        raise ValueError("runtime command may not use shell -c")
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


def _run_command(command: list[str], *, cwd: Path, timeout_seconds: float, env: Mapping[str, str]) -> dict[str, Any]:
    argv = _runtime_command(command)
    started = monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=dict(env),
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
    except FileNotFoundError as exc:
        return {
            "command": argv,
            "exit_code": 127,
            "timed_out": False,
            "elapsed_ms": int((monotonic() - started) * 1000),
            "stdout": "",
            "stderr": _clip(str(exc)),
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
            default_image="eurecoms3/symcc:latest",
            env_name="AGENTIC_FUZZ_SYMCC_IMAGE",
            fallback_env_name="AGENTIC_FUZZ_SYMCC_IMAGE",
        )
        if wrapper is not None:
            return {"ok": wrapper["ok"], "path": path, "alternatives": [name], **wrapper}
    if path and name in {"symqemu", "symqemu-x86_64"}:
        wrapper = _docker_wrapper_image_check(
            path,
            env,
            default_image="agentic-fuzz/symqemu:latest",
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
    default_image: str,
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

    image = env.get(env_name) or (env.get(fallback_env_name) if fallback_env_name else None) or default_image
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
        proc = subprocess.run(
            [docker, "image", "inspect", image],
            env=dict(env),
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "docker_wrapper": True,
            "image": image,
            "image_ok": False,
            "reason": f"could not inspect Docker image: {str(exc)[:240]}",
        }
    if proc.returncode != 0:
        return {
            "ok": False,
            "docker_wrapper": True,
            "image": image,
            "image_ok": False,
            "reason": f"Docker image is not present: {(proc.stderr or '')[:240]}",
        }
    return {"ok": True, "docker_wrapper": True, "image": image, "image_ok": True}


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

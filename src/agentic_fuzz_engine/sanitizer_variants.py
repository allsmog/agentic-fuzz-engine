"""Build and replay bounded MemorySanitizer/ThreadSanitizer variants.

Reports are grouped as candidates. A clean sweep is not absence evidence,
especially for schedule-dependent races or partially instrumented processes.
"""
from __future__ import annotations

import json
import math
import os
import re
import secrets
import stat
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from .crash_identity import parse_crash_output, root_signature
from .differential import (
    MAX_INPUT_BYTES,
    _ExemplarLimit,
    _atomic_json,
    _copy_exemplar,
    _corpus_inputs,
    _open_anchored_directory,
    _read_bounded_regular,
    _reject_symlink_within,
    _safe_managed_dir,
    _same_file_snapshot,
    _target_name,
    _validated_declared_env,
    _verify_directory_identity,
)
from .process_safety import bounded_run, tool_env, validate_command_shape
from .workspace import resolve_workspace_root

SUPPORTED_SANITIZERS = ("msan", "tsan")
MAX_INPUTS = 4_096
MAX_PER_INPUT_TIMEOUT = 120.0
MAX_WALL_SECONDS = 3_600.0
MAX_RUNS_PER_INPUT = 16
MAX_OUTPUT_CHARS = 4 * 1024 * 1024
MAX_SANITIZER_DEPS = 4
MAX_CONFIG_BYTES = 256 * 1024
MAX_DEP_FILES = 20_000
MAX_DEP_DIRS = 4_000
MAX_DEP_FILE_BYTES = 16 * 1024 * 1024
MAX_DEP_TOTAL_BYTES = 512 * 1024 * 1024
MAX_DEP_ARGS = 128
MAX_REPORTED_GROUPS = 500

_REPLACED_RUNTIMES = {"address", "leak", "undefined", "memory", "thread", "hwaddress"}
_PROFILES: dict[str, dict[str, Any]] = {
    "msan": {
        "runtime": "memory",
        "extra_cflags": ("-fsanitize-memory-track-origins=2", "-fsanitize-recover=memory", "-fno-omit-frame-pointer"),
        "run_env": {"MSAN_OPTIONS": "halt_on_error=0:print_stats=0"},
        "caveat": "Libraries not built with MemorySanitizer can produce noise or hide data-flow; grouped reports still require triage.",
    },
    "tsan": {
        "runtime": "thread", "extra_cflags": ("-fno-omit-frame-pointer",),
        "run_env": {"TSAN_OPTIONS": "halt_on_error=0:second_deadlock_stack=1"},
        "caveat": "Race reports are schedule-dependent; a clean bounded sweep is not evidence that races are absent.",
    },
}
_REPORT_BOUNDARY_RE = re.compile(
    r"(?=(?:==\d+==\s*)?(?:WARNING|ERROR):\s*(?:Address|Memory|Thread|Leak|UndefinedBehavior)Sanitizer)"
)


def iter_crash_signals(output: str, *, max_reports: int = 32) -> list[tuple[str, Any]]:
    limit = min(max(int(max_reports), 1), 128)
    signals: list[tuple[str, Any]] = []
    seen: set[str] = set()
    for chunk in _REPORT_BOUNDARY_RE.split(output):
        if len(signals) >= limit:
            break
        signal = parse_crash_output(chunk)
        if signal is None:
            continue
        signature = root_signature(signal)
        if signature not in seen:
            seen.add(signature)
            signals.append((signature, signal))
    return signals


def _rewrite_sanitize_token(token: str, runtime: str) -> str:
    prefix, separator, value = token.partition("=")
    if not separator:
        return token
    kept = [part for part in value.split(",") if part and part not in _REPLACED_RUNTIMES]
    if runtime not in kept:
        kept.append(runtime)
    return f"{prefix}={','.join(kept)}"


def derive_variant_config(
    config: Mapping[str, Any], *, sanitizer: str, ignorelist: Path | None = None,
    path_rewrites: Sequence[tuple[str, str]] | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    if sanitizer not in SUPPORTED_SANITIZERS:
        return None, f"unsupported sanitizer {sanitizer!r}"
    try:
        derived = json.loads(json.dumps(dict(config)))
    except (TypeError, ValueError) as exc:
        return None, f"build config must be JSON-compatible: {exc}"
    steps = derived.get("steps")
    if not isinstance(steps, list):
        return None, "build config steps must be a list"
    matched = False
    output_token = f"{{bin_dir}}/fuzzer-{sanitizer}"
    for step in steps:
        if not isinstance(step, Mapping):
            return None, "build config steps must be objects"
        raw_argv = step.get("argv")
        if not isinstance(raw_argv, list) or not all(isinstance(item, str) for item in raw_argv):
            return None, "build step argv must be a string list"
        if not any(item.startswith("-fsanitize=") for item in raw_argv) or "{bin_dir}/fuzzer" not in raw_argv:
            continue
        matched = True
        rewritten: list[str] = []
        for item in raw_argv:
            if item.startswith("-fsanitize="):
                item = _rewrite_sanitize_token(item, _PROFILES[sanitizer]["runtime"])
            if item == "{bin_dir}/fuzzer":
                item = output_token
            for old, new in path_rewrites or ():
                item = _rewrite_path_argument(item, old, new)
            rewritten.append(item)
        rewritten.extend(_PROFILES[sanitizer]["extra_cflags"])
        if ignorelist is not None and _regular_file(ignorelist):
            rewritten.append(f"-fsanitize-ignorelist={ignorelist}")
        step["argv"] = rewritten
    if not matched:
        return None, "no build step has both a -fsanitize token and the exact {bin_dir}/fuzzer output token"
    return derived, None


def variant_step_names(config: Mapping[str, Any], *, sanitizer: str) -> list[str]:
    token = f"{{bin_dir}}/fuzzer-{sanitizer}"
    names: list[str] = []
    for index, step in enumerate(config.get("steps", []) or []):
        if isinstance(step, Mapping) and token in (step.get("argv") or []):
            names.append(str(step.get("name") or f"step-{index}"))
    return names


def load_sanitizer_deps(target_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    path = target_dir / ".localfuzz" / "sanitizer-deps.json"
    try:
        payload = json.loads(_read_bounded_regular(
            path, MAX_CONFIG_BYTES, label="dependency recipe", anchor=target_dir,
        ))
    except FileNotFoundError:
        return [], []
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        return [], [f"unparseable {path}: {exc}"]
    deps = payload.get("deps") if isinstance(payload, Mapping) else None
    if not isinstance(deps, list) or not deps:
        return [], [f"{path}: expected a non-empty deps list"]
    if len(deps) > MAX_SANITIZER_DEPS:
        return [], [f"{path}: at most {MAX_SANITIZER_DEPS} dependencies"]
    blockers: list[str] = []
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(deps):
        if not isinstance(raw, Mapping):
            blockers.append(f"{path}: deps[{index}] must be an object")
            continue
        dep = dict(raw)
        label = dep.get("name") or f"deps[{index}]"
        if "env" in dep:
            blockers.append(f"{path}: {label} env is unsupported; use declared_env")
        for field in ("name", "source", "dest", "artifacts"):
            if not dep.get(field):
                blockers.append(f"{path}: {label} missing {field!r}")
        if "{sanitizer}" not in str(dep.get("dest", "")):
            blockers.append(f"{path}: {label} dest must contain {{sanitizer}}")
        if not isinstance(dep.get("artifacts"), list) or not all(isinstance(item, str) for item in dep.get("artifacts", [])):
            blockers.append(f"{path}: {label} artifacts must be a string list")
        for field in ("configureArgs", "makeArgs", "cxxflagsExtra"):
            value = dep.get(field, [])
            if not isinstance(value, list) or len(value) > MAX_DEP_ARGS or not all(isinstance(item, str) for item in value):
                blockers.append(f"{path}: {label} {field} must be a bounded string list")
        result.append(dep)
    return ([], blockers) if blockers else (result, [])


def ensure_sanitizer_dep(
    *, root: Path, dep: Mapping[str, Any], sanitizer: str,
    timeout_seconds: float, env: Mapping[str, str], declared_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if sanitizer not in SUPPORTED_SANITIZERS:
        return {"name": str(dep.get("name") or "dependency"), "status": "failed", "blockers": ["unsupported sanitizer"]}
    name = str(dep["name"])
    try:
        timeout = _bounded_timeout(timeout_seconds)
        declared = _validated_declared_env(declared_env)
        deadline = time.monotonic() + timeout
        source = _contained_declared_path(root, str(dep["source"]), label=f"{name} source")
        dest_text = str(dep["dest"]).replace("{sanitizer}", sanitizer)
        dest = _contained_declared_path(root, dest_text, label=f"{name} destination", may_not_exist=True)
        if source == dest:
            raise ValueError(f"{name}: destination must differ from source")
        artifacts = [_relative_component(dest, item, label=f"{name} artifact") for item in dep["artifacts"]]
    except ValueError as exc:
        return {"name": name, "status": "failed", "blockers": [str(exc)]}
    result = {"name": name, "source": str(source), "dest": str(dest)}
    if dest.is_dir() and not dest.is_symlink():
        try:
            dest_fd = _open_anchored_directory(dest, anchor=root.resolve())
        except (OSError, ValueError):
            dest_fd = -1
        if dest_fd >= 0:
            try:
                if all(_regular_relative_at(dest_fd, path.relative_to(dest)) for path in artifacts):
                    return {**result, "status": "present", "blockers": []}
            finally:
                os.close(dest_fd)
    if dest.exists() or dest.is_symlink():
        return {**result, "status": "failed", "blockers": [f"{name}: incomplete destination exists; refusing destructive replacement: {dest}"]}
    if not source.is_dir() or source.is_symlink():
        return {**result, "status": "failed", "blockers": [f"{name}: source tree missing or symlinked: {source}"]}
    parent_fd = staging_fd = -1
    staging_name = ""
    staging = dest.parent / f".{dest.name}.stage-pending"
    published = False
    cleanup_name = staging_name
    try:
        parent = _safe_managed_dir(root, dest.parent)
        staging, staging_name, parent_fd, staging_fd = _stage_dependency_tree(
            source, parent, dest.name, anchor=root.resolve(), deadline=deadline
        )
        cleanup_name = staging_name
    except (OSError, ValueError) as exc:
        return {**result, "status": "failed", "blockers": [f"{name}: staging failed: {exc}"]}

    try:
        flags = " ".join(_dep_cflags(sanitizer))
        cxx_extra = " ".join(str(item) for item in dep.get("cxxflagsExtra") or [])
        configure = [
            "./configure", f"CC={dep.get('cc') or 'clang'}", f"CXX={dep.get('cxx') or 'clang++'}",
            f"CFLAGS={flags}", f"CXXFLAGS={flags}{' ' + cxx_extra if cxx_extra else ''}",
            *[str(item) for item in dep.get("configureArgs") or []],
        ]
        make = ["make", *[str(item) for item in dep.get("makeArgs") or ["-j8"]]]
        run_env = tool_env(env, declared=declared, extra={"DEBUGINFOD_URLS": ""})
        for argv in (configure, make):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError(f"{name}: total dependency build budget exhausted")
            validated = validate_command_shape(argv, context=f"sanitizer dependency {name}")
            _verify_directory_identity(staging, staging_fd)
            _verify_directory_identity(parent, parent_fd)
            run = bounded_run(
                validated, cwd=staging, env=run_env, timeout_seconds=remaining,
                max_output_chars=12_000,
            )
            _verify_directory_identity(staging, staging_fd)
            _verify_directory_identity(parent, parent_fd)
            if run.timed_out or run.exit_code != 0:
                reason = "timed out" if run.timed_out else f"exit {run.exit_code}: {run.stderr[-2000:]}"
                raise ValueError(f"{name}: {validated[0]} {reason}")
        missing = [
            str(path.relative_to(dest)) for path in artifacts
            if not _regular_relative_at(staging_fd, path.relative_to(dest))
        ]
        if missing:
            raise ValueError(
                f"{name}: build completed without declared artifacts: {', '.join(missing)}"
            )
        _verify_directory_identity(staging, staging_fd)
        _verify_directory_identity(parent, parent_fd)
        try:
            os.stat(dest.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError(f"{name}: destination appeared during build: {dest}")
        os.replace(staging_name, dest.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        cleanup_name = dest.name
        _verify_directory_identity(parent, parent_fd)
        _verify_directory_identity(dest, staging_fd)
        os.fsync(parent_fd)
        published = True
        return {**result, "status": "built", "blockers": []}
    except (OSError, ValueError) as exc:
        failure = {**result, "status": "failed", "staging": str(staging), "blockers": [str(exc)]}
        return failure
    finally:
        if staging_fd >= 0:
            if not published:
                cleanup_error = _cleanup_staging(parent_fd, cleanup_name, staging_fd)
                if cleanup_error and "failure" in locals():
                    failure["blockers"].append(f"staging cleanup failed: {cleanup_error}")
            os.close(staging_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def sanitizer_build(
    *, target: str, sanitizer: str, timeout_seconds: int | float = 1_200,
    workspace_root: str | Path | None = None, env: Mapping[str, str] | None = None,
    declared_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    from .container_build import build_target

    environment = dict(os.environ if env is None else env)
    try:
        declared = _validated_declared_env(declared_env)
        if sanitizer not in SUPPORTED_SANITIZERS:
            raise ValueError(f"unsupported sanitizer {sanitizer!r}")
        name = _target_name(target)
        root = resolve_workspace_root(workspace_root, env=environment)
        timeout = _bounded_timeout(timeout_seconds)
        deadline = time.monotonic() + timeout
    except ValueError as exc:
        return _build_blocked(target, sanitizer, str(exc))
    try:
        target_dir = _contained_declared_path(root, f"targets/c/{name}", label="target directory")
        bin_dir = _safe_managed_dir(root, root / "bin" / name)
    except ValueError as exc:
        return _build_blocked(name, sanitizer, str(exc))
    config_path = target_dir / ".localfuzz" / "build.json"
    try:
        config = json.loads(_read_bounded_regular(
            config_path, MAX_CONFIG_BYTES, label="build config", anchor=target_dir,
        ))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return _build_blocked(name, sanitizer, str(exc))
    deps, blockers = load_sanitizer_deps(target_dir)
    if blockers:
        return _build_blocked(name, sanitizer, blockers[0], extra=blockers[1:])
    dep_results: list[dict[str, Any]] = []
    rewrites: list[tuple[str, str]] = []
    for dep in deps:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _build_blocked(name, sanitizer, "total sanitizer build budget exhausted")
        ensured = ensure_sanitizer_dep(
            root=root, dep=dep, sanitizer=sanitizer, timeout_seconds=remaining,
            env=environment, declared_env=declared,
        )
        dep_results.append(ensured)
        if ensured["status"] == "failed":
            return {**_build_blocked(name, sanitizer, ensured["blockers"][0]), "deps": dep_results}
        rewrites.append((ensured["source"], ensured["dest"]))
    ignorelist = target_dir / ".localfuzz" / f"{sanitizer}-ignorelist.txt"
    if ignorelist.is_symlink():
        return _build_blocked(name, sanitizer, f"refusing symlinked ignorelist: {ignorelist}")
    derived, blocker = derive_variant_config(config, sanitizer=sanitizer, ignorelist=ignorelist, path_rewrites=rewrites)
    if derived is None:
        return _build_blocked(name, sanitizer, str(blocker))
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return _build_blocked(name, sanitizer, "total sanitizer build budget exhausted")
    steps = variant_step_names(derived, sanitizer=sanitizer)
    binary = bin_dir / f"fuzzer-{sanitizer}"
    if binary.is_symlink():
        return _build_blocked(name, sanitizer, f"refusing symlinked variant output: {binary}")
    try:
        built = build_target(project=f"localfuzz/c/{name}", workspace_root=root, only_steps=steps,
            timeout_seconds=remaining, total_timeout_seconds=remaining,
            env=environment, build_env=declared, config_override=derived)
    except (FileNotFoundError, OSError, TypeError, ValueError) as exc:
        return _build_blocked(name, sanitizer, f"variant build failed before completion: {exc}")
    ok = bool(built.get("ok")) and _executable_regular(binary)
    result_blockers = [] if ok else list(built.get("blockers") or [f"variant binary missing: {binary}"])
    return {"ok": ok, "mode": "sanitizer-build", "target": name, "sanitizer": sanitizer,
        "binary": str(binary), "deps": dep_results,
        "ignorelist": str(ignorelist) if _regular_file(ignorelist) else None,
        "caveat": _PROFILES[sanitizer]["caveat"], "build": built, "blockers": result_blockers}


def sanitizer_sweep(
    *, target: str, sanitizer: str, corpus_dir: str | Path | None = None,
    binary: str | Path | None = None, max_inputs: int = 2_000,
    per_input_timeout: float = 15.0, max_seconds: float = 900.0,
    runs_per_input: int = 1, top: int = 50,
    workspace_root: str | Path | None = None, env: Mapping[str, str] | None = None,
    declared_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    try:
        declared = _validated_declared_env(declared_env)
        if sanitizer not in SUPPORTED_SANITIZERS:
            raise ValueError(f"unsupported sanitizer {sanitizer!r}")
        name = _target_name(target)
        root = resolve_workspace_root(workspace_root, env=environment)
        input_cap = _bounded_integer(max_inputs, 1, MAX_INPUTS, "max_inputs")
        per_timeout = _finite_between(per_input_timeout, 0.01, MAX_PER_INPUT_TIMEOUT, "per_input_timeout")
        wall_budget = _finite_between(max_seconds, 0.01, MAX_WALL_SECONDS, "max_seconds")
        repetitions = _bounded_integer(runs_per_input, 1, MAX_RUNS_PER_INPUT, "runs_per_input")
        top_cap = _bounded_integer(top, 1, MAX_REPORTED_GROUPS, "top")
        deadline = time.monotonic() + wall_budget
    except (TypeError, ValueError) as exc:
        return _sweep_blocked(target, sanitizer, str(exc))
    raw_variant = Path(binary).expanduser() if binary else root / "bin" / name / f"fuzzer-{sanitizer}"
    try:
        _reject_symlink_within(root, raw_variant, label="variant binary")
    except ValueError as exc:
        return _sweep_blocked(name, sanitizer, str(exc))
    variant = raw_variant.resolve()
    if not _executable_regular(variant):
        return _sweep_blocked(name, sanitizer, f"variant binary missing, non-regular, or non-executable: {variant}")
    try:
        validate_command_shape([str(variant)], context="sanitizer replay")
    except ValueError as exc:
        return _sweep_blocked(name, sanitizer, str(exc))
    raw_corpus = Path(corpus_dir).expanduser() if corpus_dir else root / "work" / name / "seeds"
    try:
        _reject_symlink_within(root, raw_corpus, label="corpus")
    except ValueError as exc:
        return _sweep_blocked(name, sanitizer, str(exc))
    corpus = raw_corpus.resolve()
    try:
        inputs, skipped_inputs, corpus_truncated = _corpus_inputs(corpus, input_cap)
    except (OSError, ValueError) as exc:
        return _sweep_blocked(name, sanitizer, f"unable to enumerate corpus safely: {exc}")
    if not inputs:
        return _sweep_blocked(name, sanitizer, f"no bounded regular inputs under {corpus}")
    try:
        report_dir = _safe_managed_dir(root, root / "work" / name)
    except (OSError, ValueError) as exc:
        return _sweep_blocked(name, sanitizer, f"unable to prepare sanitizer report directory: {exc}")
    run_env = tool_env(
        environment, declared=declared,
        extra={"DEBUGINFOD_URLS": "", **_PROFILES[sanitizer]["run_env"]},
    )

    def run_once(input_path: Path) -> tuple[list[tuple[str, Any]], bool, bool]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return [], True, False
        run = bounded_run([str(variant), str(input_path)], cwd=root, env=run_env,
            timeout_seconds=min(per_timeout, remaining), max_output_chars=MAX_OUTPUT_CHARS)
        output = f"{run.stderr}\n{run.stdout}"
        signals = iter_crash_signals(output)
        infrastructure = not run.timed_out and (run.exit_code == 127 or (run.exit_code != 0 and not signals))
        return signals, run.timed_out, infrastructure

    baseline: dict[str, dict[str, Any]] = {}
    baseline_fd, baseline_path, baseline_dir_fd, baseline_name, baseline_info = _create_anchored_empty_file(
        report_dir, ".sanitizer-baseline-", anchor=root
    )
    baseline_cleanup_error: str | None = None
    try:
        os.close(baseline_fd)
        baseline_signals, baseline_timed_out, baseline_infrastructure = run_once(baseline_path)
    finally:
        baseline_cleanup_error = _unlink_anchored_file(
            report_dir, baseline_dir_fd, baseline_name, expected=baseline_info
        )
        os.close(baseline_dir_fd)
    if baseline_cleanup_error:
        return _sweep_blocked(
            name, sanitizer, f"baseline cleanup failed: {baseline_cleanup_error}"
        )
    if baseline_timed_out or baseline_infrastructure:
        reason = "timed out" if baseline_timed_out else "exited without parsed sanitizer evidence"
        return _sweep_blocked(name, sanitizer, f"baseline replay {reason}")
    for signature, signal in baseline_signals:
        baseline[signature] = signal.to_dict()

    started_count = 0
    timeouts = infrastructure_failures = 0
    groups: dict[str, dict[str, Any]] = {}
    counts: dict[str, int] = {}
    hits_dir: Path | None = None
    exemplar_budget = {"files": 0, "bytes": 0}
    exemplars_skipped = 0
    for entry in inputs:
        if time.monotonic() >= deadline:
            break
        started_count += 1
        input_signatures: set[str] = set()
        for _ in range(repetitions):
            signals, timed_out, infrastructure = run_once(entry)
            if timed_out:
                timeouts += 1
                break
            if infrastructure:
                infrastructure_failures += 1
                break
            for signature, signal in signals:
                if signature in baseline or signature in input_signatures:
                    continue
                input_signatures.add(signature)
                counts[signal.crash_type] = counts.get(signal.crash_type, 0) + 1
                group = groups.get(signature)
                if group is None:
                    try:
                        hits_dir = _safe_managed_dir(root, report_dir / f"{sanitizer}-hits")
                        exemplar = _copy_exemplar(
                            entry, hits_dir, budget=exemplar_budget, anchor=root
                        )
                    except _ExemplarLimit:
                        exemplars_skipped += 1
                        continue
                    except (OSError, ValueError) as exc:
                        return _sweep_blocked(name, sanitizer, f"unable to publish sanitizer exemplar: {exc}")
                    groups[signature] = {"root_signature": signature, "signal": signal.to_dict(),
                        "exemplar_input": str(exemplar), "first_input": str(entry), "inputs": 1}
                else:
                    group["inputs"] += 1
    ranked = sorted(groups.values(), key=lambda group: (
        0 if group["signal"].get("access") == "WRITE" else 1, -group["inputs"], group["root_signature"]
    ))
    budget_exhausted = time.monotonic() >= deadline
    report_path = report_dir / f"{sanitizer}-sweep.json"
    report = {"mode": "sanitizer-sweep", "target": name, "sanitizer": sanitizer,
        "binary": str(variant), "corpus": str(corpus), "caveat": _PROFILES[sanitizer]["caveat"],
        "inputs_scanned": started_count, "inputs_total": len(inputs), "inputs_skipped": skipped_inputs,
        "corpus_enumeration_truncated": corpus_truncated,
        "inputs_timed_out": timeouts, "infrastructure_failures": infrastructure_failures,
        "runs_per_input": repetitions, "budget_exhausted": budget_exhausted,
        "baseline_signatures": {key: value.get("crash_type") for key, value in baseline.items()},
        "unique_candidate_signatures": len(groups), "counts_by_crash_type": counts,
        "exemplars_skipped_by_cap": exemplars_skipped,
        "hits_dir": str(hits_dir) if hits_dir else None, "groups": ranked[:top_cap],
        "interpretation": "Reports are candidates requiring triage; a clean bounded sweep is not absence evidence.",
    }
    try:
        _safe_managed_dir(root, report_dir)
        _atomic_json(report_path, report, anchor=root)
    except (OSError, ValueError) as exc:
        return _sweep_blocked(name, sanitizer, f"unable to publish sanitizer report: {exc}")
    return {"ok": True, "mode": "sanitizer-sweep", "target": name, "sanitizer": sanitizer,
        "binary": str(variant), "corpus": str(corpus), "blockers": [],
        "inputs_scanned": started_count, "inputs_total": len(inputs), "inputs_skipped": skipped_inputs,
        "corpus_enumeration_truncated": corpus_truncated,
        "inputs_timed_out": timeouts, "infrastructure_failures": infrastructure_failures,
        "budget_exhausted": budget_exhausted, "baseline_signature_count": len(baseline),
        "exemplars_skipped_by_cap": exemplars_skipped,
        "unique_signatures": len(groups), "counts_by_crash_type": counts,
        "hits_dir": report["hits_dir"], "groups": report["groups"], "report": str(report_path),
        "caveat": _PROFILES[sanitizer]["caveat"]}


def _build_blocked(target: str, sanitizer: str, message: str, *, extra: Sequence[str] = ()) -> dict[str, Any]:
    return {"ok": False, "mode": "sanitizer-build", "target": target, "sanitizer": sanitizer,
        "blockers": [message, *extra]}


def _sweep_blocked(target: str, sanitizer: str, message: str) -> dict[str, Any]:
    return {"ok": False, "mode": "sanitizer-sweep", "target": target, "sanitizer": sanitizer,
        "blockers": [message]}


def _finite_between(value: Any, minimum: float, maximum: float, field: str) -> float:
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ValueError(f"{field} must be finite and between {minimum} and {maximum}")
    return number


def _bounded_integer(value: Any, minimum: int, maximum: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer between {minimum} and {maximum}")
    return value


def _bounded_timeout(value: Any) -> float:
    return _finite_between(value, 0.01, MAX_WALL_SECONDS, "timeout_seconds")


def _dep_cflags(sanitizer: str) -> list[str]:
    profile = _PROFILES[sanitizer]
    return ["-g", "-O1", f"-fsanitize={profile['runtime']}", *profile["extra_cflags"]]


def _rewrite_path_argument(argument: str, old: str, new: str) -> str:
    if argument == old or argument.startswith(old.rstrip("/") + "/"):
        return new.rstrip("/") + argument[len(old.rstrip("/")):]
    for prefix in ("-I", "-L", "-isystem="):
        if argument.startswith(prefix):
            value = argument[len(prefix):]
            if value == old or value.startswith(old.rstrip("/") + "/"):
                return prefix + new.rstrip("/") + value[len(old.rstrip("/")):]
    return argument


def _contained_declared_path(root: Path, value: str, *, label: str, may_not_exist: bool = False) -> Path:
    raw = Path(value).expanduser()
    path = raw if raw.is_absolute() else root / raw
    if ".." in raw.parts:
        raise ValueError(f"{label} may not contain parent traversal")
    try:
        resolved = path.resolve(strict=not may_not_exist)
    except OSError as exc:
        raise ValueError(f"{label} does not resolve: {path}") from exc
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} escapes workspace: {resolved}") from exc
    if path.is_symlink():
        raise ValueError(f"refusing symlinked {label}: {path}")
    return resolved


def _relative_component(root: Path, value: str, *, label: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"{label} must be a relative contained path")
    return root / relative


def _regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _executable_regular(path: Path) -> bool:
    return _regular_file(path) and os.access(path, os.X_OK)


def _stage_dependency_tree(
    source: Path, parent: Path, destination_name: str, *, anchor: Path, deadline: float
) -> tuple[Path, str, int, int]:
    parent_fd = _open_anchored_directory(parent, anchor=anchor)
    staging_fd = -1
    staging_name = ""
    try:
        _verify_directory_identity(parent, parent_fd)
        for _ in range(32):
            staging_name = f".{destination_name}.stage-{secrets.token_hex(8)}"
            try:
                os.mkdir(staging_name, 0o700, dir_fd=parent_fd)
                break
            except FileExistsError:
                continue
        else:
            raise ValueError("unable to allocate unique dependency staging directory")
        staging_fd = os.open(
            staging_name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        source_fd = _open_anchored_directory(source, anchor=anchor)
        try:
            state = {"files": 0, "directories": 1, "bytes": 0}
            _copy_dep_tree_fds(
                source_fd, staging_fd, source=source, relative=Path(), state=state,
                deadline=deadline,
            )
            _verify_directory_identity(source, source_fd)
        finally:
            os.close(source_fd)
        staging = parent / staging_name
        _verify_directory_identity(staging, staging_fd)
        _verify_directory_identity(parent, parent_fd)
        return staging, staging_name, parent_fd, staging_fd
    except BaseException:
        if staging_fd >= 0:
            cleanup_error = _cleanup_staging(parent_fd, staging_name, staging_fd)
            os.close(staging_fd)
        os.close(parent_fd)
        if "cleanup_error" in locals() and cleanup_error:
            raise ValueError(f"dependency staging failed and cleanup failed: {cleanup_error}")
        raise


def _copy_dep_tree_fds(
    source_fd: int, destination_fd: int, *, source: Path, relative: Path,
    state: dict[str, int], deadline: float,
) -> None:
    before_directory = os.fstat(source_fd)
    with os.scandir(source_fd) as entries:
        for entry in entries:
            if time.monotonic() >= deadline:
                raise ValueError("total dependency build budget exhausted during staging")
            name = entry.name
            if name in {".", ".."} or "/" in name or "\x00" in name:
                raise ValueError(f"dependency tree contains unsafe entry name: {name!r}")
            info = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            display = source / relative / name
            if stat.S_ISDIR(info.st_mode):
                state["directories"] += 1
                if state["directories"] > MAX_DEP_DIRS:
                    raise ValueError(f"dependency tree exceeds {MAX_DEP_DIRS} directories")
                child_source_fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=source_fd,
                )
                opened = os.fstat(child_source_fd)
                if not _same_file_snapshot(info, opened):
                    os.close(child_source_fd)
                    raise ValueError(f"dependency directory changed before copy: {display}")
                os.mkdir(name, info.st_mode & 0o777, dir_fd=destination_fd)
                child_destination_fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=destination_fd,
                )
                try:
                    _copy_dep_tree_fds(
                        child_source_fd, child_destination_fd, source=source,
                        relative=relative / name, state=state, deadline=deadline,
                    )
                    current = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
                    if not _same_file_snapshot(opened, current):
                        raise ValueError(f"dependency directory changed while copying: {display}")
                finally:
                    os.close(child_source_fd)
                    os.close(child_destination_fd)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"dependency tree contains non-regular file: {display}")
            state["files"] += 1
            if state["files"] > MAX_DEP_FILES:
                raise ValueError(f"dependency tree exceeds {MAX_DEP_FILES} files")
            if info.st_size > MAX_DEP_FILE_BYTES or state["bytes"] + info.st_size > MAX_DEP_TOTAL_BYTES:
                raise ValueError("dependency tree exceeds file or aggregate byte cap")
            _copy_dep_file_at(
                source_fd, destination_fd, name, info=info, display=display,
                state=state, deadline=deadline,
            )
    after_directory = os.fstat(source_fd)
    if not _same_file_snapshot(before_directory, after_directory):
        raise ValueError(f"dependency directory changed while copying: {source / relative}")


def _copy_dep_file_at(
    source_dir_fd: int, destination_dir_fd: int, name: str, *, info: os.stat_result,
    display: Path, state: dict[str, int], deadline: float,
) -> None:
    source_fd = os.open(
        name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=source_dir_fd
    )
    destination_fd = -1
    try:
        opened = os.fstat(source_fd)
        if not stat.S_ISREG(opened.st_mode) or not _same_file_snapshot(info, opened):
            raise ValueError(f"dependency file changed before copying: {display}")
        destination_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            info.st_mode & 0o777,
            dir_fd=destination_dir_fd,
        )
        os.fchmod(destination_fd, info.st_mode & 0o777)
        copied = 0
        while True:
            if time.monotonic() >= deadline:
                raise ValueError("total dependency build budget exhausted during staging")
            chunk = os.read(source_fd, min(64 * 1024, MAX_DEP_FILE_BYTES + 1 - copied))
            if not chunk:
                break
            copied += len(chunk)
            if copied > info.st_size or copied > MAX_DEP_FILE_BYTES:
                raise ValueError(f"dependency file changed while copying: {display}")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        current = os.stat(name, dir_fd=source_dir_fd, follow_symlinks=False)
        if copied != info.st_size or not _same_file_snapshot(opened, os.fstat(source_fd)) or not _same_file_snapshot(opened, current):
            raise ValueError(f"dependency file changed while copying: {display}")
        os.fsync(destination_fd)
        state["bytes"] += copied
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)


def _regular_relative_at(root_fd: int, relative: Path) -> bool:
    descriptor = os.dup(root_fd)
    try:
        parts = relative.parts
        for part in parts[:-1]:
            child = os.open(
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        info = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
        return stat.S_ISREG(info.st_mode)
    except OSError:
        return False
    finally:
        os.close(descriptor)


def _cleanup_staging(parent_fd: int, staging_name: str, staging_fd: int) -> str | None:
    try:
        _remove_directory_contents(staging_fd)
        os.rmdir(staging_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return None
    except OSError as exc:
        return str(exc)


def _remove_directory_contents(directory_fd: int) -> None:
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            name = entry.name
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child_fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                try:
                    _remove_directory_contents(child_fd)
                finally:
                    os.close(child_fd)
                os.rmdir(name, dir_fd=directory_fd)
            else:
                os.unlink(name, dir_fd=directory_fd)


def _create_anchored_empty_file(
    directory: Path, prefix: str, *, anchor: Path
) -> tuple[int, Path, int, str, os.stat_result]:
    directory_fd = _open_anchored_directory(directory, anchor=anchor)
    for _ in range(32):
        name = f"{prefix}{secrets.token_hex(8)}"
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
            _verify_directory_identity(directory, directory_fd)
            return descriptor, directory / name, directory_fd, name, os.fstat(descriptor)
        except FileExistsError:
            continue
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
                try:
                    os.unlink(name, dir_fd=directory_fd)
                except OSError:
                    pass
            os.close(directory_fd)
            raise
    os.close(directory_fd)
    raise ValueError("unable to allocate bounded baseline input")


def _unlink_anchored_file(
    directory: Path, directory_fd: int, name: str, *, expected: os.stat_result
) -> str | None:
    errors: list[str] = []
    try:
        _verify_directory_identity(directory, directory_fd)
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
            errors.append(f"baseline entry identity changed: {name}")
        else:
            os.unlink(name, dir_fd=directory_fd)
            os.fsync(directory_fd)
    except OSError as exc:
        errors.append(str(exc))
    try:
        _verify_directory_identity(directory, directory_fd)
    except (OSError, ValueError) as exc:
        if str(exc) not in errors:
            errors.append(str(exc))
    return "; ".join(errors) or None

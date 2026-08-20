"""Bounded cross-implementation replay for differential *candidates*.

Different exit decisions or normalized outputs are leads for investigation;
they are not proof that either implementation is vulnerable or correct.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from .crash_identity import parse_crash_output
from .process_safety import bounded_run, tool_env, validate_command_shape, validate_declared_env
from .workspace import resolve_workspace_root

MAX_INPUTS = 4_096
MAX_COMMANDS = 6
MAX_COMMAND_ARGS = 128
MAX_ARG_CHARS = 8_192
MAX_PER_INPUT_TIMEOUT = 120.0
MAX_WALL_SECONDS = 3_600.0
MAX_BUILD_TIMEOUT = 1_800.0
MAX_RECIPE_BYTES = 256 * 1024
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_CHARS = 2 * 1024 * 1024
MAX_REPORTED_DIVERGENCES = 500
MAX_CORPUS_ENTRIES = 16_384
MAX_EXEMPLAR_FILES = 500
MAX_EXEMPLAR_TOTAL_BYTES = 128 * 1024 * 1024
KIND_SEVERITY = {"crash-split": 0, "validity-split": 1, "output-split": 2, "self-check": 0}
_TARGET_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}")
_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


def load_differential_recipe(target_dir: Path) -> tuple[list[dict[str, Any]] | None, list[str]]:
    path = target_dir / ".localfuzz" / "differential.json"
    try:
        payload = json.loads(_read_bounded_regular(
            path, MAX_RECIPE_BYTES, label="differential recipe", anchor=target_dir,
        ))
    except FileNotFoundError:
        return None, []
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        return None, [f"unparseable {path}: {exc}"]
    implementations = payload.get("implementations") if isinstance(payload, Mapping) else None
    if not isinstance(implementations, list) or not implementations:
        return None, [f"{path}: expected a non-empty implementations list"]
    if len(implementations) > MAX_COMMANDS:
        return None, [f"{path}: at most {MAX_COMMANDS} implementations"]
    result: list[dict[str, Any]] = []
    blockers: list[str] = []
    seen_labels: set[str] = set()
    for index, raw in enumerate(implementations):
        if not isinstance(raw, Mapping):
            blockers.append(f"{path}: implementations[{index}] must be an object")
            continue
        implementation = dict(raw)
        if "env" in implementation:
            blockers.append(f"{path}: implementations[{index}] env is unsupported; use declared_env")
        label = implementation.get("label")
        binary = implementation.get("binary")
        if not isinstance(label, str) or not _LABEL_RE.fullmatch(label):
            blockers.append(f"{path}: implementations[{index}] has invalid label")
        elif label in seen_labels:
            blockers.append(f"{path}: duplicate implementation label {label!r}")
        else:
            seen_labels.add(label)
        if not isinstance(binary, str) or not binary:
            blockers.append(f"{path}: implementations[{index}] missing binary")
        command = implementation.get("command")
        if command is not None:
            try:
                _validate_argv(command, context=f"differential recipe {label}", allow_input=True)
            except ValueError as exc:
                blockers.append(str(exc))
        build = implementation.get("build")
        if build is not None:
            compile_argv = build.get("compile") if isinstance(build, Mapping) else None
            if isinstance(build, Mapping) and "env" in build:
                blockers.append(f"{path}: implementations[{index}] build env is unsupported; use declared_env")
            try:
                _validate_argv(compile_argv, context=f"differential build {label}", allow_input=False)
            except ValueError as exc:
                blockers.append(str(exc))
        for field, default in (("accept_exit_codes", [0]), ("reject_exit_codes", [1])):
            try:
                implementation[field] = _validate_exit_codes(implementation.get(field, default), field=field)
            except ValueError as exc:
                blockers.append(f"{path}: {label}: {exc}")
        if set(implementation.get("accept_exit_codes", [])) & set(implementation.get("reject_exit_codes", [])):
            blockers.append(f"{path}: {label}: accept and reject exit codes overlap")
        result.append(implementation)
    return (None, blockers) if blockers else (result, [])


def resolve_auto_implementations(
    *, root: Path, name: str, build_timeout_seconds: float, env: Mapping[str, str],
    declared_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    try:
        name = _target_name(name)
        timeout = _bounded_number(build_timeout_seconds, minimum=1.0, maximum=MAX_BUILD_TIMEOUT, field="build_timeout_seconds")
        declared = _validated_declared_env(declared_env)
    except ValueError as exc:
        return {"commands": [], "labels": [], "implementations": [], "policies": [], "blockers": [str(exc)]}
    deadline = time.monotonic() + timeout
    target_dir = root / "targets" / "c" / name
    try:
        target_dir = _contained_path(root, str(target_dir), label="differential target directory")
    except ValueError as exc:
        return {"commands": [], "labels": [], "implementations": [], "policies": [], "blockers": [str(exc)]}
    recipe, blockers = load_differential_recipe(target_dir)
    if blockers:
        return {"commands": [], "labels": [], "implementations": [], "policies": [], "blockers": blockers}
    commands: list[list[str]] = []
    labels: list[str] = []
    policies: list[dict[str, list[int]]] = []
    statuses: list[dict[str, Any]] = []
    if recipe is None:
        bin_dir = root / "bin" / name
        if bin_dir.is_dir() and not bin_dir.is_symlink():
            for binary in sorted(bin_dir.glob("replay*"))[:MAX_COMMANDS]:
                if _is_executable_regular(binary):
                    commands.append([str(binary), "{input}"])
                    labels.append(binary.name[:64])
                    policies.append({"accept_exit_codes": [0], "reject_exit_codes": [1]})
                    statuses.append({"label": binary.name[:64], "binary": str(binary), "status": "present"})
        return {"commands": commands, "labels": labels, "implementations": statuses, "policies": policies, "blockers": []}

    placeholders = {
        "{target}": name, "{target_dir}": str(target_dir),
        "{bin_dir}": str(root / "bin" / name), "{workspace_root}": str(root),
    }
    run_env = tool_env(env, declared=declared, extra={"DEBUGINFOD_URLS": ""})
    for implementation in recipe:
        label = str(implementation["label"])
        binary_text = _substitute(str(implementation["binary"]), placeholders)
        binary = _contained_path(root, binary_text, label=f"{label} binary")
        status: dict[str, Any] = {"label": label, "binary": str(binary)}
        if not _is_executable_regular(binary):
            build = implementation.get("build") or {}
            compile_raw = build.get("compile") if isinstance(build, Mapping) else None
            if not compile_raw:
                statuses.append({**status, "status": "missing", "note": "no executable binary and no build recipe"})
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                statuses.append({**status, "status": "build-failed", "note": "total build budget exhausted"})
                continue
            try:
                argv = [_substitute(str(item), placeholders) for item in compile_raw]
                argv = _validate_argv(argv, context=f"differential build {label}", allow_input=False)
                _safe_managed_dir(root, binary.parent)
            except ValueError as exc:
                statuses.append({**status, "status": "build-failed", "note": str(exc)})
                continue
            run = bounded_run(argv, cwd=root, env=run_env, timeout_seconds=max(0.001, remaining), max_output_chars=12_000)
            if run.timed_out or run.exit_code != 0 or not _is_executable_regular(binary):
                note = "compile timed out" if run.timed_out else f"compile exit {run.exit_code}: {run.stderr[-2000:]}"
                statuses.append({**status, "status": "build-failed", "note": note})
                continue
            status["status"] = "built"
        else:
            status["status"] = "present"
        command_raw = implementation.get("command") or [str(binary), "{input}"]
        try:
            command = [_substitute(str(item), placeholders) for item in command_raw]
            command = _validate_argv(command, context=f"differential replay {label}", allow_input=True)
        except ValueError as exc:
            statuses.append({**status, "status": "invalid", "note": str(exc)})
            continue
        statuses.append(status)
        commands.append(command)
        labels.append(label)
        policies.append({
            "accept_exit_codes": list(implementation["accept_exit_codes"]),
            "reject_exit_codes": list(implementation["reject_exit_codes"]),
        })
    return {"commands": commands, "labels": labels, "implementations": statuses, "policies": policies, "blockers": []}


def classify_execution(
    returncode: int, output: str, *, accept_exit_codes: Sequence[int] = (0,),
    reject_exit_codes: Sequence[int] | None = None,
) -> str:
    # 127 is reserved by the process envelope for launch failure and may not
    # be reinterpreted from sanitizer-shaped path or error text.
    if returncode == 127:
        return "infrastructure"
    if returncode < 0 or parse_crash_output(output) is not None:
        return "crash"
    if returncode in accept_exit_codes:
        return "ok"
    if reject_exit_codes is None:
        return "error"  # compatibility for callers classifying a raw process result
    if returncode in reject_exit_codes:
        return "error"
    return "infrastructure"


def diverges(verdicts: Sequence[Mapping[str, Any]], *, compare: str) -> str | None:
    usable = [row for row in verdicts if row.get("exit_class") not in {"timeout", "infrastructure"}]
    if len(verdicts) == 1:
        return "self-check" if usable and usable[0].get("exit_class") == "crash" else None
    if len(usable) != len(verdicts):
        return None
    classes = {str(row.get("exit_class")) for row in usable}
    if len(classes) > 1:
        return "crash-split" if "crash" in classes else "validity-split"
    if compare == "output" and classes == {"ok"} and len({row.get("stdout_sha") for row in usable}) > 1:
        return "output-split"
    return None


def differential_run(
    *, target: str, commands: Sequence[Sequence[str]], labels: Sequence[str] | None = None,
    corpus_dir: str | Path | None = None, compare: str = "behavior", auto: bool = False,
    build_timeout_seconds: float = 600.0, max_inputs: int = 2_000,
    per_input_timeout: float = 10.0, max_seconds: float = 900.0, top: int = 50,
    accept_exit_codes: Sequence[int] = (0,), reject_exit_codes: Sequence[int] = (1,),
    workspace_root: str | Path | None = None, env: Mapping[str, str] | None = None,
    declared_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    try:
        root = resolve_workspace_root(workspace_root, env=environment)
        name = _target_name(target)
        input_cap = _bounded_integer(max_inputs, minimum=1, maximum=MAX_INPUTS, field="max_inputs")
        per_timeout = _bounded_number(per_input_timeout, minimum=0.01, maximum=MAX_PER_INPUT_TIMEOUT, field="per_input_timeout")
        wall_budget = _bounded_number(max_seconds, minimum=0.01, maximum=MAX_WALL_SECONDS, field="max_seconds")
        top_cap = _bounded_integer(top, minimum=1, maximum=MAX_REPORTED_DIVERGENCES, field="top")
        direct_policy = {
            "accept_exit_codes": _validate_exit_codes(accept_exit_codes, field="accept_exit_codes"),
            "reject_exit_codes": _validate_exit_codes(reject_exit_codes, field="reject_exit_codes"),
        }
        if set(direct_policy["accept_exit_codes"]) & set(direct_policy["reject_exit_codes"]):
            raise ValueError("accept and reject exit codes overlap")
        declared = _validated_declared_env(declared_env)
    except (TypeError, ValueError) as exc:
        return _blocked(name=target, message=str(exc))

    implementation_status: list[dict[str, Any]] | None = None
    command_list = [list(command) for command in commands]
    names = list(labels) if labels is not None else [f"impl-{index}" for index in range(len(command_list))]
    policies = [direct_policy for _ in command_list]
    if auto and not command_list:
        resolved = resolve_auto_implementations(
            root=root, name=name, build_timeout_seconds=build_timeout_seconds,
            env=environment, declared_env=declared,
        )
        implementation_status = resolved["implementations"]
        if resolved["blockers"]:
            return {**_blocked(name=name, message=resolved["blockers"][0]), "implementations": implementation_status}
        command_list, names, policies = resolved["commands"], resolved["labels"], resolved["policies"]
        if len(command_list) < 2:
            return {"ok": True, "mode": "differential-run", "target": name, "skipped": True,
                "skip_reason": f"{len(command_list)} replay implementation(s) available; differential comparison needs at least 2",
                "implementations": implementation_status, "divergent": 0, "blockers": []}
    blockers: list[str] = []
    if compare not in {"behavior", "output"}:
        blockers.append("compare must be behavior or output")
    if not command_list:
        blockers.append("commands required: one argv per implementation")
    if len(command_list) > MAX_COMMANDS:
        blockers.append(f"at most {MAX_COMMANDS} implementations per run")
    if (len(names) != len(command_list) or len(set(map(str, names))) != len(names)
            or any(not _LABEL_RE.fullmatch(str(label)) for label in names)):
        blockers.append("labels must be valid and match commands 1:1")
    validated_commands: list[list[str]] = []
    for index, command in enumerate(command_list):
        try:
            validated_commands.append(_validate_argv(command, context=f"differential replay {names[index] if index < len(names) else index}", allow_input=True))
        except ValueError as exc:
            blockers.append(str(exc))
    raw_corpus = Path(corpus_dir).expanduser() if corpus_dir else root / "work" / name / "seeds"
    try:
        _reject_symlink_within(root, raw_corpus, label="corpus")
    except ValueError as exc:
        blockers.append(str(exc))
    corpus = raw_corpus.resolve()
    try:
        inputs, skipped_inputs, corpus_truncated = _corpus_inputs(corpus, input_cap)
    except (OSError, ValueError) as exc:
        blockers.append(f"unable to enumerate corpus safely: {exc}")
        inputs, skipped_inputs, corpus_truncated = [], 0, False
    if not inputs:
        blockers.append(f"no bounded regular inputs to replay under {corpus}")
    if blockers:
        return {"ok": False, "mode": "differential-run", "target": name, "corpus": str(corpus),
            "labels": names, "blockers": blockers}

    run_env = tool_env(environment, declared=declared, extra={"DEBUGINFOD_URLS": ""})
    deadline = time.monotonic() + wall_budget
    divergences: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    agreement: dict[str, int] = {}
    infrastructure_failures = 0
    exemplar_budget = {"files": 0, "bytes": 0}
    exemplars_skipped = 0
    scanned = 0
    for entry in inputs:
        if time.monotonic() >= deadline:
            break
        verdicts: list[dict[str, Any]] = []
        scanned += 1
        for command, policy in zip(validated_commands, policies):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                verdicts.append({"exit_class": "timeout", "returncode": None, "stdout_sha": None})
                continue
            verdicts.append(_run_command(command, entry, timeout=min(per_timeout, remaining), env=run_env, cwd=root, policy=policy))
        if any(row["exit_class"] in {"timeout", "infrastructure"} for row in verdicts):
            infrastructure_failures += 1
        kind = diverges(verdicts, compare=compare)
        if kind is None:
            if verdicts and len({row["exit_class"] for row in verdicts}) == 1:
                key = verdicts[0]["exit_class"]
                agreement[key] = agreement.get(key, 0) + 1
            continue
        counts[kind] = counts.get(kind, 0) + 1
        try:
            hits_dir = _safe_managed_dir(root, root / "work" / name / "differential-hits")
            exemplar = _copy_exemplar(entry, hits_dir, budget=exemplar_budget, anchor=root)
        except _ExemplarLimit:
            exemplars_skipped += 1
            continue
        except (OSError, ValueError) as exc:
            return _blocked(name=name, message=f"unable to publish differential exemplar: {exc}")
        divergences.append({
            "input": str(entry), "exemplar_input": str(exemplar), "kind": kind,
            "verdicts": {str(label): {key: verdict[key] for key in ("exit_class", "returncode", "stdout_sha")}
                         for label, verdict in zip(names, verdicts)},
        })
    divergences.sort(key=lambda item: (KIND_SEVERITY.get(item["kind"], 99), item["input"]))
    budget_exhausted = time.monotonic() >= deadline
    try:
        report_dir = _safe_managed_dir(root, root / "work" / name)
    except (OSError, ValueError) as exc:
        return _blocked(name=name, message=f"unable to prepare differential report directory: {exc}")
    report_path = report_dir / "differential-run.json"
    report = {
        "mode": "differential-run", "target": name, "corpus": str(corpus), "labels": names,
        "compare": compare, "command_count": len(validated_commands), "inputs_scanned": scanned,
        "inputs_total": len(inputs), "inputs_skipped": skipped_inputs,
        "corpus_enumeration_truncated": corpus_truncated,
        "budget_exhausted": budget_exhausted, "infrastructure_failures": infrastructure_failures,
        "agreement_by_class": agreement, "divergent_candidates": len(divergences),
        "exemplars_skipped_by_cap": exemplars_skipped,
        "counts_by_kind": counts, "hits_dir": str(report_dir / "differential-hits") if divergences else None,
        "divergences": divergences[:top_cap],
        "interpretation": "Differences are candidates for investigation, not proof that either implementation is vulnerable or correct.",
    }
    try:
        _atomic_json(report_path, report, anchor=root)
    except (OSError, ValueError) as exc:
        return {"ok": False, "mode": "differential-run", "target": name,
            "blockers": [f"unable to publish differential report: {exc}"]}
    return {"ok": True, "mode": "differential-run", "target": name, "corpus": str(corpus),
        "labels": names, "blockers": [], "inputs_scanned": scanned, "inputs_total": len(inputs),
        "inputs_skipped": skipped_inputs, "budget_exhausted": budget_exhausted,
        "corpus_enumeration_truncated": corpus_truncated,
        "infrastructure_failures": infrastructure_failures, "agreement_by_class": agreement,
        "exemplars_skipped_by_cap": exemplars_skipped,
        "divergent": len(divergences), "counts_by_kind": counts, "hits_dir": report["hits_dir"],
        "divergences": report["divergences"], "report": str(report_path),
        **({"implementations": implementation_status} if implementation_status is not None else {})}


def _run_command(command: Sequence[str], input_path: Path, *, timeout: float, env: Mapping[str, str], cwd: Path,
                 policy: Mapping[str, Sequence[int]]) -> dict[str, Any]:
    argv = [item.replace("{input}", str(input_path)) for item in command]
    if not any("{input}" in item for item in command):
        argv.append(str(input_path))
    run = bounded_run(argv, cwd=cwd, env=env, timeout_seconds=timeout, max_output_chars=MAX_OUTPUT_CHARS)
    stdout_sha = hashlib.sha256(run.stdout.encode("utf-8", errors="replace")).hexdigest()[:16]
    if run.timed_out:
        exit_class = "timeout"
    else:
        exit_class = classify_execution(run.exit_code, f"{run.stderr}\n{run.stdout}",
            accept_exit_codes=policy["accept_exit_codes"], reject_exit_codes=policy["reject_exit_codes"])
    return {"exit_class": exit_class, "stdout_sha": stdout_sha, "returncode": run.exit_code}


def _blocked(*, name: str, message: str) -> dict[str, Any]:
    return {"ok": False, "mode": "differential-run", "target": name, "blockers": [message]}


def _target_name(value: str) -> str:
    name = str(value).removeprefix("localfuzz/c/")
    if not _TARGET_RE.fullmatch(name):
        raise ValueError("target must be a lowercase slug")
    return name


def _bounded_number(value: Any, *, minimum: float, maximum: float, field: str) -> float:
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError(f"{field} must be finite and between {minimum} and {maximum}")
    return result


def _bounded_integer(value: Any, *, minimum: int, maximum: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer between {minimum} and {maximum}")
    return value


def _validate_exit_codes(values: Any, *, field: str) -> list[int]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)) or not values:
        raise ValueError(f"{field} must be a non-empty integer list")
    result: set[int] = set()
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
            raise ValueError(f"{field} entries must be integers from 0 to 255")
        result.add(value)
    return sorted(result)


def _validated_declared_env(values: Any) -> dict[str, str]:
    if values is not None and not isinstance(values, Mapping):
        raise ValueError("declared_env must be an object of string keys and values")
    return validate_declared_env(values)


def _validate_argv(values: Any, *, context: str, allow_input: bool) -> list[str]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ValueError(f"{context} command must be an argv list")
    if len(values) > MAX_COMMAND_ARGS:
        raise ValueError(f"{context} command exceeds {MAX_COMMAND_ARGS} arguments")
    if not all(isinstance(value, str) and value for value in values):
        raise ValueError(f"{context} command must contain non-empty strings")
    argv = list(values)
    if any(len(item) > MAX_ARG_CHARS or "\x00" in item for item in argv):
        raise ValueError(f"{context} command contains an oversized or invalid argument")
    if not allow_input and any("{input}" in item for item in argv):
        raise ValueError(f"{context} command may not use the input placeholder")
    return validate_command_shape(argv, context=context)


def _substitute(text: str, placeholders: Mapping[str, str]) -> str:
    for token, value in placeholders.items():
        text = text.replace(token, value)
    return text


def _contained_path(root: Path, value: str, *, label: str) -> Path:
    path = Path(value).expanduser()
    path = path if path.is_absolute() else root / path
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} escapes the workspace: {resolved}") from exc
    if path.is_symlink():
        raise ValueError(f"refusing symlinked {label}: {path}")
    return resolved


def _reject_symlink_within(root: Path, path: Path, *, label: str) -> None:
    base = root.resolve()
    raw = path.expanduser().absolute()
    if raw.is_symlink():
        raise ValueError(f"refusing symlinked {label}: {raw}")
    try:
        relative = raw.relative_to(base)
    except ValueError:
        return
    current = base
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"refusing symlinked {label} component: {current}")


def _is_executable_regular(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode) and os.access(path, os.X_OK)
    except OSError:
        return False


def _safe_managed_dir(root: Path, path: Path) -> Path:
    root = root.resolve()
    path = path.absolute()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"managed path escapes workspace: {path}") from exc
    root.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(root, flags)
    current = root
    try:
        for part in path.relative_to(root).parts:
            current /= part
            try:
                os.mkdir(part, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except OSError as exc:
                raise ValueError(f"refusing unsafe managed directory component: {current}") from exc
            os.close(descriptor)
            descriptor = child
        _verify_directory_identity(path, descriptor)
    finally:
        os.close(descriptor)
    return path


def _corpus_inputs(corpus: Path, limit: int) -> tuple[list[Path], int, bool]:
    enumeration_truncated = False
    try:
        corpus_info = corpus.lstat()
    except OSError:
        return [], 0, False
    if stat.S_ISREG(corpus_info.st_mode):
        paths = [corpus]
    elif stat.S_ISDIR(corpus_info.st_mode):
        directory_fd = _open_anchored_directory(corpus)
        try:
            paths = []
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    if len(paths) >= MAX_CORPUS_ENTRIES:
                        enumeration_truncated = True
                        break
                    paths.append(corpus / entry.name)
            _verify_directory_identity(corpus, directory_fd)
            paths.sort(key=lambda item: item.name)
        finally:
            os.close(directory_fd)
    else:
        return [], 0, False
    result: list[Path] = []
    skipped = int(enumeration_truncated)
    for path in paths:
        try:
            info = path.lstat()
        except OSError:
            skipped += 1
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT_BYTES:
            skipped += 1
            continue
        if len(result) < limit:
            result.append(path)
        else:
            skipped += 1
    return result, skipped, enumeration_truncated


class _ExemplarLimit(ValueError):
    pass


def _copy_exemplar(
    source: Path, destination_dir: Path, *, budget: dict[str, int] | None = None,
    anchor: Path | None = None,
) -> Path:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT_BYTES:
            raise ValueError(f"refusing unbounded exemplar input: {source}")
        data = bytearray()
        while len(data) <= MAX_INPUT_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_INPUT_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        final_info = os.fstat(descriptor)
        if len(data) > MAX_INPUT_BYTES or not _same_file_snapshot(info, final_info):
            raise ValueError(f"exemplar input changed or exceeded its cap: {source}")
    finally:
        os.close(descriptor)
    target_name = hashlib.sha256(data).hexdigest()[:16]
    target = destination_dir / target_name
    directory_fd = _open_anchored_directory(destination_dir, anchor=anchor)
    try:
        if budget is not None and not budget.get("initialized"):
            _account_existing_exemplars(directory_fd, budget)
        try:
            existing = os.stat(target_name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISREG(existing.st_mode):
                raise ValueError(f"refusing unsafe exemplar destination: {target}")
            if not _existing_exemplar_matches(directory_fd, target_name, bytes(data)):
                raise ValueError(f"existing exemplar content does not match its digest: {target}")
            _verify_directory_identity(destination_dir, directory_fd)
            return target
        if budget is not None and (
            budget.get("files", 0) >= MAX_EXEMPLAR_FILES
            or budget.get("bytes", 0) + len(data) > MAX_EXEMPLAR_TOTAL_BYTES
        ):
            raise _ExemplarLimit("aggregate exemplar cap exhausted")
        temporary = f".{target_name}.tmp-{secrets.token_hex(8)}"
        out = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            try:
                view = memoryview(data)
                while view:
                    written = os.write(out, view)
                    view = view[written:]
                os.fsync(out)
            finally:
                os.close(out)
            _verify_directory_identity(destination_dir, directory_fd)
            try:
                os.link(
                    temporary, target_name,
                    src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                published = True
            except FileExistsError:
                published = False
                if not _existing_exemplar_matches(directory_fd, target_name, bytes(data)):
                    raise ValueError(f"raced exemplar content does not match its digest: {target}")
        finally:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        _verify_directory_identity(destination_dir, directory_fd)
        os.fsync(directory_fd)
        if budget is not None and published:
            budget["files"] = budget.get("files", 0) + 1
            budget["bytes"] = budget.get("bytes", 0) + len(data)
    finally:
        os.close(directory_fd)
    return target


def _atomic_json(path: Path, payload: Mapping[str, Any], *, anchor: Path | None = None) -> None:
    directory_fd = _open_anchored_directory(path.parent, anchor=anchor)
    temporary = f".{path.name}.tmp-{secrets.token_hex(8)}"
    descriptor = -1
    try:
        try:
            existing = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise ValueError(f"refusing non-regular report: {path}")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        _verify_directory_identity(path.parent, directory_fd)
        try:
            existing = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise ValueError(f"refusing non-regular report: {path}")
        os.replace(temporary, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        _verify_directory_identity(path.parent, directory_fd)
        os.fsync(directory_fd)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(directory_fd)


def _existing_exemplar_matches(directory_fd: int, name: str, expected: bytes) -> bool:
    descriptor = os.open(
        name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != len(expected):
            return False
        data = bytearray()
        while len(data) <= len(expected):
            chunk = os.read(descriptor, min(64 * 1024, len(expected) + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data) == expected and _same_file_snapshot(before, os.fstat(descriptor))
    finally:
        os.close(descriptor)


def _read_bounded_regular(
    path: Path, limit: int, *, label: str, anchor: Path | None = None
) -> str:
    parent_fd = -1
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if anchor is None:
        descriptor = os.open(path, flags)
    else:
        parent_fd = _open_anchored_directory(path.parent, anchor=anchor)
        try:
            descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        except BaseException:
            os.close(parent_fd)
            raise
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} is not a regular file: {path}")
        if before.st_size > limit:
            raise ValueError(f"{label} exceeds {limit} bytes: {path}")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        if len(data) > limit or not _same_file_snapshot(before, after):
            raise ValueError(f"{label} changed or exceeded {limit} bytes while reading: {path}")
        if parent_fd >= 0:
            _verify_directory_identity(path.parent, parent_fd)
        return bytes(data).decode("utf-8")
    finally:
        os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _same_file_snapshot(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev,
        first.st_ino,
        first.st_mode,
        first.st_size,
        first.st_mtime_ns,
        first.st_ctime_ns,
    ) == (
        second.st_dev,
        second.st_ino,
        second.st_mode,
        second.st_size,
        second.st_mtime_ns,
        second.st_ctime_ns,
    )


def _open_anchored_directory(path: Path, *, anchor: Path | None = None) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if anchor is None:
        return os.open(path, flags)
    base = anchor.resolve()
    target = path.absolute()
    try:
        try:
            parts = target.relative_to(anchor.absolute()).parts
        except ValueError:
            parts = target.relative_to(base).parts
    except ValueError as exc:
        raise ValueError(f"directory escapes anchor {base}: {target}") from exc
    descriptor = os.open(base, flags)
    try:
        for part in parts:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _verify_directory_identity(path: Path, descriptor: int) -> None:
    opened = os.fstat(descriptor)
    current = path.lstat()
    if not stat.S_ISDIR(current.st_mode) or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        raise ValueError(f"directory changed during anchored operation: {path}")


def _account_existing_exemplars(directory_fd: int, budget: dict[str, int]) -> None:
    files = total = 0
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            files += 1
            if files > MAX_EXEMPLAR_FILES:
                break
            info = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"exemplar directory contains non-regular entry: {entry.name}")
            total += info.st_size
            if total > MAX_EXEMPLAR_TOTAL_BYTES:
                break
    budget["files"] = files
    budget["bytes"] = total
    budget["initialized"] = 1

"""Spec-driven harness generation (``target-generate``).

Two layers, both codebase-agnostic:

1. Deterministic generators, parameterized entirely by JSON specs that live in
   the workspace (``<workspace>/generators/*.json``) — the engine knows the
   *shapes* (type-enumeration dispatch, direct byte-buffer calls, symbolic
   string command sinks) but none of the target codebase's names:

   - ``type_enum``   scan headers for serializable types, emit a
                     selector-dispatch harness (one decode template per type)
   - ``direct_call`` extract enclosing-function signatures at sink sites
                     (tree-sitter-cpp when available, regex fallback) and call
                     the fuzzable ones directly behind a selector byte
   - ``symbolic_string`` emit per-function KLEE mini-harnesses (symbolic
                     string arguments + a workspace-provided assert header)
                     plus a generated ci tier that links the real source file

2. A structured *authoring workorder* for everything the deterministic layer
   cannot produce (or that fails build/smoke validation): sink rows, source
   context, attempted signatures, and skip reasons — so a non-deterministic
   author (an operator or an LLM session) can write the harness body and
   re-enter the same machine validation loop.

Generation never runs unbounded work: header scans, source reads, candidate
counts, and workorder context are all capped, and validation reuses the
bounded ``target-build`` + a short smoke run.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping

from .runtime_backends import _run_command
from .scaffold import PROJECTS_RELATIVE, TARGETS_RELATIVE, _load_sink_rows, _render_project_yaml, _slugify
from .workspace import load_workspace, resolve_workspace_root

MAX_HEADERS_SCANNED = 4000
MAX_TYPES = 2000
MAX_CANDIDATES = 16
MAX_SINKS_CONSIDERED = 200
MAX_WORKORDER_SINKS = 20
MAX_CONTEXT_LINES = 60
MAX_SOURCE_BYTES = 4_000_000
SMOKE_TIMEOUT_SECONDS = 120

MAX_EXTRA_MOUNTS = 128
MAX_KLEE_POLICY_ITEMS = 64
MAX_KLEE_POLICY_ITEM_BYTES = 4096
MAX_STAGED_DIRECTORIES = 2048
MAX_STAGE_DEPTH = 32
MAX_STAGED_FILES = 10000
MAX_STAGED_FILE_BYTES = 4 * 1024 * 1024
MAX_STAGED_TOTAL_BYTES = 128 * 1024 * 1024
MAX_PACK_CONFIG_BYTES = 4 * 1024 * 1024
_HEADER_SUFFIXES = {".h", ".hpp", ".hh", ".inc", ".ipp", ".tcc", ".def"}
_LINK_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
_TARGET_SLUG_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,95}\Z")

try:  # pragma: no cover - exercised implicitly
    import tree_sitter
    import tree_sitter_cpp

    _CPP_LANGUAGE: Any = tree_sitter.Language(tree_sitter_cpp.language())
except Exception:  # pragma: no cover
    _CPP_LANGUAGE = None


def generate_target(
    *,
    name: str,
    spec: str,
    workspace_root: str | Path | None = None,
    sinks_jsonl: str | Path | None = None,
    sink_tag: str | None = None,
    validate: bool = False,
    engine: Any = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    root = resolve_workspace_root(workspace_root, env=environment)
    try:
        workspace = load_workspace(root, env=environment)
    except FileNotFoundError:
        workspace = {"root": str(root)}

    spec_path = _resolve_spec_path(spec, root)
    spec_data = json.loads(spec_path.read_text(encoding="utf-8"))
    generator = str(spec_data.get("type") or "")
    if generator not in {"type_enum", "direct_call", "symbolic_string", "sequence"}:
        raise ValueError(f"spec.type must be type_enum, direct_call, symbolic_string, or sequence: {spec_path}")

    target_dir = root / TARGETS_RELATIVE / name
    bin_dir = root / "bin" / name
    (target_dir / ".localfuzz").mkdir(parents=True, exist_ok=True)
    (target_dir / "seeds").mkdir(parents=True, exist_ok=True)
    project_dir = root / PROJECTS_RELATIVE / name
    project_dir.mkdir(parents=True, exist_ok=True)
    if not (project_dir / "project.yaml").exists():
        (project_dir / "project.yaml").write_text(_render_project_yaml(name), encoding="utf-8")
    if not (target_dir / ".localfuzz" / "config.yaml").exists():
        (target_dir / ".localfuzz" / "config.yaml").write_text(
            f"harness_files:\n  - name: {name}\n    path: harness.cpp\n", encoding="utf-8"
        )

    placeholders = {
        "workspace_root": str(root),
        "source_dir": str(workspace.get("source_dir") or ""),
        "target_dir": str(target_dir),
        "bin_dir": str(bin_dir),
    }

    sinks: list[dict[str, Any]] = []
    if generator in {"direct_call", "symbolic_string"}:
        if not sinks_jsonl:
            raise ValueError(f"{generator} generation requires sinks_jsonl")
        wanted = sink_tag or name
        rows = _load_sink_rows(Path(sinks_jsonl).expanduser().resolve())
        sinks = [
            row
            for row in rows
            if _slugify(str(row.get("tag") or "")) == _slugify(wanted) or str(row.get("tag") or "") == wanted
        ][:MAX_SINKS_CONSIDERED]
        if not sinks:
            raise ValueError(f"no sink rows matched tag {wanted!r} in {sinks_jsonl}")

    if generator == "type_enum":
        outcome = _generate_type_enum(spec_data, target_dir=target_dir, placeholders=placeholders)
    elif generator == "direct_call":
        outcome = _generate_direct_call(spec_data, target_dir=target_dir, sinks=sinks, placeholders=placeholders)
    elif generator == "sequence":
        outcome = _generate_sequence(spec_data, target_dir=target_dir, placeholders=placeholders)
    else:
        outcome = _generate_symbolic_string(
            spec_data, root=root, name=name, sinks=sinks, placeholders=placeholders
        )

    blockers = list(outcome.get("blockers", []))
    if outcome.get("build_steps"):
        build_payload = {"notes": [f"generated by target-generate from {spec_path.name}"], "steps": outcome["build_steps"]}
        (target_dir / ".localfuzz" / "build.json").write_text(
            json.dumps(build_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    validation: dict[str, Any] | None = None
    if validate and not blockers and generator != "symbolic_string":
        validation = _validate_build_and_smoke(
            engine=engine, name=name, root=root, bin_dir=bin_dir, environment=environment
        )
        blockers.extend(validation.get("blockers", []))

    status = "blocked" if blockers else "generated"
    workorder_path = None
    if blockers or outcome.get("needs_authoring"):
        workorder_path = _write_workorder(
            target_dir=target_dir,
            name=name,
            generator=generator,
            sinks=sinks,
            outcome=outcome,
            blockers=blockers,
            placeholders=placeholders,
        )
        status = "awaiting-authoring"
    # A passing build+smoke wins: remaining workorder entries are future
    # authoring opportunities, not a gate on the target that already works.
    if validation and validation.get("ok"):
        status = "validated"

    manifest = {
        "generator": generator,
        "spec": str(spec_path),
        "status": status,
        "validated": bool(validation and validation.get("ok")),
        "summary": outcome.get("summary", {}),
        "skipped": outcome.get("skipped", [])[:MAX_CANDIDATES * 4],
        "blockers": blockers,
        "workorder": workorder_path,
    }
    (target_dir / ".localfuzz" / "generate.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    return {
        "ok": not blockers,
        "mode": "target-generate",
        "name": name,
        "target": f"localfuzz/c/{name}",
        "generator": generator,
        "target_dir": str(target_dir),
        "status": status,
        "summary": outcome.get("summary", {}),
        "skipped": manifest["skipped"],
        "written": outcome.get("written", []),
        "validation": validation,
        "workorder": workorder_path,
        "blockers": blockers,
    }


def generate_all(
    *,
    spec: str,
    sinks_jsonl: str | Path,
    workspace_root: str | Path | None = None,
    max_targets: int = 10,
    validate: bool = False,
    engine: Any = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Sweep unharnessed sink vectors through generate_target, sequentially."""
    from .scaffold import select_targets

    budget = max(1, min(int(max_targets), 50))
    selection = select_targets(sinks_jsonl=sinks_jsonl, workspace_root=workspace_root, top=budget * 4, env=env)
    results = []
    for entry in selection["vectors"]:
        if entry["harnessed"] or len(results) >= budget:
            continue
        try:
            result = generate_target(
                name=entry["suggested_name"],
                spec=spec,
                workspace_root=workspace_root,
                sinks_jsonl=sinks_jsonl,
                sink_tag=entry["tag"],
                validate=validate,
                engine=engine,
                env=env,
            )
        except (ValueError, FileNotFoundError, FileExistsError) as exc:
            result = {"ok": False, "name": entry["suggested_name"], "status": "error", "blockers": [str(exc)]}
        results.append(result)
    return {
        "ok": all(item.get("ok") for item in results) if results else True,
        "mode": "target-generate-all",
        "spec": spec,
        "attempted": len(results),
        "statuses": {item.get("name"): item.get("status") for item in results},
        "results": results,
    }


def generate_klee_pack(
    *,
    name: str,
    workspace_root: str | Path | None = None,
    max_time_seconds: int = 120,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Convert an existing (typically plateaued) libFuzzer target into a
    klee-ng ci pack entry.

    The harness already carries the ``FUZZ_MAIN`` file-replay main, so the
    pack compiles it with ``-DFUZZ_MAIN``; compile flags and link sources are
    derived from the target's ``.localfuzz/build.json``. Paths under the
    build source tree pass through (mounted at the same path in-container);
    workspace-local files are copied under the klee dir. Target-specific
    declaration shims and intentionally omitted link sources must be explicit
    in ``workspace.json``; every such semantic reduction is reported.
    """
    environment = dict(os.environ if env is None else env)
    root = resolve_workspace_root(workspace_root, env=environment)
    try:
        workspace = load_workspace(root, env=environment)
    except FileNotFoundError:
        workspace = {"root": str(root)}
    source_dir = str(workspace.get("source_dir") or "")
    extra_mounts = _canonical_extra_mounts(workspace.get("extra_mounts"))
    klee_policy = workspace.get("klee") or {}
    if not isinstance(klee_policy, Mapping):
        raise ValueError("workspace klee config must be an object")
    drop_link_sources = _bounded_string_list(klee_policy, "drop_link_sources")
    force_includes = _bounded_string_list(klee_policy, "force_includes")

    short = _validate_pack_target_name(name)
    target_dir = root / TARGETS_RELATIVE / short
    harness = target_dir / "harness.cpp"
    build_path = target_dir / ".localfuzz" / "build.json"
    try:
        harness_payload = _read_managed_file_bounded(root, harness, max_bytes=MAX_SOURCE_BYTES)
    except FileNotFoundError:
        raise FileNotFoundError(f"harness not found (run target-generate/scaffold first): {harness}")
    try:
        build_text = _read_managed_file_bounded(root, build_path, max_bytes=MAX_PACK_CONFIG_BYTES).decode("utf-8")
    except FileNotFoundError:
        raise FileNotFoundError(f"build config not found: {build_path}")

    steps = json.loads(build_text).get("steps", [])
    step = next((item for item in steps if item.get("name") == "symcc"), None) or (steps[0] if steps else None)
    if step is None:
        raise ValueError(f"build config has no steps: {build_path}")

    gen_dir = root / "klee" / "harnesses" / "gen"
    _ensure_managed_directory(root, gen_dir)
    pack_source = gen_dir / f"{short}-pack.cpp"
    # KLEE entry wrapper: a symbolic buffer + bounded symbolic size into the
    # harness's LLVMFuzzerTestOneInput (the FUZZ_MAIN file-replay main is
    # useless under KLEE — there is no file to replay).
    wrapper = gen_dir / f"{short}-pack-main.cpp"
    sym_bytes = 64
    wrapper_text = "\n".join(
        [
            f"// KLEE pack entry for target '{short}' (generated by klee-pack-gen).",
            '#include "klee/klee.h"',
            "#include <cstddef>",
            "#include <cstdint>",
            'extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);',
            "int main() {",
            f"  static uint8_t data[{sym_bytes}];",
            '  klee_make_symbolic(data, sizeof data, "fuzz_input");',
            "  size_t size = 0;",
            '  klee_make_symbolic(&size, sizeof size, "fuzz_size");',
            "  klee_assume(size <= sizeof data);",
            "  return LLVMFuzzerTestOneInput(data, size);",
            "}",
            "",
        ]
    )

    compile_args = [
        "-I/work/harnesses",
        "-isystem", "/work/host-include",
        "-Wno-everything",
        "-std=c++17",
    ]
    link_sources: list[str] = []
    notes: list[str] = []
    blockers: list[str] = []
    harness_resolved = str(harness.resolve())
    placeholders = {
        "target_dir": str(target_dir),
        "bin_dir": str(root / "bin" / short),
        "workspace_root": str(root),
        "source_dir": source_dir,
    }
    argv = [_substitute(str(item), placeholders) for item in step.get("argv", [])]
    for arg in argv:
        if arg.startswith("-D") and arg != "-DFUZZ_MAIN":
            compile_args.append(arg)
        elif arg.startswith("-I"):
            mapped = _map_pack_path(
                arg[2:], source_dir=source_dir, root=root, gen_dir=gen_dir,
                short=short, notes=notes, blockers=blockers, extra_mounts=extra_mounts,
            )
            if mapped:
                compile_args.append(f"-I{mapped}")
        elif Path(arg).suffix.lower() in _LINK_SOURCE_SUFFIXES:
            if str(Path(arg).resolve()) == harness_resolved:
                continue
            drop_rule = _matching_drop_rule(arg, drop_link_sources, source_dir=source_dir, root=root)
            if drop_rule is not None:
                notes.append(
                    "semantic reduction: link source dropped by "
                    f"klee.drop_link_sources rule {drop_rule!r}: {arg}"
                )
                continue
            mapped = _map_pack_path(
                arg, source_dir=source_dir, root=root, gen_dir=gen_dir,
                short=short, notes=notes, blockers=blockers, extra_mounts=extra_mounts,
            )
            if mapped:
                link_sources.append(mapped)

    for include in force_includes:
        rendered = _substitute(include, placeholders)
        try:
            trusted_roots = [root]
            if source_dir:
                trusted_roots.append(Path(source_dir))
            trusted_roots.extend(host for host, _ in extra_mounts)
            rendered = str(
                _validate_host_regular_file(
                    rendered,
                    label="klee.force_includes",
                    trusted_roots=trusted_roots,
                )
            )
        except (OSError, ValueError) as exc:
            blockers.append(str(exc))
            continue
        mapped = _map_pack_path(
            rendered, source_dir=source_dir, root=root, gen_dir=gen_dir,
            short=short, notes=notes, blockers=blockers, extra_mounts=extra_mounts,
        )
        if mapped:
            compile_args.extend(["-include", mapped])
            notes.append(
                "semantic reduction: forced include added by "
                f"klee.force_includes and may replace target declarations: {rendered}"
            )

    entry = {
        "name": f"{short}-pack",
        "source": f"/work/harnesses/gen/{wrapper.name}",
        "linkSources": [f"/work/harnesses/gen/{pack_source.name}", *link_sources],
        "libcxx": True,
        "externalCalls": "concrete",
        "report": "both",
        "compileArgs": compile_args,
        "kleeArgs": [
            "--only-output-states-covering-new",
            "--dump-states-on-halt=false",
            f"--max-time={max(30, int(max_time_seconds))}",
        ],
        "allowFindings": ["ptr.err", "model.err", "exec.err", "external.err", "div.err", "cwe78.err", "cwe119.err"],
    }

    ci_path = root / "klee" / "gen-packs.ci.json"
    if blockers:
        return {
            "ok": False,
            "mode": "klee-pack-gen",
            "name": short,
            "pack_source": str(pack_source),
            "ci_config": str(ci_path),
            "entry": entry,
            "notes": notes,
            "blockers": blockers,
            "next_command": None,
        }
    for output_path in (pack_source, wrapper, ci_path):
        _validate_managed_destination(root, output_path)
    if ci_path.exists():
        try:
            payload = json.loads(
                _read_managed_file_bounded(root, ci_path, max_bytes=MAX_PACK_CONFIG_BYTES).decode("utf-8")
            )
        except (OSError, json.JSONDecodeError):
            payload = {}
    else:
        payload = {}
    payload.setdefault("outputRoot", "/work/klee-ng-out/gen-packs")
    targets = [item for item in payload.get("targets", []) if item.get("name") != entry["name"]]
    targets.append(entry)
    payload["targets"] = targets
    _atomic_write_managed_group(
        root,
        [
            (pack_source, harness_payload, MAX_SOURCE_BYTES),
            (wrapper, wrapper_text.encode("utf-8"), MAX_SOURCE_BYTES),
            (
                ci_path,
                (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
                MAX_PACK_CONFIG_BYTES,
            ),
        ],
    )

    return {
        "ok": True,
        "mode": "klee-pack-gen",
        "name": short,
        "pack_source": str(pack_source),
        "ci_config": str(ci_path),
        "entry": entry,
        "notes": notes,
        "blockers": [],
        "next_command": f"symbolic-worker-run <run> --mode klee --klee-config {ci_path.name}",
    }


def _validate_pack_target_name(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("KLEE pack target name must be a string")
    short = value.removeprefix("localfuzz/c/")
    if not _TARGET_SLUG_RE.fullmatch(short):
        raise ValueError("KLEE pack target name must be a lowercase target slug")
    return short


def _bounded_string_list(config: Mapping[str, Any], key: str) -> list[str]:
    raw = config.get(key)
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"klee.{key} must be an array of strings")
    if len(raw) > MAX_KLEE_POLICY_ITEMS:
        raise ValueError(f"klee.{key} exceeds {MAX_KLEE_POLICY_ITEMS} entries")
    values: list[str] = []
    for index, item in enumerate(raw):
        if not isinstance(item, str):
            raise ValueError(f"klee.{key}[{index}] must be a string")
        if not item or "\x00" in item:
            raise ValueError(f"klee.{key}[{index}] must be a non-empty path")
        if len(item.encode("utf-8")) > MAX_KLEE_POLICY_ITEM_BYTES:
            raise ValueError(f"klee.{key}[{index}] exceeds {MAX_KLEE_POLICY_ITEM_BYTES} bytes")
        values.append(item)
    return values


def _canonical_extra_mounts(raw: Any) -> list[tuple[Path, str]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("workspace extra_mounts must be an array")
    if len(raw) > MAX_EXTRA_MOUNTS:
        raise ValueError(f"workspace extra_mounts exceeds {MAX_EXTRA_MOUNTS} entries")
    mounts: dict[Path, str] = {}
    containers: dict[str, Path] = {}
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise ValueError(f"workspace extra_mounts[{index}] must be an object")
        host = item.get("host")
        container = item.get("container")
        if not isinstance(host, str) or not host or "\x00" in host:
            raise ValueError(f"workspace extra_mounts[{index}].host must be a non-empty path")
        host_path = Path(host).expanduser()
        if not host_path.is_absolute():
            raise ValueError(f"workspace extra_mounts[{index}].host must be an absolute path")
        if not isinstance(container, str) or not container.startswith("/"):
            raise ValueError(f"workspace extra_mounts[{index}].container must be an absolute path")
        if any(ord(character) < 32 or ord(character) == 127 for character in container):
            raise ValueError(f"workspace extra_mounts[{index}].container contains a control character")
        if "\\" in container:
            raise ValueError(f"workspace extra_mounts[{index}].container must use '/' separators")
        normalized_container = container.rstrip("/") or "/"
        components = normalized_container.split("/")[1:]
        if any(component in ("", ".", "..") for component in components):
            raise ValueError(f"workspace extra_mounts[{index}].container is not canonical")
        canonical_host = host_path.resolve(strict=False)
        canonical_container = normalized_container
        previous = mounts.get(canonical_host)
        if previous is not None and previous != canonical_container:
            raise ValueError(f"workspace extra_mounts has conflicting mappings for {canonical_host}")
        previous_host = containers.get(canonical_container)
        if previous_host is not None:
            raise ValueError(
                "workspace extra_mounts has duplicate container identity "
                f"{canonical_container}"
            )
        mounts[canonical_host] = canonical_container
        containers[canonical_container] = canonical_host
    return sorted(mounts.items(), key=lambda item: len(item[0].parts), reverse=True)


def _mount_path(resolved: Path, mounts: list[tuple[Path, str]]) -> str | None:
    for host, container in mounts:
        try:
            relative = resolved.relative_to(host)
        except ValueError:
            continue
        if relative == Path("."):
            return container
        return f"{container.rstrip('/')}/{relative.as_posix()}"
    return None


def _matching_drop_rule(path_text: str, rules: list[str], *, source_dir: str, root: Path) -> str | None:
    if not rules:
        return None
    resolved = Path(path_text).expanduser().resolve(strict=False)
    identities = {Path(path_text).as_posix().removeprefix("./")}
    bases = [root.resolve()]
    if source_dir:
        bases.append(Path(source_dir).expanduser().resolve(strict=False))
    for base in bases:
        try:
            identities.add(resolved.relative_to(base).as_posix())
        except ValueError:
            pass
    for rule in rules:
        candidate = Path(rule).expanduser()
        if candidate.is_absolute():
            if resolved == candidate.resolve(strict=False):
                return rule
        elif candidate.as_posix().removeprefix("./") in identities:
            return rule
    return None


def _ensure_managed_directory(root: Path, directory: Path) -> None:
    root_resolved = root.resolve()
    try:
        relative = directory.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"managed directory escapes workspace: {directory}") from exc
    cursor = root_resolved
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError(f"refusing symlinked managed directory: {cursor}")
        if cursor.exists():
            if not cursor.is_dir():
                raise ValueError(f"managed directory component is not a directory: {cursor}")
        else:
            cursor.mkdir()


def _managed_relative(root: Path, path: Path) -> tuple[Path, Path]:
    root_resolved = root.resolve()
    try:
        relative = path.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"managed path escapes workspace: {path}") from exc
    return root_resolved, relative


def _validate_managed_existing_file(root: Path, path: Path) -> None:
    root_resolved, relative = _managed_relative(root, path)
    cursor = root_resolved
    for index, part in enumerate(relative.parts):
        cursor /= part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            raise FileNotFoundError(cursor) from None
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"refusing symbolic link in managed path: {cursor}")
        final = index == len(relative.parts) - 1
        if final and not stat.S_ISREG(info.st_mode):
            raise ValueError(f"managed input is not a regular file: {cursor}")
        if not final and not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"managed input parent is not a directory: {cursor}")


def _validate_managed_destination(root: Path, path: Path) -> None:
    _managed_relative(root, path)
    _ensure_managed_directory(root, path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"refusing symbolic link at managed destination: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"managed destination is not a regular file: {path}")


def _read_managed_file_bounded(root: Path, path: Path, *, max_bytes: int) -> bytes:
    _validate_managed_existing_file(root, path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"managed input is not a regular file: {path}")
        if info.st_size > max_bytes:
            raise ValueError(f"managed input exceeds {max_bytes} bytes: {path}")
        payload = bytearray()
        while len(payload) <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > max_bytes:
            raise ValueError(f"managed input exceeds {max_bytes} bytes: {path}")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _atomic_write_managed_bytes(root: Path, path: Path, payload: bytes, *, max_bytes: int) -> None:
    if len(payload) > max_bytes:
        raise ValueError(f"managed output exceeds {max_bytes} bytes: {path}")
    _validate_managed_destination(root, path)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _atomic_write_managed_group(
    root: Path,
    outputs: list[tuple[Path, bytes, int]],
) -> None:
    """Publish related managed files together, restoring every prior file on failure."""
    if len({path for path, _, _ in outputs}) != len(outputs):
        raise ValueError("managed output group contains duplicate destinations")
    staged: dict[Path, Path] = {}
    backups: dict[Path, Path | None] = {}
    promoted: list[Path] = []
    touched_directories: set[Path] = set()
    published = False
    try:
        for path, payload, max_bytes in outputs:
            if len(payload) > max_bytes:
                raise ValueError(f"managed output exceeds {max_bytes} bytes: {path}")
            _validate_managed_destination(root, path)
            descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
            temporary = Path(temporary_name)
            staged[path] = temporary
            touched_directories.add(path.parent)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())

        for path, _, _ in outputs:
            _validate_managed_destination(root, path)
            backup: Path | None = None
            if path.exists():
                descriptor, backup_name = tempfile.mkstemp(prefix=f".{path.name}.old-", dir=path.parent)
                os.close(descriptor)
                backup = Path(backup_name)
                backup.unlink()
                os.replace(path, backup)
            backups[path] = backup
            os.replace(staged[path], path)
            promoted.append(path)

        for directory in touched_directories:
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        published = True
    except BaseException:
        for path in reversed([item[0] for item in outputs]):
            backup = backups.get(path)
            if path in promoted:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            if backup is not None and backup.exists():
                os.replace(backup, path)
        raise
    finally:
        for temporary in staged.values():
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        if published:
            for backup in backups.values():
                if backup is None:
                    continue
                try:
                    backup.unlink()
                except OSError:
                    pass


def _lexical_relative_to_base(candidate: Path, base: Path) -> Path | None:
    """Find a lexical relative path while tolerating aliases such as /var -> /private/var."""
    candidate_absolute = candidate.expanduser().absolute()
    base_absolute = base.expanduser().absolute()
    try:
        return candidate_absolute.relative_to(base_absolute)
    except ValueError:
        pass

    base_resolved = base_absolute.resolve(strict=False)
    for ancestor in (candidate_absolute, *candidate_absolute.parents):
        try:
            if ancestor.resolve(strict=False) != base_resolved:
                continue
            return candidate_absolute.relative_to(ancestor)
        except (OSError, ValueError):
            continue
    return None


def _validate_host_regular_file(
    path_text: str,
    *,
    label: str,
    trusted_roots: list[Path] | None = None,
) -> Path:
    candidate = Path(path_text).expanduser()
    if not candidate.is_absolute():
        raise ValueError(f"{label} path must be absolute: {path_text}")
    candidate_absolute = candidate.absolute()
    relative: Path | None = None
    trusted_base: Path | None = None
    for base in trusted_roots or []:
        base_path = Path(base).expanduser().absolute()
        candidate_relative = _lexical_relative_to_base(candidate_absolute, base_path)
        if candidate_relative is None:
            continue
        if relative is None or len(candidate_relative.parts) < len(relative.parts):
            relative = candidate_relative
            trusted_base = base_path
    if relative is not None and trusted_base is not None:
        cursor = trusted_base
        for part in relative.parts:
            cursor /= part
            try:
                info = cursor.lstat()
            except FileNotFoundError:
                raise ValueError(f"{label} path does not exist: {path_text}") from None
            if stat.S_ISLNK(info.st_mode):
                raise ValueError(f"{label} path contains a symbolic link: {path_text}")
    try:
        path_info = candidate.lstat()
    except FileNotFoundError:
        raise ValueError(f"{label} path does not exist: {path_text}") from None
    if stat.S_ISLNK(path_info.st_mode) or not stat.S_ISREG(path_info.st_mode):
        raise ValueError(f"{label} path is not a regular non-symlink file: {path_text}")
    try:
        descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        raise ValueError(f"{label} path does not exist: {path_text}") from None
    except OSError as exc:
        raise ValueError(f"{label} path is not a regular non-symlink file: {path_text}") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"{label} path is not a regular file: {path_text}")
    finally:
        os.close(descriptor)
    return candidate.resolve()


def _copy_regular_file_bounded(source: Path, destination: Path, *, byte_cap: int) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(source, flags)
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError(f"staged path is not a regular file: {source}")
        if source_stat.st_size > byte_cap:
            raise ValueError(f"staged file exceeds {byte_cap} bytes: {source}")
        copied = 0
        with os.fdopen(os.dup(source_fd), "rb") as reader, destination.open("xb") as writer:
            while True:
                chunk = reader.read(min(1024 * 1024, byte_cap - copied + 1))
                if not chunk:
                    break
                copied += len(chunk)
                if copied > byte_cap:
                    raise ValueError(f"staged file grew beyond {byte_cap} bytes: {source}")
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
        final_stat = os.fstat(source_fd)
        trailing_data = os.read(source_fd, 1)
        eof_stat = os.fstat(source_fd)
        initial_identity = (
            source_stat.st_dev,
            source_stat.st_ino,
            source_stat.st_size,
            source_stat.st_mtime_ns,
            source_stat.st_ctime_ns,
        )
        final_identities = {
            (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
            for info in (final_stat, eof_stat)
        }
        if copied != source_stat.st_size or trailing_data or final_identities != {initial_identity}:
            raise ValueError(f"staged file changed while being copied: {source}")
        return copied
    finally:
        os.close(source_fd)


def _publish_staged_directory(staged: Path, destination: Path) -> None:
    if destination.is_symlink():
        raise ValueError(f"refusing symlinked staged destination: {destination}")
    if not destination.exists():
        os.replace(staged, destination)
        return
    if not destination.is_dir():
        raise ValueError(f"staged destination is not a directory: {destination}")
    backup = Path(tempfile.mkdtemp(prefix=f".{destination.name}.old-", dir=destination.parent))
    backup.rmdir()
    os.replace(destination, backup)
    try:
        os.replace(staged, destination)
    except Exception:
        os.replace(backup, destination)
        raise
    shutil.rmtree(backup, ignore_errors=True)


def _stage_header_tree(
    source: Path,
    destination: Path,
    *,
    directory_cap: int = MAX_STAGED_DIRECTORIES,
    depth_cap: int = MAX_STAGE_DEPTH,
    file_cap: int = MAX_STAGED_FILES,
    per_file_byte_cap: int = MAX_STAGED_FILE_BYTES,
    total_byte_cap: int = MAX_STAGED_TOTAL_BYTES,
) -> dict[str, Any]:
    """Stage a bounded header closure, publishing only after a complete scan."""
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        return {
            "ok": False,
            "directories": 0,
            "files": 0,
            "bytes": 0,
            "blocker": "header staging destination parent must be a prepared, non-symlink directory",
        }
    staged = Path(tempfile.mkdtemp(prefix=f".{destination.name}.stage-", dir=destination.parent))
    directories = 0
    files = 0
    total_bytes = 0
    try:
        pending: list[tuple[Path, Path, int]] = [(source, staged, 0)]
        while pending:
            current, output, depth = pending.pop()
            directories += 1
            if directories > directory_cap:
                raise ValueError(f"header staging exceeds directory cap {directory_cap}")
            if depth > depth_cap:
                raise ValueError(f"header staging exceeds depth cap {depth_cap}")
            output.mkdir(parents=True, exist_ok=True)
            with os.scandir(current) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
            child_directories: list[tuple[Path, Path, int]] = []
            for entry in entries:
                entry_path = Path(entry.path)
                if entry.is_symlink():
                    raise ValueError(f"header staging refuses symlink: {entry_path}")
                if entry.is_dir(follow_symlinks=False):
                    child_directories.append((entry_path, output / entry.name, depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                if entry_path.suffix.lower() not in _HEADER_SUFFIXES:
                    continue
                files += 1
                if files > file_cap:
                    raise ValueError(f"header staging exceeds file cap {file_cap}")
                remaining = total_byte_cap - total_bytes
                if remaining < 0:
                    raise ValueError(f"header staging exceeds aggregate cap {total_byte_cap} bytes")
                entry_size = entry.stat(follow_symlinks=False).st_size
                if entry_size > per_file_byte_cap:
                    raise ValueError(
                        f"header staging exceeds per-file cap {per_file_byte_cap} bytes: {entry_path}"
                    )
                if entry_size > remaining:
                    raise ValueError(f"header staging exceeds aggregate cap {total_byte_cap} bytes")
                copied = _copy_regular_file_bounded(
                    entry_path,
                    output / entry.name,
                    byte_cap=min(per_file_byte_cap, remaining),
                )
                total_bytes += copied
            pending.extend(reversed(child_directories))
        _publish_staged_directory(staged, destination)
        return {"ok": True, "directories": directories, "files": files, "bytes": total_bytes}
    except (OSError, ValueError) as exc:
        if staged.exists():
            shutil.rmtree(staged)
        return {
            "ok": False,
            "directories": directories,
            "files": files,
            "bytes": total_bytes,
            "blocker": str(exc),
        }


def _map_pack_path(
    path_text: str,
    *,
    source_dir: str,
    root: Path,
    gen_dir: Path,
    short: str,
    notes: list[str],
    blockers: list[str] | None = None,
    extra_mounts: list[tuple[Path, str]] | None = None,
) -> str | None:
    """Map a build.json path onto the klee container's view of the world."""
    candidate = Path(path_text).expanduser()
    lexical = candidate.absolute()
    resolved = candidate.resolve(strict=False)
    mounted = _mount_path(resolved, extra_mounts or [])
    if mounted is not None:
        return mounted
    root_resolved = root.resolve()
    lexical_workspace_path = _lexical_relative_to_base(lexical, root) is not None
    if lexical_workspace_path:
        try:
            resolved.relative_to(root_resolved)
        except ValueError:
            message = f"workspace path escapes through a symbolic link, dropped: {path_text}"
            notes.append(message)
            if blockers is not None:
                blockers.append(message)
            return None
    if source_dir:
        source_root = Path(source_dir).expanduser().resolve(strict=False)
        try:
            resolved.relative_to(source_root)
        except ValueError:
            pass
        else:
            return str(resolved)  # source tree is mounted at the same path in-container
    try:
        workspace_relative = resolved.relative_to(root_resolved)
    except ValueError:
        workspace_relative = None
    if workspace_relative is not None:
        if resolved.is_file():
            destination = root_resolved / "klee" / "harnesses" / "gen" / "workspace" / workspace_relative
            temporary: Path | None = None
            try:
                _ensure_managed_directory(root_resolved, destination.parent)
                temporary_fd, temporary_name = tempfile.mkstemp(
                    prefix=f".{destination.name}.", dir=destination.parent
                )
                os.close(temporary_fd)
                temporary = Path(temporary_name)
                temporary.unlink()
                _copy_regular_file_bounded(resolved, temporary, byte_cap=MAX_STAGED_FILE_BYTES)
                if destination.is_symlink():
                    raise ValueError(f"refusing symlinked staged destination: {destination}")
                os.replace(temporary, destination)
            except (OSError, ValueError) as exc:
                if temporary is not None and temporary.exists():
                    temporary.unlink()
                message = f"workspace file staging failed: {path_text}: {exc}"
                notes.append(message)
                if blockers is not None:
                    blockers.append(message)
                return None
            return f"/work/harnesses/gen/workspace/{workspace_relative.as_posix()}"
        if resolved.is_dir():
            destination = root_resolved / "klee" / "gen-include" / short / "workspace" / workspace_relative
            try:
                destination.resolve(strict=False).relative_to(resolved)
            except ValueError:
                pass
            else:
                message = f"workspace directory dropped: copy destination is inside source: {path_text}"
                notes.append(message)
                if blockers is not None:
                    blockers.append(message)
                return None
            try:
                _ensure_managed_directory(root_resolved, destination.parent)
            except (OSError, ValueError) as exc:
                result = {"ok": False, "blocker": str(exc)}
            else:
                result = _stage_header_tree(resolved, destination)
            if not result["ok"]:
                message = f"workspace header staging failed: {path_text}: {result['blocker']}"
                notes.append(message)
                if blockers is not None:
                    blockers.append(message)
                return None
            notes.append(
                "workspace header tree staged: "
                f"{path_text} ({result['files']} files, {result['bytes']} bytes)"
            )
            return f"/work/gen-include/{short}/workspace/{workspace_relative.as_posix()}"
        message = f"workspace path missing, dropped: {path_text}"
        notes.append(message)
        if blockers is not None:
            blockers.append(message)
        return None
    # system paths: keep and let the container's compiler resolve or complain
    notes.append(f"system path passed through: {path_text}")
    return path_text


# ---------------------------------------------------------------------------
# type_enum


def _generate_type_enum(spec: dict[str, Any], *, target_dir: Path, placeholders: Mapping[str, str]) -> dict[str, Any]:
    header_globs = [_substitute(str(item), placeholders) for item in spec.get("header_globs", [])]
    class_regex = re.compile(str(spec.get("class_regex") or r"^class ([A-Za-z0-9_]+)\b"), re.MULTILINE)
    include_root = Path(_substitute(str(spec.get("include_root") or ""), placeholders))
    decoder = spec.get("decoder") or {}
    max_types = max(1, min(int(spec.get("max_types", MAX_TYPES)), MAX_TYPES))

    headers: list[Path] = []
    for pattern in header_globs:
        headers.extend(sorted(Path("/").glob(pattern.lstrip("/"))) if pattern.startswith("/") else [])
        if len(headers) >= MAX_HEADERS_SCANNED:
            break
    headers = headers[:MAX_HEADERS_SCANNED]

    entries: list[tuple[str, str, str]] = []  # (include_rel, namespace, class)
    for header in headers:
        if len(entries) >= max_types:
            break
        try:
            text = header.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        namespace = _first_namespace(text)
        classes = [match.group(1) for match in class_regex.finditer(text)]
        if not classes:
            continue
        try:
            include_rel = str(header.relative_to(include_root))
        except ValueError:
            include_rel = str(header)
        for cls in sorted(set(classes)):
            if len(entries) >= max_types:
                break
            entries.append((include_rel, namespace, cls))

    if not entries:
        return {
            "summary": {"headers_scanned": len(headers), "types": 0},
            "needs_authoring": True,
            "blockers": ["type_enum matched no types (check header_globs/class_regex)"],
        }

    includes = sorted({entry[0] for entry in entries})
    include_lines = [f'#include "{rel}"' for rel in includes]
    case_lines = []
    for index, (_, namespace, cls) in enumerate(entries):
        qualified = f"{namespace}::{cls}" if namespace else cls
        case_lines.append(f"    case {index}: DecodeOne<{qualified}>(data + 3, static_cast<int>(size - 3)); break;")

    decoder_includes = [f'#include "{item}"' for item in decoder.get("includes", [])]
    decoder_template = str(
        decoder.get("template")
        or "template <class T>\nstatic inline void DecodeOne(const uint8_t* d, int n) {\n  try {\n    T value;\n    (void)d; (void)n; (void)value;\n  } catch (...) {\n  }\n}"
    )

    harness = "\n".join(
        [
            f"// Auto-generated by target-generate (type_enum, {len(entries)} types). Do not edit by hand.",
            "// Layout: [byte0 reserved][byte1-2 LE selector][bytes 3..: payload]",
            "",
            "#include <cstddef>",
            "#include <cstdint>",
            "#include <cstring>",
            *decoder_includes,
            "",
            *include_lines,
            "",
            decoder_template,
            "",
            f"static const unsigned kTypeCount = {len(entries)};",
            "",
            'extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {',
            "  if (size < 4) return 0;",
            "  unsigned which = (static_cast<unsigned>(data[1]) | (static_cast<unsigned>(data[2]) << 8)) % kTypeCount;",
            "  switch (which) {",
            *case_lines,
            "  }",
            "  return 0;",
            "}",
            "",
            _file_main_block(),
        ]
    )
    written_flag, written_note = _write_generated(target_dir / "harness.cpp", harness)
    if not written_flag:
        return {
            "summary": {"preserved": written_note},
            "written": [],
            "build_steps": [],
            "blockers": [],
            "needs_authoring": False,
            "skipped": [{"reason": written_note}],
        }

    build_steps = _substituted_build_steps(spec, placeholders)
    return {
        "summary": {"headers_scanned": len(headers), "types": len(entries), "includes": len(includes)},
        "written": [str(target_dir / "harness.cpp")],
        "build_steps": build_steps,
        "blockers": [] if build_steps else ["spec has no build.steps"],
    }


# ---------------------------------------------------------------------------
# direct_call


def _generate_direct_call(
    spec: dict[str, Any], *, target_dir: Path, sinks: list[dict[str, Any]], placeholders: Mapping[str, str]
) -> dict[str, Any]:
    source_root = Path(_substitute(str(spec.get("source_root") or ""), placeholders))
    max_candidates = max(1, min(int(spec.get("max_candidates", 8)), MAX_CANDIDATES))

    candidates = []
    skipped = []
    seen_methods: set[tuple[str, str]] = set()
    for sink in sinks:
        key = (str(sink.get("file")), str(sink.get("method")))
        if key in seen_methods:
            continue
        seen_methods.add(key)
        source_path = source_root / str(sink.get("file") or "")
        if not source_path.is_file():
            skipped.append({"method": key[1], "file": key[0], "reason": "source file not found"})
            continue
        extraction = extract_function_signature(source_path, str(sink.get("method")), line_hint=sink.get("line"))
        if extraction is None:
            skipped.append({"method": key[1], "file": key[0], "reason": "signature not found"})
            continue
        if _tu_defines_main(source_path):
            skipped.append(
                {"method": key[1], "file": key[0],
                 "reason": "translation unit defines main() (standalone tool; needs authored replica)",
                 "signature": extraction["signature"]}
            )
            continue
        shape = _classify_fuzzable(extraction)
        if shape is None:
            skipped.append(
                {"method": key[1], "file": key[0], "reason": f"unfuzzable signature: {extraction['params_text']}",
                 "signature": extraction["signature"]}
            )
            continue
        if extraction["is_static"]:
            skipped.append({"method": key[1], "file": key[0], "reason": "internal linkage (static)"})
            continue
        if extraction["is_class_method"]:
            skipped.append({"method": key[1], "file": key[0], "reason": "instance/class method (needs authored setup)"})
            continue
        candidates.append({"sink": sink, "extraction": extraction, "shape": shape, "tu": str(source_path)})
        if len(candidates) >= max_candidates:
            break

    if not candidates:
        return {
            "summary": {"sinks": len(sinks), "candidates": 0, "skipped": len(skipped)},
            "skipped": skipped,
            "needs_authoring": True,
            "blockers": [],
        }

    # When the spec names the module's public headers, include them instead of
    # rendering prototypes: functions returning project types (thrift structs,
    # spec classes) need complete type definitions at the call site, which a
    # bare prototype cannot provide.
    harness_includes = [
        _substitute(str(entry), placeholders) for entry in (spec.get("harness_includes") or []) if str(entry).strip()
    ]
    include_lines = [f'#include "{entry}"' for entry in harness_includes]

    prototypes = []
    calls = []
    tus = []
    for index, candidate in enumerate(candidates):
        extraction = candidate["extraction"]
        if not include_lines:
            prototypes.append(_render_prototype(extraction))
        calls.append(f"    case {index}: {_render_call(extraction, candidate['shape'])} break;")
        if candidate["tu"] not in tus:
            tus.append(candidate["tu"])

    harness = "\n".join(
        [
            f"// Auto-generated by target-generate (direct_call, {len(candidates)} candidates). Do not edit by hand.",
            "// Layout: [byte0 selector][bytes 1..: payload]",
            "",
            "#include <cstddef>",
            "#include <cstdint>",
            "#include <string>",
            *include_lines,
            "",
            *prototypes,
            "",
            f"static const unsigned kCandidateCount = {len(candidates)};",
            "",
            'extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {',
            "  if (size < 2) return 0;",
            "  const uint8_t* payload = data + 1;",
            "  size_t payload_size = size - 1;",
            "  unsigned which = data[0] % kCandidateCount;",
            "  try {",
            "  switch (which) {",
            *calls,
            "  }",
            "  } catch (...) {",
            "  }",
            "  return 0;",
            "}",
            "",
            _file_main_block(),
        ]
    )
    written_flag, written_note = _write_generated(target_dir / "harness.cpp", harness)
    if not written_flag:
        return {
            "summary": {"preserved": written_note},
            "written": [],
            "build_steps": [],
            "blockers": [],
            "needs_authoring": False,
            "skipped": [{"reason": written_note}],
        }

    build_steps = _substituted_build_steps(spec, placeholders, extra_sources=tus)
    return {
        "summary": {
            "sinks": len(sinks),
            "candidates": len(candidates),
            "skipped": len(skipped),
            "translation_units": tus,
            "functions": [candidate["extraction"]["qualified"] for candidate in candidates],
        },
        "skipped": skipped,
        "written": [str(target_dir / "harness.cpp")],
        "build_steps": build_steps,
        "blockers": [] if build_steps else ["spec has no build.steps"],
        "needs_authoring": bool(skipped),
    }


# ---------------------------------------------------------------------------
# sequence (stateful op-tape lane)

MAX_SEQUENCE_OPS = 64
MAX_SEQUENCE_ARG_BYTES = 1_048_576
MAX_SEQUENCE_SLOTS = 16
SEQUENCE_ARG_KINDS = {"bytes", "u8", "u32", "u64", "slot"}
_SEQUENCE_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")


def _generate_sequence(spec: dict[str, Any], *, target_dir: Path, placeholders: Mapping[str, str]) -> dict[str, Any]:
    """Stateful multi-op harness: the input is an op-tape —
    ``[1 op byte][per-arg TLV: 2-byte LE length + bytes]`` repeated up to
    ``max_ops`` times, op selected by ``tape[i] % len(ops)``. A fresh
    context per input (setup/teardown from the spec) keeps crashes
    deterministic; sequence state lives across *ops*, never across inputs.

    The tape format is deliberately simple so seedgen scripts and the
    grammar lane can author structured sequences (op byte + TLV args).
    """
    raw_context = spec.get("context") or {}
    raw_ops = spec.get("ops") or []
    if not isinstance(raw_ops, list) or not raw_ops:
        return {"summary": {"ops": 0}, "needs_authoring": True, "blockers": ["sequence spec has no ops"]}
    if len(raw_ops) > MAX_SEQUENCE_OPS:
        return {"summary": {"ops": len(raw_ops)}, "needs_authoring": True,
                "blockers": [f"sequence spec exceeds {MAX_SEQUENCE_OPS} ops"]}
    blockers: list[str] = []
    if not isinstance(raw_context, Mapping):
        blockers.append("sequence context must be an object")
        context: Mapping[str, Any] = {}
    else:
        context = raw_context
    raw_max_ops = spec.get("max_ops", 16)
    if isinstance(raw_max_ops, bool) or not isinstance(raw_max_ops, int) or not 1 <= raw_max_ops <= 256:
        blockers.append("sequence max_ops must be an integer between 1 and 256")
        max_ops = 16
    else:
        max_ops = raw_max_ops
    includes = spec.get("includes", [])
    if not isinstance(includes, list) or len(includes) > 128 or not all(isinstance(item, str) for item in includes):
        blockers.append("sequence includes must be a bounded string list")
        includes = []

    ops: list[dict[str, Any]] = []
    for op_index, raw_op in enumerate(raw_ops):
        if not isinstance(raw_op, Mapping):
            blockers.append(f"sequence ops[{op_index}] must be an object")
            continue
        op = dict(raw_op)
        op_name = str(op.get("name") or f"op{op_index}")
        if not _SEQUENCE_IDENTIFIER_RE.fullmatch(op_name):
            blockers.append(f"sequence ops[{op_index}].name must be a C++ identifier")
        call = op.get("call", "")
        if not isinstance(call, str) or len(call) > 16_384:
            blockers.append(f"sequence op {op_name}: call must be a bounded string")
        raw_args = op.get("args", []) or []
        if not isinstance(raw_args, list) or len(raw_args) > 128:
            blockers.append(f"sequence op {op_name}: args must be a bounded list")
            raw_args = []
        args: list[dict[str, Any]] = []
        seen_arg_names: set[str] = set()
        for arg_index, raw_arg in enumerate(raw_args):
            if not isinstance(raw_arg, Mapping):
                blockers.append(f"sequence op {op_name}: args[{arg_index}] must be an object")
                continue
            arg = dict(raw_arg)
            arg_name = str(arg.get("name") or "arg")
            if not _SEQUENCE_IDENTIFIER_RE.fullmatch(arg_name):
                blockers.append(f"sequence op {op_name}: arg name must be a C++ identifier")
            elif arg_name in seen_arg_names:
                blockers.append(f"sequence op {op_name}: duplicate arg name {arg_name!r}")
            seen_arg_names.add(arg_name)
            kind = str(arg.get("kind") or "bytes")
            if kind not in SEQUENCE_ARG_KINDS:
                blockers.append(f"op {op_name}: arg kind {kind!r} not in {sorted(SEQUENCE_ARG_KINDS)}")
            if kind == "bytes":
                maximum = arg.get("max", 4096)
                if isinstance(maximum, bool) or not isinstance(maximum, int) or not 0 <= maximum <= MAX_SEQUENCE_ARG_BYTES:
                    blockers.append(
                        f"sequence op {op_name}: bytes max must be an integer between 0 and {MAX_SEQUENCE_ARG_BYTES}"
                    )
            args.append(arg)
        op["name"] = op_name
        op["args"] = args
        ops.append(op)

    handles = spec.get("handles")
    slot_count = 0
    handle_lines: list[str] = []
    if handles is not None:
        if not isinstance(handles, Mapping):
            blockers.append("sequence handles must be an object")
        else:
            handle_type = str(handles.get("type") or "").strip()
            initializer = str(handles.get("init") or "").strip()
            raw_slots = handles.get("slots")
            if not handle_type:
                blockers.append("sequence handles.type is required")
            if not initializer:
                blockers.append("sequence handles.init is required")
            if isinstance(raw_slots, bool) or not isinstance(raw_slots, int):
                blockers.append("sequence handles.slots must be an integer")
            elif not 1 <= raw_slots <= MAX_SEQUENCE_SLOTS:
                blockers.append(f"sequence handles.slots must be between 1 and {MAX_SEQUENCE_SLOTS}")
            else:
                slot_count = raw_slots
            if len(handle_type) > 512 or len(initializer) > 4096:
                blockers.append("sequence handles type/init exceeds the generated-code cap")
            if not blockers:
                handle_type = _substitute(handle_type, placeholders)
                initializer = _substitute(initializer, placeholders)
                # Initializer-list construction works for non-default-constructible
                # handle types and does not assign into uninitialized slots.
                initializers = ", ".join(initializer for _ in range(slot_count))
                handle_lines = [f"  {handle_type} handles[{slot_count}] = {{{initializers}}};"]

    for op in ops:
        for arg in op["args"]:
            kind = str(arg.get("kind") or "bytes")
            if kind == "slot" and handles is None:
                blockers.append(f"op {op.get('name')}: slot arg requires a handles declaration")
    if blockers:
        return {"summary": {"ops": len(ops)}, "needs_authoring": True, "blockers": blockers}

    include_lines = [f'#include "{_substitute(item, placeholders)}"' for item in includes]
    setup = _substitute(str(context.get("setup") or ""), placeholders)
    teardown = _substitute(str(context.get("teardown") or ""), placeholders)

    case_lines: list[str] = []
    for index, op in enumerate(ops):
        op_name = str(op.get("name") or f"op{index}")
        case_lines.append(f"      case {index}: {{  // {op_name}")
        for arg in op["args"]:
            arg_name = str(arg.get("name") or "arg")
            kind = str(arg.get("kind") or "bytes")
            if kind == "bytes":
                cap = int(arg.get("max", 4096))
                case_lines.append(f"        std::string {arg_name} = tape.bytes({cap});")
            elif kind == "u8":
                case_lines.append(f"        uint8_t {arg_name} = tape.u8();")
            elif kind == "u32":
                case_lines.append(f"        uint32_t {arg_name} = tape.u32();")
            elif kind == "slot":
                case_lines.append(
                    f"        size_t {arg_name} = static_cast<size_t>(tape.u8()) % {slot_count};"
                )
            else:
                case_lines.append(f"        uint64_t {arg_name} = tape.u64();")
        call = str(op.get("call") or "").strip()
        if call:
            case_lines.append(f"        try {{ {call} }} catch (...) {{}}")
        case_lines.append("        break;")
        case_lines.append("      }")

    setup_lines = [f"  {line}" for line in setup.splitlines() if line.strip()]
    teardown_lines = [f"    {line}" for line in teardown.splitlines() if line.strip()]

    harness = "\n".join(
        [
            f"// Auto-generated by target-generate (sequence, {len(ops)} ops). Do not edit by hand.",
            "// Op-tape input: repeated [1 op byte][per-arg TLV: 2-byte LE len + bytes],",
            f"// op = byte % {len(ops)}, at most {max_ops} ops per input. Integer args are",
            "// fixed-width LE reads (zero-padded on short tape). Seedgen scripts should",
            "// emit tapes in this format.",
            "",
            "#include <cstddef>",
            "#include <cstdint>",
            "#include <cstring>",
            "#include <string>",
            *include_lines,
            "",
            "namespace {",
            "struct Tape {",
            "  const uint8_t* p;",
            "  size_t n;",
            "  bool op_byte(uint8_t* out) {",
            "    if (n == 0) return false;",
            "    *out = *p; ++p; --n;",
            "    return true;",
            "  }",
            "  std::string bytes(size_t max_len) {",
            "    if (n < 2) { p += n; n = 0; return std::string(); }",
            "    size_t len = static_cast<size_t>(p[0]) | (static_cast<size_t>(p[1]) << 8);",
            "    p += 2; n -= 2;",
            "    if (len > max_len) len = max_len;",
            "    if (len > n) len = n;",
            "    std::string out(reinterpret_cast<const char*>(p), len);",
            "    p += len; n -= len;",
            "    return out;",
            "  }",
            "  uint64_t fixed(unsigned width) {",
            "    uint64_t value = 0;",
            "    for (unsigned i = 0; i < width; ++i) {",
            "      if (n == 0) break;",
            "      value |= static_cast<uint64_t>(*p) << (8 * i);",
            "      ++p; --n;",
            "    }",
            "    return value;",
            "  }",
            "  uint8_t u8() { return static_cast<uint8_t>(fixed(1)); }",
            "  uint32_t u32() { return static_cast<uint32_t>(fixed(4)); }",
            "  uint64_t u64() { return fixed(8); }",
            "};",
            "}  // namespace",
            "",
            f"static const unsigned kOpCount = {len(ops)};",
            f"static const unsigned kMaxOps = {max_ops};",
            "",
            'extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {',
            "  if (size == 0) return 0;",
            "  Tape tape{data, size};",
            *handle_lines,
            *setup_lines,
            "  uint8_t op = 0;",
            "  for (unsigned i = 0; i < kMaxOps && tape.op_byte(&op); ++i) {",
            "    switch (op % kOpCount) {",
            *case_lines,
            "    }",
            "  }",
            "  {",
            *(teardown_lines or ["    // no teardown declared"]),
            "  }",
            "  return 0;",
            "}",
            "",
            _file_main_block(),
        ]
    )
    written_flag, written_note = _write_generated(target_dir / "harness.cpp", harness)
    if not written_flag:
        return {
            "summary": {"preserved": written_note},
            "written": [],
            "build_steps": [],
            "blockers": [],
            "needs_authoring": False,
            "skipped": [{"reason": written_note}],
        }
    build_steps = _substituted_build_steps(spec, placeholders)
    return {
        "summary": {"ops": len(ops), "max_ops": max_ops, "slots": slot_count,
                    "args": sum(len(op.get("args", []) or []) for op in ops)},
        "written": [str(target_dir / "harness.cpp")],
        "build_steps": build_steps,
        "blockers": [] if build_steps else ["spec has no build.steps"],
    }


# ---------------------------------------------------------------------------
# symbolic_string (KLEE lane)


def _generate_symbolic_string(
    spec: dict[str, Any], *, root: Path, name: str, sinks: list[dict[str, Any]], placeholders: Mapping[str, str]
) -> dict[str, Any]:
    source_root = Path(_substitute(str(spec.get("source_root") or ""), placeholders))
    assert_header = str(spec.get("assert_header") or "cmdsink_assert.h")
    sym_size = max(4, min(int(spec.get("sym_size", 16)), 64))
    max_targets = max(1, min(int(spec.get("max_targets", 6)), MAX_CANDIDATES))
    ci_defaults = spec.get("ci_defaults") or {}
    gen_dir = root / "klee" / "harnesses" / "gen"
    gen_dir.mkdir(parents=True, exist_ok=True)

    targets = []
    skipped = []
    written = []
    seen_methods: set[tuple[str, str]] = set()
    for sink in sinks:
        if len(targets) >= max_targets:
            break
        key = (str(sink.get("file")), str(sink.get("method")))
        if key in seen_methods:
            continue
        seen_methods.add(key)
        source_path = source_root / str(sink.get("file") or "")
        if not source_path.is_file():
            skipped.append({"method": key[1], "file": key[0], "reason": "source file not found"})
            continue
        extraction = extract_function_signature(source_path, str(sink.get("method")), line_hint=sink.get("line"))
        if extraction is None:
            skipped.append({"method": key[1], "file": key[0], "reason": "signature not found"})
            continue
        string_params = [
            index for index, param in enumerate(extraction["params"]) if _is_stringish(param["type"])
        ]
        returns_string = "string" in extraction["returns"].lower()
        if extraction["is_class_method"] or extraction["is_static"] or not string_params or not returns_string:
            reason = (
                "instance/class method" if extraction["is_class_method"]
                else "internal linkage (static)" if extraction["is_static"]
                else "no string parameters" if not string_params
                else "does not return a command string"
            )
            skipped.append(
                {"method": key[1], "file": key[0], "reason": f"{reason} (needs authored builder replica)",
                 "signature": extraction["signature"]}
            )
            continue

        slug = _slugify(f"{name}-{extraction['name']}")[:48]
        harness_path = gen_dir / f"{slug}.cpp"
        sym_written, sym_note = _write_generated(
            harness_path,
            _render_symbolic_harness(extraction, string_params, assert_header=assert_header, sym_size=sym_size),
        )
        written.append(sym_note if sym_written else f"(preserved) {harness_path}")
        targets.append(
            {
                "name": slug,
                "source": f"/work/harnesses/gen/{harness_path.name}",
                "linkSources": [str(source_path)],
                **ci_defaults,
            }
        )

    if not targets:
        return {
            "summary": {"sinks": len(sinks), "klee_targets": 0, "skipped": len(skipped)},
            "skipped": skipped,
            "needs_authoring": True,
            "blockers": [],
        }

    ci_payload = {
        "outputRoot": f"/work/klee-ng-out/gen-{name}",
        "targets": targets,
    }
    ci_path = root / "klee" / str(spec.get("ci_output") or f"gen-{name}.ci.json")
    ci_path.write_text(json.dumps(ci_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    written.append(str(ci_path))

    return {
        "summary": {
            "sinks": len(sinks),
            "klee_targets": len(targets),
            "skipped": len(skipped),
            "ci_config": str(ci_path),
        },
        "skipped": skipped,
        "written": written,
        "blockers": [],
        "needs_authoring": bool(skipped),
    }


def _render_symbolic_harness(
    extraction: dict[str, Any], string_params: list[int], *, assert_header: str, sym_size: int
) -> str:
    args = []
    setup = []
    for index, param in enumerate(extraction["params"]):
        var = f"a{index}"
        if index in string_params:
            setup.append(f"  std::string {var};")
            setup.append(f'  klee_make_symbolic_std_string_n({var}, {sym_size}, "{var}");')
            args.append(var)
        elif _is_integral(param["type"]):
            setup.append(f"  {param['type'].replace('const', '').strip()} {var} = 1;")
            args.append(var)
        elif "bool" in param["type"]:
            setup.append(f"  bool {var} = false;")
            args.append(var)
        else:
            setup.append(f'  std::string {var};  // best-effort placeholder')
            args.append(var)
    return "\n".join(
        [
            f"// Auto-generated by target-generate (symbolic_string) for {extraction['qualified']}.",
            f"// Property: no attacker-controlled shell metacharacters in the returned command.",
            "",
            "#include <string>",
            '#include "klee/klee.h"',
            f'#include "{assert_header}"',
            "",
            _render_prototype(extraction),
            "",
            "int main() {",
            *setup,
            f"  std::string generated_command = {extraction['qualified']}({', '.join(args)});",
            "  klee_ng_assert_shell_safe(generated_command,",
            f'      "{extraction["qualified"]}: symbolic string parameter reaches command string");',
            "  return 0;",
            "}",
            "",
        ]
    )


# ---------------------------------------------------------------------------
# signature extraction


def extract_function_signature(source_path: Path, method: str, *, line_hint: Any = None) -> dict[str, Any] | None:
    try:
        if source_path.stat().st_size > MAX_SOURCE_BYTES:
            return None
        text = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if _CPP_LANGUAGE is not None:
        extraction = _extract_with_tree_sitter(text, method, line_hint)
        if extraction is not None:
            return extraction
    return _extract_with_regex(text, method)


def _extract_with_tree_sitter(text: str, method: str, line_hint: Any) -> dict[str, Any] | None:
    parser = tree_sitter.Parser(_CPP_LANGUAGE)
    tree = parser.parse(text.encode("utf-8"))
    best = None
    best_distance = None
    hint = int(line_hint) if isinstance(line_hint, (int, float)) else None

    def visit(node: Any) -> None:
        nonlocal best, best_distance
        if node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            fn = _innermost_function_declarator(declarator)
            if fn is not None:
                name_node = fn.child_by_field_name("declarator")
                name_text = name_node.text.decode("utf-8", errors="replace") if name_node else ""
                bare = name_text.split("::")[-1]
                if bare == method:
                    distance = abs(node.start_point[0] + 1 - hint) if hint is not None else 0
                    if best is None or (best_distance is not None and distance < best_distance):
                        best = (node, fn, name_text)
                        best_distance = distance
        for child in node.children:
            visit(child)

    visit(tree.root_node)
    if best is None:
        return None
    node, fn, name_text = best
    params_node = fn.child_by_field_name("parameters")
    params_text = params_node.text.decode("utf-8", errors="replace") if params_node else "()"
    type_node = node.child_by_field_name("type")
    returns = type_node.text.decode("utf-8", errors="replace") if type_node else "void"
    prefix = text[node.start_byte: (params_node.start_byte if params_node else node.start_byte)]
    is_static = bool(re.search(r"\bstatic\b", prefix.splitlines()[0] if prefix else ""))

    namespaces: list[str] = []
    ancestor = node.parent
    is_class_method = False
    while ancestor is not None:
        if ancestor.type == "namespace_definition":
            ns_name = ancestor.child_by_field_name("name")
            if ns_name is not None:
                namespaces.insert(0, ns_name.text.decode("utf-8", errors="replace"))
        if ancestor.type in {"class_specifier", "struct_specifier"}:
            is_class_method = True
        ancestor = ancestor.parent
    bare_name = name_text.split("::")[-1]
    if "::" in name_text:
        # Out-of-line member definitions carry the class in the declarator
        # while the class keyword usually lives in a header we cannot see.
        # Only treat a qualifier component as a namespace when the file
        # proves it is one; anything unproven is class scope. A qualifier
        # ending in the function's own name is a constructor.
        qualifier_parts = name_text.split("::")[:-1]
        if qualifier_parts and qualifier_parts[-1] == bare_name:
            is_class_method = True
        elif all(re.search(rf"\bnamespace\s+{re.escape(part)}\b", text) for part in qualifier_parts):
            namespaces.extend(qualifier_parts)
        else:
            is_class_method = True

    params = _parse_params(params_text)
    bare = bare_name
    qualified = "::".join([*namespaces, bare]) if namespaces else bare
    return {
        "name": bare,
        "qualified": qualified,
        "namespaces": namespaces,
        "params": params,
        "params_text": params_text,
        "returns": returns.strip(),
        "signature": f"{returns.strip()} {qualified}{params_text}",
        "is_static": is_static,
        "is_class_method": is_class_method,
        "line": node.start_point[0] + 1,
        "extractor": "tree-sitter",
    }


def _innermost_function_declarator(node: Any) -> Any:
    current = node
    while current is not None:
        if current.type == "function_declarator":
            inner = current.child_by_field_name("declarator")
            if inner is not None and inner.type == "function_declarator":
                current = inner
                continue
            return current
        current = current.child_by_field_name("declarator")
    return None


def _extract_with_regex(text: str, method: str) -> dict[str, Any] | None:
    pattern = re.compile(
        rf"^([A-Za-z_][\w:<>,\s\*&]*?)\b((?:[A-Za-z_]\w*::)*){re.escape(method)}\s*\(",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        open_index = match.end() - 1
        params_text, end_index = _balanced_parens(text, open_index)
        if params_text is None:
            continue
        after = text[end_index: end_index + 200]
        if not re.match(r"\s*(const\s*)?(noexcept\s*)?\{", after):
            continue
        returns = match.group(1).strip()
        if returns in {"if", "while", "for", "switch", "return", "else"}:
            continue
        qualifier = match.group(2).rstrip(":")
        qualifier_parts = qualifier.split("::") if qualifier else []
        is_class_method = bool(qualifier_parts) and not all(
            re.search(rf"\bnamespace\s+{re.escape(part)}\b", text) for part in qualifier_parts
        )
        if qualifier_parts and qualifier_parts[-1] == method:
            is_class_method = True  # constructor
        line = text[: match.start()].count("\n") + 1
        prefix_line = text.splitlines()[line - 1] if line - 1 < len(text.splitlines()) else ""
        return {
            "name": method,
            "qualified": f"{qualifier}::{method}" if qualifier and not is_class_method else method,
            "namespaces": qualifier.split("::") if qualifier and not is_class_method else [],
            "params": _parse_params(params_text),
            "params_text": params_text,
            "returns": returns,
            "signature": f"{returns} {qualifier + '::' if qualifier else ''}{method}{params_text}",
            "is_static": prefix_line.lstrip().startswith("static "),
            "is_class_method": is_class_method,
            "line": line,
            "extractor": "regex",
        }
    return None


def _balanced_parens(text: str, open_index: int) -> tuple[str | None, int]:
    depth = 0
    for index in range(open_index, min(len(text), open_index + 4000)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index: index + 1], index + 1
    return None, open_index


def _parse_params(params_text: str) -> list[dict[str, str]]:
    inner = params_text.strip()
    if inner.startswith("("):
        inner = inner[1:]
    if inner.endswith(")"):
        inner = inner[:-1]
    inner = inner.strip()
    if not inner or inner == "void":
        return []
    parts = []
    depth = 0
    current = ""
    for char in inner:
        if char in "<(":
            depth += 1
        elif char in ">)":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    if current.strip():
        parts.append(current)
    params = []
    for part in parts:
        part = part.strip()
        match = re.match(r"^(.*?)([A-Za-z_]\w*)?(\s*=\s*[^=]+)?$", part)
        if match and match.group(2):
            params.append({"type": match.group(1).strip(), "name": match.group(2)})
        else:
            params.append({"type": part, "name": ""})
    return params


def _tu_defines_main(source_path: Path) -> bool:
    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(r"^\s*int\s+main\s*\(", text, re.MULTILINE))


def _classify_fuzzable(extraction: dict[str, Any]) -> str | None:
    params = extraction["params"]
    if len(params) == 2 and _is_byteptr(params[0]["type"]) and _is_integral(params[1]["type"]):
        return "ptr_len"
    if len(params) == 1 and _is_stringish(params[0]["type"]):
        return "string"
    return None


def _is_byteptr(type_text: str) -> bool:
    return bool(re.search(r"\b(const\s+)?(unsigned\s+char|u?int8_t|char)\s*\*", type_text))


def _is_integral(type_text: str) -> bool:
    return bool(re.fullmatch(r"(const\s+)?(std::)?(size_t|u?int\d+_t|int|long|unsigned(\s+\w+)?)\s*&?", type_text.strip()))


def _is_stringish(type_text: str) -> bool:
    # Plain string-like values only — a string inside a template container
    # (vector<string>, map<...>) is not directly constructible from raw bytes.
    return (
        bool(re.search(r"(std::)?string|StringPiece", type_text))
        and "*" not in type_text
        and "<" not in type_text
    )


def _normalize_std_types(type_text: str) -> str:
    # Source files often rely on `using namespace std`; a rendered prototype
    # lives at global scope in the harness and needs explicit qualification.
    return re.sub(r"(?<![\w:])(string|wstring|vector|map|set|pair)\b", r"std::\1", type_text)


def _render_prototype(extraction: dict[str, Any]) -> str:
    params = ", ".join(
        f"{_normalize_std_types(param['type'])} {param['name']}".strip() for param in extraction["params"]
    )
    declaration = f"{_normalize_std_types(extraction['returns'])} {extraction['name']}({params});"
    for namespace in reversed(extraction["namespaces"]):
        declaration = f"namespace {namespace} {{ {declaration} }}"
    return declaration


def _render_call(extraction: dict[str, Any], shape: str) -> str:
    qualified = extraction["qualified"]
    if shape == "ptr_len":
        pointer_type = "const char*" if "char" in extraction["params"][0]["type"] else "const uint8_t*"
        return (
            f"(void){qualified}(reinterpret_cast<{pointer_type}>(payload), "
            f"static_cast<{extraction['params'][1]['type'].replace('const', '').strip() or 'size_t'}>(payload_size));"
        )
    return (
        f"(void){qualified}(std::string(reinterpret_cast<const char*>(payload), payload_size));"
    )


# ---------------------------------------------------------------------------
# workorder + validation + shared helpers


def _write_workorder(
    *,
    target_dir: Path,
    name: str,
    generator: str,
    sinks: list[dict[str, Any]],
    outcome: dict[str, Any],
    blockers: list[str],
    placeholders: Mapping[str, str],
) -> str:
    source_root = Path(placeholders.get("source_dir") or "/")
    contexts = []
    for sink in sinks[:MAX_WORKORDER_SINKS]:
        entry: dict[str, Any] = {"sink": sink}
        rel = str(sink.get("file") or "")
        for candidate_root in (source_root / "src" / "cpp" / "code", source_root):
            source_path = candidate_root / rel
            if source_path.is_file():
                entry["source_path"] = str(source_path)
                entry["context"] = _source_context(source_path, sink.get("line"))
                break
        contexts.append(entry)
    payload = {
        "target": name,
        "generator": generator,
        "instructions": (
            "Author harness.cpp for this target: reach the listed sinks with attacker-controlled bytes. "
            "Follow the LLVMFuzzerTestOneInput + FUZZ_MAIN convention, update .localfuzz/build.json, "
            "then re-run: target-generate --validate (or target-build + campaign-round-run)."
        ),
        "skipped": outcome.get("skipped", []),
        "build_blockers": blockers,
        "sinks_with_context": contexts,
        "summary": outcome.get("summary", {}),
    }
    path = target_dir / ".localfuzz" / "workorder.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def _source_context(source_path: Path, line: Any) -> list[str]:
    try:
        lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    center = int(line) if isinstance(line, (int, float)) else 1
    start = max(0, center - MAX_CONTEXT_LINES // 2)
    end = min(len(lines), center + MAX_CONTEXT_LINES // 2)
    return [f"{index + 1}: {lines[index]}" for index in range(start, end)]


def _validate_build_and_smoke(
    *, engine: Any, name: str, root: Path, bin_dir: Path, environment: dict[str, str]
) -> dict[str, Any]:
    from .container_build import build_target

    blockers = []
    build = build_target(project=f"localfuzz/c/{name}", workspace_root=root, env=environment)
    if not build["ok"]:
        blockers.extend(f"build: {item}" for item in build["blockers"])
        return {"ok": False, "build": _trim_build(build), "blockers": blockers}

    fuzzer = bin_dir / "fuzzer"
    smoke: dict[str, Any] | None = None
    if fuzzer.is_file() and os.access(fuzzer, os.X_OK):
        from .campaign_rounds import default_asan_options

        smoke_env = dict(environment)
        # Uninstrumented dependency .so's leak at static init and can fault in
        # exit-time destructors; ASAN's symbolizer can also wedge on its pipe
        # for very large link sets. Keep the smoke about one question only —
        # does the harness initialize and execute inputs — so: no leak check,
        # no symbolization, and pass on the completion marker.
        smoke_env.setdefault("ASAN_OPTIONS", default_asan_options(root))
        smoke = _run_command(
            [str(fuzzer), "-runs=16", "-rss_limit_mb=2048", "-detect_leaks=0"],
            cwd=bin_dir,
            timeout_seconds=SMOKE_TIMEOUT_SECONDS,
            env=smoke_env,
        )
        output = f"{smoke.get('stdout', '')}\n{smoke.get('stderr', '')}"
        # Smoke passes when the harness demonstrably executes: a clean bounded
        # run, the libFuzzer completion marker, or a sanitizer report from an
        # executed input (an instantly-crashing harness is a working harness).
        completed = (
            smoke["exit_code"] == 0
            or re.search(r"Done \d+ runs", output) is not None
            or "ERROR: AddressSanitizer" in output
            or "SUMMARY: AddressSanitizer" in output
        )
        if smoke["timed_out"] or not completed:
            blockers.append(f"smoke: fuzzer exited {smoke['exit_code']} (timed_out={smoke['timed_out']})")
    else:
        blockers.append(f"smoke: no fuzzer binary at {fuzzer}")
    return {"ok": not blockers, "build": _trim_build(build), "smoke": smoke, "blockers": blockers}


def _trim_build(build: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": build["ok"],
        "steps": [
            {"name": step.get("name"), "ok": step.get("ok"), "skipped": step.get("skipped", False)}
            for step in build.get("steps", [])
        ],
        "artifacts": build.get("artifacts", []),
        "blockers": build.get("blockers", []),
    }


GENERATED_MARKER = "Auto-generated by target-generate"


def _write_generated(path: Path, content: str) -> tuple[bool, str]:
    """Write a generated file, but never clobber a workorder-authored one.

    Authored files are recognizable by the absence of the generated marker.
    Returns (written, path-or-note).
    """
    if path.exists():
        head = path.read_text(encoding="utf-8", errors="replace")[:400]
        if GENERATED_MARKER not in head:
            return False, f"preserved authored file: {path}"
    path.write_text(content, encoding="utf-8")
    return True, str(path)


def _substituted_build_steps(
    spec: dict[str, Any], placeholders: Mapping[str, str], *, extra_sources: list[str] | None = None
) -> list[dict[str, Any]]:
    steps = []
    for step in (spec.get("build") or {}).get("steps", []):
        argv = []
        for item in step.get("argv", []):
            item = _substitute(str(item), placeholders)
            if item == "{extra_sources}":
                argv.extend(extra_sources or [])
            else:
                argv.append(item)
        env = {str(key): _substitute(str(value), placeholders) for key, value in (step.get("env") or {}).items()}
        steps.append({"name": str(step.get("name") or f"step-{len(steps)}"), "argv": argv, "env": env})
    return steps


def _first_namespace(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("namespace "):
            tokens = re.findall(r"namespace\s+([A-Za-z_]\w*)", line)
            if tokens:
                return "::".join(tokens)
    return ""


def _file_main_block() -> str:
    return "\n".join(
        [
            "#ifdef FUZZ_MAIN",
            "#include <cstdio>",
            "#include <vector>",
            "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t*, size_t);",
            "int main(int argc, char** argv) {",
            "  if (argc < 2) { std::fprintf(stderr, \"usage: %s <input>\\n\", argv[0]); return 1; }",
            "  std::FILE* f = std::fopen(argv[1], \"rb\");",
            "  if (!f) return 1;",
            "  std::vector<uint8_t> buf;",
            "  uint8_t chunk[4096]; size_t got;",
            "  while ((got = std::fread(chunk, 1, sizeof(chunk), f)) > 0) buf.insert(buf.end(), chunk, chunk + got);",
            "  std::fclose(f);",
            "  return LLVMFuzzerTestOneInput(buf.data(), buf.size());",
            "}",
            "#endif  // FUZZ_MAIN",
        ]
    )


def _substitute(text: str, placeholders: Mapping[str, str]) -> str:
    for key, value in placeholders.items():
        text = text.replace("{" + key + "}", value)
    return text


def _resolve_spec_path(spec: str, root: Path) -> Path:
    candidate = Path(spec).expanduser()
    if candidate.is_file():
        return candidate.resolve()
    for option in (root / "generators" / spec, root / "generators" / f"{spec}.json"):
        if option.is_file():
            return option.resolve()
    raise FileNotFoundError(f"generator spec not found: {spec} (looked in {root / 'generators'})")

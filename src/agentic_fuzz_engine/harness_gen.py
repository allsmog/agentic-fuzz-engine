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
    if generator not in {"type_enum", "direct_call", "symbolic_string"}:
        raise ValueError(f"spec.type must be type_enum, direct_call, or symbolic_string: {spec_path}")

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
    workspace-local files are copied under the klee dir. Heavyweight link
    sources may still hit the stub-include closure wall — the ci run's
    compile errors then feed the normal authoring loop.
    """
    environment = dict(os.environ if env is None else env)
    root = resolve_workspace_root(workspace_root, env=environment)
    try:
        workspace = load_workspace(root, env=environment)
    except FileNotFoundError:
        workspace = {"root": str(root)}
    source_dir = str(workspace.get("source_dir") or "")

    short = name.removeprefix("localfuzz/c/")
    target_dir = root / TARGETS_RELATIVE / short
    harness = target_dir / "harness.cpp"
    build_path = target_dir / ".localfuzz" / "build.json"
    if not harness.is_file():
        raise FileNotFoundError(f"harness not found (run target-generate/scaffold first): {harness}")
    if not build_path.is_file():
        raise FileNotFoundError(f"build config not found: {build_path}")

    steps = json.loads(build_path.read_text(encoding="utf-8")).get("steps", [])
    step = next((item for item in steps if item.get("name") == "symcc"), None) or (steps[0] if steps else None)
    if step is None:
        raise ValueError(f"build config has no steps: {build_path}")

    gen_dir = root / "klee" / "harnesses" / "gen"
    gen_dir.mkdir(parents=True, exist_ok=True)
    pack_source = gen_dir / f"{short}-pack.cpp"
    shutil.copy2(harness, pack_source)
    # KLEE entry wrapper: a symbolic buffer + bounded symbolic size into the
    # harness's LLVMFuzzerTestOneInput (the FUZZ_MAIN file-replay main is
    # useless under KLEE — there is no file to replay).
    wrapper = gen_dir / f"{short}-pack-main.cpp"
    sym_bytes = 64
    wrapper.write_text(
        "\n".join(
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
        ),
        encoding="utf-8",
    )

    compile_args = [
        "-include", "/work/stub-include/klee_thread_shims.h",
        "-I/work/harnesses",
        "-I/work/stub-include",
        "-isystem", "/work/host-include",
        "-Wno-everything",
        "-std=c++17",
    ]
    link_sources: list[str] = []
    notes: list[str] = []
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
            mapped = _map_pack_path(arg[2:], source_dir=source_dir, root=root, gen_dir=gen_dir, short=short, notes=notes)
            if mapped:
                compile_args.append(f"-I{mapped}")
        elif arg.endswith(".cpp"):
            if str(Path(arg).resolve()) == harness_resolved:
                continue
            mapped = _map_pack_path(arg, source_dir=source_dir, root=root, gen_dir=gen_dir, short=short, notes=notes)
            if mapped:
                link_sources.append(mapped)

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
    if ci_path.is_file():
        try:
            payload = json.loads(ci_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
    else:
        payload = {}
    payload.setdefault("outputRoot", "/work/klee-ng-out/gen-packs")
    targets = [item for item in payload.get("targets", []) if item.get("name") != entry["name"]]
    targets.append(entry)
    payload["targets"] = targets
    ci_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return {
        "ok": True,
        "mode": "klee-pack-gen",
        "name": short,
        "pack_source": str(pack_source),
        "ci_config": str(ci_path),
        "entry": entry,
        "notes": notes,
        "next_command": f"symbolic-worker-run <run> --mode klee --klee-config {ci_path.name}",
    }


def _map_pack_path(
    path_text: str, *, source_dir: str, root: Path, gen_dir: Path, short: str, notes: list[str]
) -> str | None:
    """Map a build.json path onto the klee container's view of the world."""
    if source_dir and path_text.startswith(source_dir):
        return path_text  # source tree is mounted at the same path in-container
    resolved = Path(path_text)
    if str(resolved).startswith(str(root)):
        if resolved.is_file():
            destination = gen_dir / f"{short}-{resolved.name}"
            shutil.copy2(resolved, destination)
            return f"/work/harnesses/gen/{destination.name}"
        if resolved.is_dir():
            destination = root / "klee" / "gen-include" / short / resolved.name
            destination.mkdir(parents=True, exist_ok=True)
            for entry in resolved.iterdir():
                if entry.is_file():
                    shutil.copy2(entry, destination / entry.name)
            return f"/work/gen-include/{short}/{resolved.name}"
        notes.append(f"workspace path missing, dropped: {path_text}")
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

    prototypes = []
    calls = []
    tus = []
    for index, candidate in enumerate(candidates):
        extraction = candidate["extraction"]
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

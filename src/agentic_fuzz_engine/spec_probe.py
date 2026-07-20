"""``spec-probe``: deterministic compile-and-fix for target build specs.

Harness authoring is the campaign bottleneck, and ~80% of it is one
mechanical loop: compile, read the error, add the include dir / source
file / system lib it names, repeat. This module runs that loop boundedly
and leaves only the genuinely ambiguous residue to the operator/agent.

Per iteration:

1. Regenerate the harness from the spec when it has a generator ``type``
   (hand-authored harnesses skip regeneration), then run ``target-build``.
2. Classify each compile/link error:
   - ``fatal error: 'X.h' file not found`` → search the scan root for a
     file whose path ends with the include; a unique hit adds its base
     dir as ``-I`` to the fuzzer step. Multiple hits → residue.
   - ``undefined reference to 'sym'`` / ``undefined symbol: sym`` →
     match the symbol against the syslib table (→ ``-l``), else search
     ``.cpp`` files defining it; a unique hit appends to the step's
     sources. Multiple hits or mangled-only symbols → residue.
   - errors inside the *generated* harness → spec defect residue.
3. Apply unique resolutions directly to the spec's fuzzer step argv,
   persist the spec, append the decision to ``work/<t>/probe-state.json``,
   iterate — until buildable, out of budget, or only residue remains.

Growth caps (``max_include_dirs`` / ``max_link_sources``) stop closure
explosion on tangled trees; hitting one ends the probe with the residue
explaining why.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Mapping

from .runtime_backends import _run_command

MISSING_HEADER_RE = re.compile(r"fatal error: '([^']+)' file not found")
UNDEFINED_REF_RES = (
    re.compile(r"undefined reference to [`']([^'\n]+)'"),
    re.compile(r"undefined symbol: ([^\n(]+)"),
)
UNDECLARED_RE = re.compile(r"harness\.cpp:\d+:\d+: error: (use of undeclared identifier.+)")

DEFAULT_SYMBOL_LIBS: tuple[tuple[str, str], ...] = (
    (r"^(deflate|inflate|crc32|gz)", "-lz"),
    (r"^ZSTD_", "-lzstd"),
    (r"^LZ4_", "-llz4"),
    (r"^BZ2_", "-lbz2"),
    (r"^(EVP_|SSL_|CRYPTO_|ERR_|BIO_|RAND_)", "-lcrypto"),
    (r"^pthread_", "-lpthread"),
    (r"^uuid_", "-luuid"),
    (r"^(curl_|Curl_)", "-lcurl"),
    (r"^sqlite3_", "-lsqlite3"),
    (r"^(dlopen|dlsym|dlclose|dlerror)\b", "-ldl"),
)

MAX_ERRORS_PER_ITER = 30
MAX_SEARCH_HITS = 8


def spec_probe(
    *,
    root: Path,
    name: str,
    spec: str | Path | None = None,
    scan_root: str | Path | None = None,
    max_iterations: int = 12,
    max_include_dirs: int = 64,
    max_link_sources: int = 400,
    compile_timeout: float = 300.0,
    engine: Any = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    from .container_build import build_target
    from .workspace import load_workspace

    environment = dict(os.environ if env is None else env)
    target_dir = root / "targets" / "c" / name
    spec_path = Path(spec).expanduser() if spec else root / "generators" / f"{name}.json"
    if not spec_path.is_file():
        return {"ok": False, "blockers": [f"spec not found: {spec_path}"]}
    try:
        workspace = load_workspace(root, env=environment)
    except FileNotFoundError:
        workspace = {}
    scan = Path(scan_root).expanduser() if scan_root else Path(str(workspace.get("source_dir") or ""))
    if not scan.is_dir():
        return {"ok": False, "blockers": [f"scan root not a directory (pass --scan-root): {scan}"]}

    state_path = root / "work" / name / "probe-state.json"
    state: dict[str, Any] = {"iterations": [], "residue": [], "status": "in-progress"}

    for iteration in range(1, max(1, int(max_iterations)) + 1):
        spec_data = json.loads(spec_path.read_text(encoding="utf-8"))
        generator_type = str(spec_data.get("type") or "")
        if not generator_type:
            # Hand-authored harness: the spec IS the build recipe — sync its
            # steps into .localfuzz/build.json so target-build sees edits.
            steps = ((spec_data.get("build") or {}).get("steps")) or spec_data.get("steps")
            if steps:
                (target_dir / ".localfuzz").mkdir(parents=True, exist_ok=True)
                (target_dir / ".localfuzz" / "build.json").write_text(
                    json.dumps({"notes": [f"synced by spec-probe from {spec_path.name}"], "steps": steps},
                               indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
        if generator_type:
            from .harness_gen import generate_target

            try:
                generate_target(
                    name=name, spec=str(spec_path), workspace_root=root,
                    validate=False, engine=engine, env=environment,
                )
            except (ValueError, FileNotFoundError) as exc:
                state["residue"].append({"kind": "generator-error", "detail": str(exc)})
                break

        try:
            build = build_target(
                project=f"localfuzz/c/{name}", workspace_root=root,
                timeout_seconds=compile_timeout, env=environment,
            )
        except (FileNotFoundError, ValueError) as exc:
            state["residue"].append({"kind": "build-config-error", "detail": str(exc)})
            break
        if build.get("ok"):
            state["status"] = "buildable"
            state["iterations"].append({"n": iteration, "errors": 0, "fixed": 0, "added": {}})
            break

        stderr = "\n".join(
            str((step.get("run") or {}).get("stderr") or "")
            for step in build.get("steps", [])
            if not step.get("skipped")
        )
        errors = _classify_errors(stderr)
        fixes, residue = _resolve(errors, scan_root=scan)
        state["residue"] = residue  # latest iteration's residue is the live one
        record = {"n": iteration, "errors": len(errors), "fixed": 0, "added": {}}

        if fixes["include_dirs"] or fixes["link_sources"] or fixes["link_libs"]:
            step = _fuzzer_step(spec_data)
            if step is None:
                state["residue"].append({"kind": "spec-shape", "detail": "no fuzzer step with -o in spec build.steps"})
                state["iterations"].append(record)
                break
            argv = [str(item) for item in step.get("argv", [])]
            current_includes = sum(1 for token in argv if token.startswith("-I"))
            current_sources = sum(1 for token in argv if token.endswith((".cpp", ".cc", ".cxx", ".c")))
            added: dict[str, list[str]] = {"include_dirs": [], "link_sources": [], "link_libs": []}
            for directory in fixes["include_dirs"]:
                token = f"-I{directory}"
                if token in argv:
                    continue
                if current_includes >= max_include_dirs:
                    state["residue"].append({"kind": "budget", "detail": f"max_include_dirs={max_include_dirs} reached"})
                    break
                argv.append(token)
                added["include_dirs"].append(str(directory))
                current_includes += 1
            for source_file in fixes["link_sources"]:
                token = str(source_file)
                if token in argv:
                    continue
                if current_sources >= max_link_sources:
                    state["residue"].append({"kind": "budget", "detail": f"max_link_sources={max_link_sources} reached"})
                    break
                argv.append(token)
                added["link_sources"].append(token)
                current_sources += 1
            for lib in fixes["link_libs"]:
                if lib not in argv:
                    argv.append(lib)
                    added["link_libs"].append(lib)
            step["argv"] = argv
            record["added"] = {key: value for key, value in added.items() if value}
            record["fixed"] = sum(len(value) for value in added.values())
            spec_path.write_text(json.dumps(spec_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        state["iterations"].append(record)
        if record["fixed"] == 0:
            state["status"] = "residue" if state["residue"] else "stuck"
            break
    else:
        state["status"] = "budget-exhausted"

    if state["status"] == "in-progress":
        state["status"] = "residue" if state["residue"] else "stuck"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "ok": state["status"] == "buildable",
        "mode": "spec-probe",
        "target": name,
        "spec": str(spec_path),
        "status": state["status"],
        "iterations": len(state["iterations"]),
        "residue": state["residue"],
        "probe_state": str(state_path),
    }


def _classify_errors(stderr: str) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for match in MISSING_HEADER_RE.finditer(stderr):
        key = ("header", match.group(1))
        if key not in seen:
            seen.add(key)
            errors.append({"kind": "missing-header", "value": match.group(1)})
    for pattern in UNDEFINED_REF_RES:
        for match in pattern.finditer(stderr):
            symbol = match.group(1).strip()
            key = ("symbol", symbol)
            if key not in seen:
                seen.add(key)
                errors.append({"kind": "undefined-symbol", "value": symbol})
    for match in UNDECLARED_RE.finditer(stderr):
        key = ("undeclared", match.group(1))
        if key not in seen:
            seen.add(key)
            errors.append({"kind": "spec-defect", "value": match.group(1)})
    return errors[:MAX_ERRORS_PER_ITER]


def _resolve(errors: list[dict[str, str]], *, scan_root: Path) -> tuple[dict[str, list], list[dict[str, Any]]]:
    fixes: dict[str, list] = {"include_dirs": [], "link_sources": [], "link_libs": []}
    residue: list[dict[str, Any]] = []
    for error in errors:
        if error["kind"] == "missing-header":
            hits = _find_header(scan_root, error["value"])
            if len(hits) == 1:
                fixes["include_dirs"].append(hits[0])
            else:
                residue.append(
                    {"kind": "ambiguous-header" if hits else "header-not-found",
                     "detail": error["value"], "candidates": [str(hit) for hit in hits]}
                )
        elif error["kind"] == "undefined-symbol":
            symbol = error["value"]
            lib = _syslib_for(symbol)
            if lib:
                fixes["link_libs"].append(lib)
                continue
            if symbol.startswith("_Z"):
                residue.append({"kind": "mangled-symbol", "detail": symbol})
                continue
            hits = _find_definition(scan_root, symbol)
            if len(hits) == 1:
                fixes["link_sources"].append(hits[0])
            else:
                residue.append(
                    {"kind": "ambiguous-symbol" if hits else "symbol-not-found",
                     "detail": symbol, "candidates": [str(hit) for hit in hits]}
                )
        else:
            residue.append({"kind": "spec-defect", "detail": error["value"]})
    # de-dup while preserving order
    for key in fixes:
        seen: set[str] = set()
        unique = []
        for item in fixes[key]:
            if str(item) not in seen:
                seen.add(str(item))
                unique.append(item)
        fixes[key] = unique
    return fixes, residue


def _find_header(scan_root: Path, include: str) -> list[Path]:
    """Base dirs from which ``#include "<include>"`` resolves."""
    rg = shutil.which("rg")
    include_path = Path(include)
    hits: list[Path] = []
    if rg:
        run = _run_command(
            [rg, "--files", "-g", f"**/{include_path.name}", str(scan_root)],
            cwd=scan_root, timeout_seconds=60, env=dict(os.environ),
        )
        candidates = [Path(line) for line in str(run.get("stdout") or "").splitlines() if line.strip()]
    else:
        candidates = list(scan_root.rglob(include_path.name))[: MAX_SEARCH_HITS * 4]
    for candidate in candidates:
        text = str(candidate)
        if text.endswith(str(include_path)):
            base = Path(text[: -len(str(include_path))].rstrip("/"))
            if base not in hits:
                hits.append(base)
        if len(hits) >= MAX_SEARCH_HITS:
            break
    return hits


def _find_definition(scan_root: Path, symbol: str) -> list[Path]:
    """.cpp files defining the (demangled) symbol's function."""
    base = symbol.split("(", 1)[0].strip()
    parts = [part for part in base.split("::") if part]
    if not parts:
        return []
    function = parts[-1]
    qualifier = parts[-2] if len(parts) >= 2 else None
    qualified = (re.escape(qualifier) + r"::" + re.escape(function) + r"\s*\(") if qualifier else None
    bare = r"\b" + re.escape(function) + r"\s*\("

    hits = _grep_files(scan_root, qualified or bare)
    if not hits and qualified:
        # Definitions inside `namespace X { ... }` blocks carry no X::
        # prefix — fall back to the bare name, filtered to files that also
        # mention the qualifier at all.
        needle_ns = f"namespace {qualifier}"
        needle_scope = f"{qualifier}::"
        for candidate in _grep_files(scan_root, bare):
            try:
                body = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if needle_ns in body or needle_scope in body:
                hits.append(candidate)
            if len(hits) >= MAX_SEARCH_HITS:
                break
    return hits


def _grep_files(scan_root: Path, pattern: str) -> list[Path]:
    rg = shutil.which("rg")
    hits: list[Path] = []
    if rg:
        run = _run_command(
            [rg, "-l", "-e", pattern, "-g", "*.{cpp,cc,cxx,c}", str(scan_root)],
            cwd=scan_root, timeout_seconds=60, env=dict(os.environ),
        )
        for line in str(run.get("stdout") or "").splitlines():
            if line.strip():
                hits.append(Path(line.strip()))
            if len(hits) >= MAX_SEARCH_HITS:
                break
    else:
        compiled = re.compile(pattern)
        for path in sorted(scan_root.rglob("*.cpp"))[:2000]:
            try:
                if compiled.search(path.read_text(encoding="utf-8", errors="replace")):
                    hits.append(path)
            except OSError:
                continue
            if len(hits) >= MAX_SEARCH_HITS:
                break
    return hits


def _syslib_for(symbol: str) -> str | None:
    tail = symbol.split("(", 1)[0].split("::")[-1].strip()
    for pattern, lib in DEFAULT_SYMBOL_LIBS:
        if re.search(pattern, tail):
            return lib
    return None


def _fuzzer_step(spec_data: dict[str, Any]) -> dict[str, Any] | None:
    steps = ((spec_data.get("build") or {}).get("steps")) or spec_data.get("steps") or []
    for step in steps:
        argv = [str(item) for item in step.get("argv", [])]
        if "-o" in argv:
            return step
    return None

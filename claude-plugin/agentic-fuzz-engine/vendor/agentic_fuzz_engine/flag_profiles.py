"""Runtime flag profiles: pin harnesses to production defaults, matrix crashes.

A locally-proven primitive can die on a single shipped flag default — the
harness exercised a path production configuration routes around. The engine
previously had no notion of runtime flags at all. This module adds:

- ``flag-scan``: lexical inventory of gflags/absl flag definitions over the
  target's build-input closure → ``work/<t>/flags-inventory.json``
  (name, type, default literal, file:line). Deterministic; the judgment of
  *which* flags gate behavior stays with the operator/agent.
- ``.localfuzz/flags.json`` (authored): named profiles of flag values, e.g.
  ``production`` (shipped defaults) and ``permissive`` (gates open).
- ``render_flag_prelude`` → ``flag_profile.inc``: a generated include the
  harness calls in ``LLVMFuzzerInitialize``; the profile is chosen by env
  ``FUZZ_FLAG_PROFILE`` (default: the file's ``default_profile``). Direct
  ``FLAGS_<name> = value;`` assignments — no runtime gflags dependency.
- crash **flag-matrix** (wired through the impact pass): every verified PoV
  replays once per profile; a crash that only reproduces under a
  non-default profile is flagged in the report — the early warning that
  the finding is config-gated.

Fuzzing itself runs under one profile (the default); the matrix belongs on
crashes, where it costs one bounded replay per profile instead of doubling
every round.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

FLAGS_CONFIG_RELATIVE = Path(".localfuzz/flags.json")
PRELUDE_NAME = "flag_profile.inc"
MAX_INVENTORY_FLAGS = 500

FLAG_DEFINE_RES = (
    re.compile(
        r"DEFINE_(?P<type>bool|int32|int64|uint64|double|string)\s*\(\s*(?P<name>\w+)\s*,\s*(?P<default>[^,\n]+)"
    ),
    re.compile(r"ABSL_FLAG\s*\(\s*(?P<type>[\w:<>]+)\s*,\s*(?P<name>\w+)\s*,\s*(?P<default>[^,\n]+)"),
)


def load_flag_profiles(target_dir: Path) -> dict[str, Any] | None:
    path = target_dir / FLAGS_CONFIG_RELATIVE
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    profiles = payload.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        return None
    return payload


def profile_names(target_dir: Path) -> list[str]:
    payload = load_flag_profiles(target_dir)
    if not payload:
        return []
    return sorted(payload["profiles"])


def flag_scan(
    *,
    root: Path,
    name: str,
    source_dir: str | Path | None = None,
    max_files: int = 4000,
    max_file_bytes: int = 1_048_576,
) -> dict[str, Any]:
    """Inventory flag definitions over the target's build-input closure
    (same derivation staleness uses) plus an optional extra source dir."""
    from .staleness import collect_build_inputs

    target_dir = root / "targets" / "c" / name
    build_config_path = target_dir / ".localfuzz" / "build.json"
    if not build_config_path.is_file():
        return {"ok": False, "blockers": [f"build config not found: {build_config_path}"]}
    build_config = json.loads(build_config_path.read_text(encoding="utf-8"))
    placeholders = {
        "target_dir": str(target_dir),
        "bin_dir": str(root / "bin" / name),
        "workspace_root": str(root),
        "source_dir": str(source_dir or ""),
        "build_container": "",
    }
    inputs, truncated = collect_build_inputs(
        target_dir=target_dir,
        build_config=build_config,
        placeholders=placeholders,
        max_files=max_files,
    )
    if source_dir:
        extra_root = Path(source_dir).expanduser()
        if extra_root.is_dir():
            for path in sorted(extra_root.rglob("*.cpp"))[: max_files - len(inputs)]:
                inputs.append(path)

    flags: dict[str, dict[str, Any]] = {}
    for path in inputs:
        if path.suffix not in (".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"):
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for index, line in enumerate(text.splitlines(), start=1):
            for pattern in FLAG_DEFINE_RES:
                match = pattern.search(line)
                if not match:
                    continue
                flag_name = match.group("name")
                if flag_name not in flags:
                    flags[flag_name] = {
                        "name": flag_name,
                        "type": match.group("type"),
                        "default": match.group("default").strip(),
                        "file": str(path),
                        "line": index,
                    }
                break
        if len(flags) >= MAX_INVENTORY_FLAGS:
            break

    inventory = {
        "target": name,
        "flags": sorted(flags.values(), key=lambda item: item["name"]),
        "truncated_inputs": truncated,
        "inputs_scanned": len(inputs),
    }
    out = root / "work" / name / "flags-inventory.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"ok": True, "mode": "flag-scan", "out": str(out), "flags": len(inventory["flags"]), "truncated": truncated}


def render_flag_prelude(payload: Mapping[str, Any] | None) -> str:
    """C++ include applying the chosen profile. With no flags.json the
    prelude is a no-op, so harness templates can include it unconditionally."""
    lines = [
        "// Generated by flag-prelude from .localfuzz/flags.json. Do not edit by hand.",
        "// Profile chosen by env FUZZ_FLAG_PROFILE; default profile: "
        + (str(payload.get("default_profile")) if payload else "none (no-op)"),
        "#pragma once",
        "#include <cstdlib>",
        "#include <cstring>",
        "",
        "static void apply_flag_profile() {",
    ]
    if not payload:
        lines += ["  // no flags.json for this target — nothing to apply", "}", ""]
        return "\n".join(lines)
    default_profile = str(payload.get("default_profile") or sorted(payload["profiles"])[0])
    lines += [
        "  const char *profile_env = std::getenv(\"FUZZ_FLAG_PROFILE\");",
        f"  const char *profile = profile_env ? profile_env : \"{default_profile}\";",
    ]
    first = True
    for profile_name in sorted(payload["profiles"]):
        values = payload["profiles"][profile_name]
        keyword = "if" if first else "} else if"
        first = False
        lines.append(f"  {keyword} (std::strcmp(profile, \"{profile_name}\") == 0) {{")
        for flag_name in sorted(values):
            lines.append(f"    FLAGS_{flag_name} = {_cpp_literal(str(values[flag_name]))};")
    if not first:
        lines.append("  }")
    lines += ["}", ""]
    return "\n".join(lines)


def write_flag_prelude(*, root: Path, name: str) -> dict[str, Any]:
    target_dir = root / "targets" / "c" / name
    if not target_dir.is_dir():
        return {"ok": False, "blockers": [f"target dir not found: {target_dir}"]}
    payload = load_flag_profiles(target_dir)
    prelude = render_flag_prelude(payload)
    out = target_dir / PRELUDE_NAME
    out.write_text(prelude, encoding="utf-8")
    return {
        "ok": True,
        "mode": "flag-prelude",
        "out": str(out),
        "profiles": sorted(payload["profiles"]) if payload else [],
        "noop": payload is None,
    }


def _cpp_literal(value: str) -> str:
    stripped = value.strip()
    if stripped in ("true", "false"):
        return stripped
    try:
        int(stripped)
        return stripped
    except ValueError:
        pass
    try:
        float(stripped)
        return stripped
    except ValueError:
        pass
    if stripped.startswith('"') and stripped.endswith('"'):
        return stripped
    escaped = stripped.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


MAX_DISCOVERY_FILES = 5000
MAX_TEXT_BYTES = 262_144
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
SCRIPT_SUFFIXES = {".py", ".sh", ".pl", ".rb"}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    "target",
}


def discover_local_target(source_dir: str, *, project: str | None = None, max_files: int = MAX_DISCOVERY_FILES) -> dict[str, Any]:
    source = Path(source_dir).expanduser().resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"source_dir is not a directory: {source_dir}")

    files = _walk_files(source, max_files=max_files)
    harness_inventory_path = source / ".localfuzz" / "config.yaml"
    declared_harnesses = _load_harness_inventory(harness_inventory_path)
    source_harnesses = _scan_harness_sources(source, files)
    merged = _merge_harnesses(source, declared_harnesses, source_harnesses)
    build_systems = _detect_build_systems(source)
    dictionaries = _find_named(files, source, suffix=".dict")
    seed_corpora = _find_seed_corpora(source, files)
    blockers = _blockers(harness_inventory_path, merged, build_systems)

    return {
        "ok": not blockers,
        "project": project,
        "source_dir": str(source),
        "files_scanned": len(files),
        "truncated": len(files) >= max_files,
        "metadata": {
            "localfuzz_config": _relative_if_exists(harness_inventory_path, source),
            "project_yaml": _relative_if_exists(source / "project.yaml", source),
            "oss_fuzz_project_yaml": _relative_if_exists(source / ".clusterfuzzlite" / "project.yaml", source),
        },
        "build_systems": build_systems,
        "harnesses": merged,
        "command_map": {
            str(harness["name"]): harness["recommended_command"]
            for harness in merged
            if harness.get("recommended_command")
        },
        "dictionaries": dictionaries,
        "seed_corpora": seed_corpora,
        "blockers": blockers,
    }


def _walk_files(source: Path, *, max_files: int) -> list[Path]:
    files: list[Path] = []
    for root, dirs, names in os.walk(source):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS and not name.startswith(".cache")]
        for name in sorted(names):
            path = Path(root) / name
            if path.is_file():
                files.append(path)
                if len(files) >= max_files:
                    return files
    return files


def _load_harness_inventory(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    harnesses: list[dict[str, Any]] = []
    pending: dict[str, str] | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line == "harness_files:":
            continue
        if line.startswith("- name:"):
            if pending and "name" in pending and "path" in pending:
                harnesses.append({"name": pending["name"], "metadata_path": pending["path"], "source": "localfuzz_config"})
            pending = {"name": _strip_yaml_scalar(line.split(":", 1)[1])}
            continue
        if line.startswith("path:") and pending is not None:
            pending["path"] = _strip_yaml_scalar(line.split(":", 1)[1])
    if pending and "name" in pending and "path" in pending:
        harnesses.append({"name": pending["name"], "metadata_path": pending["path"], "source": "localfuzz_config"})
    return harnesses


def _scan_harness_sources(source: Path, files: list[Path]) -> list[dict[str, Any]]:
    harnesses: list[dict[str, Any]] = []
    for path in files:
        rel = path.relative_to(source).as_posix()
        if path.suffix not in SOURCE_SUFFIXES and path.suffix not in SCRIPT_SUFFIXES:
            continue
        name_hint = path.stem
        lower_name = path.name.lower()
        evidence = []
        if path.suffix in SOURCE_SUFFIXES:
            text = _read_small_text(path)
            if "LLVMFuzzerTestOneInput" in text:
                evidence.append("LLVMFuzzerTestOneInput")
            if "fuzz" in lower_name or "harness" in lower_name:
                evidence.append("filename")
        elif "fuzz" in lower_name or "harness" in lower_name:
            evidence.append("script_filename")
        if evidence:
            harnesses.append(
                {
                    "name": name_hint,
                    "metadata_path": rel,
                    "source": "source_scan",
                    "evidence": evidence,
                }
            )
    return harnesses


def _merge_harnesses(source: Path, declared: list[dict[str, Any]], scanned: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_name: dict[str, dict[str, Any]] = {}
    for item in [*declared, *scanned]:
        name = str(item["name"])
        current = by_name.setdefault(
            name,
            {
                "name": name,
                "metadata_path": item.get("metadata_path"),
                "sources": [],
                "evidence": [],
            },
        )
        if item.get("metadata_path") and not current.get("metadata_path"):
            current["metadata_path"] = item["metadata_path"]
        current["sources"].append(item.get("source", "unknown"))
        current["evidence"].extend(item.get("evidence", []))

    harnesses = []
    for name, item in sorted(by_name.items()):
        metadata_path = str(item.get("metadata_path") or "")
        resolved = _resolve_inside(source, metadata_path) if metadata_path else None
        command_info = _recommended_command(source, name, resolved)
        harnesses.append(
            {
                "name": name,
                "metadata_path": metadata_path or None,
                "path_exists": bool(resolved and resolved.exists()),
                "path_kind": _path_kind(resolved) if resolved else "unknown",
                "sources": sorted(set(str(value) for value in item["sources"])),
                "evidence": sorted(set(str(value) for value in item["evidence"])),
                "recommended_command": command_info["command"],
                "runnable": bool(command_info["command"]),
                "blockers": command_info["blockers"],
            }
        )
    return harnesses


def _recommended_command(source: Path, name: str, metadata_path: Path | None) -> dict[str, Any]:
    blockers = []
    candidates = []
    if metadata_path is not None:
        candidates.append(metadata_path)
    for rel in (
        name,
        f"{name}.py",
        Path("build") / name,
        Path("out") / name,
        Path(".libs") / name,
    ):
        candidates.append(source / rel)

    for candidate in candidates:
        if not _inside(source, candidate):
            blockers.append(f"path escapes source root: {candidate}")
            continue
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return {"command": [str(candidate), "{poc}"], "blockers": blockers}
        if candidate.is_file() and candidate.suffix == ".py":
            return {"command": ["python3", str(candidate), "{poc}"], "blockers": blockers}

    if metadata_path and metadata_path.exists() and metadata_path.suffix in SOURCE_SUFFIXES:
        blockers.append("harness source requires a build output before it is runnable")
    elif metadata_path and not metadata_path.exists():
        blockers.append("declared harness path does not exist")
    else:
        blockers.append("no runnable harness executable or script was found")
    return {"command": None, "blockers": blockers}


def _detect_build_systems(source: Path) -> list[dict[str, Any]]:
    candidates = [
        ("compile_commands", "compile_commands.json", None),
        ("cmake", "CMakeLists.txt", [["cmake", "-S", "{src}", "-B", "{src}/build"], ["cmake", "--build", "{src}/build"]]),
        ("make", "Makefile", [["make", "-C", "{src}", "-j2"]]),
        ("configure", "configure", [["{src}/configure"], ["make", "-C", "{src}", "-j2"]]),
        ("shell", "build.sh", [["{src}/build.sh"]]),
    ]
    systems = []
    for kind, rel, commands in candidates:
        path = source / rel
        if path.exists():
            systems.append(
                {
                    "kind": kind,
                    "path": rel,
                    "recommended_probe_commands": commands or [],
                    "runnable": bool(commands),
                }
            )
    return systems


def _find_named(files: list[Path], source: Path, *, suffix: str) -> list[dict[str, Any]]:
    result = []
    for path in files:
        if path.suffix == suffix:
            result.append({"path": path.relative_to(source).as_posix(), "size": path.stat().st_size})
    return result[:100]


def _find_seed_corpora(source: Path, files: list[Path]) -> list[dict[str, Any]]:
    corpora: dict[str, dict[str, Any]] = {}
    for path in files:
        rel = path.relative_to(source)
        lowered = rel.as_posix().lower()
        if "seed" not in lowered and "corpus" not in lowered:
            continue
        key = rel.parts[0] if len(rel.parts) > 1 else rel.as_posix()
        entry = corpora.setdefault(key, {"path": key, "files": 0, "bytes": 0})
        entry["files"] += 1
        entry["bytes"] += path.stat().st_size
    return sorted(corpora.values(), key=lambda item: str(item["path"]))[:100]


def _blockers(harness_inventory_path: Path, harnesses: list[dict[str, Any]], build_systems: list[dict[str, Any]]) -> list[str]:
    blockers = []
    if not harness_inventory_path.exists():
        blockers.append("missing .localfuzz/config.yaml harness inventory")
    if not harnesses:
        blockers.append("no harnesses discovered")
    if harnesses and not any(harness["runnable"] for harness in harnesses):
        blockers.append("no runnable harness command discovered")
    if not build_systems:
        blockers.append("no recognized local build system discovered")
    return blockers


def _read_small_text(path: Path) -> str:
    if path.stat().st_size > MAX_TEXT_BYTES:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _resolve_inside(source: Path, rel: str) -> Path:
    return (source / rel).resolve()


def _inside(source: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(source)
        return True
    except ValueError:
        return False


def _path_kind(path: Path | None) -> str:
    if path is None or not path.exists():
        return "missing"
    if path.is_dir():
        return "directory"
    if os.access(path, os.X_OK):
        return "executable"
    if path.suffix in SOURCE_SUFFIXES:
        return "source"
    if path.suffix in SCRIPT_SUFFIXES:
        return "script"
    return "file"


def _relative_if_exists(path: Path, source: Path) -> str | None:
    return path.relative_to(source).as_posix() if path.exists() else None


def _strip_yaml_scalar(value: str) -> str:
    value = value.strip()
    if value and value[0] in {"'", '"'} and value[-1:] == value[0]:
        return value[1:-1]
    return value

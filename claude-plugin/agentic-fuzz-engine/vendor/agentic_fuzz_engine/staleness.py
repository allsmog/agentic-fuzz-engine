"""Proactive target staleness detection.

A fuzz binary silently outlives its sources: the tree moves on, the binary
keeps running (or stops loading), and rounds burn budget against code that
no longer exists. The engine only noticed this reactively — when a corpus
merge failed to exec. This module makes it proactive:

- ``target-build`` records a build manifest (sha256 of the build's input
  closure) next to the binaries;
- ``check_target_staleness`` recomputes cheaply (mtime prefilter — only
  files newer than the build are rehashed) and reports what changed;
- the round loop consults it per ``round.stale_policy``:
  ``warn`` (default, note in the summary), ``block`` (refuse to fuzz),
  ``rebuild`` (run target-build, then proceed).

The input closure is derived, not declared: every file under the target
dir (configs, harness sources; corpora and scratch dirs excluded) plus
every argv token in ``build.json`` steps that resolves to an existing
file. Targets wanting an exact contract may add ``"inputs": [globs]`` to
``build.json``; those are hashed too.
"""

from __future__ import annotations

import json
import time
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

MANIFEST_NAME = "build-manifest.json"
DEFAULT_MAX_FILES = 4000
EXCLUDED_TARGET_DIRS = {"seeds", "corpus", "crashes", "tmp", "povs", "__pycache__"}


def manifest_path(root: Path, name: str) -> Path:
    return root / "bin" / name / MANIFEST_NAME


def collect_build_inputs(
    *,
    target_dir: Path,
    build_config: Mapping[str, Any],
    placeholders: Mapping[str, str],
    max_files: int = DEFAULT_MAX_FILES,
) -> tuple[list[Path], bool]:
    """The build's input closure: target-dir files, argv tokens that are
    files, and explicit ``inputs`` globs. Returns (paths, truncated)."""
    seen: dict[Path, None] = {}

    def _add(path: Path) -> None:
        if path.is_file() and not path.is_symlink():
            seen.setdefault(path.resolve())

    for entry in sorted(target_dir.rglob("*")):
        if len(seen) > max_files:
            break
        relative_parts = entry.relative_to(target_dir).parts
        if relative_parts and relative_parts[0] in EXCLUDED_TARGET_DIRS:
            continue
        _add(entry)

    def _substitute(text: str) -> str:
        for key, value in placeholders.items():
            text = text.replace("{" + key + "}", value)
        return text

    for step in build_config.get("steps", []) or []:
        for token in step.get("argv", []) or []:
            if len(seen) > max_files:
                break
            raw = _substitute(str(token))
            for candidate in (raw, raw.removeprefix("-I"), raw.split("=", 1)[-1]):
                if not candidate or candidate.startswith("-"):
                    continue
                path = Path(candidate)
                if not path.is_absolute():
                    path = target_dir / path
                _add(path)

    for pattern in build_config.get("inputs", []) or []:
        expanded = _substitute(str(pattern))
        base = Path(expanded)
        if base.is_absolute():
            anchor, glob = base.anchor, str(base.relative_to(base.anchor))
            matches = Path(anchor).glob(glob)
        else:
            matches = target_dir.glob(expanded)
        for match in sorted(matches):
            if len(seen) > max_files:
                break
            _add(match)

    truncated = len(seen) > max_files
    return list(seen)[:max_files], truncated


def write_manifest(
    *,
    root: Path,
    name: str,
    target_dir: Path,
    build_config: Mapping[str, Any],
    placeholders: Mapping[str, str],
    max_files: int = DEFAULT_MAX_FILES,
) -> dict[str, Any]:
    inputs, truncated = collect_build_inputs(
        target_dir=target_dir,
        build_config=build_config,
        placeholders=placeholders,
        max_files=max_files,
    )
    manifest = {
        "built_wall": time.time(),
        "project": f"localfuzz/c/{name}",
        "truncated": truncated,
        "inputs": {str(path): sha256(path.read_bytes()).hexdigest() for path in inputs},
    }
    path = manifest_path(root, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"path": str(path), "inputs": len(manifest["inputs"]), "truncated": truncated}


def check_target_staleness(root: Path, name: str) -> dict[str, Any]:
    """Compare recorded input hashes against the tree. mtime prefilter keeps
    this cheap: files untouched since the build are trusted, only newer ones
    are rehashed. A truncated manifest degrades to mtime-only evidence."""
    path = manifest_path(root, name)
    if not path.is_file():
        return {"stale": None, "missing_manifest": True, "changed": [], "checked": 0}
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"stale": None, "missing_manifest": True, "changed": [], "checked": 0}
    built_wall = float(manifest.get("built_wall") or 0.0)
    truncated = bool(manifest.get("truncated"))
    changed: list[str] = []
    checked = 0
    for recorded_path, recorded_hash in (manifest.get("inputs") or {}).items():
        source = Path(recorded_path)
        if not source.is_file():
            changed.append(f"{recorded_path} (removed)")
            continue
        if source.stat().st_mtime <= built_wall:
            continue
        checked += 1
        if truncated:
            # mtime-only evidence: a newer file counts as changed.
            changed.append(f"{recorded_path} (newer than build)")
            continue
        if sha256(source.read_bytes()).hexdigest() != recorded_hash:
            changed.append(recorded_path)
    return {
        "stale": bool(changed),
        "missing_manifest": False,
        "truncated": truncated,
        "changed": changed[:50],
        "changed_total": len(changed),
        "checked": checked,
        "built_wall": built_wall,
    }

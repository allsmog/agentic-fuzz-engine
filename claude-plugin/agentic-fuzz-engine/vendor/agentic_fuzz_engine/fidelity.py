from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .patching import validate_unified_diff


DEFAULT_REFERENCE_ROOT = Path("fixtures/reference")
REFERENCE_PROJECTS_RELATIVE = Path("benchmark/projects")
USERSPACE_C_PROJECTS_RELATIVE = Path("targets/c")


@dataclass(frozen=True, slots=True)
class HarnessSpec:
    name: str
    path: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class TargetProfile:
    project: str
    target: str
    language: str
    sanitizers: tuple[str, ...]
    fuzzing_engines: tuple[str, ...]
    harnesses: tuple[HarnessSpec, ...]
    project_dir: str
    userspace_project_dir: str | None
    disabled: bool
    disabled_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["harnesses"] = [harness.to_dict() for harness in self.harnesses]
        return data


@dataclass(frozen=True, slots=True)
class FixtureBenchmark:
    project: str
    fixture: str
    target: str
    harness: str
    sanitizer: str
    error_token: str
    base_commit: str
    proof_path: str
    patch_path: str
    index_path: str
    proof_sha256: str
    patch_sha256: str
    patch_size: int
    patch_changed_paths: tuple[str, ...]
    patch_valid: bool
    patch_validation_error: str | None
    disabled_project: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def resolve_reference_root(path: str | Path | None = None) -> Path:
    raw = path if path is not None else os.environ.get("AGENTIC_FUZZ_REFERENCE_ROOT")
    raw_text = os.fspath(raw).strip() if raw is not None else ""
    expanded = os.path.expandvars(raw_text) if raw_text else ""
    if not expanded or expanded.startswith("$"):
        candidate = DEFAULT_REFERENCE_ROOT
    else:
        candidate = Path(expanded)
    return candidate.expanduser().resolve()


def discover_reference_benchmarks(
    reference_root: str | Path | None = None,
    *,
    include_disabled: bool = False,
) -> tuple[FixtureBenchmark, ...]:
    root = resolve_reference_root(reference_root)
    projects_root = root / REFERENCE_PROJECTS_RELATIVE
    benchmarks: list[FixtureBenchmark] = []
    for index_path in sorted(projects_root.glob("*/vulnerabilities/*/index.json")):
        project_dir = index_path.parents[2]
        project_yaml = _parse_project_yaml(project_dir / "project.yaml")
        disabled = bool(project_yaml.get("disabled", False))
        if disabled and not include_disabled:
            continue
        payload = json.loads(index_path.read_text(encoding="utf-8"))
        proof_path = index_path.with_name("proof.bin")
        patch_path = index_path.with_name("patch.diff")
        proof_bytes = proof_path.read_bytes() if proof_path.exists() else b""
        patch_metadata = _patch_metadata(patch_path)
        project = project_dir.name
        benchmarks.append(
            FixtureBenchmark(
                project=project,
                fixture=str(payload["name"]),
                target=f"localfuzz/c/{project}",
                harness=str(payload["harness"]),
                sanitizer=str(payload["sanitizer"]),
                error_token=str(payload["error_token"]),
                base_commit=str(payload["base_commit"]),
                proof_path=str(proof_path),
                patch_path=str(patch_path),
                index_path=str(index_path),
                proof_sha256=sha256(proof_bytes).hexdigest(),
                patch_sha256=patch_metadata["sha256"],
                patch_size=patch_metadata["size"],
                patch_changed_paths=tuple(patch_metadata["changed_paths"]),
                patch_valid=bool(patch_metadata["valid"]),
                patch_validation_error=patch_metadata["validation_error"],
                disabled_project=disabled,
            )
        )
    return tuple(benchmarks)


def validate_reference_fixtures(reference_root: str | Path | None = None, *, include_disabled: bool = True) -> dict[str, Any]:
    benchmarks = discover_reference_benchmarks(reference_root, include_disabled=include_disabled)
    missing: list[dict[str, str]] = []
    invalid_patches: list[dict[str, str]] = []
    for benchmark in benchmarks:
        for field, path in (
            ("index_path", benchmark.index_path),
            ("proof_path", benchmark.proof_path),
            ("patch_path", benchmark.patch_path),
        ):
            if not Path(path).exists():
                missing.append({"project": benchmark.project, "fixture": benchmark.fixture, "field": field, "path": path})
        if Path(benchmark.patch_path).exists() and not benchmark.patch_valid:
            invalid_patches.append(
                {
                    "project": benchmark.project,
                    "fixture": benchmark.fixture,
                    "path": benchmark.patch_path,
                    "error": benchmark.patch_validation_error or "invalid patch diff",
                }
            )
    enabled = [benchmark for benchmark in benchmarks if not benchmark.disabled_project]
    disabled = [benchmark for benchmark in benchmarks if benchmark.disabled_project]
    return {
        "ok": not missing and not invalid_patches,
        "total_fixtures": len(benchmarks),
        "enabled_fixtures": len(enabled),
        "disabled_fixtures": len(disabled),
        "projects": sorted({benchmark.project for benchmark in benchmarks}),
        "enabled_projects": sorted({benchmark.project for benchmark in enabled}),
        "disabled_projects": sorted({benchmark.project for benchmark in disabled}),
        "missing": missing,
        "invalid_patches": invalid_patches,
        "benchmarks": [benchmark.to_dict() for benchmark in benchmarks],
    }


def load_target_profile(project: str, reference_root: str | Path | None = None) -> TargetProfile:
    project_name = project.removeprefix("localfuzz/c/")
    root = resolve_reference_root(reference_root)
    project_dir = root / REFERENCE_PROJECTS_RELATIVE / project_name
    if not project_dir.exists():
        raise FileNotFoundError(f"unknown benchmark project: {project}")
    project_yaml = _parse_project_yaml(project_dir / "project.yaml")
    userspace_project_dir = root / USERSPACE_C_PROJECTS_RELATIVE / project_name
    harnesses = _load_userspace_harnesses(userspace_project_dir / ".localfuzz" / "config.yaml")
    disabled = bool(project_yaml.get("disabled", False))
    return TargetProfile(
        project=project_name,
        target=f"localfuzz/c/{project_name}",
        language=str(project_yaml.get("language", "c++")),
        sanitizers=tuple(str(item) for item in project_yaml.get("sanitizers", ())),
        fuzzing_engines=tuple(str(item) for item in project_yaml.get("fuzzing_engines", ())),
        harnesses=harnesses,
        project_dir=str(project_dir),
        userspace_project_dir=str(userspace_project_dir) if userspace_project_dir.exists() else None,
        disabled=disabled,
        disabled_reason=str(project_yaml.get("disabled_reason", "")) or None,
    )


def _load_userspace_harnesses(path: Path) -> tuple[HarnessSpec, ...]:
    if not path.exists():
        return ()
    harnesses: list[HarnessSpec] = []
    pending: dict[str, str] | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line == "harness_files:":
            continue
        if line.startswith("- name:"):
            if pending and "name" in pending and "path" in pending:
                harnesses.append(HarnessSpec(name=pending["name"], path=pending["path"]))
            pending = {"name": _strip_yaml_scalar(line.split(":", 1)[1])}
            continue
        if line.startswith("path:") and pending is not None:
            pending["path"] = _strip_yaml_scalar(line.split(":", 1)[1])
    if pending and "name" in pending and "path" in pending:
        harnesses.append(HarnessSpec(name=pending["name"], path=pending["path"]))
    return tuple(harnesses)


def _parse_project_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data: dict[str, Any] = {}
    current_key: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = _remove_comment(raw_line.rstrip())
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("- ") and current_key:
            data.setdefault(current_key, []).append(_strip_yaml_scalar(stripped[2:]))
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        current_key = key.strip()
        value = value.strip()
        if not value:
            data[current_key] = []
        else:
            data[current_key] = _strip_yaml_scalar(value)
    return data


def _patch_metadata(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"sha256": "", "size": 0, "changed_paths": [], "valid": False, "validation_error": "missing patch.diff"}
    patch_bytes = path.read_bytes()
    try:
        changed_paths = validate_unified_diff(patch_bytes.decode("utf-8", errors="replace"))
    except ValueError as exc:
        return {
            "sha256": sha256(patch_bytes).hexdigest(),
            "size": len(patch_bytes),
            "changed_paths": [],
            "valid": False,
            "validation_error": str(exc),
        }
    return {
        "sha256": sha256(patch_bytes).hexdigest(),
        "size": len(patch_bytes),
        "changed_paths": changed_paths,
        "valid": True,
        "validation_error": None,
    }


def _strip_yaml_scalar(value: str) -> Any:
    value = value.strip()
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value and value[0] in {"'", '"'} and value[-1:] == value[0]:
        return value[1:-1]
    return value


def _remove_comment(line: str) -> str:
    quote: str | None = None
    for index, char in enumerate(line):
        if char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
        if char == "#" and quote is None:
            return line[:index].rstrip()
    return line

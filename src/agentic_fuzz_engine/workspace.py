"""Generated dot-directory workspace holding target assets, build outputs, and campaign state.

The workspace root doubles as the engine reference root: it carries the same
``benchmark/projects`` + ``targets/c`` layout that :mod:`fidelity` resolves, so
target profiles generated here work with the existing campaign flow unchanged.

Docker-outside-of-docker hosts (where the docker daemon resolves bind-mount
paths on an outer host) are supported through ``path_maps``: ordered
``host-prefix=outer-prefix`` pairs recorded in ``workspace.json`` and applied
by :func:`translate_host_path` whenever a module mounts a host path into a
container.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Mapping

WORKSPACE_ENV = "AGENTIC_FUZZ_WORKSPACE"
POLICY_FILE_NAME = "campaign-policy.json"
DEFAULT_POLICY: dict[str, Any] = {
    "round": {"fuzz_seconds": 1800, "sync_max_inputs": 32, "klee_every": 4, "rss_limit_mb": 2048},
    "plateau": {"metric": "features", "flat_rounds": 3},
    "ladder": ["dictionary", "structured-seeds", "klee-directed", "symcc-long"],
    "gc": {
        "gc_every": 5,
        "run_retention": 10,
        "klee_out_retention": 5,
        "gc_corpus_min_files": 2000,
        "gc_corpus_max_mb": 512,
        "merge_timeout_seconds": 600,
    },
    "disk": {"min_free_gb": 10},
}
KLEE_IMAGE_ENV = "AGENTIC_FUZZ_KLEE_IMAGE"
WORKSPACE_CONFIG_NAME = "workspace.json"
WORKSPACE_ENV_FILE = "env.sh"
DEFAULT_KLEE_IMAGE = "klee-ng:dev-libcxx"
WORKSPACE_SUBDIRS = (
    "data",
    "targets/c",
    "benchmark/projects",
    "bin",
    "work",
    "klee",
)
SKIP_COPY_DIRS = {".git", "__pycache__", ".pytest_cache"}


def resolve_workspace_root(path: str | Path | None = None, *, env: Mapping[str, str] | None = None) -> Path:
    environment = env if env is not None else os.environ
    raw = path if path is not None else environment.get(WORKSPACE_ENV)
    if raw is None or not os.fspath(raw).strip():
        raw = Path.home() / ".cache" / "agentic-fuzz"
    return Path(raw).expanduser().resolve()


def load_workspace(path: str | Path | None = None, *, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    root = resolve_workspace_root(path, env=env)
    config_path = root / WORKSPACE_CONFIG_NAME
    if not config_path.is_file():
        raise FileNotFoundError(f"workspace config not found: {config_path} (run workspace-init first)")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["root"] = str(root)
    return config


def load_policy(root: str | Path | None = None, *, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Campaign policy: workspace file overrides defaults, section-wise."""
    workspace_root = resolve_workspace_root(root, env=env)
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    policy_path = workspace_root / POLICY_FILE_NAME
    if policy_path.is_file():
        try:
            overrides = json.loads(policy_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            overrides = {}
        for section, value in overrides.items():
            if isinstance(value, dict) and isinstance(policy.get(section), dict):
                policy[section].update(value)
            else:
                policy[section] = value
    policy["_path"] = str(policy_path)
    return policy


def translate_host_path(path: str | Path, workspace: Mapping[str, Any]) -> str:
    """Map a host path to the path the docker daemon must use for bind mounts."""
    text = str(Path(path).expanduser())
    best_host = ""
    best_outer = ""
    for entry in workspace.get("path_maps", []):
        host = str(entry.get("host", "")).rstrip("/")
        outer = str(entry.get("outer", "")).rstrip("/")
        if not host or not outer:
            continue
        if (text == host or text.startswith(host + "/")) and len(host) > len(best_host):
            best_host = host
            best_outer = outer
    if not best_host:
        return text
    return best_outer + text[len(best_host):]


def workspace_init(
    *,
    root: str | Path | None = None,
    path_maps: list[str] | None = None,
    source_dir: str | Path | None = None,
    klee_image: str | None = None,
    build_container: str | None = None,
    extra_mounts: list[str] | None = None,
    copies: list[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = env if env is not None else os.environ
    workspace_root = resolve_workspace_root(root, env=environment)
    workspace_root.mkdir(parents=True, exist_ok=True)
    for relative in WORKSPACE_SUBDIRS:
        (workspace_root / relative).mkdir(parents=True, exist_ok=True)

    parsed_maps = [_parse_pair(item, kind="path map", separator="=") for item in (path_maps or [])]
    resolved_source = str(Path(source_dir).expanduser().resolve()) if source_dir else None
    image = klee_image or environment.get(KLEE_IMAGE_ENV) or DEFAULT_KLEE_IMAGE

    copy_results = []
    blockers = []
    for item in copies or []:
        src_text, dest_rel = _parse_pair(item, kind="copy", separator="=")
        result = _copy_into_workspace(Path(src_text).expanduser(), workspace_root, dest_rel)
        copy_results.append(result)
        if result.get("blocker"):
            blockers.append(result["blocker"])

    parsed_mounts = []
    for item in extra_mounts or []:
        host_text, container_text = _parse_pair(item, kind="mount", separator="=")
        mode = "rw"
        if container_text.endswith(":ro") or container_text.endswith(":rw"):
            container_text, mode = container_text[:-3], container_text[-2:]
        parsed_mounts.append({"host": str(Path(host_text).expanduser()), "container": container_text, "mode": mode})

    config = {
        "path_maps": [{"host": host, "outer": outer} for host, outer in parsed_maps],
        "source_dir": resolved_source,
        "docker": {"klee_image": image, "build_container": build_container},
        "extra_mounts": parsed_mounts,
        "layout": {name: name for name in WORKSPACE_SUBDIRS},
    }
    (workspace_root / WORKSPACE_CONFIG_NAME).write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (workspace_root / WORKSPACE_ENV_FILE).write_text(_render_env_file(workspace_root, image), encoding="utf-8")
    policy_path = workspace_root / POLICY_FILE_NAME
    if not policy_path.exists():  # never clobber a tuned policy
        policy_path.write_text(json.dumps(DEFAULT_POLICY, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return {
        "ok": not blockers,
        "root": str(workspace_root),
        "config_path": str(workspace_root / WORKSPACE_CONFIG_NAME),
        "env_file": str(workspace_root / WORKSPACE_ENV_FILE),
        "path_maps": config["path_maps"],
        "source_dir": resolved_source,
        "docker": config["docker"],
        "extra_mounts": parsed_mounts,
        "copies": copy_results,
        "blockers": blockers,
    }


def _render_env_file(root: Path, klee_image: str) -> str:
    lines = [
        "# Generated by agentic-fuzz-engine workspace-init. Source this before CLI use.",
        f'export {WORKSPACE_ENV}="{root}"',
        f'export AGENTIC_FUZZ_REFERENCE_ROOT="{root}"',
        f'export CLAUDE_PLUGIN_DATA="{root / "data"}"',
        f'export {KLEE_IMAGE_ENV}="{klee_image}"',
    ]
    return "\n".join(lines) + "\n"


def _parse_pair(item: str, *, kind: str, separator: str) -> tuple[str, str]:
    left, sep, right = item.partition(separator)
    if not sep or not left.strip() or not right.strip():
        raise ValueError(f"invalid {kind} entry (expected LEFT{separator}RIGHT): {item!r}")
    return left.strip(), right.strip()


def _copy_into_workspace(source: Path, workspace_root: Path, dest_rel: str) -> dict[str, Any]:
    destination = (workspace_root / dest_rel).resolve()
    if not str(destination).startswith(str(workspace_root)):
        return {"source": str(source), "dest": dest_rel, "copied_files": 0, "blocker": f"copy destination escapes workspace: {dest_rel}"}
    if not source.exists():
        return {"source": str(source), "dest": str(destination), "copied_files": 0, "blocker": f"copy source missing: {source}"}
    if source.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return {"source": str(source), "dest": str(destination), "copied_files": 1, "blocker": None}
    copied = 0
    for dirpath, dirnames, filenames in os.walk(source):
        dirnames[:] = [name for name in dirnames if name not in SKIP_COPY_DIRS]
        rel = Path(dirpath).relative_to(source)
        target_dir = destination / rel
        target_dir.mkdir(parents=True, exist_ok=True)
        for filename in filenames:
            shutil.copy2(Path(dirpath) / filename, target_dir / filename)
            copied += 1
    return {"source": str(source), "dest": str(destination), "copied_files": copied, "blocker": None}

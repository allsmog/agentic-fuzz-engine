"""Dispatcher configuration: paths, engine invocation, fleet policy."""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

POLICY_FILE = "campaign-policy.json"
# Launch-priority order; build-heavy types share the build sublimit.
TYPE_ORDER = (
    "fleet_plan",
    "triage",
    "allowlist_build",
    "harness_author",
    "frontier_seed",
    "steering",
    "solver_assist",
    "vuln_hunt",
    "pov_produce",
)
BUILD_HEAVY = {"allowlist_build", "harness_author"}
ALLOWED_TOOLS = "Bash Read Write Edit Glob Grep"
DISALLOWED_TOOLS = "WebFetch WebSearch Task"

DEFAULT_FLEET_POLICY: dict[str, Any] = {
    "enabled": False,
    "max_workers": 4,
    "max_build_workers": 2,
    "daily_usd_cap": 150.0,
    "max_attempts": 3,
    "model": None,
    "job_caps": {},
}


@dataclass
class Config:
    workspace: Path
    engine_root: Path
    plugin_root: Path
    claude_bin: str
    add_dirs: list[str] = field(default_factory=list)

    @property
    def jobs_dir(self) -> Path:
        return self.workspace / "work" / "_fleet" / "jobs"

    @property
    def spend_path(self) -> Path:
        return self.workspace / "data" / "fleet-spend.json"

    def engine_cmd(self, *args: str) -> list[str]:
        return [sys.executable, "-m", "agentic_fuzz_engine.cli", *args]

    def engine_env(self) -> dict[str, str]:
        env = dict(os.environ)
        src = str(self.engine_root / "src")
        env["PYTHONPATH"] = src + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        env["AGENTIC_FUZZ_WORKSPACE"] = str(self.workspace)
        env["AGENTIC_FUZZ_REFERENCE_ROOT"] = str(self.workspace)
        env["CLAUDE_PLUGIN_DATA"] = str(self.workspace / "data")
        return env

    def fleet_policy(self) -> dict[str, Any]:
        policy = dict(DEFAULT_FLEET_POLICY)
        path = self.workspace / POLICY_FILE
        try:
            overrides = json.loads(path.read_text(encoding="utf-8")).get("fleet")
        except (OSError, json.JSONDecodeError):
            overrides = None
        if isinstance(overrides, dict):
            policy.update(overrides)
        return policy

    def playbook_path(self, playbook: str) -> Path:
        return self.plugin_root / "agents" / playbook


def load_config(
    *,
    workspace: str | None = None,
    engine_root: str | None = None,
    plugin_root: str | None = None,
    claude_bin: str | None = None,
    add_dir: list[str] | None = None,
) -> Config:
    ws = Path(
        workspace
        or os.environ.get("AGENTIC_FUZZ_WORKSPACE")
        or (Path.home() / ".cache" / "agentic-fuzz")
    ).expanduser().resolve()
    engine = Path(
        engine_root
        or os.environ.get("AFE_ENGINE_ROOT")
        or Path(__file__).resolve().parents[3]
    ).resolve()
    plugin = Path(
        plugin_root
        or os.environ.get("AFE_PLUGIN_ROOT")
        or engine / "claude-plugin" / "agentic-fuzz-engine"
    ).resolve()
    default_dirs = [d for d in [os.environ.get("AFE_ADD_DIR")] if d]
    return Config(
        workspace=ws,
        engine_root=engine,
        plugin_root=plugin,
        claude_bin=claude_bin or os.environ.get("AFE_CLAUDE_BIN") or "claude",
        add_dirs=add_dir if add_dir is not None else default_dirs,
    )


def doctor(cfg: Config) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    claude_path = shutil.which(cfg.claude_bin)
    check("claude binary", claude_path is not None, claude_path or f"{cfg.claude_bin} not on PATH")
    check("workspace", (cfg.workspace / "workspace.json").is_file(), str(cfg.workspace))
    check("engine src", (cfg.engine_root / "src" / "agentic_fuzz_engine" / "cli.py").is_file(), str(cfg.engine_root))
    check("plugin playbooks", (cfg.plugin_root / "agents").is_dir(), str(cfg.plugin_root / "agents"))
    policy = cfg.fleet_policy()
    check("fleet enabled", bool(policy.get("enabled")), f"fleet.enabled={policy.get('enabled')} in {cfg.workspace / POLICY_FILE}")
    try:
        usage = shutil.disk_usage(cfg.workspace)
        free_gb = usage.free / 1e9
        check("disk headroom", free_gb > 10, f"{free_gb:.1f} GB free")
    except OSError as exc:
        check("disk headroom", False, str(exc))
    return {"ok": all(c["ok"] for c in checks), "checks": checks, "policy": policy}

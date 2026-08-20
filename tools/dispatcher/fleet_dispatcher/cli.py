"""fleet_dispatcher CLI: run-once / dispatch / doctor."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .config import doctor, load_config
from .governor import dispatch, select_wave
from .runner import run_job


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fleet_dispatcher")
    parser.add_argument("--workspace", default=None)
    parser.add_argument("--engine-root", default=None)
    parser.add_argument("--plugin-root", default=None)
    parser.add_argument("--claude-bin", default=None)
    parser.add_argument("--add-dir", action="append", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    run_once = sub.add_parser("run-once", help="run exactly one job by id")
    run_once.add_argument("--job", required=True)
    run_once.add_argument("--dry-run", action="store_true")
    run_once.add_argument("--force", action="store_true", help="ignore fleet.enabled for this single job")

    disp = sub.add_parser("dispatch", help="drain queued jobs in bounded waves")
    disp.add_argument("--workers", type=int, default=2)
    disp.add_argument("--once", action="store_true", help="one wave then exit")
    disp.add_argument("--types", default=None, help="comma-separated job types")
    disp.add_argument("--plan", action="store_true", help="print the wave selection without launching")

    sub.add_parser("doctor", help="environment + policy preflight")

    args = parser.parse_args(argv)
    cfg = load_config(
        workspace=args.workspace,
        engine_root=args.engine_root,
        plugin_root=args.plugin_root,
        claude_bin=args.claude_bin,
        add_dir=args.add_dir,
    )

    payload: dict[str, Any]
    if args.command == "doctor":
        payload = doctor(cfg)
    elif args.command == "run-once":
        if not args.dry_run and not args.force and not cfg.fleet_policy().get("enabled"):
            payload = {"ok": False, "blockers": ["fleet.enabled is false — flip the policy or pass --force"]}
        else:
            payload = run_job(cfg, args.job, dry_run=args.dry_run)
    elif args.command == "dispatch":
        types = [t.strip() for t in args.types.split(",")] if args.types else None
        if args.plan:
            payload = select_wave(cfg, workers=args.workers, types=types)
        else:
            payload = dispatch(cfg, workers=args.workers, once=args.once, types=types)
    else:  # pragma: no cover
        parser.error(f"unknown command {args.command}")
        return 2

    json.dump(payload, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0 if payload.get("ok", True) else 1

#!/usr/bin/env python3
from __future__ import annotations

import json
import sys


BLOCKED = (
    "RealExternalExecutionPlane",
    "external_runtime.py",
    "EXTERNAL_RUNTIME_ROOT",
    "runtime-userspace/docker-run.py",
    "runtime-multilang/run.py",
)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    command = str((payload.get("tool_input") or {}).get("command") or "")
    for pattern in BLOCKED:
        if pattern in command:
            decision = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "agentic-fuzz blocks real external runtime invocation; use plugin-local fuzzing tools instead",
                }
            }
            print(json.dumps(decision))
            return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

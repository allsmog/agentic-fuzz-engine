#!/usr/bin/env bash
# PreToolUse guard: block real external runtime invocation from Bash commands.
# Pure bash/grep so it runs on hosts where EDR policy blocks `python3 <file>`.
set -euo pipefail

payload="$(cat)"

blocked_patterns=(
  "RealExternalExecutionPlane"
  "external_runtime.py"
  "EXTERNAL_RUNTIME_ROOT"
  "runtime-userspace/docker-run.py"
  "runtime-multilang/run.py"
)

for pattern in "${blocked_patterns[@]}"; do
  if printf '%s' "${payload}" | grep -qF "${pattern}"; then
    printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"agentic-fuzz blocks real external runtime invocation; use plugin-local fuzzing tools instead"}}'
    exit 0
  fi
done

exit 0

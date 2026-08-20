#!/usr/bin/env bash
# Monitor: publish a compact count of plugin-local fuzzing campaigns.
# Pure bash so it runs on hosts where EDR policy blocks `python3 <file>`.
set -u

if [ -n "${CLAUDE_PLUGIN_DATA:-}" ]; then
  data_root="${CLAUDE_PLUGIN_DATA}"
elif [ -n "${XDG_STATE_HOME:-}" ]; then
  data_root="${XDG_STATE_HOME}/agentic-fuzz-engine"
else
  data_root="${HOME:-/tmp}/.local/state/agentic-fuzz-engine"
fi
runs_root="${data_root}/runs"

while true; do
  count=0
  if [ -d "${runs_root}" ]; then
    count="$(find "${runs_root}" -mindepth 2 -maxdepth 2 -name campaign.json 2>/dev/null | wc -l | tr -d ' ')"
  fi
  printf '{"source":"agentic-fuzz","campaigns":%s}\n' "${count}"
  sleep 60
done

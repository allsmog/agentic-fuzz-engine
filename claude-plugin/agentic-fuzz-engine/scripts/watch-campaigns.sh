#!/usr/bin/env bash
# Monitor: publish a compact count of plugin-local fuzzing campaigns.
# Pure bash so it runs on hosts where EDR policy blocks `python3 <file>`.
set -u

data_root="${CLAUDE_PLUGIN_DATA:-runs/agentic-fuzz-engine}"
runs_root="${data_root}/runs"

while true; do
  count=0
  if [ -d "${runs_root}" ]; then
    count="$(find "${runs_root}" -mindepth 2 -maxdepth 2 -name campaign.json 2>/dev/null | wc -l | tr -d ' ')"
  fi
  printf '{"source":"agentic-fuzz","campaigns":%s}\n' "${count}"
  sleep 60
done

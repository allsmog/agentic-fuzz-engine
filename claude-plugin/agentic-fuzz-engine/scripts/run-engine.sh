#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/engine-env.sh"

exec "${python_bin}" -m agentic_fuzz_engine.cli \
  --data-root "${data_root}" \
  --audit-root "${engine_root}/src/agentic_fuzz_engine" \
  --audit-root "${engine_root}/src/agentic_fuzz_full" \
  --audit-root "${plugin_root}" \
  "$@"

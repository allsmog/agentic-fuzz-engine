#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/engine-env.sh"

run_vendored_module agentic_fuzz_engine.mcp_stdio \
  --data-root "${data_root}" \
  --audit-root "${vendor_root}/agentic_fuzz_engine" \
  --audit-root "${vendor_root}/agentic_fuzz_full" \
  --audit-root "${plugin_root}"

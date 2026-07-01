#!/usr/bin/env bash
set -euo pipefail

plugin_root="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
project_root="${CLAUDE_PROJECT_DIR:-$(pwd)}"
export CLAUDE_PROJECT_DIR="${project_root}"

if [ -d "${project_root}/tools/bin" ]; then
  export PATH="${project_root}/tools/bin:${PATH}"
fi

for tool_dir in /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin; do
  if [ -d "${tool_dir}" ]; then
    export PATH="${tool_dir}:${PATH}"
  fi
done

export AGENTIC_FUZZ_CLAUDE_CODE_MODEL="${AGENTIC_FUZZ_CLAUDE_CODE_MODEL:-1}"
export PYTHONPATH="${project_root}/src:${PYTHONPATH:-}"
python_bin="${AGENTIC_FUZZ_PYTHON:-}"
if [ -z "${python_bin}" ] && [ -x "${project_root}/.venv/bin/python" ]; then
  python_bin="${project_root}/.venv/bin/python"
fi
python_bin="${python_bin:-python3}"
exec "${python_bin}" -m agentic_fuzz_engine.mcp_stdio \
  --data-root "${CLAUDE_PLUGIN_DATA:-${project_root}/runs/agentic-fuzz-engine}" \
  --audit-root "${project_root}/src/agentic_fuzz_engine" \
  --audit-root "${plugin_root}"

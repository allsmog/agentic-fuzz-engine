#!/usr/bin/env bash
# Shared environment resolution for plugin launchers.
# Locates the agentic-fuzz-engine checkout even when this plugin runs from the
# Claude Code plugin cache (which only contains the plugin subtree).

plugin_root="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

engine_root="${AGENTIC_FUZZ_ENGINE_ROOT:-}"
if [ -z "${engine_root}" ]; then
  for cand in "${plugin_root}/../.." "${CLAUDE_PROJECT_DIR:-}" "${HOME}/agentic-fuzz-engine"; do
    if [ -n "${cand}" ] && [ -f "${cand}/src/agentic_fuzz_engine/cli.py" ]; then
      engine_root="$(cd "${cand}" && pwd)"
      break
    fi
  done
fi
if [ -z "${engine_root}" ]; then
  echo "agentic-fuzz: engine checkout not found; set AGENTIC_FUZZ_ENGINE_ROOT" >&2
  exit 1
fi

export CLAUDE_PROJECT_DIR="${CLAUDE_PROJECT_DIR:-${engine_root}}"

if [ -d "${engine_root}/tools/bin" ]; then
  export PATH="${engine_root}/tools/bin:${PATH}"
fi

for tool_dir in /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin; do
  if [ -d "${tool_dir}" ]; then
    export PATH="${tool_dir}:${PATH}"
  fi
done

export AGENTIC_FUZZ_CLAUDE_CODE_MODEL="${AGENTIC_FUZZ_CLAUDE_CODE_MODEL:-1}"
export PYTHONPATH="${engine_root}/src:${PYTHONPATH:-}"

python_bin="${AGENTIC_FUZZ_PYTHON:-}"
if [ -z "${python_bin}" ] && [ -x "${engine_root}/.venv/bin/python" ]; then
  python_bin="${engine_root}/.venv/bin/python"
fi
python_bin="${python_bin:-python3}"

data_root="${CLAUDE_PLUGIN_DATA:-${engine_root}/runs/agentic-fuzz-engine}"

#!/usr/bin/env bash
# Shared, cache-safe environment resolution for plugin launchers.
set -euo pipefail

plugin_root="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
vendor_root="${plugin_root}/vendor"

if [ ! -f "${vendor_root}/agentic_fuzz_engine/cli.py" ]; then
  echo "agentic-fuzz: vendored engine package is missing from this plugin" >&2
  exit 1
fi

export AGENTIC_FUZZ_PLUGIN_ROOT="${plugin_root}"
export AGENTIC_FUZZ_CLAUDE_CODE_MODEL="${AGENTIC_FUZZ_CLAUDE_CODE_MODEL:-1}"

# Checkout-only binaries are optional. An installed plugin never guesses a
# sibling checkout and therefore never makes a cached installation look ready.
engine_root="${AGENTIC_FUZZ_ENGINE_ROOT:-}"
if [ -n "${engine_root}" ] && [ -d "${engine_root}/tools/bin" ]; then
  export PATH="${engine_root}/tools/bin:${PATH}"
fi
for tool_dir in /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin; do
  if [ -d "${tool_dir}" ]; then
    export PATH="${tool_dir}:${PATH}"
  fi
done

python_is_supported() {
  if [[ "$1" == */* ]]; then
    [ -x "$1" ] || return 1
  else
    command -v "$1" >/dev/null 2>&1 || return 1
  fi
  "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1
}

python_bin=""
if [ -n "${AGENTIC_FUZZ_PYTHON:-}" ]; then
  if ! python_is_supported "${AGENTIC_FUZZ_PYTHON}"; then
    echo "agentic-fuzz: AGENTIC_FUZZ_PYTHON must refer to Python 3.11 or newer" >&2
    exit 1
  fi
  python_bin="${AGENTIC_FUZZ_PYTHON}"
fi
if [ -z "${python_bin}" ]; then
  IFS=':' read -r -a python_path_entries <<< "${PATH:-}"
  for python_path_entry in "${python_path_entries[@]}"; do
    [ -n "${python_path_entry}" ] || python_path_entry="."
    for candidate in "${python_path_entry}"/python3.*; do
      if [ -x "${candidate}" ] && python_is_supported "${candidate}"; then
        python_bin="${candidate}"
        break 2
      fi
    done
  done
  if [ -z "${python_bin}" ] && python_is_supported python3; then
    python_bin="python3"
  fi
fi
if [ -z "${python_bin}" ]; then
  echo "agentic-fuzz: Python 3.11 or newer is required" >&2
  exit 1
fi

# State must survive cache replacement without becoming part of the plugin.
if [ -n "${CLAUDE_PLUGIN_DATA:-}" ]; then
  data_root="${CLAUDE_PLUGIN_DATA}"
elif [ -n "${XDG_STATE_HOME:-}" ]; then
  data_root="${XDG_STATE_HOME}/agentic-fuzz-engine"
else
  data_root="${HOME:-/tmp}/.local/state/agentic-fuzz-engine"
fi

run_vendored_module() {
  local module="$1"
  shift
  exec "${python_bin}" -I -B -c '
import runpy
import sys
vendor, module, *args = sys.argv[1:]
sys.path.insert(0, vendor)
sys.argv = [module, *args]
runpy.run_module(module, run_name="__main__")
' "${vendor_root}" "${module}" "$@"
}

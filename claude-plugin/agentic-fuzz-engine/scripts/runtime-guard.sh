#!/usr/bin/env bash
# PreToolUse guard. It execs the tokenizer implementation and preserves its I/O
# and status; this is a narrow backstop, not a sandbox.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${AGENTIC_FUZZ_PYTHON:-python3}" "${script_dir}/runtime-guard.py"

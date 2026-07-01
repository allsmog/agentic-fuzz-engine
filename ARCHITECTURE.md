# Architecture

Agentic Fuzz Engine is split into three layers:

1. Claude Code plugin surface in `claude-plugin/agentic-fuzz-engine`
2. Local engine runtime exposed through `agentic_fuzz_engine`
3. Dependency-gated backend adapters for fuzzing, symbolic execution, reachability, and patch checks

The plugin exposes specialist agents, skills, friendly commands, a stdio MCP server, and hook/monitor metadata. The local runtime owns state, artifacts, checkpoints, finding grading, dedupe, reports, and backend invocation.

## Execution Model

Commands are explicit and local. The engine records blockers when required binaries, source paths, harness commands, or model runtime access are missing.

Readiness checks:

- `runtime-doctor`
- `runtime-backend-status`
- `parity-full --strict`

Worker commands:

- `fuzz-ensemble-run`
- `symbolic-worker-run`
- `sarif-reachability-run`
- `patch-environment-prepare`

## Safety Model

The plugin does not start background infrastructure by default. It uses bounded local subprocesses, explicit paths, and plugin-local artifact state. Mutating flows should remain gated by operator intent and command-specific confirmation.

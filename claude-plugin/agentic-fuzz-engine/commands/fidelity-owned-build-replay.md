---
description: Compile owned direct-ASAN replay binaries from fixture source snapshots and compare verified proofs against benchmark fixtures.
allowed-tools: [Bash]
---

# Owned Build Replay

Run the owned direct-ASAN replay comparison:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" fidelity-owned-build-replay $ARGUMENTS
```

Use `--summary-only` for smoke tests and broad comparisons. Add `--project targets/<name>` to scope to one project, or omit it to compare against the enabled fixture corpus. Add `--require-all` only when every selected harness is expected to compile and verify.

Report selected fixtures, enabled fixtures, compiled harnesses, executed proofs, verified proofs, represented fixtures, missing fixtures, coverage ratio, and the first build blockers.

This command may compile local source snapshots with Clang and replay fixture proofs through the plugin-local guarded harness executor. It must not start external services, Kubernetes jobs, Redis, Kafka, ZeroMQ, Docker, distributed fuzzers, symbolic executors, patch sandboxes, SARIF workers, or real export clients.

---
description: Validate the benchmark fidelity fixtures and full-runtime parity contract.
allowed-tools: [Bash]
---

# Benchmark Fidelity Fixtures

Validate the read-only fidelity fixtures and the full-runtime parity contract:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" benchmark-fixtures $ARGUMENTS
```

Report fixture counts, missing fixture files, prompt fixture status, and full-runtime parity blockers.

This command reads fixture metadata only. It does not call external runtime launchers or run live target campaigns.

---
description: Check owned full-runtime prerequisites for the full local-equivalent rebuild.
allowed-tools: [Bash]
---

# Runtime Doctor

Run the owned full-runtime readiness doctor:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" runtime-doctor $ARGUMENTS
```

Report the subsystem readiness table, missing binaries, missing Python modules, missing model credentials, missing prompt fidelity fixtures, and blockers.

Do not start Kubernetes jobs, Redis, Kafka, ZeroMQ, fuzzers, symbolic executors, patch environments, SARIF workers, or export clients from this command.

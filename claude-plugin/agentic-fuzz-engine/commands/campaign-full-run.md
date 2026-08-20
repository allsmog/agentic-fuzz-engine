---
description: Run a bounded plugin-local full fuzzing campaign over benchmark fixtures using an explicit local harness command.
allowed-tools: [Bash]
---

# Full Local Campaign Run

Run the owned local full-runtime campaign:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-full-run $ARGUMENTS
```

The first argument must be the target project such as `targets/mongoose`. Provide a local harness command with `--harness-command-json` or a harness command map with `--command-map-json` / `--command-map-file`.

For automated smoke tests, include `--summary-only` in the arguments. Report the run id, target, harness, source directory, benchmark proof verification count, finding grade, minimized PoV verdict, dedupe/lifecycle status, report artifacts, mock export receipts, and strict completion gate.

This command may run only the explicit local harness command supplied by the operator. It must not start external services, Kubernetes jobs, Redis, Kafka, ZeroMQ, Docker, distributed fuzzers, symbolic executors, patch sandboxes, SARIF workers, or real export clients.

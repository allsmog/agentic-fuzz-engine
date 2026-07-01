---
description: Build owned OSS-Fuzz harness binaries and replay matching fixture proofs in a bounded base-runner container.
allowed-tools: [Bash]
---

# OSS-Fuzz Build Replay

Run the owned OSS-Fuzz build plus proof replay comparison:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" fidelity-oss-fuzz-build-replay $ARGUMENTS
```

Pass the project as the first argument, for example `targets/mongoose` or `mongoose`. Use `--summary-only` for smoke tests. Add `--require-all` only when every selected fixture proof is expected to replay and verify on the current host.

Run this command in the foreground and wait for it to complete. Do not background it, daemonize it, start a separate monitor, or report that the user should wait for a later notification.

This command invokes the local OSS-Fuzz `infra/helper.py`, builds fuzzer binaries in a plugin-owned external project workspace, and then runs matching fixture proofs inside the benchmark base-runner image with read-only mounts for `/out` and the proof file.

It does not start external services, Kubernetes allocators, Redis, Kafka, ZeroMQ, distributed fuzzing coordinators, symbolic engines, patch sandboxes, SARIF workers, or real export clients. A represented fixture requires a matching ASAN signal from the bounded container replay; build-only harness coverage is not counted as a finding.

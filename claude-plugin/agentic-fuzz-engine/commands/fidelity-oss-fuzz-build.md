---
description: Build owned OSS-Fuzz harness binaries for a fixture project and compare produced harness names against the fixture corpus.
allowed-tools: [Bash]
---

# OSS-Fuzz Harness Build

Run the owned OSS-Fuzz build comparison:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" fidelity-oss-fuzz-build $ARGUMENTS
```

Pass the project as the first argument, for example `targets/mongoose` or `mongoose`. Use `--summary-only` for smoke tests and broad comparisons.

This command invokes the local OSS-Fuzz `infra/helper.py` against a plugin-owned external project workspace. It can use Docker or Colima to build the harness image and fuzzer binaries, then reports the produced fuzzer names and which fixture harnesses they cover.

It does not start external services, Kubernetes allocators, Redis, Kafka, ZeroMQ, distributed fuzzers, symbolic engines, patch sandboxes, SARIF workers, or real export clients. Proof replay is intentionally separate because Docker/QEMU runner behavior must be validated independently on the host.

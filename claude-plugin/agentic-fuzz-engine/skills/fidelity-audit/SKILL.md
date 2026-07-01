---
description: Inspect reference C/C++ fixture benchmark fidelity fixtures used by the Agentic Fuzz plugin.
disable-model-invocation: true
allowed-tools: [Bash]
---

# Fidelity Audit

List and validate the C/C++ fixture corpus used as parity fixtures for the agentic reimplementation.

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" fidelity-list-fixtures --include-disabled
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" fidelity-validate-fixtures --include-disabled
```

For each fixture, summarize:
- project and target slug
- harness
- sanitizer
- exact `error_token`
- proof sha256 and size if available
- benchmark patch path, benchmark patch sha256, and patch changed paths
- disabled status

Fidelity means the agentic pipeline can represent these cases as target, harness, proof, sanitizer token, finding signature, dedupe group, report, benchmark patch metadata, and patch-evaluation input. It does not mean executing external code or applying benchmark patches blindly.

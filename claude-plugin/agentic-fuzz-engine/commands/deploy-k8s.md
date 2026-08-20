---
description: Build a non-mutating Kubernetes deployment plan for the owned full runtime.
allowed-tools: [Bash]
---

# Kubernetes Deploy Plan

Build a Kubernetes deployment plan:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" deploy-k8s $ARGUMENTS
```

Report required subsystems, namespace, ordered apply/readiness steps, mutation gate, and blockers that must be cleared before execution.

Do not run `kubectl apply`, create namespaces, start jobs, or submit artifacts from this command.

---
description: Build a non-mutating local Colima/kind deployment plan for the owned full runtime.
allowed-tools: [Bash]
---

# Local Deploy Plan

Build a local deployment plan:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" deploy-local $ARGUMENTS
```

Report required local subsystems, ordered setup steps, namespace, mutation gate, and the follow-up `runtime-doctor` command.

Do not create clusters, pull images, start containers, or run worker services from this command.

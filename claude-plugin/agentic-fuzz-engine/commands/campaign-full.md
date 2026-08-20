---
description: Build a full owned-runtime fuzzing campaign phase graph without launching workers.
allowed-tools: [Bash]
---

# Full Campaign Plan

Build a full owned-runtime campaign plan for the requested target:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-full $ARGUMENTS
```

The first argument must be the target name. Optional arguments include `--task-id`, `--language`, and `--seconds`.

Report the required subsystems, ordered phase graph, expected checkpoints, MCP tools per phase, and the execution gate.

Do not start fuzzers or workers from this command.

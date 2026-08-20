---
description: Friendly readiness check for the Agentic Fuzz plugin and real local backends.
allowed-tools: [Bash]
---

# Ready

Run the two checks humans usually want first:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" parity-full --strict
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" runtime-backend-status
```

Report:
- whether the plugin/MCP/subagent contract is wired correctly
- which real local backends are ready
- the exact missing tools or credentials, if any
- the next command to run

This command is read-only.

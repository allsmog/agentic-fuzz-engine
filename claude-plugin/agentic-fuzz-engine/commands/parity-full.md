---
description: Audit the owned full-runtime subsystem contract, plugin commands, MCP tools, and prompt fixtures.
allowed-tools: [Bash]
---

# Full Runtime Parity Audit

Run the full-runtime parity audit:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" parity-full $ARGUMENTS
```

Report missing full-runtime MCP tools, missing plugin commands, subsystem coverage, specialist subagent names, MCP server names, and prompt fidelity fixture status.

This command is a structure and fidelity gate. It does not prove live fuzzing, patching, SARIF execution, or real exports.

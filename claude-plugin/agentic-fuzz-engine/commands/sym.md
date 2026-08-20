---
description: Friendly wrapper help for real local SymCC, SymQEMU, and Z3 workers.
allowed-tools: [Bash]
---

# Sym

Use this as the short form for `symbolic-worker-run`.

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" symbolic-worker-run $ARGUMENTS
```

Examples:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" symbolic-worker-run <run_id> \
  --mode z3 \
  --constraints-smt2-file <constraints.smt2>

"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" symbolic-worker-run <run_id> \
  --mode symcc \
  --command-json '["/path/to/instrumented-target", "{output_dir}"]'
```

On macOS this plugin resolves repo-local Docker wrappers for SymCC and SymQEMU when the corresponding images are available.

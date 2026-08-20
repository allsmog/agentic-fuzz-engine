---
description: Friendly wrapper help for CodeQL, Joern, and SootUp SARIF reachability.
allowed-tools: [Bash]
---

# Reach

Use this as the short form for `sarif-reachability-run`.

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" sarif-reachability-run $ARGUMENTS
```

Typical CodeQL-only shape:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" sarif-reachability-run <run_id> \
  --source-dir <target-source-dir> \
  --sarif-file <input.sarif.json> \
  --database-dir <codeql-db> \
  --codeql-query-suite <query-suite> \
  --no-joern \
  --no-sootup
```

Use Joern or SootUp by adding `--joern-command-json` or `--sootup-command-json` with explicit analyzer commands.

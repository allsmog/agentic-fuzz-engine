---
description: Run bounded real local CodeQL/Joern/SootUp SARIF reachability workers over source and SARIF input.
allowed-tools: [Bash]
---

# SARIF Reachability Run

Run real local SARIF reachability checks:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" sarif-reachability-run <run_id> \
  --source-dir <target-source-dir> \
  --sarif-file <input.sarif.json> \
  --language c-cpp \
  --database-dir <codeql-db> \
  --codeql-query-suite <query-suite-or-query-pack> \
  --no-joern \
  --no-sootup
```

Analyzer rules:
- CodeQL requires `codeql`, a database, and a query suite. Add `--create-database` when the plugin should create the database from `--source-dir`.
- Joern requires `joern` and `--joern-command-json`; placeholders include `{source_dir}`, `{sarif_file}`, and `{work_dir}`.
- SootUp requires `java` plus `SOOTUP_JAR` or `sootup`, and usually `--sootup-command-json` for the project-specific invocation.

The command parses the input SARIF, counts source-location hits, stores analyzer outputs, and records a conservative reachability verdict. Missing analyzers are blockers unless disabled with `--no-codeql`, `--no-joern`, or `--no-sootup`.

Do not call the reference SARIF service. This command invokes local CodeQL/Joern/SootUp tooling only.

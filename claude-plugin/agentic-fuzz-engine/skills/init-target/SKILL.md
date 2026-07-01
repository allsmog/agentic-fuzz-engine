---
description: Initialize or inspect an OSS-Fuzz/benchmark C/C++ target profile for agentic fuzzing campaigns.
argument-hint: targets/<project>
disable-model-invocation: true
allowed-tools: [Bash]
---

# Init Target

Use `$ARGUMENTS` as the target name, for example `targets/mongoose`.

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" target-validate "$ARGUMENTS"
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" harness-list "$ARGUMENTS"
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" target-discover <local-source-dir> --project "$ARGUMENTS"
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" target-build-probe <run_id> <local-source-dir> --project "$ARGUMENTS"
```

Confirm:
- language is C/C++ compatible
- sanitizers include the expected family
- fuzzing engines are declared
- harness inventory exists
- enabled fixtures map to listed harness names
- local source discovery finds build-system hints, dictionaries, seed corpora, and runnable harness commands
- campaign-local build probing resolves source-only harnesses into runnable commands without mutating the original source tree
- disabled projects are treated as diagnostic-only

If no harness inventory is available, stop and report that the target is not ready for campaign execution. Do not synthesize harness names or C/C++ harness commands to make a plan look complete.

---
description: Validate the Agentic Fuzz plugin, local C/C++ fidelity fixtures, and no-external runtime guardrails.
disable-model-invocation: true
allowed-tools: [Bash]
---

# Agentic fuzzing Doctor

Run non-mutating plugin health checks. This skill is for proving the plugin is loadable, the fidelity corpus is present, and the no-runtime guardrail is intact.

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" fidelity-validate-fixtures --include-disabled
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" runtime-guard-audit --strict
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" engine-parity-audit --strict
```

Report:
- total, enabled, and disabled fixture counts
- missing `index.json`, `proof.bin`, or `patch.diff` files
- enabled and disabled project names
- no-runtime audit result
- `engine_parity_audit` group score and any missing tools, agents, skills, files, or prompt terms
- plugin manifest validation result if the user asks for packaging status

Do not run external launchers, Docker campaigns, Compose, Kafka, Redis, or target fuzzers from this skill.

---
description: Read plugin-local Agentic fuzzing campaign status and summarize artifacts and findings.
argument-hint: <run_id>
disable-model-invocation: true
allowed-tools: [Bash]
---

# Status

Use `$ARGUMENTS` as the run id:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-status "$ARGUMENTS"
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-phase-audit "$ARGUMENTS"
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-checkpoint-list "$ARGUMENTS"
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" finding-lifecycle-audit "$ARGUMENTS"
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-completion-audit "$ARGUMENTS" --project <targets/project> --no-require-report
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" export-list "$ARGUMENTS"
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-full-completion-audit "$ARGUMENTS" --project <targets/project> --no-require-report
```

Summarize:
- campaign target and created time
- phase coverage, required phases, missing required phases, missing checkpoints, and stale checkpoints
- checkpoint ledger phases, blockers, and next commands
- latest events
- finding lifecycle gaps for artifact, verification, classification, and dedupe evidence
- artifacts by purpose when names make that clear
- findings by signature
- missing PoV artifacts
- duplicate bursts
- patch/report stages that are ahead of grading
- export bundle and mock export API receipt counts
- enabled fidelity cases not yet represented
- final completion gate blockers from `campaign_completion_audit`, including required phase blockers
- full campaign blockers from `campaign_full_completion_audit`, including missing export receipts and specialist subagent checkpoints

Do not start new work from this skill. It is a read-only operational view.

---
description: Produce a concise C/C++ sanitizer finding report from plugin-local campaign records.
argument-hint: <run_id>
disable-model-invocation: true
allowed-tools: [Bash, Agent]
---

# Report

Read campaign state:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-status "$ARGUMENTS"
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-phase-audit "$ARGUMENTS"
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-checkpoint-list "$ARGUMENTS"
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" finding-lifecycle-audit "$ARGUMENTS" --strict
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-fidelity-audit "$ARGUMENTS" --project <targets/project>
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-report "$ARGUMENTS" --project <targets/project> --artifact-prefix reports/$ARGUMENTS
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-checkpoint-record "$ARGUMENTS" --target <targets/project> --phase report --tool-evidence "campaign-report: REPORT.md and REPORT.json" --next-command "campaign-completion-audit $ARGUMENTS --project <targets/project> --strict" --agent reporter
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-completion-audit "$ARGUMENTS" --project <targets/project> --strict
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" export-list "$ARGUMENTS"
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-full-completion-audit "$ARGUMENTS" --project <targets/project> --strict
```

Generate the report artifact first, then summarize it. Before the final completion audit, verify the required phases `readiness`, `scope`, `input-material`, `fuzzing`, `grading`, `dedupe`, and `report` have checkpoint ledger entries; `patch` is also required when patch work was attempted. Hand off to `export-agent` for `export_bundle_create`, `export_mock_api_submit_pov`, `export_mock_api_submit_patch`, `export_mock_api_submit_sarif`, and the `export` checkpoint before claiming full campaign closure. Report only findings that passed crash grading and dedupe. For each finding include:
- target and harness
- sanitizer token and ASAN signature
- PoV artifact and sha256
- 3/3 or weaker reproduction evidence
- primitive, reachability, root-cause hypothesis, constraints, and severity
- matching benchmark fixture when present
- campaign fidelity audit score, represented fixtures, missing fixtures, and blockers
- finding lifecycle audit score, missing classifier evidence, missing verification evidence, and dedupe freshness
- campaign phase audit coverage, missing required phases, missing checkpoints, and stale checkpoints
- checkpoint ledger phases, blocked handoffs, and next commands
- final completion gate status from `campaign_completion_audit`
- mock export API receipt status and `campaign_full_completion_audit` blockers when full campaign closure was requested
- patch guidance and sibling call sites to inspect

The `campaign_report` output writes a Markdown report artifact and a JSON report artifact using quality-ranked dedupe representatives and checkpoint ledger coverage. Keep benchmarks as expected inputs only. Do not claim live fuzzing parity unless actual harness execution evidence is present, `finding-lifecycle-audit` proves the finding lifecycle, `campaign-phase-audit` proves phase coverage, `campaign-fidelity-audit` proves the enabled fixture coverage or names the remaining blockers, and `campaign-completion-audit` passes the final completion gate or lists the missing required phases and remaining blockers. Do not claim full full local campaign closure unless `campaign_full_completion_audit` is green after the export-agent records plugin-local mock export receipts.

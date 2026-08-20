---
description: Generate and verify candidate C/C++ patches for verified sanitizer findings.
argument-hint: <run_id>
disable-model-invocation: true
allowed-tools: [Bash, Agent]
---

# Patch

Read campaign state:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" campaign-status "$ARGUMENTS"
```

Patch only verified, deduped findings. Use `patcher` to produce a minimal root-cause fix and `patch-grader` to verify it.

Record candidate diffs before grading:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" patch-candidate-record <run_id> \
  --patch-file <patch.diff> \
  --artifact-name <project>/<harness>/patches/<finding-id>.diff \
  --finding-id <finding-id> \
  --rationale "root-cause fix summary" \
  --variant-checked "adjacent length and parser-state variation"
```

When the patch, PoV, source directory, and harness command are available, run the plugin-local grader:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" patch-grade <run_id> \
  --source-dir <target-source-dir> \
  --patch-artifact <patch.diff> \
  --pov-artifact <pov.bin> \
  --harness-command-json '["/path/to/harness", "{poc}"]' \
  --expected-error-token "AddressSanitizer: heap-buffer-overflow"
```

## Required Ladder

1. Patch applies cleanly.
2. Target rebuilds.
3. Original PoV no longer triggers the expected sanitizer token.
4. Available tests or harness smoke checks pass.
5. Focused re-attack around the same input family does not rediscover the root cause.

`patch_candidate_record` validates the unified diff, rejects unsafe paths, and writes patch plus metadata artifacts for the ladder. Do not apply benchmark `patch.diff` blindly unless the user explicitly asks for benchmark comparison. The benchmark patch is an oracle for fidelity, not the default output.

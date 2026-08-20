---
description: Run bounded real local libFuzzer, AFL++, and/or LibAFL workers through the Agentic Fuzz plugin.
allowed-tools: [Bash]
---

# Fuzz Ensemble Run

Run a real bounded local fuzzing worker set:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" fuzz-ensemble-run <run_id> \
  --target <targets/project> \
  --harness <harness> \
  --seed-artifact <seed-artifact-name> \
  --worker libfuzzer \
  --worker afl \
  --harness-command-json '["/path/to/libfuzzer-or-target", "{seed_corpus}"]' \
  --runs 128 \
  --timeout-seconds 60
```

Worker rules:
- `libfuzzer` requires `clang` visibility and an explicit libFuzzer-compatible command. The engine appends a corpus directory plus `-runs` and `-artifact_prefix` when absent.
- `afl` requires `afl-fuzz`. Use `{poc}` in the target command when the input filename should become AFL's `@@`.
- `libafl` requires `cargo` and `--libafl-command-json`; the command receives `{seed_corpus}`, `{crash_dir}`, and `{work_dir}` placeholders.

The command stores discovered crash files as plugin-local artifacts and records a `fuzz_ensemble_run` event. Missing dependencies are blockers, not success.

Do not call existing reference workers or distributed infrastructure. This command invokes only the local third-party fuzzers and harness commands supplied by the operator.

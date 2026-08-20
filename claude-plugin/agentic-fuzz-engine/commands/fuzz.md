---
description: Friendly wrapper help for real local libFuzzer, AFL++, and LibAFL campaigns.
allowed-tools: [Bash]
---

# Fuzz

Use this as the short form for `fuzz-ensemble-run`.

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" fuzz-ensemble-run $ARGUMENTS
```

Typical shape:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" fuzz-ensemble-run <run_id> \
  --target targets/<project> \
  --harness <harness> \
  --worker libfuzzer \
  --worker afl \
  --seed-artifact <seed.bin> \
  --harness-command-json '["/path/to/target-or-fuzzer", "{seed_corpus}"]'
```

Run `/agentic-fuzz:ready` first if you are unsure whether AFL++, LLVM, or LibAFL prerequisites are available.

---
description: Run bounded real local SymCC, SymQEMU, or Z3 workers and collect generated inputs.
allowed-tools: [Bash]
---

# Symbolic Worker Run

Run a real bounded symbolic worker:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" symbolic-worker-run <run_id> \
  --mode symcc \
  --command-json '["/path/to/instrumented-target", "{output_dir}"]' \
  --timeout-seconds 60
```

Modes:
- `symcc` requires `symcc`; `SYMCC_OUTPUT_DIR` is set to a plugin-local output directory.
- `symqemu` requires `symqemu` or `symqemu-x86_64`; if the command does not start with SymQEMU, the engine prepends it.
- `z3` requires Python `z3` and `--constraints-smt2-file` or `--constraints-smt2-b64`.

Generated output files are stored as plugin-local artifacts and a `symbolic_worker_run` event is recorded. Missing tools or missing explicit commands are blockers.

Do not call reference concolic services or distributed queues. This command runs the local symbolic toolchain directly.

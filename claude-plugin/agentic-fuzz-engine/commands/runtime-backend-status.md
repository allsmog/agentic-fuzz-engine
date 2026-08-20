---
description: Check real local backend availability for fuzzing, symbolic execution, SARIF reachability, and patch environments.
allowed-tools: [Bash]
---

# Runtime Backend Status

Check whether the real local tools are installed and visible to the plugin:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" runtime-backend-status $ARGUMENTS
```

Report each group separately:
- AFL++/LibAFL/libFuzzer: `clang`, `llvm-symbolizer`, `afl-fuzz`, `cargo`
- SymCC/SymQEMU/Z3: `symcc`, `symqemu` or `symqemu-x86_64`, Python `z3`
- SARIF reachability: `codeql`, `joern`, `java`, `SOOTUP_JAR` or `sootup`
- cached patch pool: `docker`, `git`, `uv`, model credentials

This command is read-only. It does not start fuzzers, symbolic workers, SARIF analyzers, patch environments, containers, or exports.

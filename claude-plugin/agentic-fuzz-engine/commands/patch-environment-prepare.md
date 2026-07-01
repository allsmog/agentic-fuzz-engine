---
description: Prepare a cached cached patch environment pool entry and optionally apply/build/test a patch artifact.
allowed-tools: [Bash]
---

# Patch Environment Prepare

Prepare a cached patch environment:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" patch-environment-prepare <run_id> \
  --source-dir <target-source-dir> \
  --env-name <finding-or-patch-id> \
  --patch-artifact <stored-patch.diff> \
  --build-command-json '["make", "-j2"]' \
  --test-command-json '["make", "test"]'
```

The engine:
- fingerprints the source tree
- creates or reuses a plugin-local cache entry
- copies the cached source into a fresh pool environment
- optionally validates and applies a stored patch artifact
- optionally runs build and test commands in the copied environment
- writes an environment manifest and records `patch_environment_prepare`

This is a local cached environment pool/cache path. It does not call the benchmark patch framework or mutate the original source tree.

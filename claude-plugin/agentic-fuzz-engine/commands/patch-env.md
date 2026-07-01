---
description: Friendly wrapper help for preparing a cached cached patch environment.
allowed-tools: [Bash]
---

# Patch Env

Use this as the short form for `patch-environment-prepare`.

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" patch-environment-prepare $ARGUMENTS
```

Typical shape:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh" patch-environment-prepare <run_id> \
  --source-dir <target-source-dir> \
  --env-name <finding-or-patch-id> \
  --patch-artifact <stored-patch.diff> \
  --build-command-json '["make", "-j2"]' \
  --test-command-json '["make", "test"]'
```

This prepares a copied environment from a plugin-local cache. It does not mutate the original source tree.

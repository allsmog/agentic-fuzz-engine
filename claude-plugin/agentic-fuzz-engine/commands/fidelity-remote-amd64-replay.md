---
description: Run owned OSS-Fuzz build+replay on an already-provisioned native amd64 Linux host and sync artifacts back.
allowed-tools: [Bash]
---

# Remote AMD64 Replay

Run the native-amd64 OSS-Fuzz replay helper:

```bash
"${CLAUDE_PROJECT_DIR}/scripts/remote-amd64-oss-fuzz-replay.sh" $ARGUMENTS
```

Set `REMOTE_HOST` before invoking this command. The first argument is the project, for example `targets/mongoose`; the second optional argument is the run id.

Run this command in the foreground and wait for it to complete. Do not background it, daemonize it, start a separate monitor, or report that the user should wait for a later notification.

This command does not create, resize, or destroy cloud VMs. It only connects to an already-provisioned native x86_64/amd64 Linux host, syncs the minimum repo/reference slices, installs Docker prerequisites if missing, runs `fidelity-oss-fuzz-build-replay`, and syncs run artifacts back to `runs/remote-amd64`.

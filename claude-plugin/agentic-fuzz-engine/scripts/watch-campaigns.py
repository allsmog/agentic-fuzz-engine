#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
from pathlib import Path


def main() -> int:
    data_root = Path(
        os.environ.get("CLAUDE_PLUGIN_DATA")
        or (Path(os.environ["XDG_STATE_HOME"]) / "agentic-fuzz-engine" if os.environ.get("XDG_STATE_HOME") else Path.home() / ".local" / "state" / "agentic-fuzz-engine")
    )
    runs_root = data_root / "runs"
    while True:
        campaigns = sorted(runs_root.glob("*/campaign.json")) if runs_root.exists() else []
        print(json.dumps({"source": "agentic-fuzz", "campaigns": len(campaigns)}), flush=True)
        time.sleep(60)


if __name__ == "__main__":
    raise SystemExit(main())

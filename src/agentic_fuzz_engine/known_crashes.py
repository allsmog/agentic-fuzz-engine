"""Known-crash suppression: the fuzz-blocker tier of the round loop.

Once a root cause is recorded, every later round rediscovers it: libFuzzer
stops on the known shallow crash (capping the round at time-to-known-crash)
and intake replays each rediscovered PoV three times through the ASAN
harness before dedupe finally says DUP_SKIP. This module keeps a per-target
ledger of known root signatures (``work/<target>/known-crashes.json``) so
the round loop can:

- probe each intake candidate ONCE (sidecar text when present, else a
  single bounded replay), compute its cross-harness ``root_signature``, and
  quarantine known rediscoveries to ``work/<target>/known-crash-inputs/``
  instead of grading them again;
- flip the target into fork mode (``-fork=1 -ignore_crashes=1``) so the
  fuzzer keeps exploring past known crashes instead of exiting.

Unparseable outputs fail open into the normal grading path — suppression
must never eat a novel crash.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Mapping

from .crash_identity import parse_crash_output, root_signature

KNOWN_CRASHES_FILE = "known-crashes.json"
KNOWN_INPUTS_DIR = "known-crash-inputs"
DEFAULT_PROBE_TIMEOUT = 10.0
MAX_PROBE_OUTPUT_BYTES = 256 * 1024


def load_known(work_dir: Path) -> dict[str, dict[str, Any]]:
    path = work_dir / KNOWN_CRASHES_FILE
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    signatures = payload.get("signatures")
    return dict(signatures) if isinstance(signatures, dict) else {}


def save_known(work_dir: Path, signatures: dict[str, dict[str, Any]]) -> Path:
    path = work_dir / KNOWN_CRASHES_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps({"version": 1, "signatures": signatures}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)
    return path


def record_known(
    work_dir: Path,
    *,
    root_sig: str,
    crash_type: str | None = None,
    crash_state: list[str] | None = None,
    error_token: str | None = None,
    finding_id: str | None = None,
    round_index: int | None = None,
) -> dict[str, dict[str, Any]]:
    """Insert-or-increment a root signature in the known set."""
    signatures = load_known(work_dir)
    entry = signatures.get(root_sig)
    if entry is None:
        entry = {
            "count": 1,
            "first_seen_round": round_index,
            "last_seen_round": round_index,
            "crash_type": crash_type,
            "crash_state": crash_state or [],
            "error_token": error_token,
            "finding_id": finding_id,
        }
    else:
        entry = dict(entry)
        entry["count"] = int(entry.get("count") or 0) + 1
        entry["last_seen_round"] = round_index if round_index is not None else entry.get("last_seen_round")
        if finding_id and not entry.get("finding_id"):
            entry["finding_id"] = finding_id
    signatures[root_sig] = entry
    save_known(work_dir, signatures)
    return signatures


def probe_and_partition(
    files: list[Path],
    *,
    known: dict[str, dict[str, Any]],
    replay_command: list[str],
    work_dir: Path,
    timeout_seconds: float = DEFAULT_PROBE_TIMEOUT,
    env: Mapping[str, str] | None = None,
    sidecar_text_fn: Any = None,
) -> dict[str, Any]:
    """Partition intake candidates into unknown files (worth grading) and
    suppressed known rediscoveries (quarantined, counted).

    Probe order per file: sidecar log text when the import shipped one
    (external crash dirs), else one bounded replay. Round-loop crash dirs
    from ``fuzz_ensemble_run`` have no sidecars, so the single replay is the
    common path — still 3x cheaper than the grading replay it replaces.
    """
    if not known:
        return {"unknown_files": list(files), "suppressed": {}, "probed": 0, "probe_failures": 0}

    quarantine = work_dir / KNOWN_INPUTS_DIR
    unknown: list[Path] = []
    suppressed: dict[str, int] = {}
    probed = 0
    failures = 0
    for path in files:
        output = ""
        if sidecar_text_fn is not None:
            try:
                output = str(sidecar_text_fn(path) or "")
            except Exception:
                output = ""
        if not output:
            output = _probe_replay(path, replay_command=replay_command, timeout_seconds=timeout_seconds, env=env)
            probed += 1
        signal = parse_crash_output(output)
        if signal is None:
            # Fail open: no parseable crash identity means the normal grading
            # path decides, never the suppressor.
            failures += 1
            unknown.append(path)
            continue
        signature = root_signature(signal)
        if signature in known:
            suppressed[signature] = suppressed.get(signature, 0) + 1
            _quarantine(path, quarantine, signature)
        else:
            unknown.append(path)
    return {
        "unknown_files": unknown,
        "suppressed": suppressed,
        "probed": probed,
        "probe_failures": failures,
    }


def prune_known_inputs(work_dir: Path, *, retention: int = 200) -> dict[str, Any]:
    """Keep only the newest ``retention`` quarantined inputs (GC hook)."""
    quarantine = work_dir / KNOWN_INPUTS_DIR
    if not quarantine.is_dir():
        return {"removed": 0, "kept": 0, "bytes_freed": 0}
    entries = sorted(
        (entry for entry in quarantine.iterdir() if entry.is_file()),
        key=lambda entry: entry.stat().st_mtime,
        reverse=True,
    )
    removed = 0
    bytes_freed = 0
    for entry in entries[max(0, int(retention)):]:
        try:
            bytes_freed += entry.stat().st_size
            entry.unlink()
            removed += 1
        except OSError:
            continue
    return {"removed": removed, "kept": min(len(entries), max(0, int(retention))), "bytes_freed": bytes_freed}


def _probe_replay(
    path: Path,
    *,
    replay_command: list[str],
    timeout_seconds: float,
    env: Mapping[str, str] | None,
) -> str:
    argv = [str(path) if token == "{poc}" else token for token in replay_command]
    if "{poc}" not in replay_command:
        argv = [*argv, str(path)]
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            timeout=max(1.0, float(timeout_seconds)),
            env=dict(env) if env is not None else dict(os.environ),
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return ""
    combined = (completed.stderr or b"") + b"\n" + (completed.stdout or b"")
    return combined[:MAX_PROBE_OUTPUT_BYTES].decode("utf-8", errors="replace")


def _quarantine(path: Path, quarantine: Path, signature: str) -> None:
    quarantine.mkdir(parents=True, exist_ok=True)
    destination = quarantine / f"{signature[:8]}-{path.name}"
    try:
        if destination.exists():
            path.unlink()
        else:
            path.rename(destination)
    except OSError:
        try:
            destination.write_bytes(path.read_bytes())
            path.unlink()
        except OSError:
            pass

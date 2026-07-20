"""Bounded execution of authored harness codec scripts.

An input-generator agent authors a Python script exposing
``decode(data: bytes) -> dict`` (required) and optionally
``encode(obj: dict) -> bytes``. The codec makes harness inputs legible:
validate mode proves the script actually understands the live corpus (decode
rate over real entries, encode/decode round-trip, and a qualifying replay of
one re-encoded probe through the fuzzer — the RoboDuck gate that the harness
parses what the encoder emits), and decode mode renders PoV artifacts as
structured dicts for triage, failing open to a hex preview.

The child process is launched as ``python -c <bootstrap> <script> ...`` so the
authored file is loaded via importlib rather than passed as the interpreter's
script argument (endpoint protection on some hosts kills ``python file.py``).
Same envelope as seedgen: one child, wall-clock timeout, prlimit address-space
cap, output size caps.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from .workspace import resolve_workspace_root

CODEC_STATUS_FILE = "codec-status.json"
MAX_VALIDATE_SAMPLES = 256
MAX_DECODE_PATHS = 8
MAX_SECONDS_CAP = 600.0
MAX_DECODE_BYTES_CAP = 1024 * 1024
HEX_PREVIEW_BYTES = 256

_BOOTSTRAP = r"""
import importlib.util, json, sys
from pathlib import Path

script, mode, input_dir, probe_out = sys.argv[1], sys.argv[2], Path(sys.argv[3]), sys.argv[4]
max_decode_bytes = int(sys.argv[5])
spec = importlib.util.spec_from_file_location("codec_authored", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
decode = getattr(module, "decode", None)
if not callable(decode):
    print(json.dumps({"fatal": "script does not define decode(data: bytes) -> dict"}))
    raise SystemExit(3)
encode = getattr(module, "encode", None)
encode_present = callable(encode)

def _canon(obj):
    return json.dumps(obj, sort_keys=True, default=repr)

files = sorted(p for p in input_dir.iterdir() if p.is_file())
if mode == "validate":
    parsed, failed, roundtrip_ok, roundtrip_failed = 0, 0, 0, 0
    errors = []
    probe_written = False
    for path in files:
        data = path.read_bytes()
        try:
            obj = decode(data)
            if not isinstance(obj, dict):
                raise TypeError(f"decode returned {type(obj).__name__}, not dict")
            canonical = _canon(obj)
        except Exception as exc:
            failed += 1
            if len(errors) < 5:
                errors.append(f"{path.name}: {type(exc).__name__}: {exc}")
            continue
        parsed += 1
        if encode_present:
            try:
                blob = encode(obj)
                if not isinstance(blob, (bytes, bytearray)):
                    raise TypeError(f"encode returned {type(blob).__name__}, not bytes")
                if _canon(decode(bytes(blob))) == canonical:
                    roundtrip_ok += 1
                else:
                    roundtrip_failed += 1
                if not probe_written:
                    Path(probe_out).write_bytes(bytes(blob))
                    probe_written = True
            except Exception as exc:
                roundtrip_failed += 1
                if len(errors) < 5:
                    errors.append(f"{path.name} roundtrip: {type(exc).__name__}: {exc}")
        elif not probe_written:
            Path(probe_out).write_bytes(data)
            probe_written = True
    print(json.dumps({
        "samples": len(files), "parsed": parsed, "failed": failed,
        "encode_present": encode_present,
        "roundtrip_ok": roundtrip_ok, "roundtrip_failed": roundtrip_failed,
        "probe_written": probe_written, "errors": errors,
    }))
else:
    results = []
    for path in files:
        data = path.read_bytes()
        try:
            obj = decode(data)
            if not isinstance(obj, dict):
                raise TypeError(f"decode returned {type(obj).__name__}, not dict")
            rendered = json.dumps(obj, indent=2, sort_keys=True, default=repr)
            truncated = len(rendered) > max_decode_bytes
            results.append({
                "name": path.name, "ok": True,
                "decoded": rendered[:max_decode_bytes], "truncated": truncated,
            })
        except Exception as exc:
            results.append({
                "name": path.name, "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "hex_preview": data[:256].hex(),
            })
    print(json.dumps({"files": results}))
"""


def default_codec_script(root: Path, name: str) -> Path:
    return root / "generators" / "codec" / f"{name}.py"


def load_codec_status(work_dir: Path) -> dict[str, Any]:
    path = work_dir / CODEC_STATUS_FILE
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def run_codec(
    *,
    target: str,
    mode: str = "validate",
    script_path: str | Path | None = None,
    paths: list[str] | None = None,
    max_samples: int = 64,
    qualify_functions: list[str] | None = None,
    min_parse_rate: float = 0.9,
    require_roundtrip: bool = False,
    qualify_default_from_sinks: bool = True,
    timeout_seconds: float = 60.0,
    memory_mb: int = 1024,
    max_decode_bytes: int = 65536,
    workspace_root: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(env) if env is not None else dict(os.environ)
    root = resolve_workspace_root(workspace_root, env=environment)
    name = str(target).strip().rstrip("/").split("/")[-1]
    blockers: list[str] = []
    if not name:
        blockers.append("target name is empty")
    mode = str(mode or "validate")
    if mode not in ("validate", "decode"):
        blockers.append(f"mode must be 'validate' or 'decode', got {mode!r}")
    script = Path(script_path).expanduser().resolve() if script_path else default_codec_script(root, name)
    if not script.is_file():
        blockers.append(f"codec script not found: {script}")
    if mode == "decode" and not paths:
        blockers.append("decode mode requires at least one --path")
    if blockers:
        return {"ok": False, "target": name, "mode": mode, "script": str(script), "blockers": blockers}

    timeout_seconds = max(1.0, min(float(timeout_seconds), MAX_SECONDS_CAP))
    max_decode_bytes = max(256, min(int(max_decode_bytes), MAX_DECODE_BYTES_CAP))
    work_dir = root / "work" / name
    work_dir.mkdir(parents=True, exist_ok=True)
    script_digest = hashlib.sha256(script.read_bytes()).hexdigest()

    staging = work_dir / "codec-staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    probe_path = work_dir / "codec-probe.bin"

    if mode == "validate":
        seeds_dir = work_dir / "seeds"
        candidates = (
            sorted(
                (entry for entry in seeds_dir.iterdir() if entry.is_file()),
                key=lambda entry: entry.stat().st_mtime,
                reverse=True,
            )
            if seeds_dir.is_dir()
            else []
        )[: max(1, min(int(max_samples), MAX_VALIDATE_SAMPLES))]
        if not candidates:
            shutil.rmtree(staging, ignore_errors=True)
            return {
                "ok": False, "target": name, "mode": mode, "script": str(script),
                "blockers": [f"validate mode requires a non-empty corpus in {seeds_dir}"],
            }
        for entry in candidates:
            shutil.copy2(entry, staging / entry.name)
        probe_path.unlink(missing_ok=True)
    else:
        decode_paths = [Path(p).expanduser().resolve() for p in (paths or [])][:MAX_DECODE_PATHS]
        missing = [str(p) for p in decode_paths if not p.is_file()]
        if missing:
            shutil.rmtree(staging, ignore_errors=True)
            return {
                "ok": False, "target": name, "mode": mode, "script": str(script),
                "blockers": [f"decode path not found: {p}" for p in missing],
            }
        for index, p in enumerate(decode_paths):
            shutil.copy2(p, staging / f"{index:02d}-{p.name}")

    argv = [
        sys.executable, "-c", _BOOTSTRAP,
        str(script), mode, str(staging), str(probe_path), str(max_decode_bytes),
    ]
    prlimit = shutil.which("prlimit")
    if prlimit:
        argv = [prlimit, f"--as={int(memory_mb) * 1024 * 1024}", "--", *argv]

    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout_seconds, check=False,
        )
        exit_code, stdout, stderr = proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = 124
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    elapsed_ms = int((time.monotonic() - started) * 1000)
    shutil.rmtree(staging, ignore_errors=True)

    child_report: dict[str, Any] = {}
    for line in reversed(stdout.strip().splitlines()):
        try:
            child_report = json.loads(line)
            break
        except json.JSONDecodeError:
            continue
    if child_report.get("fatal"):
        blockers.append(str(child_report["fatal"]))
    if timed_out:
        blockers.append(f"codec script exceeded {timeout_seconds:.0f}s wall clock")
    elif exit_code != 0 and not child_report.get("fatal"):
        tail = stderr.strip().splitlines()[-3:]
        blockers.append(f"codec subprocess exited {exit_code}: {' | '.join(tail) if tail else 'no stderr'}")

    if mode == "decode":
        files = child_report.get("files") or []
        status = load_codec_status(work_dir)
        if status and status.get("script_sha256") and status["script_sha256"] != script_digest:
            blockers.append(
                "codec script changed since last validate (stale codec-status.json) — re-run --mode validate"
            )
        return {
            "ok": not blockers and bool(files),
            "target": name, "mode": mode, "script": str(script),
            "script_sha256": script_digest,
            "validated": bool(status.get("validated")),
            "files": files,
            "elapsed_ms": elapsed_ms,
            "blockers": blockers,
        }

    samples = int(child_report.get("samples") or 0)
    parsed = int(child_report.get("parsed") or 0)
    encode_present = bool(child_report.get("encode_present"))
    roundtrip_ok = int(child_report.get("roundtrip_ok") or 0)
    roundtrip_failed = int(child_report.get("roundtrip_failed") or 0)
    parse_rate = parsed / samples if samples else 0.0
    roundtrip_pass = (not encode_present) or (not require_roundtrip) or roundtrip_failed == 0
    validated = not blockers and parse_rate >= float(min_parse_rate) and roundtrip_pass
    if samples and parse_rate < float(min_parse_rate):
        blockers.append(f"parse rate {parse_rate:.2f} below min_parse_rate {float(min_parse_rate):.2f}")
    if encode_present and require_roundtrip and roundtrip_failed:
        blockers.append(f"{roundtrip_failed} sample(s) failed the encode/decode round-trip")

    # RoboDuck qualifying gate: the re-encoded probe must still drive the
    # harness into at least one function the campaign cares about — proof the
    # encoder emits bytes the harness actually parses, not a lookalike format.
    qualifying: dict[str, Any] = {"ran": False}
    if validated and child_report.get("probe_written") and probe_path.is_file():
        qualifying = _qualify_probe(
            root=root, name=name, work_dir=work_dir, probe=probe_path,
            qualify_functions=qualify_functions,
            qualify_default_from_sinks=qualify_default_from_sinks,
            environment=environment,
            timeout=timeout_seconds,
        )
        if qualifying["ran"] and not qualifying["qualified"]:
            validated = False
            blockers.append(
                "qualifying gate failed: probe replay covered none of "
                f"{qualifying['functions'][:5]} — the encoder output is not being parsed"
            )

    status_payload = {
        "script": str(script),
        "script_sha256": script_digest,
        "validated": validated,
        "samples": samples,
        "parse_rate": round(parse_rate, 4),
        "encode_present": encode_present,
        "roundtrip_ok": roundtrip_ok,
        "roundtrip_failed": roundtrip_failed,
        "qualifying": qualifying,
        "errors": child_report.get("errors") or [],
        "blockers": blockers,
        "updated_ts": time.time(),
    }
    tmp = (work_dir / CODEC_STATUS_FILE).with_suffix(".json.tmp")
    tmp.write_text(json.dumps(status_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(work_dir / CODEC_STATUS_FILE)

    return {
        "ok": validated,
        "target": name, "mode": mode, "script": str(script),
        "script_sha256": script_digest,
        "validated": validated,
        "samples": samples,
        "parse_rate": round(parse_rate, 4),
        "encode_present": encode_present,
        "roundtrip_ok": roundtrip_ok,
        "roundtrip_failed": roundtrip_failed,
        "qualifying": qualifying,
        "status_path": str(work_dir / CODEC_STATUS_FILE),
        "elapsed_ms": elapsed_ms,
        "errors": child_report.get("errors") or [],
        "blockers": blockers,
    }


def _qualify_probe(
    *,
    root: Path,
    name: str,
    work_dir: Path,
    probe: Path,
    qualify_functions: list[str] | None,
    qualify_default_from_sinks: bool,
    environment: dict[str, str],
    timeout: float = 20.0,
) -> dict[str, Any]:
    functions = [str(f) for f in (qualify_functions or []) if str(f).strip()]
    if not functions and qualify_default_from_sinks:
        from .sink_status import load_sink_status

        status = load_sink_status(work_dir)
        functions = sorted(
            {
                str(entry.get("method"))
                for entry in status.get("sinks", {}).values()
                if entry.get("method") and str(entry.get("status")) in ("reached", "exploited")
            }
        )
    fuzzer = root / "bin" / name / "fuzzer"
    if not functions:
        return {"ran": False, "skipped": "no qualify functions (no reached sinks yet, none supplied)"}
    if not fuzzer.is_file() or not os.access(fuzzer, os.X_OK):
        return {"ran": False, "skipped": f"no fuzzer binary at {fuzzer}"}

    from .seed_weights import replay_entry_coverage

    covered = replay_entry_coverage(fuzzer=fuzzer, entry=probe, env=environment, timeout=max(20.0, float(timeout)))
    if covered is None:
        return {"ran": False, "skipped": "probe replay failed or timed out", "functions": functions}
    hit = sorted(set(functions) & covered)
    return {"ran": True, "qualified": bool(hit), "functions": functions, "covered_qualifiers": hit}

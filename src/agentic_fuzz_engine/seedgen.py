"""Bounded execution of authored seed-generator scripts.

An input-generator agent authors a Python script exposing
``generate(rnd: random.Random) -> bytes``. This module executes that script in
a bounded subprocess (wall-clock timeout, address-space cap, blob-size and
blob-count caps) and merges the deduplicated blobs into the target's
persistent corpus at ``<workspace>/work/<target>/seeds``, recording
provenance in ``work/<target>/seedgen.jsonl``.

The child process is launched as ``python -c <bootstrap> <script> ...`` so the
authored file is loaded via importlib rather than passed as the interpreter's
script argument (endpoint protection on some hosts kills ``python file.py``).
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

MAX_COUNT = 4096
MAX_BLOB_BYTES_CAP = 8 * 1024 * 1024
MAX_SECONDS_CAP = 600.0
MAX_PROVENANCE_BLOBS = 1024

_BOOTSTRAP = r"""
import hashlib, importlib.util, json, random, sys
from pathlib import Path

script, out_dir = sys.argv[1], Path(sys.argv[2])
count, base_seed, max_bytes = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
mode, samples_dir = sys.argv[6], sys.argv[7]
spec = importlib.util.spec_from_file_location("seedgen_authored", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
samples = []
if mode == "mutate":
    mutate = getattr(module, "mutate", None)
    if not callable(mutate):
        print(json.dumps({"fatal": "script does not define mutate(rnd, seed) -> bytes"}))
        raise SystemExit(3)
    samples = sorted(p for p in Path(samples_dir).iterdir() if p.is_file())
    if not samples:
        print(json.dumps({"fatal": "mutate mode requires at least one corpus sample"}))
        raise SystemExit(3)
else:
    generate = getattr(module, "generate", None)
    if not callable(generate):
        print(json.dumps({"fatal": "script does not define generate(rnd) -> bytes"}))
        raise SystemExit(3)
out_dir.mkdir(parents=True, exist_ok=True)
written, errors, oversize = {}, 0, 0
for index in range(count):
    try:
        rnd = random.Random(base_seed + index)
        if mode == "mutate":
            blob = mutate(rnd, samples[index % len(samples)].read_bytes())
        else:
            blob = generate(rnd)
    except Exception:
        errors += 1
        continue
    if not isinstance(blob, (bytes, bytearray)) or len(blob) == 0:
        errors += 1
        continue
    blob = bytes(blob)
    if len(blob) > max_bytes:
        oversize += 1
        blob = blob[:max_bytes]
    name = "seedgen-" + hashlib.sha256(blob).hexdigest()[:16]
    if name in written:
        continue
    (out_dir / name).write_bytes(blob)
    written[name] = len(blob)
print(json.dumps({"written": len(written), "errors": errors, "oversize_truncated": oversize}))
"""


def run_seedgen(
    *,
    target: str,
    script_path: str,
    count: int = 256,
    max_seconds: float = 60.0,
    max_blob_bytes: int = 1024 * 1024,
    memory_mb: int = 1024,
    base_seed: int = 0,
    mode: str = "generate",
    sample_max: int = 64,
    workspace_root: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(env) if env is not None else dict(os.environ)
    root = resolve_workspace_root(workspace_root, env=environment)
    name = str(target).strip().rstrip("/").split("/")[-1]
    blockers: list[str] = []
    if not name:
        blockers.append("target name is empty")
    script = Path(script_path).expanduser().resolve()
    if not script.is_file():
        blockers.append(f"seedgen script not found: {script}")
    mode = str(mode or "generate")
    if mode not in ("generate", "mutate"):
        blockers.append(f"mode must be 'generate' or 'mutate', got {mode!r}")
    if blockers:
        return _result(name, script, blockers=blockers)

    count = max(1, min(int(count), MAX_COUNT))
    max_blob_bytes = max(1, min(int(max_blob_bytes), MAX_BLOB_BYTES_CAP))
    max_seconds = max(1.0, min(float(max_seconds), MAX_SECONDS_CAP))

    work_dir = root / "work" / name
    seeds_dir = work_dir / "seeds"
    seeds_dir.mkdir(parents=True, exist_ok=True)
    staging = work_dir / "seedgen-staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    # Mutate mode riffs on real corpus entries: newest-mtime-first sampling
    # (like concolic sync) biases toward recent coverage winners.
    samples_dir = work_dir / "seedgen-samples"
    samples_used = 0
    if mode == "mutate":
        if samples_dir.exists():
            shutil.rmtree(samples_dir)
        samples_dir.mkdir(parents=True)
        candidates = sorted(
            (entry for entry in seeds_dir.iterdir() if entry.is_file() and entry.stat().st_size <= max_blob_bytes),
            key=lambda entry: entry.stat().st_mtime,
            reverse=True,
        )[: max(1, min(int(sample_max), MAX_COUNT))]
        for entry in candidates:
            shutil.copy2(entry, samples_dir / entry.name)
        samples_used = len(candidates)
        if samples_used == 0:
            shutil.rmtree(samples_dir, ignore_errors=True)
            shutil.rmtree(staging, ignore_errors=True)
            return _result(name, script, blockers=["mutate mode requires a non-empty corpus in work/<target>/seeds"])

    argv = [
        sys.executable,
        "-c",
        _BOOTSTRAP,
        str(script),
        str(staging),
        str(count),
        str(int(base_seed)),
        str(max_blob_bytes),
        mode,
        str(samples_dir) if mode == "mutate" else "-",
    ]
    prlimit = shutil.which("prlimit")
    if prlimit:
        argv = [prlimit, f"--as={int(memory_mb) * 1024 * 1024}", "--", *argv]

    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max_seconds,
            check=False,
        )
        exit_code, stdout, stderr = proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = 124
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    elapsed_ms = int((time.monotonic() - started) * 1000)

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
        blockers.append(f"seedgen script exceeded {max_seconds:.0f}s wall clock (partial blobs kept)")
    elif exit_code != 0 and not child_report.get("fatal"):
        tail = stderr.strip().splitlines()[-3:]
        blockers.append(f"seedgen subprocess exited {exit_code}: {' | '.join(tail) if tail else 'no stderr'}")

    merged_new = 0
    generated = 0
    blob_names: list[str] = []
    for entry in sorted(staging.iterdir()):
        if not entry.is_file():
            continue
        generated += 1
        if len(blob_names) < MAX_PROVENANCE_BLOBS:
            blob_names.append(entry.name)
        destination = seeds_dir / entry.name
        if not destination.exists():
            shutil.move(str(entry), destination)
            merged_new += 1
    shutil.rmtree(staging, ignore_errors=True)

    if mode == "mutate":
        shutil.rmtree(samples_dir, ignore_errors=True)

    script_digest = hashlib.sha256(script.read_bytes()).hexdigest()
    provenance = {
        "script": str(script),
        "script_sha256": script_digest,
        "mode": mode,
        "samples_used": samples_used,
        "count_requested": count,
        "generated": generated,
        "merged_new": merged_new,
        # Blob names make later corpus-residency attribution possible: a
        # generator family whose blobs survive GC merges is earning its keep.
        "blobs": blob_names,
        "blobs_truncated": generated > len(blob_names),
        "errors": int(child_report.get("errors", 0)),
        "oversize_truncated": int(child_report.get("oversize_truncated", 0)),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "elapsed_ms": elapsed_ms,
    }
    with (work_dir / "seedgen.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(provenance) + "\n")

    ok = not blockers and merged_new + generated > 0
    if not ok and not blockers:
        blockers.append("seedgen script produced no usable blobs")
    return _result(
        name,
        script,
        blockers=blockers,
        ok=ok,
        seeds_dir=str(seeds_dir),
        provenance=provenance,
        stderr_tail="\n".join(stderr.strip().splitlines()[-5:]),
    )


def measure_seedgen_effectiveness(
    *,
    target: str,
    workspace_root: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Which generator scripts earn corpus residency?

    Unions each script's provenance blob names from ``seedgen.jsonl`` and
    intersects with one listing of the live corpus: blobs that survived GC
    ``-merge=1`` passes carried coverage the corpus wanted. Written to
    ``work/<target>/seedgen-effectiveness.json`` for the input-generator
    agent to read before authoring the next script.
    """
    environment = dict(env) if env is not None else dict(os.environ)
    root = resolve_workspace_root(workspace_root, env=environment)
    name = str(target).strip().rstrip("/").split("/")[-1]
    work_dir = root / "work" / name
    seeds_dir = work_dir / "seeds"
    provenance_path = work_dir / "seedgen.jsonl"

    surviving_names = (
        {entry.name for entry in seeds_dir.iterdir() if entry.is_file() and entry.name.startswith("seedgen-")}
        if seeds_dir.is_dir()
        else set()
    )
    scripts: dict[str, dict[str, Any]] = {}
    attributed: set[str] = set()
    if provenance_path.is_file():
        for line in provenance_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            digest = str(record.get("script_sha256") or "unknown")
            entry = scripts.setdefault(
                digest,
                {"script": record.get("script"), "runs": 0, "generated_total": 0, "merged_total": 0, "blobs": set()},
            )
            entry["runs"] += 1
            entry["generated_total"] += int(record.get("generated") or 0)
            entry["merged_total"] += int(record.get("merged_new") or 0)
            for blob in record.get("blobs") or []:
                entry["blobs"].add(str(blob))
                attributed.add(str(blob))

    payload_scripts = {}
    for digest, entry in scripts.items():
        surviving = len(entry["blobs"] & surviving_names)
        payload_scripts[digest] = {
            "script": entry["script"],
            "runs": entry["runs"],
            "generated_total": entry["generated_total"],
            "merged_total": entry["merged_total"],
            "surviving": surviving,
        }
    payload = {
        "ok": True,
        "target": name,
        "scripts": payload_scripts,
        "surviving_total": len(surviving_names & attributed),
        "unattributed_seedgen_blobs": len(surviving_names - attributed),
    }
    report_path = work_dir / "seedgen-effectiveness.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {**payload, "report": str(report_path)}


def _result(name: str, script: Path, *, blockers: list[str], ok: bool = False, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"ok": ok and not blockers, "target": name, "script": str(script), "blockers": blockers}
    payload.update(extra)
    return payload

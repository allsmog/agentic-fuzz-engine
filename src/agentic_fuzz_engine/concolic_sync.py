"""Bounded SymCC corpus synchronization.

One bounded pass of the concolic feedback loop: pick corpus entries the SymCC
binary has not seen yet, run each one through the instrumented binary
(sequentially, with a per-input wall-clock timeout and an address-space cap),
and copy solver-generated variants back into the corpus under content-hash
names so the coverage fuzzer picks them up next round.

Runaway protection is deliberate and layered:

- strictly sequential — never more than one child process at a time
- per-input timeout (child killed by ``subprocess`` on expiry)
- address-space cap via ``prlimit`` when available
- disk-headroom hard guard before starting and per input
- ``max_inputs`` / ``max_seconds`` / ``max_new_files`` round bounds
"""

from __future__ import annotations

import os
import shutil
import time
from hashlib import sha256
from pathlib import Path
from time import monotonic
from typing import Any, Mapping

from .runtime_backends import MIN_FREE_DISK_GB, _run_command, check_disk_headroom
from .symcc_crossover import extract_solution, record_solutions

MAX_SYNC_INPUTS = 1024
MAX_SYNC_SECONDS = 3600.0
MAX_PER_INPUT_TIMEOUT = 600.0
MAX_NEW_FILES = 5000
MAX_REPORTED_INPUTS = 50
MAX_SOLUTION_PARENT_BYTES = 1_048_576


def run_corpus_sync(
    *,
    corpus_dir: str | Path,
    symcc_binary: str | Path,
    state_dir: str | Path | None = None,
    max_inputs: int = 32,
    max_seconds: int | float = 600,
    per_input_timeout: int | float = 90,
    max_memory_mb: int = 4096,
    max_new_files: int = 500,
    min_free_gb: float = MIN_FREE_DISK_GB,
    env: Mapping[str, str] | None = None,
    record_solutions_enabled: bool = True,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    corpus = Path(corpus_dir).expanduser().resolve()
    binary = Path(symcc_binary).expanduser().resolve()
    if not corpus.is_dir():
        raise FileNotFoundError(f"corpus_dir is not a directory: {corpus_dir}")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise FileNotFoundError(f"symcc_binary is not an executable file: {symcc_binary}")

    input_budget = max(1, min(int(max_inputs), MAX_SYNC_INPUTS))
    time_budget = max(1.0, min(float(max_seconds), MAX_SYNC_SECONDS))
    per_input = max(1.0, min(float(per_input_timeout), MAX_PER_INPUT_TIMEOUT))
    new_file_budget = max(1, min(int(max_new_files), MAX_NEW_FILES))

    state = Path(state_dir).expanduser().resolve() if state_dir else corpus.parent / "symcc-state"
    seen_dir = state / "seen"
    gen_dir = state / "gen"
    seen_dir.mkdir(parents=True, exist_ok=True)
    gen_dir.mkdir(parents=True, exist_ok=True)

    headroom = check_disk_headroom(corpus, min_free_gb=min_free_gb)
    if not headroom["ok"]:
        return {
            "ok": False,
            "mode": "symcc-corpus-sync",
            "corpus_dir": str(corpus),
            "disk": headroom,
            "inputs_processed": 0,
            "new_seeds_added": 0,
            "blockers": [headroom["blocker"]],
        }

    prlimit = shutil.which("prlimit", path=environment.get("PATH"))
    started = monotonic()
    processed = 0
    added = 0
    crashes = 0
    reports = []
    blockers = []
    solution_records: list[dict[str, Any]] = []

    # Snapshot the queue up front: entries this pass writes back into the
    # corpus wait until the next round, so the budget covers real inputs.
    pending = _unseen_entries(corpus, seen_dir)
    for entry in pending:
        if processed >= input_budget or (monotonic() - started) >= time_budget or added >= new_file_budget:
            break
        (seen_dir / entry.name).touch()
        for stale in gen_dir.iterdir():
            if stale.is_file():
                stale.unlink()

        run_env = dict(environment)
        run_env["SYMCC_INPUT_FILE"] = str(entry)
        run_env["SYMCC_OUTPUT_DIR"] = str(gen_dir)
        run_env.setdefault("SYMCC_ENABLE_LINEARIZATION", "1")
        argv = [str(binary), str(entry)]
        if prlimit and max_memory_mb > 0:
            argv = [prlimit, f"--as={int(max_memory_mb) * 1_048_576}", "--", *argv]

        remaining = max(1.0, time_budget - (monotonic() - started))
        run = _run_command(
            argv,
            cwd=corpus.parent,
            timeout_seconds=min(per_input, remaining),
            env=environment,
            declared_env={
                "SYMCC_INPUT_FILE": run_env["SYMCC_INPUT_FILE"],
                "SYMCC_OUTPUT_DIR": run_env["SYMCC_OUTPUT_DIR"],
                "SYMCC_ENABLE_LINEARIZATION": run_env["SYMCC_ENABLE_LINEARIZATION"],
            },
        )
        processed += 1
        if run["exit_code"] not in (0,) and not run["timed_out"]:
            crashes += 1

        # The byte-delta child-vs-parent is the solved constraint itself;
        # recorded so the crossover lane can re-apply it to other inputs.
        parent_bytes: bytes | None = None
        if record_solutions_enabled:
            try:
                if entry.stat().st_size <= MAX_SOLUTION_PARENT_BYTES:
                    parent_bytes = entry.read_bytes()
            except OSError:
                parent_bytes = None

        new_here = 0
        for generated in sorted(gen_dir.iterdir()):
            if not generated.is_file():
                continue
            if added >= new_file_budget:
                break
            child_bytes = generated.read_bytes()
            digest = sha256(child_bytes).hexdigest()[:20]
            destination = corpus / f"symcc-{digest}"
            if destination.exists():
                continue
            free_now = check_disk_headroom(corpus, min_free_gb=min_free_gb)
            if not free_now["ok"]:
                blockers.append(free_now["blocker"])
                break
            shutil.copy2(generated, destination)
            added += 1
            new_here += 1
            if parent_bytes is not None:
                solution = extract_solution(parent_bytes, child_bytes)
                if solution is not None:
                    solution["parent"] = entry.name
                    solution["ts"] = round(time.time(), 2)
                    solution_records.append(solution)
        if len(reports) < MAX_REPORTED_INPUTS:
            reports.append(
                {
                    "input": entry.name,
                    "exit_code": run["exit_code"],
                    "timed_out": run["timed_out"],
                    "elapsed_ms": run["elapsed_ms"],
                    "new_seeds": new_here,
                }
            )
        if blockers:
            break

    solutions_recorded = record_solutions(state, solution_records) if solution_records else 0

    return {
        "ok": not blockers,
        "mode": "symcc-corpus-sync",
        "corpus_dir": str(corpus),
        "symcc_binary": str(binary),
        "state_dir": str(state),
        "memory_cap": {"prlimit": bool(prlimit), "max_memory_mb": max_memory_mb},
        "disk": headroom,
        "inputs_processed": processed,
        "nonzero_exits": crashes,
        "new_seeds_added": added,
        "solutions_recorded": solutions_recorded,
        "elapsed_seconds": round(monotonic() - started, 2),
        "inputs": reports,
        "blockers": blockers,
    }


def _unseen_entries(corpus: Path, seen_dir: Path) -> list[Path]:
    candidates = [entry for entry in corpus.iterdir() if entry.is_file()]
    candidates.sort(key=lambda entry: entry.stat().st_mtime, reverse=True)
    return [entry for entry in candidates if not (seen_dir / entry.name).exists()]

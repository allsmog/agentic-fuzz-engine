"""Bounded multi-lane campaign rounds over a workspace target.

One round = coverage fuzzing -> concolic corpus sync -> (periodic) KLEE tier
-> crash intake with ASAN replay grading -> dedupe -> checkpoint. Lanes run
strictly sequentially — at most one fuzzer process, one SymCC child, or one
KLEE container exists at any moment — and every lane is wall-clock bounded,
so a campaign can never fork-bomb or wedge the host. A disk-headroom guard
runs before every round and aborts the campaign rather than filling the
volume.

The persistent corpus lives in ``<workspace>/work/<target>/seeds``; libFuzzer
writes new coverage units there, SymCC and KLEE feed solved inputs back into
it, so progress accumulates across rounds and across campaigns.
"""

from __future__ import annotations

import json
import os
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .concolic_sync import run_corpus_sync
from .runtime_backends import MIN_FREE_DISK_GB, check_disk_headroom
from .workspace import load_policy, resolve_workspace_root

MAX_ROUNDS = 100
MAX_KLEE_SEED_MERGE = 500


def default_asan_options(workspace_root: Path) -> str:
    options = "detect_leaks=0:allocator_may_return_null=1:symbolize=0"
    suppressions = workspace_root / "asan.supp"
    if suppressions.is_file():
        options += f":suppressions={suppressions}:print_suppressions=0"
    return options


def run_campaign_rounds(
    engine: Any,
    *,
    project: str,
    run_id: str | None = None,
    rounds: int = 1,
    fuzz_seconds: int | float | None = None,
    rss_limit_mb: int | None = None,
    sync_max_inputs: int | None = None,
    sync_seconds: int | float = 600,
    sync_memory_mb: int = 4096,
    klee_config: str | None = None,
    klee_every: int | None = None,
    klee_seconds: int | float = 900,
    workspace_root: str | Path | None = None,
    min_free_gb: float | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    root = resolve_workspace_root(workspace_root, env=environment)
    # Explicit CLI flags win; the workspace policy file supplies the rest.
    policy = load_policy(root, env=environment)
    round_policy = policy.get("round", {})
    fuzz_seconds = round_policy.get("fuzz_seconds", 600) if fuzz_seconds is None else fuzz_seconds
    rss_limit_mb = int(round_policy.get("rss_limit_mb", 2048)) if rss_limit_mb is None else rss_limit_mb
    sync_max_inputs = int(round_policy.get("sync_max_inputs", 32)) if sync_max_inputs is None else sync_max_inputs
    klee_every = int(round_policy.get("klee_every", 4)) if klee_every is None else klee_every
    min_free_gb = float(policy.get("disk", {}).get("min_free_gb", MIN_FREE_DISK_GB)) if min_free_gb is None else min_free_gb
    # Fuzz binaries link uninstrumented dependency .so's whose static-init
    # allocations LSan reports (and whose exit-time suppression pass can wedge
    # on the symbolizer pipe). Memory corruption, not leaks, is the campaign
    # target — disable leak checking for every child this run spawns, and honor
    # an optional workspace-level ASAN suppression file for known vendor noise.
    asan_options = default_asan_options(root)
    os.environ.setdefault("ASAN_OPTIONS", asan_options)
    environment.setdefault("ASAN_OPTIONS", asan_options)
    name = project.removeprefix("localfuzz/c/")
    target = f"localfuzz/c/{name}"

    fuzzer = root / "bin" / name / "fuzzer"
    symcc_bin = root / "bin" / name / "symcc_bin"
    corpus = root / "work" / name / "seeds"
    corpus.mkdir(parents=True, exist_ok=True)

    blockers: list[str] = []
    if not fuzzer.is_file() or not os.access(fuzzer, os.X_OK):
        blockers.append(f"missing ASAN fuzzer binary (run target-build first): {fuzzer}")
    # Generated targets must pass build+smoke validation before consuming
    # campaign budget — an unvalidated generated stub fuzzes nothing.
    manifest_path = root / "targets" / "c" / name / ".localfuzz" / "generate.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            manifest = {}
        if not manifest.get("validated"):
            blockers.append(
                f"generated target not validated (status={manifest.get('status')!r}); "
                "run target-generate --validate first"
            )
    round_budget = max(1, min(int(rounds), MAX_ROUNDS))

    start = engine.call_tool(
        "campaign_start",
        {
            "target": target,
            "name": run_id,
            "metadata": {"mode": "campaign-rounds", "project": name, "rounds_requested": round_budget},
        },
    )
    active_run_id = str(start["run_id"])
    if blockers:
        return _summary(active_run_id, target, rounds_done=[], corpus=corpus, blockers=blockers)

    from .campaign_metrics import ledger_transition, plateau_status

    ledger_transition(root, name=name, status="fuzzing", skip_if_in={"plateaued", "confirmed", "dead"})

    dict_path = root / "targets" / "c" / name / f"{name}.dict"
    dict_args = []
    if _dictionary_has_tokens(dict_path):
        dict_args = [f"-dict={dict_path}"]

    replay_command = [str(fuzzer), "{poc}"]
    round_summaries = []
    for index in range(1, round_budget + 1):
        summary: dict[str, Any] = {"round": index}
        headroom = check_disk_headroom(root, min_free_gb=min_free_gb)
        summary["disk_free_gb"] = headroom["free_gb"]
        if not headroom["ok"]:
            blockers.append(headroom["blocker"])
            summary["aborted"] = "disk"
            round_summaries.append(summary)
            break

        fuzz = engine.call_tool(
            "fuzz_ensemble_run",
            {
                "run_id": active_run_id,
                "target": target,
                "harness": name,
                "harness_command": [
                    str(fuzzer),
                    str(corpus),
                    f"-rss_limit_mb={int(rss_limit_mb)}",
                    f"-max_total_time={max(1, int(fuzz_seconds))}",
                    "-detect_leaks=0",
                    "-print_final_stats=1",
                    *dict_args,
                ],
                "workers": ["libfuzzer"],
                "runs": 1_000_000,
                "timeout_seconds": min(3600, int(fuzz_seconds) + 60),
                "artifact_prefix": f"rounds/{index}/crashes",
            },
        )
        libfuzzer_stats = None
        for worker in fuzz.get("worker_results", []):
            if worker.get("worker") == "libfuzzer":
                libfuzzer_stats = (worker.get("run") or {}).get("parsed")
        summary["fuzz"] = {
            "ok": fuzz.get("ok"),
            "crash_files": len(fuzz.get("crash_files", [])),
            "stats": libfuzzer_stats,
            "blockers": fuzz.get("blockers", []),
        }

        if symcc_bin.is_file() and os.access(symcc_bin, os.X_OK):
            sync = run_corpus_sync(
                corpus_dir=corpus,
                symcc_binary=symcc_bin,
                max_inputs=sync_max_inputs,
                max_seconds=sync_seconds,
                max_memory_mb=sync_memory_mb,
                min_free_gb=min_free_gb,
                env=environment,
            )
            summary["symcc_sync"] = {
                "inputs_processed": sync["inputs_processed"],
                "new_seeds_added": sync["new_seeds_added"],
                "blockers": sync["blockers"],
            }
        else:
            summary["symcc_sync"] = {"skipped": f"no symcc binary at {symcc_bin}"}

        klee_seed_dirs: list[str] = []
        if klee_config and klee_every > 0 and (index - 1) % klee_every == 0:
            klee = engine.call_tool(
                "symbolic_worker_run",
                {
                    "run_id": active_run_id,
                    "mode": "klee",
                    "klee_config": klee_config,
                    "workspace_root": str(root),
                    "timeout_seconds": min(3600, int(klee_seconds)),
                    "artifact_prefix": f"rounds/{index}/klee",
                },
            )
            extraction = (klee.get("result") or {}).get("extraction") or {}
            merged = _merge_seeds(Path(str(extraction.get("seeds_dir", ""))), corpus, prefix="klee")
            summary["klee"] = {
                "ok": klee.get("ok"),
                "seeds_extracted": extraction.get("seeds_written", 0),
                "errors_extracted": extraction.get("errors_written", 0),
                "seeds_merged": merged,
                "blockers": klee.get("blockers", []),
            }
            seeds_dir = extraction.get("seeds_dir")
            if seeds_dir and Path(seeds_dir).is_dir() and any(Path(seeds_dir).iterdir()):
                klee_seed_dirs.append(str(seeds_dir))

        intake_sources = [
            crash_dir
            for crash_dir in {
                worker.get("crash_dir")
                for worker in fuzz.get("worker_results", [])
                if worker.get("executed")
            }
            if crash_dir and any(Path(crash_dir).rglob("*"))
        ] + klee_seed_dirs
        findings = 0
        for source in intake_sources:
            imported = engine.call_tool(
                "crash_import",
                {
                    "run_id": active_run_id,
                    "source_path": source,
                    "target": target,
                    "harness": name,
                    "harness_command": replay_command,
                    "artifact_prefix": f"rounds/{index}/intake",
                },
            )
            findings += len(imported.get("findings", []))
        summary["intake"] = {"sources": len(intake_sources), "findings_recorded": findings}

        dedupe = engine.call_tool("finding_dedupe", {"run_id": active_run_id})
        summary["dedupe_groups"] = len(dedupe.get("groups", []))
        summary["corpus_size"] = sum(1 for entry in corpus.iterdir() if entry.is_file())

        engine.call_tool(
            "campaign_checkpoint_record",
            {
                "run_id": active_run_id,
                "target": target,
                "harness": name,
                "phase": "fuzzing" if not findings else "grading",
                "agent": "fuzz-finder" if not findings else "crash-grader",
                "tool_evidence": [
                    f"round {index}: fuzz ok={fuzz.get('ok')} crashes={summary['fuzz']['crash_files']}",
                    f"round {index}: symcc {summary['symcc_sync']}",
                    f"round {index}: findings={findings} dedupe_groups={summary['dedupe_groups']}",
                ],
                "blockers": [],
                "next_command": "campaign-round-run" if index < round_budget else "campaign-report",
            },
        )
        if findings:
            ledger_transition(root, name=name, status="confirmed", round_index=index,
                              note=f"{findings} finding(s) recorded")

        _append_round_metrics(root / "work" / name / "rounds.jsonl", run_id=active_run_id, summary=summary)

        assessment = plateau_status(workspace_root=root, target=f"localfuzz/c/{name}", env=environment)
        target_assessment = assessment["targets"][0] if assessment.get("targets") else {}
        summary["plateau"] = {
            "verdict": target_assessment.get("verdict"),
            "next_rung": target_assessment.get("next_rung"),
            "flat_rounds": target_assessment.get("flat_rounds"),
        }
        if str(target_assessment.get("verdict", "")).startswith("plateaued"):
            ledger_transition(
                root, name=name, status="plateaued", round_index=index,
                note=target_assessment.get("verdict"),
                skip_if_in={"confirmed", "dead"},
            )
        round_summaries.append(summary)

    return _summary(active_run_id, target, rounds_done=round_summaries, corpus=corpus, blockers=blockers)


def _dictionary_has_tokens(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                return True
    except OSError:
        return False
    return False


def _append_round_metrics(path: Path, *, run_id: str, summary: dict[str, Any]) -> None:
    """Durable per-round metrics line — the plateau signal's source of truth."""
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"run_id": run_id, **summary}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def _merge_seeds(seeds_dir: Path, corpus: Path, *, prefix: str) -> int:
    if not seeds_dir.is_dir():
        return 0
    merged = 0
    for entry in sorted(seeds_dir.iterdir()):
        if merged >= MAX_KLEE_SEED_MERGE:
            break
        if not entry.is_file():
            continue
        digest = sha256(entry.read_bytes()).hexdigest()[:20]
        destination = corpus / f"{prefix}-{digest}"
        if destination.exists():
            continue
        destination.write_bytes(entry.read_bytes())
        merged += 1
    return merged


def _summary(
    run_id: str,
    target: str,
    *,
    rounds_done: list[dict[str, Any]],
    corpus: Path,
    blockers: list[str],
) -> dict[str, Any]:
    total_findings = sum(item.get("intake", {}).get("findings_recorded", 0) for item in rounds_done)
    return {
        "ok": not blockers,
        "mode": "campaign-rounds",
        "run_id": run_id,
        "target": target,
        "rounds_completed": len([item for item in rounds_done if not item.get("aborted")]),
        "rounds": rounds_done,
        "corpus_dir": str(corpus),
        "findings_recorded": total_findings,
        "blockers": blockers,
    }

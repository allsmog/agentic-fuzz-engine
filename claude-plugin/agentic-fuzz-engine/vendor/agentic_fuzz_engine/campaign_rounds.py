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
from .known_crashes import (
    KNOWN_INPUTS_DIR,
    load_known,
    probe_and_partition,
    record_known,
)
from .runtime_backends import MIN_FREE_DISK_GB, check_disk_headroom
from .seed_weights import (
    merge_back_focus,
    prepare_focus_round,
    resolve_sinks_jsonl,
    update_weights_after_round,
    weights_policy,
)
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
    # Distro llvm-symbolizer builds may query remote debuginfod servers when
    # symbolizing; without that egress each lookup stalls until the TCP
    # timeout, wedging coverage replays and crash reports alike.
    os.environ.setdefault("DEBUGINFOD_URLS", "")
    environment.setdefault("DEBUGINFOD_URLS", "")
    name = project.removeprefix("localfuzz/c/")
    target = f"localfuzz/c/{name}"

    fuzzer = root / "bin" / name / "fuzzer"
    symcc_bin = root / "bin" / name / "symcc_bin"
    corpus = root / "work" / name / "seeds"
    corpus.mkdir(parents=True, exist_ok=True)
    # Authored seeds live in targets/c/<name>/seeds, but libFuzzer only
    # mutates what is in the work corpus — sync them in content-addressed
    # at campaign start so a target never fuzzes scaffold samples while its
    # valid seeds sit unimported next to the harness.
    seeds_imported = _merge_seeds(
        root / "targets" / "c" / name / "seeds", corpus, prefix="authored"
    )

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

    # Proactive staleness: don't burn rounds against a binary whose sources
    # moved on. Policy round.stale_policy: warn (note) | block | rebuild.
    from .staleness import check_target_staleness

    stale_policy = str(round_policy.get("stale_policy", "warn"))
    staleness = check_target_staleness(root, name)
    if staleness.get("stale"):
        detail = f"{staleness['changed_total']} changed inputs, e.g. {staleness['changed'][:3]}"
        if stale_policy == "rebuild":
            from .container_build import build_target

            rebuild = build_target(project=target, workspace_root=root, env=environment)
            if rebuild.get("ok"):
                staleness = check_target_staleness(root, name)
            else:
                blockers.append(f"stale fuzzer binary and rebuild failed: {rebuild.get('blockers')}")
        elif stale_policy == "block":
            blockers.append(f"stale fuzzer binary vs sources ({detail}); run target-build")
        else:
            staleness["note"] = f"stale fuzzer binary vs sources ({detail}); run target-build"
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
        return _summary(active_run_id, target, rounds_done=[], corpus=corpus, blockers=blockers, staleness=staleness)

    from .campaign_metrics import ledger_transition, plateau_status

    ledger_transition(root, name=name, status="fuzzing", skip_if_in={"plateaued", "confirmed", "dead"})

    dict_path = root / "targets" / "c" / name / f"{name}.dict"

    # Per-target libFuzzer arg overrides (targets/c/<t>/.localfuzz/fuzz.json
    # {"extra_args": [...]}) on top of an optional workspace-wide default
    # (policy round.fuzz_extra_args). Primary use: fork-mode conversion
    # (-fork=1 -ignore_timeouts=1 -ignore_ooms=1) for targets whose parsers
    # need child-process isolation instead of in-harness signal watchdogs.
    extra_args = [str(a) for a in round_policy.get("fuzz_extra_args", [])]
    fuzz_cfg: dict[str, Any] = {}
    fuzz_json = root / "targets" / "c" / name / ".localfuzz" / "fuzz.json"
    if fuzz_json.is_file():
        try:
            fuzz_cfg = json.loads(fuzz_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            fuzz_cfg = {}
        target_extra = fuzz_cfg.get("extra_args", [])
        if isinstance(target_extra, list):
            extra_args.extend(str(a) for a in target_extra)

    # Resource-class artifacts (libFuzzer timeout-/oom-/slow-unit- files,
    # collected deliberately in fork mode via -ignore_timeouts/-ignore_ooms)
    # are never gradeable findings, and replaying each through the ASAN
    # harness burns the full per-PoV timeout on known noise. Skip them at
    # intake; per-target fuzz.json "intake_skip_prefixes" overrides the
    # policy/default list.
    _skip_cfg = fuzz_cfg.get("intake_skip_prefixes")
    if not isinstance(_skip_cfg, list):
        _skip_cfg = round_policy.get("intake_skip_prefixes", ["timeout-", "oom-", "slow-unit-"])
    intake_skip_prefixes = tuple(str(p) for p in _skip_cfg)

    # Known-crash suppression policy (the fuzz-blocker tier): once a root
    # signature is recorded, later rediscoveries are probed once and
    # quarantined instead of re-graded, and the fuzzer defaults into fork
    # mode so it explores past known crashes instead of exiting on them.
    fork_on_known = bool(round_policy.get("fork_on_known_crashes", True)) and fuzz_cfg.get(
        "fork_on_known_crashes"
    ) is not False
    known_probe_timeout = float(round_policy.get("known_probe_timeout_seconds", 10))
    work_dir = corpus.parent
    engine_state = getattr(engine, "state", None)

    # Per-seed weighted scheduling (the FuzzDB/BIT tier): policy-gated,
    # advisory, and split across the round — the focus segment fuzzes on
    # weights computed at the end of the *previous* round.
    weights_cfg = weights_policy(policy, fuzz_cfg)
    weights_enabled = bool(weights_cfg.get("enabled"))
    focus_fraction = min(0.9, max(0.0, float(weights_cfg.get("focus_fraction", 0.25))))
    last_sink_changes = 0

    symcc_policy = policy.get("symcc", {}) if isinstance(policy.get("symcc"), dict) else {}

    replay_command = [str(fuzzer), "{poc}"]
    round_summaries = []
    for index in range(1, round_budget + 1):
        summary: dict[str, Any] = {"round": index}
        # Re-evaluated per round: the crossover lane harvests solved magic
        # values into the dictionary, which must take effect next round.
        dict_args = [f"-dict={dict_path}"] if _dictionary_has_tokens(dict_path) else []
        known = load_known(work_dir)
        known_before = set(known)
        fork_args: list[str] = []
        if known and fork_on_known and not any(str(arg).startswith("-fork=") for arg in extra_args):
            # -ignore_crashes is only valid with -fork; the stat-line format
            # changes under fork mode, which plateau detection tolerates by
            # falling back to corpus_size.
            fork_args = ["-fork=1", "-ignore_crashes=1", "-ignore_timeouts=1", "-ignore_ooms=1"]
        summary["fork_mode"] = bool(fork_args)
        headroom = check_disk_headroom(root, min_free_gb=min_free_gb)
        summary["disk_free_gb"] = headroom["free_gb"]
        if not headroom["ok"]:
            blockers.append(headroom["blocker"])
            summary["aborted"] = "disk"
            round_summaries.append(summary)
            break

        focus: dict[str, Any] | None = None
        main_fuzz_seconds = max(1, int(fuzz_seconds))
        if weights_enabled and focus_fraction > 0:
            try:
                focus = prepare_focus_round(work_dir=work_dir, corpus=corpus, policy_weights=weights_cfg)
            except Exception as exc:
                focus = {"ready": False, "reason": f"focus-prepare failed: {exc}"}
            if focus.get("ready"):
                main_fuzz_seconds = max(1, int(int(fuzz_seconds) * (1 - focus_fraction)))

        # Directed execution slice: when the active directed task has a
        # built allowlist binary (directed-build), it gets a fraction of the
        # round's fuzz time; its new units link back into the main corpus.
        exec_directed_policy = policy.get("directed", {}) if isinstance(policy.get("directed"), dict) else {}
        directed_task: dict[str, Any] | None = None
        directed_seconds = 0
        if exec_directed_policy.get("execute", True):
            try:
                from .directed import active_or_queued

                candidate_task = active_or_queued(root, name)
            except Exception:
                candidate_task = None
            binary = Path(str(candidate_task.get("binary"))) if candidate_task and candidate_task.get("binary") else None
            if binary is not None and binary.is_file() and os.access(binary, os.X_OK):
                directed_task = candidate_task
                fraction = min(0.9, max(0.0, float(exec_directed_policy.get("fraction", 0.25))))
                directed_seconds = max(1, int(int(fuzz_seconds) * fraction))
                main_fuzz_seconds = max(1, main_fuzz_seconds - directed_seconds)

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
                    f"-max_total_time={main_fuzz_seconds}",
                    "-detect_leaks=0",
                    "-print_final_stats=1",
                    *dict_args,
                    *extra_args,
                    *fork_args,
                ],
                "workers": ["libfuzzer"],
                "runs": 1_000_000,
                "timeout_seconds": min(3600, main_fuzz_seconds + 60),
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

        # Focus segment: the remaining slice of round budget fuzzes with the
        # top-weighted seeds as the write-corpus (libFuzzer writes new units
        # into the first dir), then new units link back into the main corpus
        # with their content-hash names intact.
        focus_fuzz = None
        if focus is not None:
            focus_block: dict[str, Any] = {
                "ready": bool(focus.get("ready")),
                "size": int(focus.get("size") or 0),
            }
            if focus.get("reason"):
                focus_block["reason"] = focus["reason"]
            if focus.get("ready"):
                focus_seconds = max(1, int(fuzz_seconds) - main_fuzz_seconds)
                focus_fuzz = engine.call_tool(
                    "fuzz_ensemble_run",
                    {
                        "run_id": active_run_id,
                        "target": target,
                        "harness": name,
                        "harness_command": [
                            str(fuzzer),
                            str(focus["focus_dir"]),
                            str(corpus),
                            f"-rss_limit_mb={int(rss_limit_mb)}",
                            f"-max_total_time={focus_seconds}",
                            "-detect_leaks=0",
                            "-print_final_stats=1",
                            *dict_args,
                            *extra_args,
                            *fork_args,
                        ],
                        "workers": ["libfuzzer"],
                        "runs": 1_000_000,
                        "timeout_seconds": min(3600, focus_seconds + 60),
                        "artifact_prefix": f"rounds/{index}/focus-crashes",
                    },
                )
                merged = merge_back_focus(
                    focus_dir=Path(str(focus["focus_dir"])),
                    corpus=corpus,
                    baseline=set(focus.get("baseline") or []),
                )
                focus_block.update(
                    {
                        "fuzz_ok": focus_fuzz.get("ok"),
                        "crash_files": len(focus_fuzz.get("crash_files", [])),
                        "new_units_merged": merged["merged_new"],
                    }
                )
            summary["weights"] = {"focus": focus_block}

        if directed_task is not None and directed_seconds > 0:
            scratch = work_dir / "directed-scratch"
            if scratch.is_dir():
                for stale_unit in scratch.iterdir():
                    if stale_unit.is_file():
                        stale_unit.unlink(missing_ok=True)
            scratch.mkdir(parents=True, exist_ok=True)
            directed_fuzz = engine.call_tool(
                "fuzz_ensemble_run",
                {
                    "run_id": active_run_id,
                    "target": target,
                    "harness": name,
                    "harness_command": [
                        str(directed_task["binary"]),
                        str(scratch),
                        str(corpus),
                        f"-rss_limit_mb={int(rss_limit_mb)}",
                        f"-max_total_time={directed_seconds}",
                        "-detect_leaks=0",
                        "-print_final_stats=1",
                        *dict_args,
                        *extra_args,
                        *fork_args,
                    ],
                    "workers": ["libfuzzer"],
                    "runs": 1_000_000,
                    "timeout_seconds": min(3600, directed_seconds + 60),
                    "artifact_prefix": f"rounds/{index}/directed-crashes",
                },
            )
            directed_merged = merge_back_focus(focus_dir=scratch, corpus=corpus, baseline=set())
            summary["directed_exec"] = {
                "task": directed_task.get("id"),
                "binary": directed_task.get("binary"),
                "seconds": directed_seconds,
                "fuzz_ok": directed_fuzz.get("ok"),
                "crash_files": len(directed_fuzz.get("crash_files", [])),
                "new_units_merged": directed_merged["merged_new"],
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

        if symcc_policy.get("crossover_enabled", True):
            try:
                from .symcc_crossover import (
                    harvest_dictionary_tokens,
                    load_solutions,
                    run_crossover,
                )

                crossover = run_crossover(
                    work_dir=work_dir,
                    corpus=corpus,
                    round_index=index,
                    target_name=name,
                    policy=symcc_policy,
                    min_free_gb=min_free_gb,
                )
                if crossover.get("solutions_available"):
                    harvested = harvest_dictionary_tokens(
                        records=load_solutions(
                            work_dir / "symcc-state",
                            max_entries=int(symcc_policy.get("solutions_max", 512)),
                        ),
                        dict_path=dict_path,
                        max_new=int(symcc_policy.get("dict_harvest_max", 16)),
                        total_cap=int(symcc_policy.get("dict_harvest_total", 256)),
                    )
                    crossover["dict_tokens_added"] = harvested.get("tokens_added", 0)
                summary["symcc_crossover"] = crossover
                if crossover.get("new_seeds") and engine_state is not None:
                    engine_state.event_append(
                        active_run_id,
                        "symcc_crossover",
                        {
                            "round": index,
                            "applied": crossover.get("applied", 0),
                            "new_seeds": crossover.get("new_seeds", 0),
                            "dict_tokens": crossover.get("dict_tokens_added", 0),
                        },
                    )
            except Exception as exc:  # crossover never blocks the round
                summary["symcc_crossover"] = {"blockers": [f"crossover failed: {exc}"]}

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
                for result in (fuzz, focus_fuzz)
                if result is not None
                for worker in result.get("worker_results", [])
                if worker.get("executed")
            }
            if crash_dir and any(Path(crash_dir).rglob("*"))
        ] + klee_seed_dirs
        findings = 0
        skipped_noise = 0
        suppressed_round: dict[str, int] = {}
        probe_failures = 0
        new_root_sigs: set[str] = set()
        for source in intake_sources:
            src_dir = Path(source)
            files = [f for f in sorted(src_dir.rglob("*")) if f.is_file()]
            kept = [f for f in files if not f.name.startswith(intake_skip_prefixes)]
            skipped_noise += len(files) - len(kept)
            if not kept:
                continue
            # Fast-path: probe once, quarantine known root signatures, and
            # only send unknowns through the 3x grading replay.
            partition = probe_and_partition(
                kept,
                known=known,
                replay_command=replay_command,
                work_dir=work_dir,
                timeout_seconds=known_probe_timeout,
                env=environment,
            )
            for signature, count in partition["suppressed"].items():
                suppressed_round[signature] = suppressed_round.get(signature, 0) + count
                record_known(work_dir, root_sig=signature, round_index=index)
            probe_failures += partition["probe_failures"]
            kept = partition["unknown_files"]
            if not kept:
                continue
            if len(kept) != len(files):
                staged = src_dir.parent / f"{src_dir.name}-intake"
                staged.mkdir(parents=True, exist_ok=True)
                for f in kept:
                    dest = staged / f.name
                    if not dest.exists():
                        try:
                            os.link(f, dest)
                        except OSError:
                            dest.write_bytes(f.read_bytes())
                source = str(staged)
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
            for finding in imported.get("findings", []):
                findings += 1
                root_sig = finding.get("root_signature") if isinstance(finding, dict) else None
                if root_sig:
                    record_known(
                        work_dir,
                        root_sig=str(root_sig),
                        crash_type=finding.get("error_token"),
                        crash_state=finding.get("crash_state"),
                        error_token=finding.get("error_token"),
                        finding_id=finding.get("finding_id"),
                        round_index=index,
                    )
                    if root_sig not in known_before:
                        new_root_sigs.add(str(root_sig))
                else:
                    # No parseable identity: conservatively treat as new so a
                    # novel crash can never be silently absorbed.
                    new_root_sigs.add(str(finding.get("finding_id") or f"unidentified-round-{index}"))
        if suppressed_round and engine_state is not None:
            engine_state.event_append(
                active_run_id,
                "known_crash_suppressed",
                {
                    "round": index,
                    "suppressed": suppressed_round,
                    "quarantine": str(work_dir / KNOWN_INPUTS_DIR),
                },
            )
        summary["intake"] = {
            "sources": len(intake_sources),
            "findings_recorded": findings,
            "resource_noise_skipped": skipped_noise,
            "known_suppressed": sum(suppressed_round.values()),
            "probe_failures": probe_failures,
        }
        summary["new_root_signatures"] = len(new_root_sigs)

        dedupe = engine.call_tool("finding_dedupe", {"run_id": active_run_id})
        summary["dedupe_groups"] = len(dedupe.get("groups", []))
        summary["corpus_size"] = sum(1 for entry in corpus.iterdir() if entry.is_file())

        if weights_enabled:
            # Round-tail bookkeeping: index this round's new units, rebalance
            # when a trigger fired. Advisory — never fails the round.
            try:
                weights_update = update_weights_after_round(
                    engine_state=engine_state,
                    run_id=active_run_id,
                    root=root,
                    name=name,
                    work_dir=work_dir,
                    fuzzer=fuzzer,
                    corpus=corpus,
                    round_index=index,
                    policy=policy,
                    policy_weights=weights_cfg,
                    new_root_sigs=len(new_root_sigs),
                    sink_changes=last_sink_changes,
                    env=environment,
                )
            except Exception as exc:
                weights_update = {"blockers": [f"weights update failed: {exc}"]}
            summary.setdefault("weights", {}).update(weights_update)

        _append_round_metrics(root / "work" / name / "rounds.jsonl", run_id=active_run_id, summary=summary)

        assessment = plateau_status(workspace_root=root, target=f"localfuzz/c/{name}", env=environment)
        target_assessment = assessment["targets"][0] if assessment.get("targets") else {}
        summary["plateau"] = {
            "verdict": target_assessment.get("verdict"),
            "next_rung": target_assessment.get("next_rung"),
            "flat_rounds": target_assessment.get("flat_rounds"),
            "recommendation": target_assessment.get("recommendation"),
        }

        plateaued = str(target_assessment.get("verdict", "")).startswith("plateaued")
        frontier_evidence = None
        if plateaued:
            # Frontier hook: on plateau, measure which dangerous sinks the
            # corpus never executed and refresh the sinkpoint lifecycle so
            # the input-generator has a concrete work order. Advisory only —
            # never fails the round.
            try:
                summary["frontier"] = _run_frontier(
                    engine_state=engine_state,
                    run_id=active_run_id,
                    root=root,
                    name=name,
                    fuzzer=fuzzer,
                    corpus=corpus,
                    work_dir=work_dir,
                    round_index=index,
                    environment=environment,
                )
                top_methods = [item.get("method") for item in summary["frontier"].get("top_uncovered", [])[:3]]
                frontier_evidence = f"round {index}: frontier top_uncovered={top_methods}"
                last_sink_changes = int(summary["frontier"].get("status_changes") or 0)
            except Exception as exc:
                summary["frontier"] = {"blocker": str(exc)}

        evidence = [
            f"round {index}: fuzz ok={fuzz.get('ok')} crashes={summary['fuzz']['crash_files']}",
            f"round {index}: symcc {summary['symcc_sync']}",
            f"round {index}: findings={findings} new_roots={len(new_root_sigs)} "
            f"suppressed={summary['intake']['known_suppressed']} dedupe_groups={summary['dedupe_groups']}",
            f"round {index}: plateau={summary['plateau']['verdict']}",
        ]
        if frontier_evidence:
            evidence.append(frontier_evidence)
        engine.call_tool(
            "campaign_checkpoint_record",
            {
                "run_id": active_run_id,
                "target": target,
                "harness": name,
                "phase": "fuzzing" if not findings else "grading",
                "agent": "fuzz-finder" if not findings else "crash-grader",
                "tool_evidence": evidence,
                "blockers": [],
                "next_command": "campaign-round-run" if index < round_budget else "campaign-report",
            },
        )
        # Only a NEW root cause advances the candidate; rediscoveries of a
        # known signature must not keep re-confirming (deprioritize-on-PoV).
        if new_root_sigs:
            ledger_transition(root, name=name, status="confirmed", round_index=index,
                              note=f"{findings} finding(s), {len(new_root_sigs)} new root signature(s)")
        if plateaued:
            note = str(target_assessment.get("verdict"))
            top_frontier = (summary.get("frontier") or {}).get("top_uncovered") or []
            if top_frontier:
                note += " frontier: " + ",".join(str(item.get("method")) for item in top_frontier[:3])
            ledger_transition(
                root, name=name, status="plateaued", round_index=index,
                note=note,
                skip_if_in={"confirmed", "dead"},
            )

        directed_policy = policy.get("directed", {}) if isinstance(policy.get("directed"), dict) else {}
        if directed_policy.get("enabled", True):
            # Scheduler time advances every round: the active directed task
            # burns budget and rotates out when exhausted; a queued task is
            # promoted when nothing is active. Advisory bookkeeping only.
            try:
                from .directed import tick_budget

                tick = tick_budget(root=root, name=name, round_index=index, policy=directed_policy)
                if tick["changes"]:
                    summary.setdefault("directed", {})["tick"] = tick["changes"]
                    if engine_state is not None:
                        engine_state.event_append(
                            active_run_id,
                            "directed_task_changed",
                            {"round": index, "changes": tick["changes"][:20]},
                        )
            except Exception as exc:
                summary.setdefault("directed", {})["blocker"] = f"directed tick failed: {exc}"

        gc_every = int(load_policy(root, env=environment).get("gc", {}).get("gc_every", 5))
        if gc_every > 0 and index % gc_every == 0:
            from .gc import run_campaign_gc

            gc_result = run_campaign_gc(
                workspace_root=root,
                target=name,
                data_root=getattr(getattr(engine, "state", None), "data_root", None),
                env=environment,
            )
            summary["gc"] = {
                "bytes_freed": gc_result["bytes_freed"],
                "runs_pruned": gc_result["runs_pruned"]["removed"],
                "known_inputs_pruned": gc_result["known_inputs_pruned"]["removed"],
                "blockers": gc_result["blockers"],
            }
            # Post-merge corpus residency per generator script: which seedgen
            # families survived GC is the signal the input-generator agent
            # reads before authoring the next script.
            try:
                from .seedgen import measure_seedgen_effectiveness

                effectiveness = measure_seedgen_effectiveness(target=name, workspace_root=root, env=environment)
                summary["seedgen_effectiveness"] = {
                    "scripts": len(effectiveness["scripts"]),
                    "surviving_total": effectiveness["surviving_total"],
                }
            except Exception as exc:  # never fail a round on bookkeeping
                summary["seedgen_effectiveness"] = {"blocker": str(exc)}
            try:
                from .symcc_crossover import measure_crossover_effectiveness

                summary["symx_effectiveness"] = measure_crossover_effectiveness(
                    work_dir=work_dir, corpus=corpus
                )
            except Exception as exc:  # never fail a round on bookkeeping
                summary["symx_effectiveness"] = {"blocker": str(exc)}
        round_summaries.append(summary)

    return _summary(
        active_run_id,
        target,
        rounds_done=round_summaries,
        corpus=corpus,
        blockers=blockers,
        staleness=staleness,
        seeds_imported=seeds_imported,
    )


def _run_frontier(
    *,
    engine_state: Any,
    run_id: str,
    root: Path,
    name: str,
    fuzzer: Path,
    corpus: Path,
    work_dir: Path,
    round_index: int,
    environment: dict[str, str],
) -> dict[str, Any]:
    """Plateau-time frontier pass: sink-coverage replay -> sinkpoint status
    update (with bounded close-seed sampling) -> events + summary block.

    Imports are lazy: sink_coverage imports default_asan_options from this
    module, so a top-level import would be circular.
    """
    from .sink_coverage import sink_coverage
    from .sink_status import frontier_summary, sample_close_seeds, update_sink_status

    policy = load_policy(root, env=environment)
    frontier_policy = policy.get("frontier", {}) if isinstance(policy.get("frontier"), dict) else {}
    coverage_timeout = float(frontier_policy.get("coverage_timeout", 120))
    top = int(frontier_policy.get("top", 5))

    # Sinks JSONL resolution: per-target fuzz.json override first (workspaces
    # keep per-vector sink files), then policy, then the sink-scan default.
    sinks_jsonl = str(resolve_sinks_jsonl(root, name, policy))

    report = sink_coverage(
        target=name,
        sinks_jsonl=sinks_jsonl,
        workspace_root=root,
        timeout_seconds=coverage_timeout,
        max_inputs=int(frontier_policy.get("coverage_max_inputs", 512)),
        env=environment,
    )
    if not report.get("ok"):
        return {"blockers": report.get("blockers", []), "top_uncovered": []}

    def _sampler(methods: list[str]) -> dict[str, list[str]]:
        return sample_close_seeds(
            fuzzer=fuzzer,
            corpus=corpus,
            methods=methods,
            env=environment,
            max_inputs=int(frontier_policy.get("close_seed_max_inputs", 16)),
            max_seconds=float(frontier_policy.get("close_seed_max_seconds", 120)),
        )

    findings = engine_state.finding_list(run_id) if engine_state is not None else []
    status = update_sink_status(
        work_dir=work_dir,
        coverage_report=report,
        findings=findings,
        round_index=round_index,
        close_seed_sampler=_sampler,
    )
    if status["changes"] and engine_state is not None:
        engine_state.event_append(
            run_id,
            "sink_status_changed",
            {"round": round_index, "changes": status["changes"][:50], "counts": status["counts"]},
        )

    directed_policy = policy.get("directed", {}) if isinstance(policy.get("directed"), dict) else {}
    directed_block: dict[str, Any] | None = None
    if directed_policy.get("enabled", True):
        # The frontier just refreshed sink-status.json — reconcile the
        # directed task queue against it while both views agree.
        from .directed import sync_queue

        try:
            directed_block = sync_queue(
                root=root,
                name=name,
                round_index=round_index,
                policy=directed_policy,
                sinks_jsonl=sinks_jsonl,
            )
            if directed_block.get("changes") and engine_state is not None:
                engine_state.event_append(
                    run_id,
                    "directed_task_changed",
                    {"round": round_index, "changes": directed_block["changes"][:20]},
                )
        except Exception as exc:  # scheduling is advisory, never blocks
            directed_block = {"blockers": [f"directed sync failed: {exc}"]}

    return {
        **({"directed": directed_block} if directed_block is not None else {}),
        "sinks_total": report.get("sinks_total"),
        "sinks_covered": report.get("sinks_covered"),
        "sinks_uncovered": report.get("sinks_uncovered"),
        "top_uncovered": frontier_summary(report, top=top),
        "status_changes": len(status["changes"]),
        "status_counts": status["counts"],
        "reports": {"coverage": report.get("report"), "status": status["report"]},
    }


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
    staleness: dict[str, Any] | None = None,
    seeds_imported: int = 0,
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
        "seeds_imported": seeds_imported,
        "findings_recorded": total_findings,
        "staleness": staleness,
        "blockers": blockers,
    }

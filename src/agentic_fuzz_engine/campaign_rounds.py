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
import secrets
import stat
import time
from contextvars import ContextVar
from functools import wraps
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
from .managed_persistence import MAX_RECORD_BYTES, append_jsonl, validate_target_slug
from .runtime_backends import (
    MAX_KLEE_SEED_BYTES,
    MAX_KLEE_TOTAL_SEED_BYTES,
    MIN_FREE_DISK_GB,
    check_disk_headroom,
)
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
MAX_KLEE_SEED_DIRECTORY_ENTRIES = MAX_KLEE_SEED_MERGE

_ACTIVE_ROUND_GUARDS: ContextVar[list["_RoundTelemetryGuard"] | None] = ContextVar(
    "active_campaign_round_guards", default=None
)


def _clean_telemetry_reason(reason: Any) -> str | None:
    if reason in (None, ""):
        return None
    return " ".join(str(reason).split())[:500]


class _RoundTelemetryGuard:
    def __init__(
        self,
        *,
        root: Path,
        name: str,
        run_id: str,
        summary: dict[str, Any],
        fuzz_budget_seconds: float,
    ) -> None:
        self.root = root
        self.name = validate_target_slug(name)
        self.run_id = run_id
        self.summary = summary
        try:
            budget = float(fuzz_budget_seconds)
        except (TypeError, ValueError, OverflowError):
            budget = 0.0
        self.fuzz_budget_seconds = budget if budget >= 0 and budget < float("inf") else 0.0
        self.started_ts = time.time()
        self.started_monotonic = time.monotonic()
        self.pending_outcome: str | None = None
        self.pending_reason: str | None = None
        self.finished = False

    def mark(self, outcome: str, reason: Any = None) -> None:
        if not self.finished:
            self.pending_outcome = outcome
            self.pending_reason = _clean_telemetry_reason(reason)

    def finish(self, outcome: str | None = None, reason: Any = None) -> None:
        if self.finished:
            return
        if outcome is not None:
            self.mark(outcome, reason)
        ended_ts = time.time()
        selected_outcome = self.pending_outcome or "aborted"
        selected_reason = self.pending_reason
        if selected_reason is None and selected_outcome != "completed":
            selected_reason = "campaign exited before round completion"
        self.summary["telemetry"] = {
            "lane": "fuzz",
            "started_ts": self.started_ts,
            "ended_ts": ended_ts,
            "duration_seconds": max(0.0, time.monotonic() - self.started_monotonic),
            "fuzz_budget_seconds": self.fuzz_budget_seconds,
            "scope": "full-round",
            "outcome": selected_outcome,
            "reason": selected_reason,
        }
        _append_round_metrics(
            self.root,
            name=self.name,
            run_id=self.run_id,
            summary=self.summary,
        )
        self.finished = True


def _telemetry_guarded(function: Any) -> Any:
    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        guards: list[_RoundTelemetryGuard] = []
        token = _ACTIVE_ROUND_GUARDS.set(guards)
        caught: BaseException | None = None
        try:
            return function(*args, **kwargs)
        except BaseException as exc:
            caught = exc
            for guard in guards:
                guard.mark("exception", f"{type(exc).__name__}: {exc}")
            raise
        finally:
            append_error: Exception | None = None
            for guard in guards:
                try:
                    guard.finish()
                except Exception as exc:
                    append_error = append_error or exc
            _ACTIVE_ROUND_GUARDS.reset(token)
            if caught is None and append_error is not None:
                raise append_error

    return wrapped


def default_asan_options(workspace_root: Path) -> str:
    options = "detect_leaks=0:allocator_may_return_null=1:symbolize=0"
    suppressions = workspace_root / "asan.supp"
    if suppressions.is_file():
        options += f":suppressions={suppressions}:print_suppressions=0"
    return options


@_telemetry_guarded
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
    name = validate_target_slug(project)
    target = f"localfuzz/c/{name}"

    fuzzer = root / "bin" / name / "fuzzer"
    symcc_bin = root / "bin" / name / "symcc_bin"
    corpus = root / "work" / name / "seeds"
    corpus.mkdir(parents=True, exist_ok=True)
    # Authored seeds live in targets/c/<name>/seeds, but libFuzzer only
    # mutates what is in the work corpus — sync them in content-addressed
    # at campaign start so a target never fuzzes scaffold samples while its
    # valid seeds sit unimported next to the harness.
    blockers: list[str] = []
    try:
        seeds_imported = _merge_seeds(
            root / "targets" / "c" / name / "seeds", corpus, prefix="authored"
        )
    except (OSError, ValueError) as exc:
        seeds_imported = 0
        blockers.append(f"unable to import authored seeds safely: {exc}")
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
        round_guard = _RoundTelemetryGuard(
            root=root,
            name=name,
            run_id=active_run_id,
            summary=summary,
            fuzz_budget_seconds=float(fuzz_seconds),
        )
        active_guards = _ACTIVE_ROUND_GUARDS.get()
        if active_guards is None:
            raise RuntimeError("round telemetry guard is unavailable")
        active_guards.append(round_guard)
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
            round_guard.finish("aborted", headroom["blocker"])
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
            backend_result = klee.get("result")
            extraction_value = (
                backend_result.get("extraction")
                if isinstance(backend_result, Mapping) else None
            )
            extraction = extraction_value if isinstance(extraction_value, Mapping) else {}
            merge_blockers: list[str] = []
            merged = 0
            safe_seeds_dir: Path | None = None
            seeds_written = extraction.get("seeds_written", 0)
            if type(seeds_written) is not int or seeds_written < 0:
                merge_blockers.append("KLEE extraction returned an invalid seeds_written count")
            elif klee.get("ok") is True and seeds_written > 0:
                seeds_value = extraction.get("seeds_dir")
                output_value = klee.get("output_dir")
                if not isinstance(seeds_value, str) or not seeds_value:
                    merge_blockers.append("KLEE extraction omitted its seed directory")
                elif not isinstance(output_value, str) or not output_value:
                    merge_blockers.append("KLEE worker omitted its output directory")
                else:
                    candidate = Path(seeds_value).expanduser()
                    expected = Path(output_value).expanduser() / "seeds"
                    if (
                        not candidate.is_absolute()
                        or not expected.is_absolute()
                        or candidate.absolute() != expected.absolute()
                    ):
                        merge_blockers.append("KLEE extraction seed directory does not match the worker output")
                    else:
                        try:
                            merged = _merge_seeds(
                                candidate, corpus, prefix="klee", missing_ok=False
                            )
                            safe_seeds_dir = candidate
                        except (OSError, ValueError) as exc:
                            merge_blockers.append(f"unable to import KLEE seeds safely: {exc}")
            klee_blockers = [
                str(item) for item in klee.get("blockers", []) if isinstance(item, str)
            ] + [
                str(item) for item in extraction.get("blockers", []) if isinstance(item, str)
            ] + merge_blockers
            summary["klee"] = {
                "ok": klee.get("ok") is True and not klee_blockers,
                "seeds_extracted": seeds_written if type(seeds_written) is int else 0,
                "errors_extracted": extraction.get("errors_written", 0),
                "seeds_merged": merged,
                "blockers": klee_blockers,
            }
            if safe_seeds_dir is not None:
                klee_seed_dirs.append(str(safe_seeds_dir))

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
        round_guard.finish("completed")
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


def _append_round_metrics(
    root: Path,
    *,
    name: str | None = None,
    run_id: str,
    summary: dict[str, Any],
) -> None:
    """Durable per-round metrics line — the plateau signal's source of truth."""
    if name is None:
        # Backward-compatible internal form used by focused lifecycle tests.
        path = Path(root)
        if path.name != "rounds.jsonl" or path.parent.parent.name != "work":
            raise ValueError("round metrics path must be work/<target>/rounds.jsonl")
        name = path.parent.name
        root = path.parents[2]
    name = validate_target_slug(name)
    record = {"run_id": run_id, **summary}
    try:
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError, OverflowError):
        encoded = b""
    if not encoded or len(encoded) > MAX_RECORD_BYTES:
        intake = summary.get("intake") if isinstance(summary.get("intake"), dict) else {}
        record = {
            "run_id": run_id,
            "round": summary.get("round"),
            "telemetry": summary.get("telemetry"),
            "corpus_size": summary.get("corpus_size"),
            "new_root_signatures": summary.get("new_root_signatures"),
            "intake": {"findings_recorded": intake.get("findings_recorded")},
            "metrics_truncated": True,
        }
    append_jsonl(root, Path("work") / name / "rounds.jsonl", record)


def _merge_seeds(
    seeds_dir: Path, corpus: Path, *, prefix: str, missing_ok: bool = True
) -> int:
    if not seeds_dir.is_absolute() or not corpus.is_absolute():
        raise ValueError("seed source and corpus must be absolute paths")
    seeds_dir = _normalize_platform_root_alias(seeds_dir)
    corpus = _normalize_platform_root_alias(corpus)
    try:
        source_path_info = seeds_dir.lstat()
    except FileNotFoundError:
        if missing_ok:
            return 0
        raise ValueError(f"seed source directory is missing: {seeds_dir}")
    if not stat.S_ISDIR(source_path_info.st_mode) or stat.S_ISLNK(source_path_info.st_mode):
        raise ValueError(f"seed source is not a regular directory: {seeds_dir}")
    try:
        corpus_path_info = corpus.lstat()
    except OSError as exc:
        raise ValueError(f"unable to inspect seed corpus directory: {corpus}") from exc
    if not stat.S_ISDIR(corpus_path_info.st_mode) or stat.S_ISLNK(corpus_path_info.st_mode):
        raise ValueError(f"seed corpus is not a regular directory: {corpus}")
    source_fd = _open_expected_directory(seeds_dir, source_path_info)
    try:
        corpus_fd = _open_expected_directory(corpus, corpus_path_info)
    except BaseException:
        os.close(source_fd)
        raise
    source_info = os.fstat(source_fd)
    corpus_info = os.fstat(corpus_fd)
    candidates: list[tuple[str, os.stat_result]] = []
    payloads: list[tuple[bytes, str]] = []
    merged = 0
    try:
        entries_seen = 0
        with os.scandir(source_fd) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > MAX_KLEE_SEED_DIRECTORY_ENTRIES:
                    raise ValueError(
                        f"seed directory exceeds {MAX_KLEE_SEED_DIRECTORY_ENTRIES} entries"
                    )
                info = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError(f"seed source contains a non-regular entry: {entry.name}")
                candidates.append((entry.name, info))
        if len(candidates) > MAX_KLEE_SEED_MERGE:
            raise ValueError(f"seed directory exceeds {MAX_KLEE_SEED_MERGE} regular files")

        total_bytes = 0
        for name, expected in sorted(candidates):
            if expected.st_size > MAX_KLEE_SEED_BYTES:
                raise ValueError(f"seed exceeds {MAX_KLEE_SEED_BYTES} bytes: {name}")
            if total_bytes + expected.st_size > MAX_KLEE_TOTAL_SEED_BYTES:
                raise ValueError(
                    f"seed directory exceeds {MAX_KLEE_TOTAL_SEED_BYTES} aggregate bytes"
                )
            payload = _read_seed_at(source_fd, name, expected)
            total_bytes += len(payload)
            payloads.append((payload, f"{prefix}-{sha256(payload).hexdigest()[:20]}"))
        _verify_open_directory(seeds_dir, source_fd, source_info)
        _verify_open_directory(corpus, corpus_fd, corpus_info)

        for payload, destination_name in payloads:
            if _publish_seed_at(corpus_fd, destination_name, payload):
                merged += 1
        _verify_open_directory(corpus, corpus_fd, corpus_info)
        os.fsync(corpus_fd)
        return merged
    finally:
        os.close(source_fd)
        os.close(corpus_fd)


def _normalize_platform_root_alias(path: Path) -> Path:
    """Normalize only the immutable macOS /tmp and /var root aliases."""
    absolute = path.absolute()
    if len(absolute.parts) < 2 or absolute.parts[1] not in {"tmp", "var"}:
        return absolute
    alias = Path(absolute.anchor) / absolute.parts[1]
    try:
        info = alias.lstat()
    except OSError:
        return absolute
    if not stat.S_ISLNK(info.st_mode):
        return absolute
    canonical = alias.resolve(strict=True)
    if canonical not in {Path("/private/tmp"), Path("/private/var")}:
        return absolute
    return canonical.joinpath(*absolute.parts[2:])


def _open_absolute_directory(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path.anchor or "/", flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_expected_directory(path: Path, expected: os.stat_result) -> int:
    try:
        descriptor = _open_absolute_directory(path)
    except OSError as exc:
        raise ValueError(f"unable to open seed directory safely: {path}") from exc
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or not _same_directory_identity(expected, opened):
        os.close(descriptor)
        raise ValueError(f"seed directory changed before opening: {path}")
    return descriptor


def _same_directory_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev, first.st_ino, stat.S_IFMT(first.st_mode)
    ) == (
        second.st_dev, second.st_ino, stat.S_IFMT(second.st_mode)
    )


def _same_seed_snapshot(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev, first.st_ino, first.st_mode, first.st_size,
        first.st_mtime_ns, first.st_ctime_ns,
    ) == (
        second.st_dev, second.st_ino, second.st_mode, second.st_size,
        second.st_mtime_ns, second.st_ctime_ns,
    )


def _read_seed_at(directory_fd: int, name: str, expected: os.stat_result) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        dir_fd=directory_fd,
    )
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_seed_snapshot(expected, opened):
            raise ValueError(f"seed changed before opening: {name}")
        remaining = opened.st_size
        payload = bytearray()
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise ValueError(f"seed shrank while reading: {name}")
            payload.extend(chunk)
            remaining -= len(chunk)
        if not _same_seed_snapshot(opened, os.fstat(descriptor)):
            raise ValueError(f"seed changed while reading: {name}")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _publish_seed_at(directory_fd: int, name: str, payload: bytes) -> bool:
    try:
        existing = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if not stat.S_ISREG(existing.st_mode) or _read_seed_at(directory_fd, name, existing) != payload:
            raise ValueError(f"unsafe or mismatched existing corpus entry: {name}")
        return False

    temporary = f".{name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=directory_fd,
    )
    try:
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short seed write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(
                temporary, name,
                src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            return True
        except FileExistsError:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(current.st_mode) or _read_seed_at(directory_fd, name, current) != payload:
                raise ValueError(f"raced corpus entry does not match its digest: {name}")
            return False
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _verify_open_directory(path: Path, descriptor: int, expected: os.stat_result) -> None:
    current = path.lstat()
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(current.st_mode)
        or not _same_directory_identity(expected, opened)
        or not _same_directory_identity(current, opened)
    ):
        raise ValueError(f"seed directory changed during import: {path}")


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

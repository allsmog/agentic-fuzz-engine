# Architecture

Agentic Fuzz Engine is split into three layers:

1. Claude Code plugin surface in `claude-plugin/agentic-fuzz-engine`
2. Local engine runtime exposed through `agentic_fuzz_engine`
3. Dependency-gated backend adapters for fuzzing, symbolic execution, reachability, and patch checks

The plugin exposes specialist agents, skills, friendly commands, a stdio MCP server, and hook/monitor metadata. The local runtime owns state, artifacts, checkpoints, finding grading, dedupe, reports, and backend invocation.

## Execution Model

Commands are explicit and local. The engine records blockers when required binaries, source paths, harness commands, or model runtime access are missing.

Readiness checks:

- `runtime-doctor`
- `runtime-backend-status`
- `parity-full --strict`

Worker commands:

- `fuzz-ensemble-run`
- `symbolic-worker-run`
- `sarif-reachability-run`
- `patch-environment-prepare`

## Crash Identity and Findings Integrity

Crash identity is two-layered (`crash_identity.py`). The per-finding signature (schema 2, `dedupe.py`) hashes the normalized `crash_state` — the top stack frames after dropping sanitizer-runtime, allocator, libc, and harness-driver frames — with libFuzzer `DEDUP_TOKEN`s taking priority when present. The cross-harness `root_signature` drops target/harness/token material entirely so one root cause reached from two harnesses shares a key. `finding_dedupe` groups by recomputed signatures at read time (stored rows are never rewritten; each keeps its `recorded_signature`) and then runs a fuzzy consolidation tier (ClusterFuzz thresholds: LCS >= 2 shared frames or average frame-similarity > 0.8) that merges groups split by inlining flap.

Verified findings are constructive: the `finding_record` tool rejects `verified=true` unless a matching engine-emitted verification event (`harness_run`, `finding_grade`, `crash_import`) exists for that PoV, and `event_append` refuses engine-reserved event types so the evidence cannot be forged. Recording therefore flows through the executing paths (`record_finding=true`), never through assertion.

## Campaign Round Intelligence

The round loop (`campaign_rounds.py`) carries three feedback mechanisms:

- **Known-crash suppression** (`known_crashes.py`): recorded root signatures land in `work/<target>/known-crashes.json`; later intake candidates are probed once (sidecar text or a single bounded replay) and known rediscoveries are quarantined to `work/<target>/known-crash-inputs/` instead of re-graded, while the fuzzer defaults into fork mode (`-fork=1 -ignore_crashes=1`) to explore past known bugs. Unparseable outputs fail open into normal grading. Rediscoveries do not re-confirm the candidate; only new root signatures do.
- **Frontier loop** (`sink_status.py`): on plateau, the round replays the corpus (sampled newest-first for slow-unit targets, `frontier.coverage_max_inputs`) against the sink inventory and maintains a per-sink lifecycle in `work/<target>/sink-status.json` — `unreached -> reached -> exploited`, never demoting — with `close_seeds` recorded for newly reached sinks as byte templates for the input-generator agent. `frontier` is the first plateau-ladder rung.
- **Rotate-target** (`campaign_metrics.py`): `plateau-status` counts trailing rounds whose crash activity was all-known signatures and recommends `rotate-target` past the policy threshold, moving budget to the next candidate instead of deepening exhausted holes.

Seed generation (`seedgen.py`) accepts two authored contracts — `generate(rnd) -> bytes` and `mutate(rnd, seed) -> bytes` (fed newest corpus entries) — and attributes surviving corpus residency per script in `work/<target>/seedgen-effectiveness.json` after GC merges.

## Safety Model

The plugin does not start background infrastructure by default. It uses bounded local subprocesses, explicit paths, and plugin-local artifact state. Mutating flows should remain gated by operator intent and command-specific confirmation.

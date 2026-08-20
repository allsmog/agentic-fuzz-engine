---
description: Run a self-contained, resource-guarded fuzzing campaign against a local C/C++ codebase (workspace verbs + plugin subagent orchestration).
argument-hint: <target-name> | init <source-dir> | status | fleet
disable-model-invocation: true
allowed-tools: [Bash, Read, Write, Edit, Agent]
---

# Workspace Campaign

Point the engine at a local C/C++ codebase and run bounded fuzz/symbolic rounds
with automatic plateau detection, a candidate lifecycle ledger, and corpus GC.
The deterministic engine executes; LLM work happens here or in THIS PLUGIN'S
subagents (`agentic-fuzz:*` types) — never detached LLM processes, never
ad-hoc agents outside the plugin. Agents AUTHOR artifacts (specs,
dictionaries, seed-generator scripts, harnesses); the engine EXECUTES them at
scale under resource guards.

Every command goes through the plugin launcher:

```bash
ENGINE="${CLAUDE_PLUGIN_ROOT}/scripts/run-engine.sh"
```

If a workspace already exists, `source <workspace>/env.sh` first (default
workspace: `~/.cache/agentic-fuzz`). `$ARGUMENTS` is a target name under
`targets/c/`, or `init <source-dir>` to create a workspace, or `status`, or
`fleet` for the whole-workspace end-to-end loop (section 6).

## 1. Workspace (one-time per codebase)

```bash
"$ENGINE" workspace-init --source <code-root> [--mount <host-dir>] [--workspace-root <dir>]
source <workspace>/env.sh
```

This writes the layout, DooD path maps, `campaign-policy.json` (bounds every
later step), and `env.sh`. Re-running preserves authored files and the policy.

## 2. Candidates and target creation

```bash
"$ENGINE" sink-scan --source-root <code-root>           # code -> sinks JSONL (no other input)
"$ENGINE" fork-scan --source-root <code-root> --vendor-marker <marker>
"$ENGINE" entry-scan --source-root <code-root> --lib-prefix <prefix>
"$ENGINE" candidates sync --sinks-jsonl <workspace>/data/sink-scan.jsonl
"$ENGINE" candidates list                               # budget view
"$ENGINE" target-generate <vector> --spec <workspace>/generators/<spec>.json \
    --sinks-jsonl <workspace>/data/sink-scan.jsonl --sink-tag <module> --validate
```

`sink-scan` deterministically inventories fuzzable entry points (Parse/Decode/
From*-shaped definitions taking a string or ptr+len) and dangerous call sites
(memcpy/exec*/...) attributed to their enclosing functions, tagged by module —
so the only required input is the source tree. A curated sinks JSONL (Joern,
manual) can replace or augment it via the same flag.

`fork-scan` and `entry-scan` add bounded package/build-consumer and candidate
input-boundary evidence. They do not prove that an input reaches a component;
keep their confidence and evidence fields attached when choosing a target.

Generators are spec-driven (type_enum / direct_call / symbolic_string). When a
vector cannot be generated deterministically, the engine emits
`targets/c/<t>/workorder.json` — author `harness.cpp` in-session from its sink
rows, then re-run `target-generate <t> --validate`. Authored files (anything
without the auto-generated marker) are never clobbered.

```bash
"$ENGINE" target-build <t>        # runs .localfuzz/build.json steps
```

## 2b. Subagent pipeline (plugin agents only)

For a new module, spawn this plugin's agents in sequence; each authors an
artifact the engine then executes:

1. `agentic-fuzz:planner` — reads the module's sink rows + entry sources,
   returns ranked vectors, harness shapes, and per-specialist next commands.
2. `agentic-fuzz:harness-builder` — authors `generators/<name>.json` via a
   bounded compile-and-fix loop; must end with `target-generate --validate`
   passing (or exact blockers).
3. In parallel after validation: `agentic-fuzz:dictionary-generator`
   (writes `targets/c/<t>/<t>.dict`, auto-attached next round) and
   `agentic-fuzz:input-generator` (authors
   `generators/seedgen/<t>.py` with `generate(rnd)->bytes`, then runs
   `"$ENGINE" seedgen-run <t> --script ... --count 256`).
4. After rounds: `agentic-fuzz:crash-grader` for any crash artifact;
   `agentic-fuzz:dedupe-judge` before reporting; `agentic-fuzz:reporter`
   for verified findings.

Give every spawn the workspace path, the exact target name, and the module's
source root. Agents never run detached processes and never edit product code.

## 3. Rounds (the loop)

```bash
"$ENGINE" campaign-round-run localfuzz/c/<t> --rounds <N>
```

Each round: libFuzzer (RSS/time-bounded) → bounded SymCC corpus sync →
periodic KLEE lane → ASAN replay intake → grade → dedupe → checkpoint →
`work/<t>/rounds.jsonl` metrics. Disk headroom is a hard guard; GC runs every
`gc_every` rounds. Unvalidated targets are refused.

Known-crash suppression: once a finding is recorded, its cross-harness
`root_signature` lands in `work/<t>/known-crashes.json`. Later rounds probe
each intake candidate once and quarantine known rediscoveries to
`work/<t>/known-crash-inputs/` (counted in `intake.known_suppressed` and a
`known_crash_suppressed` event) instead of re-grading them 3x — and the
fuzzer defaults into fork mode (`-fork=1 -ignore_crashes=1`) so it explores
past known crashes instead of exiting on the first one. Tradeoff: fork mode
changes libFuzzer stat lines (plateau falls back to corpus_size) and slightly
slows exec rate; disable per-target with `fuzz.json`
`"fork_on_known_crashes": false` or policy `round.fork_on_known_crashes`.

## 4. Signals and escalation (session decisions)

```bash
"$ENGINE" plateau-status          # verdicts + next-rung recommendation
"$ENGINE" candidates list
"$ENGINE" campaign-db sync        # derived, rebuildable campaign index
"$ENGINE" campaign-db report --report summary
"$ENGINE" candidate-scoring report
"$ENGINE" schedule-plan sync      # advisory only; disabled by default
"$ENGINE" schedule-plan list      # stale plans expose no usable ranks
```

Named campaign reports replace arbitrary database queries. Candidate scores
and schedule rows are operator advice only: neither can launch, gate, or
reprioritize jobs. Use `campaign-context sync --target <t>` when an agent needs
a bounded summary; workspace excerpts remain inside an explicit untrusted-data
boundary and the tool reports whether the summary is still fresh.

On plateau, the round loop automatically runs the frontier pass: sink-coverage
replay + sinkpoint lifecycle update (`work/<t>/sink-coverage.json`,
`work/<t>/sink-status.json` — per-sink unreached/reached/exploited with
`close_seeds` byte templates for reached-but-unexploited sinks). The round
summary and checkpoint carry the top uncovered write/exec sinks.

When a target plateaus, execute the recommended rung in-session or via the
matching plugin agent:
- `frontier` (first rung, before anything heavier): spawn
  `agentic-fuzz:input-generator` — it MUST read the two frontier JSONs and
  author generator families aimed at the top uncovered write/exec sinks,
  using `close_seeds` as mutate templates for reached-but-unexploited sinks
  (`seedgen-run --mode mutate`).
- `dictionary`: distill literals (concolic-plan output, source magic values)
  into `targets/c/<t>/<t>.dict` — auto-attached next round
  (`agentic-fuzz:dictionary-generator`).
- `structured-seeds`: author/refresh the `generate(rnd)->bytes` /
  `mutate(rnd, seed)->bytes` script and run
  `"$ENGINE" seedgen-run <t> --script <ws>/generators/seedgen/<t>.py`
  (`agentic-fuzz:input-generator`); hand-placed seeds in `work/<t>/seeds/`
  are the fallback.
- `klee-directed`: `"$ENGINE" klee-pack-gen <t>` then
  `"$ENGINE" symbolic-worker-run <id> --mode klee --klee-config gen-packs.ci.json`.
- `symcc-long`: `"$ENGINE" symbolic-corpus-sync <t> --max-seconds <long>`.
- `differential`: compare explicit implementations with repeatable JSON argv
  arrays through `differential-run`; treat differences as triage candidates.
- `sanitizer-variant`: use `sanitizer-build <t> msan|tsan`, then the matching
  `sanitizer-sweep`; a clean bounded sweep is not evidence of absence.
- `rotate-target`: when `plateau-status` reports
  `recommendation: rotate-target` (N trailing rounds where every crash mapped
  to a known root signature — `known_only_rounds`), stop deepening this
  target: mark it `escalated:rotate-target` or `dead` and move the round
  budget to the next candidate in `candidates list`.

Record outcomes: `"$ENGINE" candidates update <t> --status escalated:<rung>|dead --note <why>`.

## 5. Housekeeping and reporting

```bash
"$ENGINE" campaign-gc             # resumable corpus minimize + run retention
"$ENGINE" campaign-report <run_id> ...   # findings write-up from dedupe reps
```

## 6. Fleet mode (end-to-end, whole workspace)

`fleet` runs the full lifecycle across every candidate until the budget the
caller sets is spent. Each numbered step runs inline in this session or via
the matching plugin subagent — never a detached LLM process either way:

1. **Fleet pass** (`agentic-fuzz:planner`, workspace scope): plateau-status
   across all targets + `candidates list` + the workorder backlog
   (`targets/c/*/workorder.json`) + directed-queue health → a fleet table
   of target → verdict, next rung, allotted rounds, owning specialist.
2. **Backlog drain**: for each scheduled unharnessed vector, run the 2b
   pipeline (planner → harness-builder → dictionary-generator +
   input-generator including the codec contract) until
   `target-generate --validate` passes; workorders that stall get exact
   blockers recorded in the candidates ledger, not silence.
3. **Rounds**: `campaign-round-run` per target under its allotted budget.
   Enable `weights` in the target's `fuzz.json` once a corpus exists; author
   `bits.json` (planner) when the sink map says where to aim — batch bits
   edits, since every universe change invalidates the seed-cov index.
4. **Escalations as they surface**, all agent-executable: `frontier` and
   `structured-seeds` (input-generator, iterating to the COVERED_FUNC
   flip), `dictionary`, `klee-directed`/`symcc-long`, the solver-stuck
   fallback (concolic-generator hand-solves guarded branches), and
   `directed-allowlist` end-to-end — harness-builder authors the allowlist
   build, fuzz-finder runs it, crash-import intakes it.
5. **Triage every new root signature**: crash-grader (including
   variant/fork parity replay when the target's build notes declare a
   parity driver) → dedupe-judge → reporter.
6. Loop back to 1 while budget remains; `rotate-target` verdicts release
   budget to the next candidate automatically.

The loop's invariants: the engine executes everything at scale under
resource guards; agents only author artifacts and read ledgers; every
finding that reaches a report has engine-observed verification.

## Hard rules

- Never exceed policy bounds; never launch detached processes. A marathon is
  `campaign-round-run --rounds N` in one foreground (or nohup'd) invocation.
- Findings require reproducible sanitizer evidence; dedupe before reporting.
- `status` argument = `plateau-status` + `candidates list` + disk headroom.

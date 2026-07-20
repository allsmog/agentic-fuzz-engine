# Design: closing the campaign-audit gaps

Status: IMPLEMENTED 2026-07-16 (uncommitted, like all work on this branch).
All ten items landed: G1 findings_index.py + gc archive, G2 reachability.py
+ report gate, G3 flag_profiles.py + impact flag-matrix, G4 directed_build
+ round split + queue hygiene, G5 impact.py + primitive field, G6
boundaries.py + boundary ranking, G7 staleness.py + build manifests, G8
sequence generator in harness_gen.py, G9 spec_probe.py, G10 workspace
adoption (weights on, boundaries/services/flags authored, fuzzer-ubsan
steps added to 10 targets, pkgstore exemplar rebuilt). 247 tests green;
end-to-end verified on the live workspace via archive-reimport
(crash-import → index mirror → primitive stamp → auto-impact).
Scope: nine engine work items (G1–G9) plus one adoption sweep (G10),
derived from a source-level audit of the engine after a full C/C++
campaign. Each item states the problem evidence, the design, data model,
CLI/MCP surface, guardrails, tests, and size. Implementation order and
dependencies are at the end.

Design principles carried through every item:

- **Deterministic engine, judgment at the edges.** New verbs compute and
  record evidence; verdicts that require judgment (entry-class maps,
  reachability review, escalation leads) are *inputs or outputs* of agent
  work, never hidden heuristics pretending to be truth.
- **Everything bounded.** Every subprocess gets a timeout; every scan gets
  file/byte caps; every loop gets an iteration cap; disk operations check
  headroom (`check_disk_headroom`) and are containment-checked.
- **Additive schemas.** New fields on findings/rows are optional blocks;
  old records stay readable. Policy keys get defaults in
  `workspace.DEFAULT_POLICY` so absent config never crashes.
- **No new execution surfaces.** In-process Python (importlib) or
  existing runner plumbing (`_run_command`) only; no `python3 file.py`
  spawn pattern, no network.

---

## G1. Durable findings index + evidence archive before GC

**Problem.** `gc.py::_prune_oldest` deletes run dirs wholesale on the
keep-N-newest rule. Findings, reports, and checkpoints live *only* inside
run dirs, so a burst of new runs (e.g. a second session sharing the
workspace) silently evicts the ledgers of completed campaigns. Observed
in production use: four named recon runs lost their ledgers within hours.

**Design.** Two pieces — a global index that makes run dirs disposable,
and an archive step that preserves the small durable core of a run before
pruning.

### 1a. Global findings index (`findings_index.py`, new)

Append-only JSONL at `data/findings-index.jsonl`. One row per finding
*event* (recorded, verified, classified, deduped, graded), written at the
same moment the per-run ledger is written:

```json
{"ts": "...", "run_id": "...", "finding_id": "finding-...",
 "event": "recorded|verified|classified|deduped|graded",
 "target": "...", "harness": "...", "sanitizer": "asan",
 "error_token": "heap-buffer-overflow", "root_signature": "...",
 "poc_artifact": "...", "poc_sha256": "...", "detail": {...}}
```

- Writer: one function `append_index_event(data_root, row)` called from
  `engine.finding_record`, crash intake, `finding_grade`,
  `finding_classify`, and `finding_dedupe`. Atomic append (single
  `write` of one line, `O_APPEND`).
- Reader: `load_index(data_root, *, run_id=None, target=None,
  finding_id=None)` returning latest-state-per-finding (fold events).
- New CLI/MCP verb `findings-index` (list/query) — read-only.
- `finding-dedupe` and `campaign-report` gain `--across-runs`: fold index
  rows for a *target* rather than one run, so dedupe/report survive run
  pruning and naturally deduplicate across the campaign, not per-run.

### 1b. Archive-before-prune (extend `gc.py`)

`_prune_oldest` for the runs root is replaced by
`_prune_runs_with_archive(runs_root, keep, archive_root, max_mb)`:

1. For each run dir slated for deletion, copy the durable core into
   `data/archive/runs/<run_id>/`: `campaign.json`, `findings.jsonl`,
   `checkpoints.jsonl`, `events.jsonl` (tail-capped, policy
   `gc.archive_events_tail_kb` default 256), every artifact whose name
   matches `*report*`, `*REPORT*`, or is referenced as `poc_artifact` by
   a finding row.
2. Enforce a per-run byte cap (`gc.archive_max_mb`, default 64): PoVs
   first (they are tiny), then ledgers, then reports, then events tail;
   items over the cap are skipped with a note in the archive manifest.
3. Write `manifest.json` (file list + sha256 + skipped list), then delete
   the run dir via the existing containment-checked rmtree.
4. Archive dirs themselves are retention-pruned (keep
   `gc.archive_retention`, default 100) — they are ~KBs each.

KLEE-out pruning keeps the plain `_prune_oldest` (no ledgers inside).

**Guardrails.** Copy phase never follows symlinks (`shutil.copy2` on
`is_file()` checks); archive root containment-checked like all deletes.

**Tests** (`test_gc_archive.py`, `test_findings_index.py`): synth run
dirs with findings + oversized events; assert archive content, cap
behavior, manifest, and that `findings-index --target X` returns rows
after the run dir is gone.

**Size.** ~140 LOC gc + ~160 LOC index + tests.

---

## G2. Reachability evidence block + report tiering gate

**Problem.** Nothing between "verified crash" and "report" represents
*who can reach the crashing entry in production*. A campaign shipped a
P0-candidate whose entry op had no production caller and whose vulnerable
path was behind a non-default flag — facts that were statically
checkable. `sarif-reachability-run` exists but nothing consumes it.

**Design.** A `reachability` block attached to findings, a verb that
assembles it from three bounded evidence sources, and a report-time gate
that enforces its *presence* (not its truth — truth stays with the
operator/agent review).

### Data model

Attached to the finding record and mirrored to the findings index:

```json
"reachability": {
  "verdict": "reachable|flag-gated|no-production-caller|local-only|unknown",
  "entry_symbol": "Service::HandleOp",
  "production_callers": [{"symbol": "...", "file": "...", "line": 123,
                          "via": "rg|joern|declared"}],
  "flag_gates": [{"flag": "use_feature_x", "default": "true",
                  "required_value": "false", "file": "...", "line": 456}],
  "bind_surface": "remote|internal|localhost|unknown",
  "notes": "...", "checked_ts": "..."
}
```

`verdict` is chosen by the caller of the verb (agent/operator) from the
gathered evidence; the verb defaults it conservatively (`unknown` if any
source came back empty).

### Verb `finding-reachability`

`finding-reachability <run_id> <finding_id> --entry-symbol SYM
[--source-dir D] [--verdict V] [--note ...]`

Evidence sources, all bounded:

1. **Caller scan (always).** Reverse text-search over the source dir for
   call sites of `entry_symbol` (and its unqualified tail), bounded:
   `reachability.max_files` (default 20000 file-name candidates via rg
   glob prefilter), depth 1 by default, `--depth K` (≤3) to chase the
   found callers' enclosing functions upward using the same
   tree-sitter/regex function-extraction helpers `sink_scan.py` already
   has. Emits `production_callers` rows tagged `via: rg`.
2. **CPG query (optional).** If policy `reachability.joern_cpg` (or a
   CodeQL DB path) is set, shell through the existing
   `sarif_reachability_run` plumbing with a generated single-symbol
   query; results merge as `via: joern`. Timeout
   `reachability.cpg_timeout_seconds` (default 600).
3. **Flag-gate scan (always).** For each crash frame's file (from the
   stored ASAN output via `crash_identity.parse_crash_output`), scan the
   file (byte-capped) for `DEFINE_bool|int32|int64|string(...)` /
   `ABSL_FLAG(...)` definitions and `FLAGS_<name>` references inside
   `if`/ternary guards within ±40 lines of the frame line. Records the
   flag, its literal default, and the guarded line. Purely lexical —
   emits *candidates* for the reviewer, never a verdict.
4. **Declared service facts (optional).** `work/services.json`, authored
   once per codebase by the operator/agent:
   `{"services": [{"name": "...", "binds": "localhost", "flags":
   {"use_feature_x": "true"}}]}`. Anything matched from here is tagged
   `via: declared`. The engine never guesses runtime topology.

### Gate wiring

- `campaign-report`: each reported finding row gains
  `reachability_verdict`. New policy `report.require_reachability`
  (default `"warn"`, values `off|warn|block`): `warn` appends a blocker
  note; `block` fails `phase_coverage_ok` until every deduped
  representative has a block with verdict ≠ `unknown`.
- New checkpoint phase name `reachability` accepted by the phase audit.
- `finding_grade` unchanged (grading is about the PoV, not the caller).

**Tests.** Fixture tree with a caller, a flag guard, and a services.json;
assert block assembly, verdict defaulting, and report gating in all three
policy modes.

**Size.** ~320 LOC + tests. Depends on G1 (index mirror) but degrades
fine without it.

---

## G3. Runtime flag profiles + crash flag-matrix

**Problem.** Harnesses pin `FLAGS_*` values ad hoc with no record of
whether they match production defaults; a locally-proven primitive died
on a shipped flag default. The engine has no notion of runtime flags.

**Design.** Flag inventory scan → per-target profile file → harness
prelude that applies a profile → replay matrix on crashes.

### 3a. `flag-scan` verb (`flag_profiles.py`, new)

`flag-scan <target> [--source-dir D]` walks the target's source closure
(the union of `.localfuzz/build.json` sources + harness includes, capped
by `flags.max_files`/`max_file_bytes`) extracting gflags/absl flag
definitions: name, type, default literal, file:line. Output:
`work/<t>/flags-inventory.json`. Deterministic, lexical.

### 3b. Profile file `.localfuzz/flags.json` (per target, authored)

```json
{"profiles": {
   "production": {"use_feature_x": "true", "page_size": "65536"},
   "permissive": {"use_feature_x": "false", "page_size": "4096"}},
 "default_profile": "production",
 "provenance": "flags-inventory + operator review 2026-07-16"}
```

The *authoring* is agent/operator work (that is where judgment about
"what does production run" lives); the inventory makes it mechanical.

### 3c. Harness prelude (extend `scaffold.py` / `harness_gen.py`)

Generated harnesses gain a generated `flag_profile.inc` and a call in
`LLVMFuzzerInitialize`:

```c
// generated: applies .localfuzz/flags.json profile chosen by
// FUZZ_FLAG_PROFILE (default: default_profile)
apply_flag_profile();
```

Implementation writes direct `FLAGS_<name> = <value>;` assignments per
profile behind an env switch — no gflags parsing dependency at runtime.
Targets without `flags.json` generate a no-op prelude (fully backward
compatible).

### 3d. Crash flag-matrix (extend crash intake + `harness_run`)

- `campaign-round-run` fuzzes under the default profile only (matrix
  fuzzing doubles cost for little gain; the *matrix belongs on crashes*).
- Crash intake replays every verified PoV once per profile
  (`FUZZ_FLAG_PROFILE=<p>`), timeout per replay
  `flags.replay_timeout_seconds` (default 30), and records:

```json
"flag_matrix": {"production": "reproduces", "permissive": "reproduces|no-repro|error"}
```

- `campaign-report` surfaces `reproduces under production profile` per
  finding. A crash that only reproduces under a non-default profile is
  the exact early warning that was missed.

**Tests.** Toy target with one flag gating a crash; assert inventory,
prelude codegen, matrix rows, report column.

**Size.** ~360 LOC + tests.

---

## G4. Directed execution half (consume the queue)

**Problem.** `directed.py` is a complete scheduler (queue, budgets,
rotation, preemption) but *nothing executes tasks*: the "aiming half" is
recipe-level, no verb builds or runs a directed fuzzer, so tasks rotate
forever. Also: the queue does not consult candidate verdicts, so sinks
already ruled `dead` (false positives) re-queue indefinitely (observed).

**Design.**

### 4a. Directed build (`directed-build` verb, extends `target_build.py`)

For the active task of a target:

1. Write `work/<t>/directed/<sink-hash>/allowlist.txt` containing the
   sink row's file (`src:*<file>` clang allowlist syntax) plus optional
   extra files from `--also FILE` (agent-supplied neighborhood).
2. Rebuild the target's fuzzer with the *same* recipe steps plus
   `-fsanitize-coverage-allowlist=<allowlist>` appended to cflags, output
   `bin/<t>/fuzzer-directed-<sink-hash>`. This concentrates coverage
   feedback on the sink's file with stock clang/libFuzzer — no AFL++
   toolchain required. (`AFL_LLVM_ALLOWLIST` stays documented as the
   AFL++ ensemble recipe for targets already built that way.)
3. Record `{task_id, binary, allowlist_sha}` into the task's queue entry
   (`directed.py` gains an optional `binary` field).

### 4b. Round-loop split (extend `campaign_rounds.py`)

When (a) policy `directed.execute` is true (new, default true), (b) the
target has an `active` task with a built binary, and (c) the plateau
verdict last round was `plateaued*` — allocate
`directed.fraction` (default 0.25) of the round's fuzz seconds to the
directed binary, exactly like the existing focus-corpus split
(`prepare_focus_round` pattern): directed run writes new units into a
scratch dir, units link back into the main corpus under content-hash
names, crash artifacts flow through the ordinary intake. The task's
`rounds_used` ticks only on rounds where its binary actually ran.

### 4c. Queue ↔ candidates hygiene (fix in `directed.py::sync_queue`)

Before enqueueing, load the candidates ledger
(`campaign_metrics` loader) and skip any sink whose owning candidate has
status `dead`; on sync, transition open tasks whose candidate died to
`dropped` with note `candidate dead`. This kills the observed
false-positive requeue loop.

**Guardrails.** Directed builds go through the same bounded build runner
and disk-headroom checks; one directed binary per target retained
(previous ones deleted on new build, containment-checked).

**Tests** (`test_directed.py` extension + new `test_directed_build.py`):
allowlist emission, dead-candidate skip/drop, round-split accounting with
a stub fuzzer.

**Size.** ~260 LOC + tests.

---

## G5. Per-finding impact pass (write-escalation as a verb)

**Problem.** The engine promotes ASAN crashes and recommends coverage
rungs, but impact escalation (read→write, wrap analysis) is entirely
manual. `valgrind_replay.py` exists as an oracle but is not attached to
the finding lifecycle; UBSan exists only in new scaffolds.

**Design.** A `finding-impact` verb producing an `impact` block, run
automatically at intake when the needed binaries exist.

### Evidence sources

1. **Primitive field (free).** `crash_identity.parse_crash_output`
   already sees `READ of size N` / `WRITE of size N`; expose it:
   findings gain `primitive: read|write|abort|fpe|oom|unknown`. Dedupe
   groups inherit the strongest member primitive. (~20 LOC.)
2. **UBSan replay.** If `bin/<t>/fuzzer-ubsan` exists (new optional
   build step name recognized by `target-build`; scaffold already emits
   UBSan flags for new targets), replay the PoV under it and harvest
   `runtime error: ... overflow|implicit conversion` lines whose
   file:line lies within K frames of the crash stack → `ubsan_wraps`
   rows. Wraps on the crash path are the #1 read→write escalation
   signal.
3. **Valgrind replay.** Existing `valgrind_replay.py` on the PoV via the
   uninstrumented replay binary when present → `Invalid write` evidence
   (`write_evidence: valgrind-invalid-write`). This is the oracle that
   distinguishes "sanitizer said read" from "the real libc writes first".
4. **Static adjacency leads (lexical, advisory).** From the top
   non-blacklisted frame's file:line, scan ±`impact.lead_window` (default
   60) lines for dangerous write callees (reuse `sink_scan`'s dangerous
   call table) that share identifiers with the OOB expression's line.
   Emits `leads: [{file, line, callee, shared_idents}]` — explicitly
   labeled advisory, consumed by the agent, never auto-promoted.

### Block

```json
"impact": {"primitive": "read", "write_evidence": "none|asan-write|valgrind-invalid-write",
           "ubsan_wraps": [...], "leads": [...], "checked_ts": "..."}
```

### Wiring

- Crash intake auto-runs sources 1–3 when binaries exist, policy
  `impact.auto` (default true), per-replay timeout
  `impact.replay_timeout_seconds` (default 60).
- `campaign-report` orders findings write-evidence-first and prints the
  primitive column.
- Ladder note: `campaign_metrics` plateau recommendation, when residual
  findings are all read-class, appends "run finding-impact leads review"
  instead of only coverage rungs.

**Tests.** Stub binaries emitting canned ASAN/UBSan/valgrind output;
assert block assembly, auto-run gating, report ordering.

**Size.** ~300 LOC + tests.

---

## G6. Entry-class (trust-boundary) tagging and ranking

**Problem.** `sink_scan` tags rows only by module; ranking is
primitive-weight only. Campaign evidence: every live-validated finding
came from one entry class (attacker-storable bytes parsed by a privileged
service), but the queue ordering could not see that.

**Design.** An authored boundary map, stamped onto rows, multiplied into
ranking.

### Boundary map `work/boundaries.json` (authored once per codebase)

```json
{"classes": {"external-data": 5, "stored-data": 4, "peer-service": 3,
             "config": 2, "internal": 1},
 "globs": [
   {"glob": "pkgstore/**",   "class": "stored-data"},
   {"glob": "nas/smb/**",      "class": "peer-service"},
   {"glob": "search/**/block*","class": "external-data"}],
 "default_class": "internal"}
```

Authoring is judgment (agent/operator, from the threat model); the engine
just applies it deterministically.

### Changes

- `sink_scan.run_sink_scan`: if the map exists, stamp each row
  `entry_class` (first matching glob, `fnmatch` on the repo-relative
  path) and add `boundary_weight` to the per-module stats; module weight
  becomes `Σ primitive_weight × class_weight`.
- `target_select`: rank by the boundary-scaled weight; output gains
  per-class counts so "how much stored-data surface is unharnessed" is
  one command.
- Candidates ledger rows inherit `entry_class`; `candidates list` gains
  `--class` filter.
- Missing map ⇒ identical behavior to today (weight 1 for all).

**Tests.** Map fixture; assert stamping, ranking flip vs no-map, filter.

**Size.** ~130 LOC + tests.

---

## G7. Proactive target staleness detection

**Problem.** A stale binary (source moved on; undefined symbol at load)
was only caught when a GC merge failed. Rounds will happily fuzz a
binary that no longer matches its sources.

**Design.**

- `target-build` writes `bin/<t>/build-manifest.json`:
  `{built_ts, toolchain: clang --version line, inputs: {path: sha256}}`
  where inputs = build.json step sources + harness dir files + the
  generated flag prelude (G3). File set capped
  (`staleness.max_files` default 4000); over-cap ⇒ manifest notes
  `truncated: true` and staleness falls back to mtime-only.
- `staleness.py::check(root, name)`: mtime prefilter (only rehash files
  newer than `built_ts`), compare, return
  `{stale: bool, changed: [paths], missing_manifest: bool}`.
- Wiring: `campaign-round-run` preflight runs the check per policy
  `rounds.stale_policy`: `warn` (default — blocker note in the round
  summary, run proceeds), `block` (abort with blocker), `rebuild`
  (invoke `target-build`, then proceed; bounded by the ordinary build
  timeout). `campaign-gc` merge-skip message now cites the check result.
  `plateau-status` includes `stale: true` so recommendations aren't made
  off a dead binary.

**Tests.** Manifest write, touch-a-source detection, all three policies.

**Size.** ~150 LOC + tests.

---

## G8. `sequence` generator type (stateful/multi-op harnesses)

**Problem.** All three generators (`type_enum`, `direct_call`,
`symbolic_string`) are single-call-per-input. Bugs behind operation
sequences (open → mutate → read-back paths, multi-key stores) cannot be
expressed as a spec; the highest-value open lead of the last campaign
needs exactly this shape.

**Design.** A fourth generator in `harness_gen.py`.

### Spec

```json
{"type": "sequence",
 "context": {
   "type": "MyStoreCtx",
   "setup":   "MyStoreCtx ctx; if (!ctx.Init(tmpdir)) return 0;",
   "teardown":"ctx.Close();"},
 "ops": [
   {"name": "put",     "call": "ctx.Put(key, val);",
    "args": [{"name": "key", "kind": "bytes", "max": 64},
             {"name": "val", "kind": "bytes", "max": 4096}]},
   {"name": "get",     "call": "ctx.Get(key);",
    "args": [{"name": "key", "kind": "bytes", "max": 64}]},
   {"name": "reverse", "call": "ctx.Reverse();", "args": []}],
 "max_ops": 16,
 "headers": [...], "namespaces": [...]}
```

### Generated harness ("op-tape" format)

Input is a tape: repeated `[1 op byte][per-arg TLV: 2-byte LE len + bytes,
len clamped to arg max]`. The generated `LLVMFuzzerTestOneInput`:

1. Runs `setup` (fresh context per input — determinism beats speed here;
   a `"persistent": true` escape hatch reuses context across ops only,
   never across inputs).
2. Loops ≤ `max_ops`: read op byte mod len(ops), decode that op's args
   from the tape (short tape ⇒ zero-length args), invoke `call` inside
   the same status/exception tolerance wrapper the other generators emit.
3. Runs `teardown` unconditionally (RAII-style scope guard in the
   template so mid-sequence errors still clean up).

Codegen reuses the existing placeholder/`_write_generated`/compile-probe
machinery; validation is the same bounded compile as `direct_call`.

### Ecosystem fit

- The tape format is documented in the generated header comment so
  `seedgen` scripts and `grammar-infer` can author structured tapes
  (a seedgen script that emits `[put][key][val][reverse]` sequences is
  the intended companion).
- `dictionary-generate` runs unchanged (tokens land inside TLV args).
- Sink coverage / directed / weights all work untouched — they only see
  a fuzzer binary and a corpus.

**Tests.** Spec → codegen golden test; compile probe against a toy
context class; tape decoding edge cases (empty tape, truncated TLV,
op byte ≥ len(ops)).

**Size.** ~420 LOC + template + tests. Largest single item.

---

## G9. `spec-probe`: deterministic compile-and-fix for spec authoring

**Problem.** Harness/spec authoring is the campaign bottleneck: 64/81
candidates never got harnessed because each target costs a manual
compile-error → add-include/source/lib loop. That loop is ~80%
mechanical.

**Design.** A bounded fixpoint driver that grows a spec's build closure
from compiler errors, leaving only genuinely ambiguous residue to the
agent.

### Verb

`spec-probe <target> [--spec generators/<t>.json] [--max-iter 12]`

Loop (≤ `--max-iter`, per-compile timeout `spec_probe.compile_timeout`
default 300 s):

1. `target-generate --validate` (existing) → on success, stop: spec is
   buildable.
2. Parse the compile/link error stream into a taxonomy:
   - `fatal error: 'X.h' file not found` → search the scan root for
     `X.h` (rg filename match, capped); unique hit ⇒ add its dir to
     `include_dirs`; multiple ⇒ record ambiguity.
   - `undefined reference to 'sym'` / `undefined symbol: sym` →
     demangle-lite (strip template args), rg for `::name(` definition
     sites in `.cpp` under the scan root; unique ⇒ append to
     `link_sources`; known-symbol→syslib table (`spec_probe.symbol_libs`
     policy map, seeded with zlib/zstd/crypto/pthread patterns) ⇒ append
     to `link_libs`.
   - `use of undeclared identifier` inside the *generated* harness ⇒
     record as spec defect (wrong signature extraction) — agent residue.
   - anything else ⇒ agent residue.
3. Apply unique-resolution fixes directly to the spec file (JSON edit,
   preserving key order), append the decision to the probe ledger, and
   iterate.

### State: `work/<t>/probe-state.json`

```json
{"iterations": [{"n": 1, "errors": 14, "fixed": 9,
                 "added": {"include_dirs": [...], "link_sources": [...]}}],
 "residue": [{"kind": "ambiguous-header", "detail": "X.h: 3 candidates",
              "candidates": [...]}],
 "status": "buildable|residue|budget-exhausted"}
```

The harness-builder agent's job collapses to: resolve `residue` entries
(pick among candidates, fix a signature), re-run `spec-probe`. The error
taxonomy is exactly the one exercised by hand across the last campaign's
targets, so coverage of real cases is known-good from day one.

**Guardrails.** Spec edits are the only writes (plus probe state);
monotonic growth caps: `spec_probe.max_link_sources` (default 400),
`max_include_dirs` (64) — exceeding either ⇒ `budget-exhausted` with the
residue explaining why (prevents closure explosion on tangled trees).

**Tests.** Fixture mini-tree with a missing-header, an
undefined-reference, and an ambiguous case; assert fix application,
residue emission, idempotence when re-run on a buildable spec.

**Size.** ~450 LOC + tests. Highest expected yield per line for surface
coverage.

---

## G10. Adoption sweep (no new engine code)

1. **UBSan rebuilds**: add `-fsanitize=address,undefined
   -fno-sanitize-recover=undefined` (+ the optional `fuzzer-ubsan` step
   from G5) to the build.json of every pre-existing target; `target-build`
   each. Unlocks G5's wrap evidence for the whole fleet.
2. **`weights.enabled: true`** in the workspace policy: the BIT/focus
   tier is built, bounded, and advisory; there is no reason it should
   default off in an active campaign workspace. (Engine default stays
   `false` for fresh workspaces; this is a workspace policy edit.)
3. **Corpus harvest**: a workspace-side script (not engine) that copies
   real artifact files (store/patch/index containers) from a lab
   environment into a staging dir, then `corpus-import` with provenance
   notes. The engine side needs nothing new.
4. **Boundary map + services.json + flags.json authoring** for the
   existing campaign targets — the judgment inputs for G2/G3/G6.

---

## Implementation order & dependencies

| Phase | Items | Rationale |
|---|---|---|
| 1 | **G1** (index + archive), **G7** (staleness) | Stops active evidence loss; both self-contained. G1's index is a dependency-lite substrate the other items mirror into. |
| 2 | **G6** (boundary ranking), **G4** (directed exec + queue hygiene) | Re-aims the existing fleet at the right surface; G4c fixes a live scheduler bug. |
| 3 | **G5** (impact pass), **G2** (reachability gate) | The two lifecycle blocks; G5 first (pure local evidence), then G2 (adds the report gate — do it after G5 so tiering sees primitive+write evidence too). |
| 4 | **G3** (flag profiles) | Touches codegen; wants G2's block shape settled since flag_gates and flag_matrix are sibling evidence. |
| 5 | **G8** (sequence generator), **G9** (spec-probe) | The two big codegen items; G9 last so its error taxonomy also covers sequence-spec compiles. |
| — | **G10** | Interleaved: UBSan rebuilds right after G5 lands; policy/authoring anytime. |

Total: ~2.4k LOC engine + ~1.2k LOC tests, all uncommitted on this
branch per standing rule. Every phase leaves the engine releasable:
schemas additive, policies defaulted, verbs independent.

## Cross-cutting acceptance

- `pytest tests/` green after every phase.
- `engine-parity-audit` / `runtime-guard-audit` stay green (no external
  runtime references; new verbs registered in CLI + MCP tool tables in
  `engine.py`).
- A replayed mini-campaign on a fixture target exercises: stale detect →
  rebuild → rounds with directed split → crash → impact block → flag
  matrix → reachability block → across-runs dedupe → report with tier
  gate → GC with archive → `findings-index` still answers after prune.

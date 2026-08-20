# Agentic Fuzz Engine

<p align="center">
  <img src="docs/assets/agentic-fuzz-engine-mascot.png" alt="Agentic Fuzz Engine fuzzy robot mascot" width="420">
</p>

Agentic Fuzz Engine is a local-first agentic fuzzing framework and Claude Code plugin for security testing, vulnerability research, and automated fuzzing workflows. It coordinates specialist agents, MCP tools, benchmark fixtures, fuzzing backends, symbolic execution workers, SARIF reachability checks, and patch validation without requiring hosted infrastructure.

The project is designed for researchers and engineers who want a practical agentic security testing loop around C, C++, and JVM targets while keeping execution explicit, inspectable, and local.

## Distribution

This repository has two separately installed surfaces:

- The Python package provides the `agentic-fuzz-engine` CLI and the
  `agentic-fuzz-engine-mcp` stdio server. It is not currently published on
  PyPI; install it from this source checkout or build a wheel locally.
- The Claude Code plugin lives in `claude-plugin/agentic-fuzz-engine` and
  carries a vendored runtime so it can be installed independently of the
  Python package. The wheel does not contain the plugin.

## Keywords

agentic fuzzing, Claude Code plugin, MCP security tools, automated fuzzing, vulnerability research, security testing, libFuzzer, AFL++, LibAFL, SymCC, SymQEMU, Z3, CodeQL, Joern, SootUp, SARIF reachability, Jazzer, sanitizer triage, crash dedupe, patch validation

## Why Use It

Agentic Fuzz Engine gives Claude Code a structured fuzzing workspace instead of a loose prompt-only workflow. The plugin exposes agents, commands, skills, and MCP tools that keep each phase explicit:

- target discovery and harness inventory
- corpus import and dictionary generation
- grammar inference and concolic seed planning
- bounded fuzz campaign execution
- crash import, sanitizer parsing, minimization, grading, and dedupe
- SARIF reachability analysis through local tools
- patch candidate recording and temporary-copy validation
- durable campaign checkpoints, reports, and local export bundles

Missing dependencies are reported as blockers. The runtime does not silently pretend a backend ran.

## Project Status

This repository is an early local runtime and Claude Code plugin. It is useful for plugin development, agentic workflow experiments, benchmark fixture replay, and local fuzzing orchestration. Treat it as research tooling, not as a hosted service.

## Repository Layout

```text
.
├── claude-plugin/agentic-fuzz-engine/   # Claude Code plugin surface
│   ├── agents/                          # specialist agent prompts
│   ├── commands/                        # slash command definitions
│   ├── skills/                          # workflow instructions
│   ├── scripts/                         # plugin launch helpers
│   ├── monitors/                        # monitor metadata
│   ├── hooks/                           # hook metadata
│   └── .mcp.json                        # stdio MCP server config
├── src/agentic_fuzz_engine/             # local engine and MCP tools
├── src/agentic_fuzz_full/               # full-runtime readiness model
├── tests/                               # focused regression tests
├── configs/                             # policy and runtime configs
├── scripts/                             # repo-level helper scripts
├── tools/                               # tool wrappers and SootUp CLI source
├── docs/                                # docs and assets
├── ARCHITECTURE.md                      # architecture notes
├── Makefile                             # common developer tasks
├── pyproject.toml                       # Python package metadata
└── uv.lock                              # pinned dependency lockfile
```

## Core Capabilities

### Claude Code Plugin

The plugin contains ready-to-use command and agent definitions for Claude Code.
Common entry points include:

- `/agentic-fuzz:ready`
- `/agentic-fuzz:fuzz`
- `/agentic-fuzz:sym`
- `/agentic-fuzz:reach`
- `/agentic-fuzz:patch-env`
- `/agentic-fuzz:campaign-full`
- `/agentic-fuzz:runtime-doctor`
- `/agentic-fuzz:runtime-backend-status`

After cloning the repository, add its local marketplace and install the plugin:

```bash
claude plugin marketplace add ./claude-plugin
claude plugin install agentic-fuzz@agentic-fuzz-local
```

Run `claude plugin marketplace update agentic-fuzz-local` to refresh the
catalog after pulling a newer release. The complete command catalog is under
`claude-plugin/agentic-fuzz-engine/commands`. Plugin tools execute locally and
may invoke explicitly configured binaries or containers; optional checkout
tools and fidelity fixtures are not bundled with an installed plugin.

### MCP Tools

The stdio MCP server exposes tools for:

- readiness and parity checks
- target validation and discovery
- harness listing and bounded harness execution
- corpus, crash, and artifact management
- dictionary, grammar, and concolic planning
- bounded fork/package and candidate entry-point inventories
- fuzz campaign orchestration
- bounded differential replay and MemorySanitizer/ThreadSanitizer variant lanes
- crash grading, minimization, classification, and dedupe
- a derived campaign index, deterministic advisory scoring, and freshness-checked planning context
- SARIF reachability worker execution
- patch environment preparation and patch grading
- campaign reporting and local export bundles

### Local Runtime Backends

The runtime detects local tools and reports readiness:

- fuzzing: libFuzzer, AFL++, LibAFL-style workers
- symbolic execution: SymCC, SymQEMU, Z3
- reachability: CodeQL, Joern, SootUp
- JVM fuzzing: Jazzer
- patch validation: temporary source copies, rebuild checks, proof replay, and regression commands

## Quickstart

Clone the repository:

```bash
git clone https://github.com/allsmog/agentic-fuzz-engine.git
cd agentic-fuzz-engine
```

Agentic Fuzz Engine requires Python 3.11 or newer. Create or activate a Python
environment, then install the package in editable mode:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[runtime,test]'
```

Run the local readiness checks:

```bash
agentic-fuzz-engine runtime-doctor
agentic-fuzz-engine runtime-backend-status
agentic-fuzz-engine parity-full --strict
```

Run the test suite:

```bash
pytest -q
```

## Command Examples

List available subcommands:

```bash
agentic-fuzz-engine --help
```

Check real backend visibility:

```bash
agentic-fuzz-engine runtime-backend-status
```

Validate the plugin, command files, agents, skills, and prompt contract:

```bash
agentic-fuzz-engine parity-full --strict
```

Prepare a cached patch environment from a local source tree:

```bash
agentic-fuzz-engine patch-environment-prepare \
  --source-dir /path/to/source \
  --pool-root /tmp/agentic-fuzz-patches \
  --env-name bug-001
```

Run a bounded local fuzz ensemble when the required workers are installed:

```bash
agentic-fuzz-engine fuzz-ensemble-run \
  --work-dir /tmp/agentic-fuzz-work \
  --target localfuzz/c/example \
  --harness fuzz \
  --harness-command-json '["/path/to/fuzzer", "{seed_corpus}", "{crash_dir}"]' \
  --worker libfuzzer \
  --runs 2 \
  --timeout-seconds 30
```

## Workspace Campaign Loop

The engine can drive a fully self-contained campaign from a generated
dot-directory workspace (default `~/.cache/agentic-fuzz`, override with
`AGENTIC_FUZZ_WORKSPACE`). The workspace doubles as the reference root
(`benchmark/projects` + `targets/c` layout) and holds target skeletons,
build outputs, persistent corpora, and campaign state.

```bash
# one-time: create the workspace (DooD path maps, docker images, extra mounts, asset imports)
agentic-fuzz-engine workspace-init \
  --source-dir /path/to/source \
  --map /path/to/source=/outer/path/to/source \
  --mount /path/to/source=/workspace/source:ro \
  --copy /path/to/seeds=seed-import

# pick the next unharnessed sink vector, generate its skeleton, build it
agentic-fuzz-engine target-select --sinks-jsonl sinks.jsonl
agentic-fuzz-engine target-scaffold example-target --sinks-jsonl sinks.jsonl
agentic-fuzz-engine target-build localfuzz/c/example-target

# or generate targets automatically from a workspace generator spec:
#   type_enum        enumerate serializable types -> selector-dispatch harness
#   direct_call      signature-extract sink functions -> direct-call harness
#   symbolic_string  KLEE mini-harnesses + generated ci tier
# anything a generator cannot produce becomes .localfuzz/workorder.json for a
# human/LLM author; the same build+smoke loop then validates the authored file
# (authored files are never overwritten by regeneration).
agentic-fuzz-engine target-generate example-target \
  --spec /path/to/generator-spec.json \
  --sinks-jsonl sinks.jsonl \
  --validate
agentic-fuzz-engine target-generate --all \
  --spec /path/to/generator-spec.json \
  --sinks-jsonl sinks.jsonl \
  --max-targets 10

# bounded, resource-guarded campaign rounds (defaults from campaign-policy.json)
agentic-fuzz-engine campaign-round-run localfuzz/c/example-target \
  --rounds 4 \
  --klee-config tier.ci.json

# campaign indexing and operator-reviewed advice over many targets
agentic-fuzz-engine candidates sync --sinks-jsonl sinks.jsonl   # lifecycle ledger from the sink inventory
agentic-fuzz-engine campaign-db sync                            # rebuild the bounded derived index
agentic-fuzz-engine campaign-db report --report summary         # named reports only; no raw SQL
agentic-fuzz-engine candidate-scoring report                    # deterministic advisory scores
agentic-fuzz-engine schedule-plan sync                          # disabled by default; never dispatches work
agentic-fuzz-engine schedule-plan list                          # suppresses stale ranks
agentic-fuzz-engine campaign-context sync --target example-target
agentic-fuzz-engine plateau-status                              # per-target verdicts + next escalation rung
agentic-fuzz-engine candidates update example-target \
  --status escalated:dictionary \
  --note "dictionary escalation selected"
agentic-fuzz-engine klee-pack-gen example-target                # requires explicit KLEE policy/image config
agentic-fuzz-engine campaign-gc                                 # resumable corpus minimize + retention pruning
```

The discovery and alternate-runtime lanes are also available directly:

```bash
agentic-fuzz-engine fork-scan \
  --source-root /path/to/source \
  --vendor-marker third_party
agentic-fuzz-engine entry-scan \
  --source-root /path/to/source \
  --lib-prefix libexample
agentic-fuzz-engine differential-run example-target \
  --command-json '["/path/to/replay-a", "{input}"]' \
  --command-json '["/path/to/replay-b", "{input}"]'
agentic-fuzz-engine sanitizer-build example-target msan
agentic-fuzz-engine sanitizer-sweep example-target msan
```

Fork, entry-point, differential, and scoring output is candidate evidence,
not proof of reachability or a vulnerability verdict. Sanitizer sweeps are
bounded observations; a clean sweep does not establish that a defect is
absent. Schedule output is advisory, disabled by default, and never feeds the
job dispatcher automatically.

Rounds append durable metrics to `work/<target>/rounds.jsonl` (true libFuzzer
coverage/feature counts, parsed pre-clipping); `plateau-status` folds them
into `growing / plateaued / insufficient-data` verdicts and recommends the
next untried rung from the policy ladder. The ledger transitions
automatically (`fuzzing`, `plateaued`, `confirmed`); `escalated:<rung>` and
`dead` are operator decisions. Plateau and schedule output can recommend a
different allocation, but neither dispatches work automatically. GC runs every
N rounds: corpus minimization is resumable (`-merge_control_file`) and only
swaps atomically on clean completion.

Every lane is bounded and sequential: libFuzzer runs with an explicit RSS
limit and `-max_total_time`, the SymCC corpus sync runs one input at a time
under a `prlimit` address-space cap, and the KLEE lane runs inside a
container with `--memory`, `--pids-limit`, and `--cpus` limits. A
disk-headroom guard aborts work before a volume fills. Generated targets are
gated: `campaign-round-run` refuses a target whose `generate.json` has not
passed build+smoke validation.

## Agent Roles

The plugin breaks the workflow into specialist roles so a Claude Code session can delegate narrowly:

- `planner`: validates readiness and selects the next phase
- `harness-builder`: discovers build systems and runnable harnesses
- `native-harness`: coordinates bounded local C/C++ harness execution
- `input-generator`: creates dictionaries, grammar artifacts, and seed plans
- `dictionary-generator`: derives bounded dictionary candidates
- `grammar-reverser`: derives structured-input grammar candidates
- `concolic-generator`: plans branch-targeted symbolic inputs
- `fuzz-finder`: runs fuzzing loops and records crash evidence
- `vuln-hunter`: prioritizes evidence-backed vulnerability leads
- `pov-producer`: turns verified crash evidence into reproducible proofs
- `corpus-manager`: imports and promotes seeds, crashes, and artifacts
- `crash-grader`: grades sanitizer evidence and proof stability
- `dedupe-judge`: groups equivalent findings
- `sarif-agent`: runs reachability checks and reports conservative verdicts
- `patcher`: drafts and records patch candidates
- `patch-grader`: validates patches in temporary copies
- `artifact-manager`: packages reports and local export bundles
- `export-agent`: creates local mock receipts for completed work
- `monitor`: tracks blockers, phase coverage, and completion state
- `reporter`: writes campaign reports from verified findings

## Safety Model

Agentic Fuzz Engine is intentionally local and explicit:

- no background infrastructure starts by default
- long-running commands require operator-provided paths and command arguments
- mutating workflows operate on temporary copies unless a command states otherwise
- missing tools become blockers
- reports distinguish actual execution evidence from planned work
- local export bundles are stored as artifacts, not sent to a remote endpoint by default

Before running campaign work, use:

```bash
agentic-fuzz-engine runtime-doctor
agentic-fuzz-engine runtime-backend-status
```

## Benchmark Fixtures

The runtime can use local benchmark fixtures as fidelity inputs. By default it looks under:

```text
fixtures/reference
```

You can override the fixture root:

```bash
export AGENTIC_FUZZ_REFERENCE_ROOT=/path/to/fixtures
```

Expected fixture shape:

```text
fixtures/reference/
├── benchmark/projects/<project>/
│   ├── project.yaml
│   ├── sources/<commit>/src/
│   └── vulnerabilities/<fixture>/
│       ├── index.json
│       ├── proof.bin
│       └── patch.diff
└── targets/c/<project>/.localfuzz/config.yaml
```

## Development

Run formatting or linting tools of your choice, then run the focused tests:

```bash
pytest -q
```

Useful plugin checks:

```bash
agentic-fuzz-engine parity-full --strict
agentic-fuzz-engine runtime-doctor
agentic-fuzz-engine runtime-backend-status
```

## Suggested GitHub Topics

For repository discoverability, use topics like:

- `agentic-fuzzing`
- `fuzzing`
- `security-testing`
- `vulnerability-research`
- `claude-code`
- `mcp`
- `libfuzzer`
- `aflplusplus`
- `libafl`
- `symbolic-execution`
- `sarif`
- `codeql`
- `jazzer`

## FAQ

### Does this require hosted infrastructure?

No. The default workflow is local. External services are not required for readiness checks, fixture validation, local campaign state, or report generation. The optional remote replay helper connects only to the host, user, directory, and fixture root that you explicitly provide; it does not create machines, install packages, start services, or pull container images.

### Does it run real fuzzers?

It can run real local fuzzing workers when they are installed and explicitly requested. If a tool is missing, the runtime reports a blocker.

### Does it replace manual vulnerability research?

No. It provides an agentic workflow and durable artifacts around fuzzing, triage, and patch validation. Human review is still required before trusting a finding or patch.

### Is this only for Claude Code?

The plugin surface is built for Claude Code, but the Python runtime and CLI can be used directly.

## License

Licensed under the [Apache License 2.0](LICENSE).

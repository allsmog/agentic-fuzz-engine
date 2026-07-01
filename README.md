# Agentic Fuzz Engine

<p align="center">
  <img src="docs/assets/agentic-fuzz-engine-mascot.png" alt="Agentic Fuzz Engine fuzzy robot mascot" width="420">
</p>

Agentic Fuzz Engine is a local-first agentic fuzzing framework and Claude Code plugin for security testing, vulnerability research, and automated fuzzing workflows. It coordinates specialist agents, MCP tools, benchmark fixtures, fuzzing backends, symbolic execution workers, SARIF reachability checks, and patch validation without requiring hosted infrastructure.

The project is designed for researchers and engineers who want a practical agentic security testing loop around C, C++, and JVM targets while keeping execution explicit, inspectable, and local.

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
│   └── .mcp.json                        # stdio MCP server config
├── src/agentic_fuzz_engine/             # local engine and MCP tools
├── src/agentic_fuzz_full/               # full-runtime readiness model
├── tests/                               # focused regression tests
├── ARCHITECTURE.md                      # architecture notes
└── pyproject.toml                       # Python package metadata
```

## Core Capabilities

### Claude Code Plugin

The plugin contains ready-to-use command and agent definitions for Claude Code:

- `/agentic-fuzz:ready`
- `/agentic-fuzz:fuzz`
- `/agentic-fuzz:sym`
- `/agentic-fuzz:reach`
- `/agentic-fuzz:patch-env`

The plugin path is:

```bash
claude-plugin/agentic-fuzz-engine
```

If your Claude Code build supports local plugin directories, point it at that folder. The plugin also works through its local shell helpers without invoking Claude Code directly.

### MCP Tools

The stdio MCP server exposes tools for:

- readiness and parity checks
- target validation and discovery
- harness listing and bounded harness execution
- corpus, crash, and artifact management
- dictionary, grammar, and concolic planning
- fuzz campaign orchestration
- crash grading, minimization, classification, and dedupe
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

Create or activate a Python environment, then install the package in editable mode:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[runtime]'
```

Run the local readiness checks:

```bash
PYTHONPATH=src claude-plugin/agentic-fuzz-engine/scripts/run-engine.sh runtime-doctor
PYTHONPATH=src claude-plugin/agentic-fuzz-engine/scripts/run-engine.sh runtime-backend-status
PYTHONPATH=src claude-plugin/agentic-fuzz-engine/scripts/run-engine.sh parity-full --strict
```

Run the test suite:

```bash
PYTHONPATH=src python -m pytest -q
```

## Command Examples

List available MCP-style engine tools:

```bash
PYTHONPATH=src python -m agentic_fuzz_engine.cli list-tools
```

Check real backend visibility:

```bash
PYTHONPATH=src python -m agentic_fuzz_engine.cli runtime-backend-status
```

Validate the plugin, command files, agents, skills, and prompt contract:

```bash
PYTHONPATH=src python -m agentic_fuzz_engine.cli parity-full --strict
```

Prepare a cached patch environment from a local source tree:

```bash
PYTHONPATH=src python -m agentic_fuzz_engine.cli patch-environment-prepare \
  --source-dir /path/to/source \
  --pool-root /tmp/agentic-fuzz-patches \
  --env-name bug-001
```

Run a bounded local fuzz ensemble when the required workers are installed:

```bash
PYTHONPATH=src python -m agentic_fuzz_engine.cli fuzz-ensemble-run \
  --work-dir /tmp/agentic-fuzz-work \
  --target localfuzz/c/example \
  --harness fuzz \
  --harness-command-json '["/path/to/fuzzer", "{seed_corpus}", "{crash_dir}"]' \
  --worker libfuzzer \
  --runs 2 \
  --timeout-seconds 30
```

## Agent Roles

The plugin breaks the workflow into specialist roles so a Claude Code session can delegate narrowly:

- `planner`: validates readiness and selects the next phase
- `harness-builder`: discovers build systems and runnable harnesses
- `native-harness`: coordinates bounded local C/C++ harness execution
- `input-generator`: creates dictionaries, grammar artifacts, and seed plans
- `concolic-generator`: plans branch-targeted symbolic inputs
- `fuzz-finder`: runs fuzzing loops and records crash evidence
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
PYTHONPATH=src claude-plugin/agentic-fuzz-engine/scripts/run-engine.sh runtime-doctor
PYTHONPATH=src claude-plugin/agentic-fuzz-engine/scripts/run-engine.sh runtime-backend-status
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
PYTHONPATH=src python -m pytest -q
```

Useful plugin checks:

```bash
PYTHONPATH=src claude-plugin/agentic-fuzz-engine/scripts/run-engine.sh parity-full --strict
PYTHONPATH=src claude-plugin/agentic-fuzz-engine/scripts/run-engine.sh runtime-doctor
PYTHONPATH=src claude-plugin/agentic-fuzz-engine/scripts/run-engine.sh runtime-backend-status
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

No. The default workflow is local. External services are not required for readiness checks, fixture validation, local campaign state, or report generation.

### Does it run real fuzzers?

It can run real local fuzzing workers when they are installed and explicitly requested. If a tool is missing, the runtime reports a blocker.

### Does it replace manual vulnerability research?

No. It provides an agentic workflow and durable artifacts around fuzzing, triage, and patch validation. Human review is still required before trusting a finding or patch.

### Is this only for Claude Code?

The plugin surface is built for Claude Code, but the Python runtime and CLI can be used directly.

## License

No license file is included yet. Add a license before encouraging external reuse or contributions.

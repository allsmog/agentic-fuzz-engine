from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from .guardrails import audit_runtime_guard_runtime_calls


@dataclass(frozen=True, slots=True)
class ParityRequirement:
    name: str
    description: str
    tools: tuple[str, ...] = ()
    agents: tuple[str, ...] = ()
    skills: tuple[str, ...] = ()
    engine_files: tuple[str, ...] = ()
    plugin_files: tuple[str, ...] = ()
    prompt_terms: tuple[str, ...] = ()


ENGINE_PARITY_REQUIREMENTS: tuple[ParityRequirement, ...] = (
    ParityRequirement(
        name="claude_code_plugin_surface",
        description="Claude Code loads the workflow as a plugin with stdio MCP tools, skills, agents, hooks, and monitors.",
        plugin_files=(
            ".claude-plugin/plugin.json",
            ".mcp.json",
            "scripts/mcp-server.sh",
            "scripts/run-engine.sh",
            "hooks/hooks.json",
            "monitors/monitors.json",
        ),
        skills=("campaign", "doctor", "status"),
        prompt_terms=("inside Claude Code", "plugin-local state", "MCP tools"),
    ),
    ParityRequirement(
        name="fixture_fidelity",
        description="Benchmark fixtures are treated as read-only oracles for target, harness, sanitizer, proof, and patch evidence.",
        tools=("fidelity_list_fixtures", "fidelity_validate_fixtures", "fidelity_replay_campaign"),
        agents=("planner.md", "corpus-manager.md", "crash-grader.md"),
        skills=("fidelity-audit", "campaign"),
        engine_files=("fidelity.py", "grading.py"),
        prompt_terms=("benchmark fixtures", "read-only fidelity fixtures", "proof sha256", "benchmark patch sha256", "patch changed paths", "fidelity_replay_campaign"),
    ),
    ParityRequirement(
        name="target_discovery_and_build",
        description="The engine discovers target metadata, harness inventory, build systems, seeds, dictionaries, and campaign-local build probes.",
        tools=("target_describe", "target_discover", "target_build_probe", "target_validate", "harness_list"),
        agents=("planner.md", "harness-builder.md"),
        skills=("init-target", "campaign"),
        engine_files=("discovery.py", "build_probe.py"),
        prompt_terms=("target_discover", "target_build_probe", "campaign-local build probe", "runnable harness commands"),
    ),
    ParityRequirement(
        name="campaign_state_and_artifacts",
        description="Campaign state, phase checkpoints, phase coverage audits, event logs, artifacts, findings, and operational status are persisted plugin-locally.",
        tools=("campaign_start", "campaign_status", "campaign_phase_audit", "campaign_checkpoint_record", "campaign_checkpoint_list", "event_append", "artifact_put", "artifact_get", "artifact_list"),
        agents=("monitor.md", "reporter.md", "corpus-manager.md"),
        skills=("campaign", "status", "report"),
        engine_files=("state.py", "checkpoints.py", "phase_audit.py"),
        prompt_terms=("plugin-local campaign state", "campaign-status", "campaign_phase_audit", "campaign-phase-audit", "checkpoint ledger", "phase coverage", "required phases", "latest events"),
    ),
    ParityRequirement(
        name="corpus_and_dictionary",
        description="Seed corpora and fuzz dictionaries can be imported or generated from source with provenance.",
        tools=("corpus_import", "dictionary_generate"),
        agents=("corpus-manager.md", "dictionary-generator.md"),
        skills=("campaign",),
        engine_files=("corpus.py", "dictionary.py"),
        prompt_terms=("corpus_import", "seed_artifacts", "dictionary_tokens", "dictionary_generate"),
    ),
    ParityRequirement(
        name="grammar_and_concolic",
        description="Parser grammar, branch-target seed planning, and real local symbolic workers are represented as agentic source-derived artifacts.",
        tools=("grammar_infer", "concolic_plan", "symbolic_worker_run"),
        agents=("grammar-reverser.md", "concolic-generator.md"),
        skills=("campaign",),
        engine_files=("grammar.py", "concolic.py", "runtime_backends.py"),
        prompt_terms=("grammar artifact", "grammar_infer", "branch-plan artifact", "concolic_plan", "symbolic_worker_run"),
    ),
    ParityRequirement(
        name="fuzzing_and_coverage_feedback",
        description="Bounded plugin-local fuzzing and real local fuzz ensemble workers mutate/promote seeds and record verified crashes.",
        tools=("fuzz_campaign", "fuzz_ensemble_run", "harness_run", "runtime_backend_status"),
        agents=("fuzz-finder.md", "native-harness.md"),
        skills=("campaign",),
        engine_files=("fuzzing.py", "execution.py", "runtime_backends.py"),
        prompt_terms=("fuzz_campaign", "fuzz_ensemble_run", "coverage feedback", "promoted corpus", "feedback_rounds", "3 out of 3"),
    ),
    ParityRequirement(
        name="sarif_reachability",
        description="Real local CodeQL/Joern/SootUp SARIF reachability workers are dependency-gated and conservative.",
        tools=("sarif_reachability_run", "runtime_backend_status"),
        agents=("sarif-agent.md",),
        skills=("campaign", "report"),
        engine_files=("runtime_backends.py",),
        plugin_files=("commands/sarif-reachability-run.md",),
        prompt_terms=("sarif_reachability_run", "CodeQL", "Joern", "SootUp", "conservative verdict"),
    ),
    ParityRequirement(
        name="external_crash_intake",
        description="External libFuzzer/AFL-style crash outputs can be imported, preserved as artifacts, verified, deduped, and recorded.",
        tools=("crash_import", "harness_run", "finding_classify", "finding_record"),
        agents=("corpus-manager.md", "fuzz-finder.md", "crash-grader.md"),
        skills=("campaign",),
        engine_files=("crash_intake.py", "execution.py", "dedupe.py"),
        prompt_terms=("crash_import", "external fuzzer crash outputs", "libFuzzer/AFL-style", "crash-import"),
    ),
    ParityRequirement(
        name="crash_grading_minimization_dedupe",
        description="Crash evidence is graded, minimized, classified, lifecycle-audited, deduped, and recorded before reporting.",
        tools=("finding_record", "finding_dedupe", "finding_lifecycle_audit", "finding_grade", "finding_classify", "pov_minimize"),
        agents=("crash-grader.md", "dedupe-judge.md"),
        skills=("campaign", "report"),
        engine_files=("asan.py", "grading.py", "minimization.py", "dedupe.py", "finding_lifecycle.py"),
        prompt_terms=("Five Criteria", "WEAK_PASS", "DUP_BETTER", "DUP_SKIP", "finding_lifecycle_audit", "finding-lifecycle-audit", "finding lifecycle", "signal-preservation"),
    ),
    ParityRequirement(
        name="patch_ladder",
        description="Verified findings can be routed through patch candidate provenance, cached environment caching, and a temporary-copy patch ladder with rebuild, PoV, tests, and re-attack checks.",
        tools=("patch_candidate_record", "patch_environment_prepare", "patch_grade"),
        agents=("patcher.md", "patch-grader.md"),
        skills=("patch", "campaign"),
        engine_files=("patching.py", "runtime_backends.py"),
        prompt_terms=("patch_candidate_record", "patch-candidate-record", "patch_environment_prepare", "patch_grade", "T0 apply and rebuild", "T3 focused re-attack", "temporary source copy"),
    ),
    ParityRequirement(
        name="reporting_and_campaign_audit",
        description="Reporting is gated on verified non-duplicate findings, campaign-level fixture coverage evidence, and a final completion audit, then written as durable artifacts.",
        tools=("campaign_fidelity_audit", "campaign_report", "campaign_completion_audit", "campaign_status"),
        agents=("reporter.md", "monitor.md"),
        skills=("report", "status"),
        engine_files=("campaign_audit.py", "completion_audit.py", "reporting.py"),
        prompt_terms=("campaign_fidelity_audit", "campaign_report", "campaign-report", "campaign_completion_audit", "campaign-completion-audit", "final completion gate", "required phases", "report artifact", "blockers", "enabled Fixture"),
    ),
    ParityRequirement(
        name="mock_export_and_full_completion",
        description="Full full local Fuzz campaign closure is represented by plugin-local mock PoV, patch, and SARIF exports plus specialist subagent orchestration gates.",
        tools=(
            "export_bundle_create",
            "export_mock_api_submit_pov",
            "export_mock_api_submit_patch",
            "export_mock_api_submit_sarif",
            "export_list",
            "campaign_full_completion_audit",
        ),
        agents=("export-agent.md", "monitor.md", "reporter.md"),
        skills=("campaign", "report", "status"),
        engine_files=("export.py", "completion_audit.py", "phase_audit.py"),
        prompt_terms=(
            "export_bundle_create",
            "export_mock_api_submit_pov",
            "export_mock_api_submit_patch",
            "export_mock_api_submit_sarif",
            "campaign_full_completion_audit",
            "export-agent",
            "plugin-local mock export API",
            "specialist subagent",
        ),
    ),
    ParityRequirement(
        name="specialist_no_runtime_subagents",
        description="Specialist subagent coordinators use only plugin-local fuzzing tools.",
        tools=(
            "target_discover",
            "target_build_probe",
            "fuzz_campaign",
            "fuzz_ensemble_run",
            "dictionary_generate",
            "grammar_infer",
            "concolic_plan",
            "symbolic_worker_run",
            "export_bundle_create",
            "campaign_full_completion_audit",
        ),
        agents=("native-harness.md", "input-generator.md", "artifact-manager.md", "sarif-agent.md"),
        skills=("campaign",),
        engine_files=("export.py", "fuzzing.py", "execution.py"),
        prompt_terms=(
            "native-harness",
            "input-generator",
            "artifact-manager",
            "artifact_manager",
            "specialist subagent",
            "bounded local fuzzing",
            "local generator planning",
            "local mock receipts only",
        ),
    ),
    ParityRequirement(
        name="runtime_guardrails",
        description="The no-runtime plugin has an executable guardrail and prompt contract preventing external runtime calls.",
        tools=("runtime_guard_audit", "engine_parity_audit"),
        skills=("doctor",),
        engine_files=("guardrails.py", "parity.py"),
        plugin_files=("scripts/runtime-guard.py",),
        prompt_terms=("runtime-guard-audit", "engine-parity-audit", "engine_parity_audit"),
    ),
    ParityRequirement(
        name="adaptive_scheduling_and_codec",
        description="Per-seed weighted scheduling, SymCC solution crossover, cached harness codecs, and the directed-fuzzing task queue steer plateaued campaigns.",
        tools=("codec_run", "directed_queue"),
        agents=(
            "planner.md",
            "input-generator.md",
            "fuzz-finder.md",
            "crash-grader.md",
            "concolic-generator.md",
            "dictionary-generator.md",
            "monitor.md",
        ),
        engine_files=("seed_weights.py", "symcc_crossover.py", "codec.py", "directed.py"),
        prompt_terms=(
            "seed-weights.json",
            "bits.json",
            "symcc-harvest",
            "symx-",
            "codec-status.json",
            "directed-queue",
            "directed-allowlist",
        ),
    ),
)


def audit_engine_parity(
    *,
    tool_specs: Iterable[dict[str, Any]],
    plugin_root: str | Path,
    engine_root: str | Path,
    audit_roots: Iterable[str | Path] | None = None,
) -> dict[str, Any]:
    plugin = Path(plugin_root)
    engine = Path(engine_root)
    tool_names = _tool_names(tool_specs)
    agents = _agent_names(plugin)
    skills = _skill_names(plugin)
    prompt_text = _prompt_text(plugin)
    prompt_text_lower = prompt_text.lower()

    group_results = []
    blockers: list[str] = []
    for requirement in ENGINE_PARITY_REQUIREMENTS:
        result = _audit_requirement(
            requirement,
            tool_names=tool_names,
            agents=agents,
            skills=skills,
            engine_root=engine,
            plugin_root=plugin,
            prompt_text_lower=prompt_text_lower,
        )
        group_results.append(result)
        if not result["ok"]:
            blockers.append(_blocker_for(result))

    guard_roots = tuple(Path(root) for root in audit_roots) if audit_roots is not None else (engine, plugin)
    guardrail_findings = audit_runtime_guard_runtime_calls(guard_roots)
    if guardrail_findings:
        blockers.append(f"runtime_guardrails: {len(guardrail_findings)} forbidden runtime references")

    ok_groups = sum(1 for result in group_results if result["ok"])
    return {
        "ok": not blockers,
        "score": {
            "groups": len(group_results),
            "passing_groups": ok_groups,
            "failing_groups": len(group_results) - ok_groups,
            "coverage_ratio": ok_groups / len(group_results) if group_results else 0.0,
        },
        "tool_count": len(tool_names),
        "agent_count": len(agents),
        "skill_count": len(skills),
        "prompt_contract": {
            "files": len(_prompt_paths(plugin)),
            "bytes": len(prompt_text.encode("utf-8")),
            "lines": prompt_text.count("\n"),
        },
        "groups": group_results,
        "guardrails": {
            "ok": not guardrail_findings,
            "findings": [finding.to_dict() for finding in guardrail_findings],
        },
        "blockers": blockers,
    }


def _audit_requirement(
    requirement: ParityRequirement,
    *,
    tool_names: set[str],
    agents: set[str],
    skills: set[str],
    engine_root: Path,
    plugin_root: Path,
    prompt_text_lower: str,
) -> dict[str, Any]:
    missing_tools = sorted(set(requirement.tools) - tool_names)
    missing_agents = sorted(set(requirement.agents) - agents)
    missing_skills = sorted(set(requirement.skills) - skills)
    missing_engine_files = sorted(name for name in requirement.engine_files if not (engine_root / name).is_file())
    missing_plugin_files = sorted(name for name in requirement.plugin_files if not (plugin_root / name).is_file())
    missing_prompt_terms = sorted(term for term in requirement.prompt_terms if term.lower() not in prompt_text_lower)
    ok = not any((missing_tools, missing_agents, missing_skills, missing_engine_files, missing_plugin_files, missing_prompt_terms))
    return {
        **asdict(requirement),
        "tools": list(requirement.tools),
        "agents": list(requirement.agents),
        "skills": list(requirement.skills),
        "engine_files": list(requirement.engine_files),
        "plugin_files": list(requirement.plugin_files),
        "prompt_terms": list(requirement.prompt_terms),
        "ok": ok,
        "missing_tools": missing_tools,
        "missing_agents": missing_agents,
        "missing_skills": missing_skills,
        "missing_engine_files": missing_engine_files,
        "missing_plugin_files": missing_plugin_files,
        "missing_prompt_terms": missing_prompt_terms,
        "evidence": {
            "tools_present": sorted(set(requirement.tools).intersection(tool_names)),
            "agents_present": sorted(set(requirement.agents).intersection(agents)),
            "skills_present": sorted(set(requirement.skills).intersection(skills)),
        },
    }


def _blocker_for(result: dict[str, Any]) -> str:
    missing = []
    for key in (
        "missing_tools",
        "missing_agents",
        "missing_skills",
        "missing_engine_files",
        "missing_plugin_files",
        "missing_prompt_terms",
    ):
        if result[key]:
            missing.append(f"{key.removeprefix('missing_')}={','.join(result[key])}")
    return f"{result['name']}: {'; '.join(missing)}"


def _tool_names(tool_specs: Iterable[dict[str, Any]]) -> set[str]:
    names = set()
    for spec in tool_specs:
        name = spec.get("name")
        if isinstance(name, str) and name:
            names.add(name)
    return names


def _agent_names(plugin_root: Path) -> set[str]:
    agent_dir = plugin_root / "agents"
    if not agent_dir.is_dir():
        return set()
    return {path.name for path in agent_dir.glob("*.md") if path.is_file()}


def _skill_names(plugin_root: Path) -> set[str]:
    skill_dir = plugin_root / "skills"
    if not skill_dir.is_dir():
        return set()
    return {path.parent.name for path in skill_dir.glob("*/SKILL.md") if path.is_file()}


def _prompt_text(plugin_root: Path) -> str:
    chunks = []
    for path in _prompt_paths(plugin_root):
        try:
            chunks.append(path.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            continue
    return "\n".join(chunks)


def _prompt_paths(plugin_root: Path) -> tuple[Path, ...]:
    candidates: list[Path] = []
    agent_dir = plugin_root / "agents"
    if agent_dir.is_dir():
        candidates.extend(agent_dir.glob("*.md"))
    skill_dir = plugin_root / "skills"
    if skill_dir.is_dir():
        candidates.extend(skill_dir.glob("*/SKILL.md"))
    candidates.extend((plugin_root / ".claude-plugin" / "plugin.json", plugin_root / ".mcp.json"))
    return tuple(sorted(path for path in candidates if path.is_file()))

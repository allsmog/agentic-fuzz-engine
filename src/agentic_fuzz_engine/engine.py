from __future__ import annotations

import base64
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable

from .build_probe import probe_target_build
from .campaign_audit import audit_campaign_fidelity
from .checkpoints import prepare_campaign_checkpoint
from .completion_audit import audit_campaign_completion
from .concolic import plan_concolic_branches
from .crash_intake import collect_crash_import
from .corpus import collect_corpus_import
from .dedupe import classify_finding_candidate
from .dictionary import generate_dictionary_from_source
from .discovery import discover_local_target
from .execution import run_harness_artifact
from .fidelity import discover_reference_benchmarks, load_target_profile, resolve_reference_root, validate_reference_fixtures
from .finding_lifecycle import audit_finding_lifecycle
from .fuzzing import build_fuzz_candidates, extract_coverage_features, summarize_harness_run
from .full_campaign import run_owned_local_full_campaign
from .grading import grade_finding_artifact
from .grammar import infer_grammar_from_source
from .guardrails import audit_runtime_guard_runtime_calls
from .minimization import minimize_pov_artifact
from .owned_replay import run_owned_direct_asan_replay
from .oss_fuzz_build import run_owned_oss_fuzz_build, run_owned_oss_fuzz_build_replay
from .parity import audit_engine_parity
from .patching import grade_patch_artifact, prepare_patch_candidate
from .phase_audit import audit_campaign_phases
from .reporting import build_campaign_report
from .runtime_backends import (
    prepare_patch_environment,
    run_fuzz_ensemble,
    run_sarif_reachability,
    run_symbolic_worker,
    runtime_backend_status,
)
from .container_build import build_target
from .scaffold import scaffold_target, select_targets
from .state import EngineState
from .workspace import workspace_init
from .export import (
    audit_subagent_orchestration,
    audit_export_completion,
    create_export_bundle,
    list_export_receipts,
    mock_submit_patch,
    mock_submit_pov,
    mock_submit_sarif,
)
from agentic_fuzz_full.runtime import (
    build_full_runtime_doctor,
    build_full_runtime_parity_audit,
    build_owned_campaign_plan,
    build_owned_deploy_plan,
)


ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


class AgenticFuzzEngine:
    def __init__(
        self,
        *,
        data_root: str | Path,
        reference_root: str | Path | None = None,
        audit_roots: tuple[str | Path, ...] = (),
    ) -> None:
        self.state = EngineState(data_root)
        self.reference_root = reference_root
        self.audit_roots = audit_roots

    def tool_specs(self) -> list[dict[str, Any]]:
        return [
            _tool("fidelity_list_fixtures", "List C/C++ benchmark fixtures used for fidelity testing.", {"include_disabled": "boolean"}),
            _tool("fidelity_validate_fixtures", "Validate local proof files, patches, and fixture indexes.", {"include_disabled": "boolean"}),
            _tool("target_describe", "Describe a C/C++ target profile.", {"project": "string"}),
            _tool("target_discover", "Read-only local source discovery for build systems, harness commands, dictionaries, and seed corpora.", {"source_dir": "string", "project": "string"}),
            _tool("target_build_probe", "Copy a local target into campaign state, run bounded build probes, and rediscover runnable harnesses.", {"run_id": "string", "source_dir": "string", "project": "string", "build_id": "string", "build_commands": "array", "timeout_seconds": "number"}),
            _tool("target_validate", "Validate a target profile and harness inventory.", {"project": "string"}),
            _tool("harness_list", "List harnesses for a C/C++ target.", {"project": "string"}),
            _tool("campaign_start", "Create plugin-local campaign state.", {"target": "string", "name": "string"}),
            _tool("campaign_status", "Read plugin-local campaign state.", {"run_id": "string"}),
            _tool("campaign_phase_audit", "Audit attempted campaign phases against durable checkpoint handoffs.", {"run_id": "string"}),
            _tool(
                "campaign_checkpoint_record",
                "Record a validated phase handoff checkpoint with evidence, blockers, and next command.",
                {
                    "run_id": "string",
                    "target": "string",
                    "harness": "string",
                    "phase": "string",
                    "tool_evidence": "array",
                    "blockers": "array",
                    "next_command": "string",
                    "agent": "string",
                },
            ),
            _tool("campaign_checkpoint_list", "List the durable phase handoff checkpoint ledger for a campaign.", {"run_id": "string"}),
            _tool("campaign_fidelity_audit", "Audit campaign coverage against benchmark fixtures and report missing parity evidence.", {"run_id": "string", "project": "string", "include_disabled": "boolean"}),
            _tool("campaign_report", "Generate durable Markdown and JSON campaign report artifacts from verified deduped findings.", {"run_id": "string", "project": "string", "artifact_prefix": "string", "include_disabled": "boolean"}),
            _tool(
                "campaign_completion_audit",
                "Run the final completion gate across parity, no-runtime guardrails, fixture validation, phase coverage, fidelity, and report artifacts.",
                {"run_id": "string", "project": "string", "include_disabled": "boolean", "require_report": "boolean", "required_phases": "array"},
            ),
            _tool(
                "campaign_full_completion_audit",
                "Run the strict full-campaign gate including specialist subagent orchestration and local export receipts.",
                {"run_id": "string", "project": "string", "include_disabled": "boolean", "require_report": "boolean", "required_agents": "array"},
            ),
            _tool(
                "export_bundle_create",
                "Create a plugin-local export bundle from verified proofs, reports, and passing patch evidence.",
                {"run_id": "string", "project": "string", "artifact_name": "string"},
            ),
            _tool(
                "export_mock_api_submit_pov",
                "Record a verified dedupe-representative proof in the plugin-local export API.",
                {"run_id": "string", "project": "string", "finding_id": "string", "poc_artifact": "string"},
            ),
            _tool(
                "export_mock_api_submit_patch",
                "Record a patch artifact with passing patch_grade evidence in the plugin-local export API.",
                {"run_id": "string", "project": "string", "patch_artifact": "string"},
            ),
            _tool(
                "export_mock_api_submit_sarif",
                "Record a campaign report JSON or SARIF artifact in the plugin-local export API.",
                {"run_id": "string", "project": "string", "report_artifact": "string"},
            ),
            _tool("export_list", "List plugin-local export bundles, receipts, and rejections for a campaign.", {"run_id": "string"}),
            _tool("event_append", "Append a structured campaign event.", {"run_id": "string", "event_type": "string", "payload": "object"}),
            _tool("artifact_put", "Store an artifact by base64 content.", {"run_id": "string", "name": "string", "content_b64": "string"}),
            _tool("artifact_get", "Read an artifact as base64 content.", {"run_id": "string", "name": "string"}),
            _tool("artifact_list", "List artifacts for a campaign.", {"run_id": "string"}),
            _tool(
                "corpus_import",
                "Import local seed corpus files and dictionary tokens into plugin-local campaign artifacts.",
                {
                    "run_id": "string",
                    "source_path": "string",
                    "kind": "string",
                    "artifact_prefix": "string",
                    "max_files": "integer",
                    "max_file_bytes": "integer",
                },
            ),
            _tool(
                "crash_import",
                "Import external fuzzer crash outputs, optionally verify them through a local harness, and record deduped findings.",
                {
                    "run_id": "string",
                    "source_path": "string",
                    "target": "string",
                    "harness": "string",
                    "sanitizer": "string",
                    "artifact_prefix": "string",
                    "harness_command": "array",
                    "expected_error_token": "string",
                    "timeout_seconds": "number",
                    "repetitions": "integer",
                    "record_findings": "boolean",
                    "max_files": "integer",
                    "max_file_bytes": "integer",
                },
            ),
            _tool(
                "dictionary_generate",
                "Infer fuzzing dictionary tokens from local C/C++ source and store a provenance artifact.",
                {
                    "run_id": "string",
                    "source_dir": "string",
                    "target": "string",
                    "harness": "string",
                    "artifact_name": "string",
                    "max_files": "integer",
                    "max_file_bytes": "integer",
                    "max_tokens": "integer",
                },
            ),
            _tool(
                "grammar_infer",
                "Infer a compact grammar and generated seed artifacts from local C/C++ source.",
                {
                    "run_id": "string",
                    "source_dir": "string",
                    "target": "string",
                    "harness": "string",
                    "artifact_prefix": "string",
                    "max_files": "integer",
                    "max_file_bytes": "integer",
                    "max_tokens": "integer",
                    "max_seeds": "integer",
                },
            ),
            _tool(
                "concolic_plan",
                "Plan source-derived branch constraints and seed mutations without invoking concolic services.",
                {
                    "run_id": "string",
                    "source_dir": "string",
                    "target": "string",
                    "harness": "string",
                    "artifact_prefix": "string",
                    "max_files": "integer",
                    "max_file_bytes": "integer",
                    "max_tokens": "integer",
                    "max_seeds": "integer",
                },
            ),
            _tool("finding_record", "Record a sanitizer finding and compute its dedupe signature.", {}),
            _tool("finding_dedupe", "Group campaign findings by dedupe signature.", {"run_id": "string"}),
            _tool("finding_lifecycle_audit", "Audit recorded findings for artifact, verification, classification, and dedupe evidence.", {"run_id": "string"}),
            _tool(
                "finding_grade",
                "Grade a stored PoV against crash-grader PASS, WEAK_PASS, and FAIL criteria.",
                {
                    "run_id": "string",
                    "target": "string",
                    "harness": "string",
                    "sanitizer": "string",
                    "artifact_name": "string",
                    "command": "array",
                    "expected_error_token": "string",
                    "timeout_seconds": "number",
                    "repetitions": "integer",
                    "record_finding": "boolean",
                },
            ),
            _tool(
                "finding_classify",
                "Classify a candidate finding as NEW, DUP_BETTER, or DUP_SKIP before recording/reporting.",
                {
                    "run_id": "string",
                    "target": "string",
                    "harness": "string",
                    "sanitizer": "string",
                    "error_token": "string",
                    "crash_output": "string",
                    "poc_artifact": "string",
                    "reproductions": "integer",
                    "verified": "boolean",
                },
            ),
            _tool(
                "harness_run",
                "Run a bounded non-external harness command against a stored PoV artifact.",
                {
                    "run_id": "string",
                    "target": "string",
                    "harness": "string",
                    "artifact_name": "string",
                    "command": "array",
                    "expected_error_token": "string",
                    "timeout_seconds": "number",
                    "repetitions": "integer",
                    "record_finding": "boolean",
                },
            ),
            _tool(
                "pov_minimize",
                "Minimize a stored PoV while preserving sanitizer token and crash identity.",
                {
                    "run_id": "string",
                    "artifact_name": "string",
                    "output_artifact": "string",
                    "command": "array",
                    "expected_error_token": "string",
                    "timeout_seconds": "number",
                    "repetitions": "integer",
                    "max_attempts": "integer",
                    "preserve_signal": "boolean",
                },
            ),
            _tool(
                "fidelity_replay_campaign",
                "Import and optionally execute benchmark proof fixtures through plugin-local harness commands.",
                {
                    "run_id": "string",
                    "project": "string",
                    "command_map": "object",
                    "default_command": "array",
                    "include_disabled": "boolean",
                    "timeout_seconds": "number",
                    "repetitions": "integer",
                    "record_findings": "boolean",
                    "max_cases": "integer",
                },
            ),
            _tool(
                "fuzz_campaign",
                "Run a bounded plugin-local seed mutation loop and promote coverage/crash evidence.",
                {
                    "run_id": "string",
                    "target": "string",
                    "harness": "string",
                    "sanitizer": "string",
                    "seed_artifacts": "array",
                    "dictionary": "array",
                    "harness_command": "array",
                    "expected_error_token": "string",
                    "timeout_seconds": "number",
                    "repetitions": "integer",
                    "max_iterations": "integer",
                    "feedback_rounds": "integer",
                    "record_findings": "boolean",
                    "stop_on_first_finding": "boolean",
                },
            ),
            _tool(
                "patch_candidate_record",
                "Validate and store a candidate patch diff with finding linkage and patcher rationale.",
                {
                    "run_id": "string",
                    "patch_content_b64": "string",
                    "artifact_name": "string",
                    "finding_id": "string",
                    "rationale": "string",
                    "variants_checked": "array",
                },
            ),
            _tool(
                "patch_grade",
                "Apply a candidate patch in a temporary source copy and run build, PoV, tests, and re-attack checks.",
                {
                    "run_id": "string",
                    "source_dir": "string",
                    "patch_artifact": "string",
                    "pov_artifact": "string",
                    "harness_command": "array",
                    "expected_error_token": "string",
                    "build_command": "array",
                    "test_command": "array",
                    "reattack_artifacts": "array",
                    "reattack_command": "array",
                    "timeout_seconds": "number",
                    "repetitions": "integer",
                },
            ),
            _tool("runtime_guard_audit", "Audit the engine/plugin for forbidden external-runtime references.", {}),
            _tool("engine_parity_audit", "Audit the no-runtime Agentic Fuzz engine against its C/C++ capability matrix.", {}),
            _tool("full_runtime_doctor", "Check owned full-runtime prerequisites for the complete local rebuild.", {}),
            _tool("runtime_backend_status", "Check real local backend availability for fuzzing, symbolic execution, SARIF reachability, and patch environments.", {}),
            _tool(
                "target_select",
                "Rank sink-inventory vectors against existing workspace targets so unharnessed attack surface is scaffolded first.",
                {"sinks_jsonl": "string", "top": "integer", "workspace_root": "string"},
            ),
            _tool(
                "target_scaffold",
                "Generate a workspace target skeleton (project.yaml, .localfuzz config, build.json, harness skeleton, seeds, dictionary) from the sink inventory.",
                {"name": "string", "sinks_jsonl": "string", "sink_tag": "string", "max_sink_refs": "integer", "force": "boolean", "workspace_root": "string"},
            ),
            _tool(
                "target_build",
                "Run the target's declared bounded build steps from .localfuzz/build.json and report bin artifacts.",
                {"project": "string", "only_steps": "array", "timeout_seconds": "number", "workspace_root": "string"},
            ),
            _tool(
                "workspace_init",
                "Create or refresh the generated dot-directory workspace (reference-root layout, DooD path maps, docker images, env file, optional asset imports).",
                {
                    "root": "string",
                    "path_maps": "array",
                    "source_dir": "string",
                    "klee_image": "string",
                    "build_container": "string",
                    "copies": "array",
                },
            ),
            _tool(
                "fuzz_ensemble_run",
                "Run bounded real local libFuzzer, AFL++, and/or LibAFL workers against explicit harness commands.",
                {
                    "run_id": "string",
                    "target": "string",
                    "harness": "string",
                    "harness_command": "array",
                    "seed_artifacts": "array",
                    "workers": "array",
                    "libafl_command": "array",
                    "runs": "integer",
                    "timeout_seconds": "number",
                    "artifact_prefix": "string",
                },
            ),
            _tool(
                "symbolic_worker_run",
                "Run a bounded real local SymCC, SymQEMU, or Z3 worker and collect generated inputs.",
                {
                    "run_id": "string",
                    "mode": "string",
                    "command": "array",
                    "constraints_smt2_b64": "string",
                    "timeout_seconds": "number",
                    "artifact_prefix": "string",
                },
            ),
            _tool(
                "sarif_reachability_run",
                "Run bounded real local CodeQL/Joern/SootUp SARIF reachability workers over source and SARIF input.",
                {
                    "run_id": "string",
                    "source_dir": "string",
                    "sarif_file": "string",
                    "language": "string",
                    "database_dir": "string",
                    "create_database": "boolean",
                    "codeql_query_suite": "string",
                    "joern_command": "array",
                    "sootup_command": "array",
                    "run_codeql": "boolean",
                    "run_joern": "boolean",
                    "run_sootup": "boolean",
                    "timeout_seconds": "number",
                    "artifact_prefix": "string",
                },
            ),
            _tool(
                "patch_environment_prepare",
                "Prepare a cached cached patch environment pool entry and optionally apply/build/test a patch artifact.",
                {
                    "run_id": "string",
                    "source_dir": "string",
                    "env_name": "string",
                    "patch_artifact": "string",
                    "build_command": "array",
                    "test_command": "array",
                    "timeout_seconds": "number",
                },
            ),
            _tool("full_runtime_parity_audit", "Audit the owned full-runtime subsystem contract, plugin commands, MCP tools, and prompt fixtures.", {}),
            _tool(
                "full_runtime_campaign_plan",
                "Build a full owned-runtime campaign phase graph without launching workers.",
                {"task_id": "string", "target": "string", "language": "string", "seconds": "integer"},
            ),
            _tool(
                "full_runtime_local_campaign",
                "Run a bounded plugin-local full campaign over benchmark fixtures using an explicit local harness command.",
                {
                    "project": "string",
                    "run_id": "string",
                    "harness": "string",
                    "harness_command": "array",
                    "command_map": "object",
                    "source_dir": "string",
                    "timeout_seconds": "number",
                    "repetitions": "integer",
                    "include_disabled": "boolean",
                },
            ),
            _tool(
                "fidelity_owned_build_replay",
                "Compile owned direct-ASAN replay binaries from benchmark source snapshots and replay matching proofs.",
                {
                    "run_id": "string",
                    "project": "string",
                    "include_disabled": "boolean",
                    "max_cases": "integer",
                    "compile_timeout_seconds": "number",
                    "replay_timeout_seconds": "number",
                    "repetitions": "integer",
                },
            ),
            _tool(
                "fidelity_oss_fuzz_build",
                "Build owned OSS-Fuzz harness binaries for a benchmark project without external services.",
                {
                    "project": "string",
                    "run_id": "string",
                    "oss_fuzz_root": "string",
                    "docker_host": "string",
                    "docker_platform": "string",
                    "sanitizer": "string",
                    "engine": "string",
                    "timeout_seconds": "number",
                },
            ),
            _tool(
                "fidelity_oss_fuzz_build_replay",
                "Build owned OSS-Fuzz harness binaries and replay matching benchmark proofs in a bounded base-runner container.",
                {
                    "project": "string",
                    "run_id": "string",
                    "oss_fuzz_root": "string",
                    "docker_host": "string",
                    "docker_platform": "string",
                    "sanitizer": "string",
                    "engine": "string",
                    "build_timeout_seconds": "number",
                    "replay_timeout_seconds": "number",
                    "repetitions": "integer",
                    "runner_image": "string",
                    "record_findings": "boolean",
                    "include_disabled": "boolean",
                },
            ),
            _tool(
                "full_runtime_deploy_plan",
                "Build a non-mutating local or Kubernetes deployment plan for the owned runtime.",
                {"target": "string", "namespace": "string"},
            ),
        ]

    def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        handlers: dict[str, ToolHandler] = {
            "fidelity_list_fixtures": self._fidelity_list_fixtures,
            "fidelity_list_fixtures": self._fidelity_list_fixtures,
            "fidelity_validate_fixtures": self._fidelity_validate_fixtures,
            "target_describe": self._target_describe,
            "target_discover": self._target_discover,
            "target_build_probe": self._target_build_probe,
            "target_validate": self._target_validate,
            "harness_list": self._harness_list,
            "campaign_start": self._campaign_start,
            "campaign_status": self._campaign_status,
            "campaign_phase_audit": self._campaign_phase_audit,
            "campaign_checkpoint_record": self._campaign_checkpoint_record,
            "campaign_checkpoint_list": self._campaign_checkpoint_list,
            "campaign_fidelity_audit": self._campaign_fidelity_audit,
            "campaign_report": self._campaign_report,
            "campaign_completion_audit": self._campaign_completion_audit,
            "campaign_full_completion_audit": self._campaign_full_completion_audit,
            "export_bundle_create": self._export_bundle_create,
            "export_mock_api_submit_pov": self._export_mock_api_submit_pov,
            "export_mock_api_submit_patch": self._export_mock_api_submit_patch,
            "export_mock_api_submit_sarif": self._export_mock_api_submit_sarif,
            "export_list": self._export_list,
            "export_bundle_create": self._export_bundle_create,
            "export_mock_api_submit_pov": self._export_mock_api_submit_pov,
            "export_mock_api_submit_patch": self._export_mock_api_submit_patch,
            "export_mock_api_submit_sarif": self._export_mock_api_submit_sarif,
            "export_list": self._export_list,
            "event_append": self._event_append,
            "artifact_put": self._artifact_put,
            "artifact_get": self._artifact_get,
            "artifact_list": self._artifact_list,
            "corpus_import": self._corpus_import,
            "crash_import": self._crash_import,
            "dictionary_generate": self._dictionary_generate,
            "grammar_infer": self._grammar_infer,
            "concolic_plan": self._concolic_plan,
            "finding_record": self._finding_record,
            "finding_dedupe": self._finding_dedupe,
            "finding_lifecycle_audit": self._finding_lifecycle_audit,
            "finding_grade": self._finding_grade,
            "finding_classify": self._finding_classify,
            "harness_run": self._harness_run,
            "pov_minimize": self._pov_minimize,
            "fidelity_replay_campaign": self._fidelity_replay_campaign,
            "fuzz_campaign": self._fuzz_campaign,
            "patch_candidate_record": self._patch_candidate_record,
            "patch_grade": self._patch_grade,
            "runtime_guard_audit": self._runtime_guard_audit,
            "runtime_guard_audit": self._runtime_guard_audit,
            "engine_parity_audit": self._engine_parity_audit,
            "full_runtime_doctor": self._full_runtime_doctor,
            "runtime_backend_status": self._runtime_backend_status,
            "workspace_init": self._workspace_init,
            "target_select": self._target_select,
            "target_scaffold": self._target_scaffold,
            "target_build": self._target_build,
            "fuzz_ensemble_run": self._fuzz_ensemble_run,
            "symbolic_worker_run": self._symbolic_worker_run,
            "sarif_reachability_run": self._sarif_reachability_run,
            "patch_environment_prepare": self._patch_environment_prepare,
            "full_runtime_parity_audit": self._full_runtime_parity_audit,
            "full_runtime_campaign_plan": self._full_runtime_campaign_plan,
            "full_runtime_local_campaign": self._full_runtime_local_campaign,
            "fidelity_owned_build_replay": self._fidelity_owned_build_replay,
            "fidelity_oss_fuzz_build": self._fidelity_oss_fuzz_build,
            "fidelity_oss_fuzz_build_replay": self._fidelity_oss_fuzz_build_replay,
            "full_runtime_deploy_plan": self._full_runtime_deploy_plan,
        }
        if name not in handlers:
            raise KeyError(f"unknown tool: {name}")
        return handlers[name](args)

    def _fidelity_list_fixtures(self, args: dict[str, Any]) -> dict[str, Any]:
        include_disabled = bool(args.get("include_disabled", False))
        return {
            "benchmarks": [
                benchmark.to_dict()
                for benchmark in discover_reference_benchmarks(self.reference_root, include_disabled=include_disabled)
            ]
        }

    def _fidelity_validate_fixtures(self, args: dict[str, Any]) -> dict[str, Any]:
        return validate_reference_fixtures(self.reference_root, include_disabled=bool(args.get("include_disabled", True)))

    def _target_describe(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"profile": load_target_profile(_required(args, "project"), self.reference_root).to_dict()}

    def _target_discover(self, args: dict[str, Any]) -> dict[str, Any]:
        return discover_local_target(
            _required(args, "source_dir"),
            project=args.get("project") if isinstance(args.get("project"), str) and args.get("project") else None,
        )

    def _target_build_probe(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        build_id = args.get("build_id") if isinstance(args.get("build_id"), str) and args.get("build_id") else "build-probe"
        result = probe_target_build(
            source_dir=_required(args, "source_dir"),
            worktree_dir=self.state.worktree_dir(run_id, build_id),
            project=args.get("project") if isinstance(args.get("project"), str) and args.get("project") else None,
            build_commands=_command_sequence_arg(args.get("build_commands")),
            timeout_seconds=args.get("timeout_seconds", 30),
        )
        self.state.event_append(
            run_id,
            "target_build_probe",
            {
                "project": result["project"],
                "ok": result["ok"],
                "worktree_dir": result["worktree_dir"],
                "runnable_harnesses": [harness["name"] for harness in result["runnable_harnesses"]],
                "blocker": result["blocker"],
            },
        )
        return {**result, "run_id": run_id, "build_id": build_id}

    def _target_validate(self, args: dict[str, Any]) -> dict[str, Any]:
        profile = load_target_profile(_required(args, "project"), self.reference_root)
        issues = []
        if profile.disabled:
            issues.append("target is marked disabled in project.yaml")
        if not profile.sanitizers:
            issues.append("target declares no sanitizers")
        if not profile.fuzzing_engines:
            issues.append("target declares no fuzzing engines")
        if not profile.harnesses:
            issues.append("target has no .localfuzz harness inventory in the local userspace fixture")
        return {"ok": not issues, "issues": issues, "profile": profile.to_dict()}

    def _harness_list(self, args: dict[str, Any]) -> dict[str, Any]:
        profile = load_target_profile(_required(args, "project"), self.reference_root)
        return {"target": profile.target, "harnesses": [harness.to_dict() for harness in profile.harnesses]}

    def _campaign_start(self, args: dict[str, Any]) -> dict[str, Any]:
        return self.state.campaign_start(
            _required(args, "target"),
            name=args.get("name") or None,
            metadata=args.get("metadata") if isinstance(args.get("metadata"), dict) else None,
        )

    def _campaign_status(self, args: dict[str, Any]) -> dict[str, Any]:
        return self.state.campaign_status(_required(args, "run_id"))

    def _campaign_phase_audit(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        result = audit_campaign_phases(
            run_id=run_id,
            events=self.state.event_list(run_id),
            checkpoints=self.state.checkpoint_list(run_id)["checkpoints"],
        )
        self.state.event_append(
            run_id,
            "campaign_phase_audit",
            {
                "ok": result["ok"],
                "coverage_ok": result["coverage_ok"],
                "missing_checkpoint_phases": result["missing_checkpoint_phases"],
                "stale_checkpoint_phases": result["stale_checkpoint_phases"],
                "blocked_phases": result["blocked_phases"],
            },
        )
        return result

    def _campaign_fidelity_audit(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        project = args.get("project") if isinstance(args.get("project"), str) and args.get("project") else None
        result = audit_campaign_fidelity(
            run_id=run_id,
            project=project,
            benchmarks=discover_reference_benchmarks(self.reference_root, include_disabled=bool(args.get("include_disabled", True))),
            findings=self.state.finding_list(run_id),
            artifacts=self.state.artifact_list(run_id)["artifacts"],
            events=self.state.event_list(run_id),
        )
        self.state.event_append(
            run_id,
            "campaign_fidelity_audit",
            {
                "project": project,
                "ok": result["ok"],
                "score": result["score"],
                "blockers": result["blockers"],
            },
        )
        return result

    def _campaign_report(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        project = args.get("project") if isinstance(args.get("project"), str) and args.get("project") else None
        artifacts = self.state.artifact_list(run_id)["artifacts"]
        fidelity = audit_campaign_fidelity(
            run_id=run_id,
            project=project,
            benchmarks=discover_reference_benchmarks(self.reference_root, include_disabled=bool(args.get("include_disabled", True))),
            findings=self.state.finding_list(run_id),
            artifacts=artifacts,
            events=self.state.event_list(run_id),
        )
        built = build_campaign_report(
            run_id=run_id,
            project=project,
            campaign=self.state.campaign_status(run_id)["campaign"],
            findings=self.state.finding_list(run_id),
            artifacts=artifacts,
            checkpoints=self.state.checkpoint_list(run_id)["checkpoints"],
            phase_audit=audit_campaign_phases(
                run_id=run_id,
                events=self.state.event_list(run_id),
                checkpoints=self.state.checkpoint_list(run_id)["checkpoints"],
            ),
            finding_lifecycle_audit=audit_finding_lifecycle(
                run_id=run_id,
                findings=self.state.finding_list(run_id),
                artifacts=artifacts,
                events=self.state.event_list(run_id),
            ),
            fidelity_audit=fidelity,
            dedupe=self.state.finding_dedupe(run_id),
        )
        artifact_prefix = str(args.get("artifact_prefix") or f"reports/{run_id}")
        markdown_artifact = self.state.artifact_put(run_id, f"{artifact_prefix}/REPORT.md", built["markdown_content_b64"])
        json_artifact = self.state.artifact_put(run_id, f"{artifact_prefix}/REPORT.json", built["json_content_b64"])
        summary = {
            "run_id": run_id,
            "project": project,
            "markdown_artifact": markdown_artifact,
            "json_artifact": json_artifact,
            "summary": built["report"]["summary"],
            "fidelity": built["report"]["fidelity"],
        }
        self.state.event_append(run_id, "campaign_report", summary)
        return {**summary, "report": built["report"], "markdown": built["markdown"]}

    def _campaign_completion_audit(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        project = args.get("project") if isinstance(args.get("project"), str) and args.get("project") else None
        include_disabled = bool(args.get("include_disabled", True))
        require_report = bool(args.get("require_report", True))
        artifacts = self.state.artifact_list(run_id)["artifacts"]
        events = self.state.event_list(run_id)
        checkpoints = self.state.checkpoint_list(run_id)["checkpoints"]
        phase = audit_campaign_phases(run_id=run_id, events=events, checkpoints=checkpoints)
        fidelity = audit_campaign_fidelity(
            run_id=run_id,
            project=project,
            benchmarks=discover_reference_benchmarks(self.reference_root, include_disabled=include_disabled),
            findings=self.state.finding_list(run_id),
            artifacts=artifacts,
            events=events,
        )
        result = audit_campaign_completion(
            run_id=run_id,
            project=project,
            engine_parity=self._engine_parity_audit({}),
            runtime_guard=self._runtime_guard_audit({}),
            fixture_validation=validate_reference_fixtures(self.reference_root, include_disabled=include_disabled),
            finding_lifecycle=audit_finding_lifecycle(
                run_id=run_id,
                findings=self.state.finding_list(run_id),
                artifacts=artifacts,
                events=events,
            ),
            phase_audit=phase,
            fidelity_audit=fidelity,
            artifacts=artifacts,
            events=events,
            require_report=require_report,
            required_phases=(
                _string_list(args.get("required_phases"), key="required_phases")
                if args.get("required_phases") is not None
                else None
            ),
        )
        self.state.event_append(
            run_id,
            "campaign_completion_audit",
            {
                "project": project,
                "ok": result["ok"],
                "gates": {name: bool(gate.get("ok")) for name, gate in result["gates"].items()},
                "blockers": result["blockers"],
            },
        )
        return result

    def _campaign_full_completion_audit(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        project = args.get("project") if isinstance(args.get("project"), str) and args.get("project") else None
        base = self._campaign_completion_audit(
            {
                "run_id": run_id,
                "project": project,
                "include_disabled": bool(args.get("include_disabled", True)),
                "require_report": bool(args.get("require_report", True)),
                "required_phases": ["export"],
            }
        )
        events = self.state.event_list(run_id)
        checkpoints = self.state.checkpoint_list(run_id)["checkpoints"]
        export_gate = audit_export_completion(findings=self.state.finding_list(run_id), events=events)
        subagent_gate = audit_subagent_orchestration(
            checkpoints=checkpoints,
            events=events,
            required_agents=(
                _string_list(args.get("required_agents"), key="required_agents")
                if args.get("required_agents") is not None
                else None
            ),
        )
        gates = {
            **base["gates"],
            "export": export_gate,
            "subagent_orchestration": subagent_gate,
        }
        blockers = [
            f"{name}: {blocker}"
            for name, gate in gates.items()
            for blocker in gate.get("blockers", [])
        ]
        result = {
            "run_id": run_id,
            "project": project,
            "ok": all(bool(gate.get("ok")) for gate in gates.values()),
            "gates": gates,
            "blockers": blockers,
        }
        self.state.event_append(
            run_id,
            "campaign_full_completion_audit",
            {
                "project": project,
                "ok": result["ok"],
                "gates": {name: bool(gate.get("ok")) for name, gate in gates.items()},
                "blockers": blockers,
            },
        )
        return result

    def _export_bundle_create(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        project = args.get("project") if isinstance(args.get("project"), str) and args.get("project") else None
        built = create_export_bundle(
            run_id=run_id,
            project=project,
            findings=self.state.finding_list(run_id),
            artifacts=self.state.artifact_list(run_id)["artifacts"],
            events=self.state.event_list(run_id),
            dedupe=self.state.finding_dedupe(run_id),
            artifact_name=args.get("artifact_name") if isinstance(args.get("artifact_name"), str) and args.get("artifact_name") else None,
        )
        artifact = self.state.artifact_put(run_id, str(built["artifact_name"]), str(built["content_b64"]))
        result = {
            "run_id": run_id,
            "project": project,
            "ok": built["ok"],
            "bundle_artifact": artifact,
            "bundle": built["bundle"],
        }
        self.state.event_append(
            run_id,
            "export_bundle_created",
            {
                "project": project,
                "ok": result["ok"],
                "bundle_artifact": artifact["name"],
                "pov_exports": len(result["bundle"]["pov_exports"]),
                "patch_exports": len(result["bundle"]["patch_exports"]),
                "sarif_exports": len(result["bundle"]["sarif_exports"]),
                "blockers": result["bundle"]["blockers"],
            },
        )
        return result

    def _export_mock_api_submit_pov(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        project = args.get("project") if isinstance(args.get("project"), str) and args.get("project") else None
        result = mock_submit_pov(
            run_id=run_id,
            project=project,
            findings=self.state.finding_list(run_id),
            artifacts=self.state.artifact_list(run_id)["artifacts"],
            events=self.state.event_list(run_id),
            dedupe=self.state.finding_dedupe(run_id),
            finding_id=args.get("finding_id") if isinstance(args.get("finding_id"), str) and args.get("finding_id") else None,
            poc_artifact=args.get("poc_artifact") if isinstance(args.get("poc_artifact"), str) and args.get("poc_artifact") else None,
        )
        return self._record_mock_export(run_id, result)

    def _export_mock_api_submit_patch(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        project = args.get("project") if isinstance(args.get("project"), str) and args.get("project") else None
        result = mock_submit_patch(
            run_id=run_id,
            project=project,
            artifacts=self.state.artifact_list(run_id)["artifacts"],
            events=self.state.event_list(run_id),
            patch_artifact=args.get("patch_artifact") if isinstance(args.get("patch_artifact"), str) and args.get("patch_artifact") else None,
        )
        return self._record_mock_export(run_id, result)

    def _export_mock_api_submit_sarif(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        project = args.get("project") if isinstance(args.get("project"), str) and args.get("project") else None
        result = mock_submit_sarif(
            run_id=run_id,
            project=project,
            artifacts=self.state.artifact_list(run_id)["artifacts"],
            events=self.state.event_list(run_id),
            report_artifact=args.get("report_artifact") if isinstance(args.get("report_artifact"), str) and args.get("report_artifact") else None,
        )
        return self._record_mock_export(run_id, result)

    def _record_mock_export(self, run_id: str, result: dict[str, Any]) -> dict[str, Any]:
        receipt = result["receipt"]
        if result.get("accepted"):
            artifact = self.state.artifact_put(run_id, str(result["artifact_name"]), str(result["content_b64"]))
            recorded = {**result, "receipt_artifact": artifact}
            recorded.pop("content_b64", None)
            self.state.event_append(
                run_id,
                "export_accepted",
                {
                    **receipt,
                    "receipt_artifact": artifact["name"],
                },
            )
            return recorded
        self.state.event_append(run_id, "export_rejected", receipt)
        return result

    def _export_list(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        return {"run_id": run_id, **list_export_receipts(self.state.event_list(run_id))}

    def _event_append(self, args: dict[str, Any]) -> dict[str, Any]:
        payload = args.get("payload")
        return self.state.event_append(
            _required(args, "run_id"),
            _required(args, "event_type"),
            payload if isinstance(payload, dict) else {},
        )

    def _campaign_checkpoint_record(self, args: dict[str, Any]) -> dict[str, Any]:
        checkpoint = prepare_campaign_checkpoint(
            target=_required(args, "target"),
            harness=args.get("harness") if isinstance(args.get("harness"), str) else None,
            phase=_required(args, "phase"),
            tool_evidence=_string_list(args.get("tool_evidence"), key="tool_evidence"),
            blockers=_string_list(args.get("blockers"), key="blockers"),
            next_command=_required(args, "next_command"),
            agent=args.get("agent") if isinstance(args.get("agent"), str) and args.get("agent") else None,
        )
        record = self.state.checkpoint_record(_required(args, "run_id"), checkpoint)
        return {"run_id": _required(args, "run_id"), "checkpoint": record}

    def _campaign_checkpoint_list(self, args: dict[str, Any]) -> dict[str, Any]:
        return self.state.checkpoint_list(_required(args, "run_id"))

    def _full_runtime_doctor(self, args: dict[str, Any]) -> dict[str, Any]:
        return build_full_runtime_doctor(reference_root=self.reference_root)

    def _runtime_backend_status(self, args: dict[str, Any]) -> dict[str, Any]:
        return runtime_backend_status()

    def _target_select(self, args: dict[str, Any]) -> dict[str, Any]:
        return select_targets(
            sinks_jsonl=_required(args, "sinks_jsonl"),
            workspace_root=args.get("workspace_root") or None,
            top=int(args.get("top", 25)),
        )

    def _target_scaffold(self, args: dict[str, Any]) -> dict[str, Any]:
        return scaffold_target(
            name=_required(args, "name"),
            workspace_root=args.get("workspace_root") or None,
            sinks_jsonl=args.get("sinks_jsonl") or None,
            sink_tag=args.get("sink_tag") or None,
            max_sink_refs=int(args.get("max_sink_refs", 20)),
            force=bool(args.get("force", False)),
        )

    def _target_build(self, args: dict[str, Any]) -> dict[str, Any]:
        return build_target(
            project=_required(args, "project"),
            workspace_root=args.get("workspace_root") or None,
            only_steps=_string_list(args.get("only_steps"), key="only_steps") or None,
            timeout_seconds=args.get("timeout_seconds", 900),
        )

    def _workspace_init(self, args: dict[str, Any]) -> dict[str, Any]:
        return workspace_init(
            root=args.get("root") or None,
            path_maps=_string_list(args.get("path_maps"), key="path_maps"),
            source_dir=args.get("source_dir") or None,
            klee_image=args.get("klee_image") or None,
            build_container=args.get("build_container") or None,
            copies=_string_list(args.get("copies"), key="copies"),
        )

    def _fuzz_ensemble_run(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        seed_artifacts = []
        for seed_name in _string_list(args.get("seed_artifacts"), key="seed_artifacts"):
            artifact = self.state.artifact_get(run_id, seed_name)
            seed_artifacts.append({"name": str(artifact["name"]), "content_b64": str(artifact["content_b64"])})
        result = run_fuzz_ensemble(
            work_dir=self.state.worktree_dir(run_id, "fuzz-ensemble"),
            target=_required(args, "target"),
            harness=_required(args, "harness"),
            harness_command=_optional_command(args.get("harness_command")),
            seed_artifacts=seed_artifacts,
            workers=_string_list(args.get("workers"), key="workers") or None,
            libafl_command=_optional_command(args.get("libafl_command")),
            runs=int(args.get("runs", 128)),
            timeout_seconds=args.get("timeout_seconds", 60),
        )
        stored = self._store_runtime_output_files(
            run_id,
            result.get("crash_files", []),
            artifact_prefix=str(args.get("artifact_prefix") or "runtime/fuzz-ensemble/crashes"),
        )
        result["stored_crash_artifacts"] = stored
        self.state.event_append(
            run_id,
            "fuzz_ensemble_run",
            {
                "target": result["target"],
                "harness": result["harness"],
                "ok": result["ok"],
                "workers_requested": result["workers_requested"],
                "workers_executed": result["workers_executed"],
                "crash_files": len(result["crash_files"]),
                "stored_crash_artifacts": [artifact["name"] for artifact in stored],
                "blockers": result["blockers"],
            },
        )
        return {"run_id": run_id, **result}

    def _symbolic_worker_run(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        result = run_symbolic_worker(
            work_dir=self.state.worktree_dir(run_id, "symbolic-worker"),
            mode=str(args.get("mode") or "symcc"),
            command=_optional_command(args.get("command")),
            constraints_smt2_b64=args.get("constraints_smt2_b64") if isinstance(args.get("constraints_smt2_b64"), str) else None,
            timeout_seconds=args.get("timeout_seconds", 60),
        )
        stored = self._store_runtime_output_files(
            run_id,
            result.get("output_files", []),
            artifact_prefix=str(args.get("artifact_prefix") or f"runtime/symbolic/{result['worker']}"),
        )
        result["stored_output_artifacts"] = stored
        self.state.event_append(
            run_id,
            "symbolic_worker_run",
            {
                "worker": result["worker"],
                "ok": result["ok"],
                "output_files": len(result["output_files"]),
                "stored_output_artifacts": [artifact["name"] for artifact in stored],
                "blockers": result["blockers"],
            },
        )
        return {"run_id": run_id, **result}

    def _sarif_reachability_run(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        result = run_sarif_reachability(
            work_dir=self.state.worktree_dir(run_id, "sarif-reachability"),
            source_dir=_required(args, "source_dir"),
            sarif_file=_required(args, "sarif_file"),
            language=str(args.get("language") or "c-cpp"),
            database_dir=args.get("database_dir") if isinstance(args.get("database_dir"), str) and args.get("database_dir") else None,
            create_database=bool(args.get("create_database", False)),
            codeql_query_suite=args.get("codeql_query_suite") if isinstance(args.get("codeql_query_suite"), str) and args.get("codeql_query_suite") else None,
            joern_command=_optional_command(args.get("joern_command")),
            sootup_command=_optional_command(args.get("sootup_command")),
            run_codeql=bool(args.get("run_codeql", True)),
            run_joern=bool(args.get("run_joern", True)),
            run_sootup=bool(args.get("run_sootup", True)),
            timeout_seconds=args.get("timeout_seconds", 300),
        )
        stored = self._store_runtime_output_files(
            run_id,
            result.get("output_files", []),
            artifact_prefix=str(args.get("artifact_prefix") or "runtime/sarif-reachability"),
        )
        result["stored_output_artifacts"] = stored
        self.state.event_append(
            run_id,
            "sarif_reachability_run",
            {
                "ok": result["ok"],
                "verdict": result["verdict"],
                "input_results": result["input_sarif"]["results"],
                "source_location_hits": result["input_sarif"]["source_location_hits"],
                "stages": [stage.get("analyzer") for stage in result["stages"]],
                "stored_output_artifacts": [artifact["name"] for artifact in stored],
                "blockers": result["blockers"],
            },
        )
        return {"run_id": run_id, **result}

    def _patch_environment_prepare(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        patch_artifact_name = args.get("patch_artifact") if isinstance(args.get("patch_artifact"), str) and args.get("patch_artifact") else None
        patch_content_b64 = None
        if patch_artifact_name:
            patch_artifact = self.state.artifact_get(run_id, patch_artifact_name)
            patch_content_b64 = str(patch_artifact["content_b64"])
        result = prepare_patch_environment(
            source_dir=_required(args, "source_dir"),
            pool_root=self.state.worktree_dir(run_id, "patch-environment-pool"),
            env_name=str(args.get("env_name") or "patch-env"),
            patch_name=patch_artifact_name,
            patch_content_b64=patch_content_b64,
            build_command=_optional_command(args.get("build_command")),
            test_command=_optional_command(args.get("test_command")),
            timeout_seconds=args.get("timeout_seconds", 300),
        )
        self.state.event_append(
            run_id,
            "patch_environment_prepare",
            {
                "ok": result["ok"],
                "source_dir": _required(args, "source_dir"),
                "cache_hit": result["cache_hit"],
                "cache_dir": result["cache_dir"],
                "env_dir": result["env_dir"],
                "patch_artifact": patch_artifact_name,
                "blockers": result["blockers"],
            },
        )
        return {"run_id": run_id, **result}

    def _full_runtime_parity_audit(self, args: dict[str, Any]) -> dict[str, Any]:
        repo_root = Path(__file__).resolve().parents[2]
        return build_full_runtime_parity_audit(
            tool_names={tool["name"] for tool in self.tool_specs()},
            plugin_root=repo_root / "claude-plugin" / "agentic-fuzz-engine",
            reference_root=self.reference_root,
        )

    def _full_runtime_campaign_plan(self, args: dict[str, Any]) -> dict[str, Any]:
        return build_owned_campaign_plan(
            task_id=str(args.get("task_id") or "task-full-runtime"),
            target=str(args.get("target") or "localfuzz/c/unknown"),
            language=str(args.get("language") or "c-cpp"),
            seconds=int(args.get("seconds", 300)),
        )

    def _full_runtime_local_campaign(self, args: dict[str, Any]) -> dict[str, Any]:
        command = args.get("harness_command")
        if command in (None, "", []):
            command = None
        if command is not None and not (isinstance(command, list) and all(isinstance(item, str) for item in command)):
            raise ValueError("harness_command must be an argv list")
        command_map = args.get("command_map")
        if command_map in (None, ""):
            command_map = {}
        if not isinstance(command_map, dict):
            raise ValueError("command_map must be an object")
        return run_owned_local_full_campaign(
            self,
            project=_required(args, "project"),
            run_id=args.get("run_id") if isinstance(args.get("run_id"), str) and args.get("run_id") else None,
            harness=args.get("harness") if isinstance(args.get("harness"), str) and args.get("harness") else None,
            harness_command=command,
            command_map=command_map,
            source_dir=args.get("source_dir") if isinstance(args.get("source_dir"), str) and args.get("source_dir") else None,
            timeout_seconds=args.get("timeout_seconds", 5),
            repetitions=int(args.get("repetitions", 3)),
            include_disabled=bool(args.get("include_disabled", False)),
        )

    def _full_runtime_deploy_plan(self, args: dict[str, Any]) -> dict[str, Any]:
        return build_owned_deploy_plan(
            target=str(args.get("target") or "local"),
            namespace=str(args.get("namespace") or "agentic-fuzz"),
        )

    def _fidelity_owned_build_replay(self, args: dict[str, Any]) -> dict[str, Any]:
        return run_owned_direct_asan_replay(
            self,
            run_id=args.get("run_id") if isinstance(args.get("run_id"), str) and args.get("run_id") else None,
            project=args.get("project") if isinstance(args.get("project"), str) and args.get("project") else None,
            include_disabled=bool(args.get("include_disabled", False)),
            max_cases=_bounded_optional_int(args.get("max_cases"), limit=100),
            compile_timeout_seconds=args.get("compile_timeout_seconds", 30),
            replay_timeout_seconds=args.get("replay_timeout_seconds", 10),
            repetitions=int(args.get("repetitions", 1)),
        )

    def _fidelity_oss_fuzz_build(self, args: dict[str, Any]) -> dict[str, Any]:
        return run_owned_oss_fuzz_build(
            self,
            project=_required(args, "project"),
            run_id=args.get("run_id") if isinstance(args.get("run_id"), str) and args.get("run_id") else None,
            oss_fuzz_root=args.get("oss_fuzz_root") if isinstance(args.get("oss_fuzz_root"), str) and args.get("oss_fuzz_root") else None,
            docker_host=args.get("docker_host") if isinstance(args.get("docker_host"), str) and args.get("docker_host") else None,
            docker_platform=str(args.get("docker_platform") or "linux/amd64"),
            sanitizer=str(args.get("sanitizer") or "address"),
            engine_name=str(args.get("engine") or "libfuzzer"),
            timeout_seconds=args.get("timeout_seconds", 900),
        )

    def _fidelity_oss_fuzz_build_replay(self, args: dict[str, Any]) -> dict[str, Any]:
        return run_owned_oss_fuzz_build_replay(
            self,
            project=_required(args, "project"),
            run_id=args.get("run_id") if isinstance(args.get("run_id"), str) and args.get("run_id") else None,
            oss_fuzz_root=args.get("oss_fuzz_root") if isinstance(args.get("oss_fuzz_root"), str) and args.get("oss_fuzz_root") else None,
            docker_host=args.get("docker_host") if isinstance(args.get("docker_host"), str) and args.get("docker_host") else None,
            docker_platform=str(args.get("docker_platform") or "linux/amd64"),
            sanitizer=str(args.get("sanitizer") or "address"),
            engine_name=str(args.get("engine") or "libfuzzer"),
            build_timeout_seconds=args.get("build_timeout_seconds", 900),
            replay_timeout_seconds=args.get("replay_timeout_seconds", 30),
            repetitions=int(args.get("repetitions", 1)),
            runner_image=str(args.get("runner_image") or "ghcr.io/agentic-fuzz/base-runner:v1.3.0"),
            record_findings=bool(args.get("record_findings", True)),
            include_disabled=bool(args.get("include_disabled", False)),
        )

    def _artifact_put(self, args: dict[str, Any]) -> dict[str, Any]:
        # Validate early so MCP clients get a clear error.
        base64.b64decode(_required(args, "content_b64").encode("ascii"))
        return self.state.artifact_put(_required(args, "run_id"), _required(args, "name"), _required(args, "content_b64"))

    def _artifact_get(self, args: dict[str, Any]) -> dict[str, Any]:
        return self.state.artifact_get(_required(args, "run_id"), _required(args, "name"))

    def _artifact_list(self, args: dict[str, Any]) -> dict[str, Any]:
        return self.state.artifact_list(_required(args, "run_id"))

    def _corpus_import(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        collected = collect_corpus_import(
            _required(args, "source_path"),
            kind=str(args.get("kind") or "auto"),
            artifact_prefix=str(args.get("artifact_prefix") or "corpus"),
            max_files=int(args.get("max_files", 100)),
            max_file_bytes=int(args.get("max_file_bytes", 262144)),
        )
        stored = []
        for item in collected["artifacts"]:
            artifact = self.state.artifact_put(run_id, str(item["artifact_name"]), str(item["content_b64"]))
            stored.append(
                {
                    **artifact,
                    "source_path": item["source_path"],
                    "source_rel": item["source_rel"],
                    "kind": item["kind"],
                }
            )
        result = {
            "run_id": run_id,
            "source_path": collected["source_path"],
            "kind": collected["kind"],
            "artifact_prefix": collected["artifact_prefix"],
            "artifacts": stored,
            "seed_artifacts": [item["name"] for item in stored if item["kind"] == "seed"],
            "dictionary_artifacts": [item["name"] for item in stored if item["kind"] == "dictionary"],
            "dictionary_tokens": collected["dictionary_tokens"],
            "skipped": collected["skipped"],
            "truncated": collected["truncated"],
        }
        self.state.event_append(
            run_id,
            "corpus_import",
            {
                "source_path": result["source_path"],
                "artifact_count": len(stored),
                "seed_artifacts": result["seed_artifacts"],
                "dictionary_tokens": len(result["dictionary_tokens"]),
                "skipped": result["skipped"],
            },
        )
        return result

    def _crash_import(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        target = _required(args, "target")
        harness = _required(args, "harness")
        sanitizer = str(args.get("sanitizer") or "address")
        expected_error_token = args.get("expected_error_token") if isinstance(args.get("expected_error_token"), str) and args.get("expected_error_token") else None
        command = _optional_command(args.get("harness_command"))
        record_findings = bool(args.get("record_findings", True))
        collected = collect_crash_import(
            _required(args, "source_path"),
            artifact_prefix=str(args.get("artifact_prefix") or f"{target}/{harness}/crashes"),
            max_files=int(args.get("max_files", 100)),
            max_file_bytes=int(args.get("max_file_bytes", 1048576)),
        )

        cases = []
        findings = []
        blocked = []
        for item in collected["artifacts"]:
            artifact = self.state.artifact_put(run_id, str(item["artifact_name"]), str(item["content_b64"]))
            case: dict[str, Any] = {
                "source_path": item["source_path"],
                "source_rel": item["source_rel"],
                "artifact": artifact,
                "sidecar_signal": item["sidecar_signal"],
                "sidecar_excerpt": item["sidecar_excerpt"],
                "status": "imported",
            }
            if command is None:
                case["status"] = "blocked"
                case["blocker"] = "missing harness command"
                blocked.append(case)
                cases.append(case)
                continue

            run = run_harness_artifact(
                artifact_name=str(artifact["name"]),
                content_b64=str(item["content_b64"]),
                command=command,
                timeout_seconds=args.get("timeout_seconds", 10),
                repetitions=int(args.get("repetitions", 3)),
                workdir=args.get("workdir") if isinstance(args.get("workdir"), str) else None,
                expected_error_token=expected_error_token,
            )
            case["run"] = run
            case["status"] = "verified" if run["verified"] else "failed"
            observed_token = expected_error_token or run.get("observed_error_token")
            if run["verified"] and observed_token:
                candidate = {
                    "target": target,
                    "harness": harness,
                    "sanitizer": sanitizer,
                    "error_token": str(observed_token),
                    "crash_output": str(run["crash_output"]),
                    "poc_artifact": str(artifact["name"]),
                    "reproductions": int(run["matches_expected"] if expected_error_token else run["crashes"]),
                    "verified": True,
                }
                recorded = self._classify_verify_and_record(
                    run_id,
                    candidate,
                    source="crash_import",
                    record=record_findings,
                )
                case["classification"] = recorded["classification"]
                if recorded["finding"] is not None:
                    finding = recorded["finding"]
                    case["finding"] = finding
                    findings.append(finding)
            cases.append(case)

        summary = {
            "run_id": run_id,
            "target": target,
            "harness": harness,
            "sanitizer": sanitizer,
            "source_path": collected["source_path"],
            "artifact_prefix": collected["artifact_prefix"],
            "imported": len(cases),
            "verified": sum(1 for case in cases if case["status"] == "verified"),
            "failed": sum(1 for case in cases if case["status"] == "failed"),
            "blocked": len(blocked),
            "findings_recorded": len(findings),
            "skipped": collected["skipped"],
            "truncated": collected["truncated"],
            "blockers": collected["blockers"] + (["missing harness command"] if blocked else []),
        }
        self.state.event_append(run_id, "crash_import", summary)
        return {**summary, "cases": cases, "findings": findings}

    def _dictionary_generate(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        target = _required(args, "target")
        harness = _required(args, "harness")
        artifact_name = args.get("artifact_name")
        generated = generate_dictionary_from_source(
            _required(args, "source_dir"),
            artifact_name=str(artifact_name) if isinstance(artifact_name, str) and artifact_name else f"{target}/{harness}/generated.dict",
            max_files=int(args.get("max_files", 500)),
            max_file_bytes=int(args.get("max_file_bytes", 262144)),
            max_tokens=int(args.get("max_tokens", 64)),
        )
        artifact = self.state.artifact_put(run_id, str(generated["artifact_name"]), str(generated["artifact_content_b64"]))
        result = {
            "run_id": run_id,
            "target": target,
            "harness": harness,
            "source_dir": generated["source_dir"],
            "artifact": artifact,
            "dictionary_tokens": generated["dictionary_tokens"],
            "token_entries": generated["token_entries"],
            "source_files_scanned": generated["source_files_scanned"],
            "skipped": generated["skipped"],
            "truncated": generated["truncated"],
        }
        self.state.event_append(
            run_id,
            "dictionary_generate",
            {
                "target": target,
                "harness": harness,
                "artifact": artifact["name"],
                "token_count": len(result["dictionary_tokens"]),
                "source_files_scanned": result["source_files_scanned"],
                "skipped": result["skipped"],
                "truncated": result["truncated"],
            },
        )
        return result

    def _grammar_infer(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        target = _required(args, "target")
        harness = _required(args, "harness")
        inferred = infer_grammar_from_source(
            _required(args, "source_dir"),
            target=target,
            harness=harness,
            artifact_prefix=str(args.get("artifact_prefix") or f"{target}/{harness}/grammar"),
            max_files=int(args.get("max_files", 500)),
            max_file_bytes=int(args.get("max_file_bytes", 262144)),
            max_tokens=int(args.get("max_tokens", 32)),
            max_seeds=int(args.get("max_seeds", 32)),
        )
        grammar_artifact = self.state.artifact_put(
            run_id,
            str(inferred["grammar_artifact_name"]),
            str(inferred["grammar_content_b64"]),
        )
        seed_artifacts = []
        for seed in inferred["seed_artifacts"]:
            artifact = self.state.artifact_put(run_id, str(seed["artifact_name"]), str(seed["content_b64"]))
            seed_artifacts.append(
                {
                    **artifact,
                    "family": seed["family"],
                    "mutation": seed["mutation"],
                    "source_tokens": seed["source_tokens"],
                }
            )
        result = {
            "run_id": run_id,
            "target": target,
            "harness": harness,
            "source_dir": inferred["source_dir"],
            "artifact_prefix": inferred["artifact_prefix"],
            "grammar_artifact": grammar_artifact,
            "seed_artifacts": [artifact["name"] for artifact in seed_artifacts],
            "seeds": seed_artifacts,
            "dictionary_tokens": inferred["dictionary_tokens"],
            "token_entries": inferred["token_entries"],
            "source_files_scanned": inferred["source_files_scanned"],
            "skipped": inferred["skipped"],
            "truncated": inferred["truncated"],
            "blockers": inferred["blockers"],
        }
        self.state.event_append(
            run_id,
            "grammar_infer",
            {
                "target": target,
                "harness": harness,
                "grammar_artifact": grammar_artifact["name"],
                "seed_artifacts": result["seed_artifacts"],
                "dictionary_tokens": len(result["dictionary_tokens"]),
                "blockers": result["blockers"],
                "source_files_scanned": result["source_files_scanned"],
            },
        )
        return result

    def _concolic_plan(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        target = _required(args, "target")
        harness = _required(args, "harness")
        planned = plan_concolic_branches(
            _required(args, "source_dir"),
            target=target,
            harness=harness,
            artifact_prefix=str(args.get("artifact_prefix") or f"{target}/{harness}/concolic"),
            max_files=int(args.get("max_files", 500)),
            max_file_bytes=int(args.get("max_file_bytes", 262144)),
            max_tokens=int(args.get("max_tokens", 32)),
            max_seeds=int(args.get("max_seeds", 32)),
        )
        branch_plan_artifact = self.state.artifact_put(
            run_id,
            str(planned["branch_plan_artifact_name"]),
            str(planned["branch_plan_content_b64"]),
        )
        seed_artifacts = []
        for seed in planned["seed_artifacts"]:
            artifact = self.state.artifact_put(run_id, str(seed["artifact_name"]), str(seed["content_b64"]))
            seed_artifacts.append(
                {
                    **artifact,
                    "family": seed["family"],
                    "mutation": seed["mutation"],
                    "branch_ids": seed["branch_ids"],
                    "source_tokens": seed["source_tokens"],
                }
            )
        result = {
            "run_id": run_id,
            "target": target,
            "harness": harness,
            "source_dir": planned["source_dir"],
            "artifact_prefix": planned["artifact_prefix"],
            "branch_plan_artifact": branch_plan_artifact,
            "seed_artifacts": [artifact["name"] for artifact in seed_artifacts],
            "seeds": seed_artifacts,
            "dictionary_tokens": planned["dictionary_tokens"],
            "token_entries": planned["token_entries"],
            "branches": planned["branches"],
            "source_files_scanned": planned["source_files_scanned"],
            "skipped": planned["skipped"],
            "truncated": planned["truncated"],
            "blockers": planned["blockers"],
        }
        self.state.event_append(
            run_id,
            "concolic_plan",
            {
                "target": target,
                "harness": harness,
                "branch_plan_artifact": branch_plan_artifact["name"],
                "seed_artifacts": result["seed_artifacts"],
                "branches": len(result["branches"]),
                "blockers": result["blockers"],
                "source_files_scanned": result["source_files_scanned"],
            },
        )
        return result

    def _finding_record(self, args: dict[str, Any]) -> dict[str, Any]:
        return self.state.finding_record(
            _required(args, "run_id"),
            target=_required(args, "target"),
            harness=_required(args, "harness"),
            sanitizer=str(args.get("sanitizer") or "address"),
            error_token=_required(args, "error_token"),
            crash_output=str(args.get("crash_output") or args.get("error_token") or ""),
            poc_artifact=args.get("poc_artifact") or None,
            reproductions=int(args.get("reproductions")) if args.get("reproductions") not in (None, "") else None,
            verified=bool(args.get("verified")) if args.get("verified") is not None else None,
        )

    def _finding_dedupe(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        result = self.state.finding_dedupe(run_id)
        self.state.event_append(
            run_id,
            "finding_dedupe",
            {
                "groups": len(result["groups"]),
                "representatives": [
                    group.get("representative", {}).get("finding_id")
                    for group in result["groups"]
                    if isinstance(group, dict)
                ],
            },
        )
        return result

    def _finding_lifecycle_audit(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        result = audit_finding_lifecycle(
            run_id=run_id,
            findings=self.state.finding_list(run_id),
            artifacts=self.state.artifact_list(run_id)["artifacts"],
            events=self.state.event_list(run_id),
        )
        self.state.event_append(
            run_id,
            "finding_lifecycle_audit",
            {
                "ok": result["ok"],
                "score": result["score"],
                "blockers": result["blockers"],
            },
        )
        return result

    def _finding_grade(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        artifact_name = _required(args, "artifact_name")
        artifact = self.state.artifact_get(run_id, artifact_name)
        target = _required(args, "target")
        harness = _required(args, "harness")
        sanitizer = str(args.get("sanitizer") or "address")
        expected_error_token = args.get("expected_error_token") if isinstance(args.get("expected_error_token"), str) else None
        result = grade_finding_artifact(
            artifact_name=artifact_name,
            content_b64=str(artifact["content_b64"]),
            artifact_size=int(artifact["size"]),
            target=target,
            harness=harness,
            sanitizer=sanitizer,
            command=_command_arg(args.get("command")),
            expected_error_token=expected_error_token,
            benchmarks=discover_reference_benchmarks(self.reference_root, include_disabled=True),
            timeout_seconds=args.get("timeout_seconds", 10),
            repetitions=int(args.get("repetitions", 3)),
            workdir=args.get("workdir") if isinstance(args.get("workdir"), str) else None,
        )
        if result["verdict"] == "PASS" and bool(args.get("record_finding", False)):
            recorded = self._classify_verify_and_record(
                run_id,
                {
                    "target": target,
                    "harness": harness,
                    "sanitizer": sanitizer,
                    "error_token": str(expected_error_token or result["reproduction"]["observed_error_token"] or "AddressSanitizer"),
                    "crash_output": str(result["run"]["crash_output"]),
                    "poc_artifact": artifact_name,
                    "reproductions": int(result["reproduction"]["matching"]),
                    "verified": True,
                },
                source="finding_grade",
                record=True,
            )
            result["classification"] = recorded["classification"]
            if recorded["finding"] is not None:
                result["finding"] = recorded["finding"]
        self.state.event_append(
            run_id,
            "finding_graded",
            {
                "artifact": artifact_name,
                "target": target,
                "harness": harness,
                "verdict": result["verdict"],
                "record_recommended": result["record_recommended"],
                "fidelity_aligned": result["fidelity"]["aligned"],
            },
        )
        return {"run_id": run_id, **result}

    def _finding_classify(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        candidate = {
            "target": _required(args, "target"),
            "harness": _required(args, "harness"),
            "sanitizer": str(args.get("sanitizer") or "address"),
            "error_token": _required(args, "error_token"),
            "crash_output": _required(args, "crash_output"),
            "poc_artifact": args.get("poc_artifact") if isinstance(args.get("poc_artifact"), str) else None,
            "reproductions": int(args.get("reproductions")) if args.get("reproductions") not in (None, "") else None,
            "verified": bool(args.get("verified")) if args.get("verified") is not None else None,
        }
        result = classify_finding_candidate(
            existing_findings=self.state.finding_list(run_id),
            candidate=candidate,
            artifact_sizes=_artifact_sizes(self.state.artifact_list(run_id)),
        )
        self.state.event_append(
            run_id,
            "finding_classified",
            {
                "source": "finding_classify",
                "verdict": result["verdict"],
                "signature": result["signature"],
                "target": candidate["target"],
                "harness": candidate["harness"],
                "poc_artifact": candidate["poc_artifact"],
                "reason": result["reason"],
            },
        )
        return {"run_id": run_id, **result}

    def _classify_verify_and_record(
        self,
        run_id: str,
        candidate: dict[str, Any],
        *,
        source: str,
        record: bool,
        force_verdict: str | None = None,
    ) -> dict[str, Any]:
        classification = classify_finding_candidate(
            existing_findings=self.state.finding_list(run_id),
            candidate=candidate,
            artifact_sizes=_artifact_sizes(self.state.artifact_list(run_id)),
        )
        if force_verdict:
            classification = {
                **classification,
                "verdict": force_verdict,
                "reason": f"{source} records each verified fixture proof as separate fidelity evidence",
            }
        self.state.event_append(
            run_id,
            "finding_classified",
            {
                "source": source,
                "verdict": classification["verdict"],
                "signature": classification["signature"],
                "target": candidate["target"],
                "harness": candidate["harness"],
                "poc_artifact": candidate.get("poc_artifact"),
                "reason": classification["reason"],
            },
        )
        self.state.event_append(
            run_id,
            "finding_verified",
            {
                "source": source,
                "signature": classification["signature"],
                "target": candidate["target"],
                "harness": candidate["harness"],
                "poc_artifact": candidate.get("poc_artifact"),
                "verified": candidate.get("verified") is True,
                "reproductions": candidate.get("reproductions"),
                "error_token": candidate.get("error_token"),
            },
        )
        finding = None
        if record and classification["verdict"] in {"NEW", "DUP_BETTER", "FIXTURE_REPLAY"}:
            finding = self.state.finding_record(run_id, **candidate)
        return {"classification": classification, "finding": finding}

    def _harness_run(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        artifact_name = _required(args, "artifact_name")
        artifact = self.state.artifact_get(run_id, artifact_name)
        result = run_harness_artifact(
            artifact_name=artifact_name,
            content_b64=str(artifact["content_b64"]),
            command=_command_arg(args.get("command")),
            timeout_seconds=args.get("timeout_seconds", 10),
            repetitions=int(args.get("repetitions", 3)),
            workdir=args.get("workdir") if isinstance(args.get("workdir"), str) else None,
            expected_error_token=args.get("expected_error_token") if isinstance(args.get("expected_error_token"), str) else None,
        )
        result.update({"run_id": run_id, "target": _required(args, "target"), "harness": _required(args, "harness")})
        self.state.event_append(
            run_id,
            "harness_run",
            {
                "target": result["target"],
                "harness": result["harness"],
                "artifact": artifact_name,
                "verified": result["verified"],
                "crashes": result["crashes"],
                "matches_expected": result["matches_expected"],
                "observed_error_token": result["observed_error_token"],
            },
        )
        if result["verified"] and bool(args.get("record_finding", False)):
            recorded = self._classify_verify_and_record(
                run_id,
                {
                    "target": result["target"],
                    "harness": result["harness"],
                    "sanitizer": str(args.get("sanitizer") or "address"),
                    "error_token": str(args.get("expected_error_token") or result["observed_error_token"] or "AddressSanitizer"),
                    "crash_output": str(result["crash_output"]),
                    "poc_artifact": artifact_name,
                    "reproductions": int(result["matches_expected"] if args.get("expected_error_token") else result["crashes"]),
                    "verified": bool(result["verified"]),
                },
                source="harness_run",
                record=True,
            )
            result["classification"] = recorded["classification"]
            if recorded["finding"] is not None:
                result["finding"] = recorded["finding"]
        return result

    def _pov_minimize(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        artifact_name = _required(args, "artifact_name")
        artifact = self.state.artifact_get(run_id, artifact_name)
        result = minimize_pov_artifact(
            artifact_name=artifact_name,
            content_b64=str(artifact["content_b64"]),
            command=_command_arg(args.get("command")),
            expected_error_token=args.get("expected_error_token") if isinstance(args.get("expected_error_token"), str) else None,
            timeout_seconds=args.get("timeout_seconds", 10),
            repetitions=int(args.get("repetitions", 3)),
            workdir=args.get("workdir") if isinstance(args.get("workdir"), str) else None,
            max_attempts=int(args.get("max_attempts", 80)),
            preserve_signal=bool(args.get("preserve_signal", True)),
        )
        output_name = args.get("output_artifact") if isinstance(args.get("output_artifact"), str) and args.get("output_artifact") else f"{artifact_name}.min"
        minimized_artifact = None
        content_b64 = result.pop("content_b64", None)
        if result.get("ok") and isinstance(content_b64, str):
            minimized_artifact = self.state.artifact_put(run_id, output_name, content_b64)
            result["minimized_artifact"] = minimized_artifact
        self.state.event_append(
            run_id,
            "pov_minimize",
            {
                "artifact": artifact_name,
                "output_artifact": minimized_artifact["name"] if minimized_artifact else None,
                "verdict": result["verdict"],
                "original_size": result["original_size"],
                "minimized_size": result["minimized_size"],
                "preserved_signal": result.get("preserved_signal", False),
            },
        )
        return {**result, "run_id": run_id}

    def _fidelity_replay_campaign(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        project_filter = args.get("project") if isinstance(args.get("project"), str) and args.get("project") else None
        command_map = args.get("command_map") if isinstance(args.get("command_map"), dict) else {}
        default_command = args.get("default_command")
        include_disabled = bool(args.get("include_disabled", False))
        record_findings = bool(args.get("record_findings", True))
        max_cases = _bounded_optional_int(args.get("max_cases"), limit=100)
        benchmarks = discover_reference_benchmarks(self.reference_root, include_disabled=include_disabled)
        if project_filter:
            project_name = project_filter.removeprefix("localfuzz/c/")
            benchmarks = tuple(benchmark for benchmark in benchmarks if benchmark.project == project_name)
        if max_cases is not None:
            benchmarks = benchmarks[:max_cases]

        cases: list[dict[str, Any]] = []
        for benchmark in benchmarks:
            proof_bytes = Path(benchmark.proof_path).read_bytes()
            artifact_name = f"fixtures_{benchmark.project}_{benchmark.fixture}_{benchmark.harness}_proof.bin"
            artifact = self.state.artifact_put(
                run_id,
                artifact_name,
                base64.b64encode(proof_bytes).decode("ascii"),
            )
            case: dict[str, Any] = {
                "project": benchmark.project,
                "target": benchmark.target,
                "fixture": benchmark.fixture,
                "harness": benchmark.harness,
                "sanitizer": benchmark.sanitizer,
                "expected_error_token": benchmark.error_token,
                "proof_sha256": benchmark.proof_sha256,
                "artifact": artifact,
                "disabled_project": benchmark.disabled_project,
                "status": "imported",
            }
            command = _command_for_harness(command_map, benchmark.harness, default_command)
            if command is None:
                case["status"] = "blocked"
                case["blocker"] = "missing harness command"
                cases.append(case)
                continue
            run = run_harness_artifact(
                artifact_name=str(artifact["name"]),
                content_b64=base64.b64encode(proof_bytes).decode("ascii"),
                command=command,
                timeout_seconds=args.get("timeout_seconds", 10),
                repetitions=int(args.get("repetitions", 3)),
                workdir=args.get("workdir") if isinstance(args.get("workdir"), str) else None,
                expected_error_token=benchmark.error_token,
            )
            case["run"] = run
            case["status"] = "verified" if run["verified"] else "failed"
            if run["verified"]:
                recorded = self._classify_verify_and_record(
                    run_id,
                    {
                        "target": benchmark.target,
                        "harness": benchmark.harness,
                        "sanitizer": benchmark.sanitizer,
                        "error_token": benchmark.error_token,
                        "crash_output": str(run["crash_output"]),
                        "poc_artifact": str(artifact["name"]),
                        "reproductions": int(run["matches_expected"]),
                        "verified": bool(run["verified"]),
                    },
                    source="fidelity_replay_campaign",
                    record=record_findings,
                    force_verdict="FIXTURE_REPLAY",
                )
                case["classification"] = recorded["classification"]
                if recorded["finding"] is not None:
                    case["finding"] = recorded["finding"]
            cases.append(case)

        summary = {
            "run_id": run_id,
            "project": project_filter,
            "total_cases": len(cases),
            "artifacts_imported": len(cases),
            "executed": sum(1 for case in cases if "run" in case),
            "verified": sum(1 for case in cases if case["status"] == "verified"),
            "failed": sum(1 for case in cases if case["status"] == "failed"),
            "blocked": sum(1 for case in cases if case["status"] == "blocked"),
            "findings_recorded": sum(1 for case in cases if "finding" in case),
        }
        payload = {**summary, "cases": cases}
        self.state.event_append(run_id, "fidelity_replay_campaign", summary)
        return payload

    def _fuzz_campaign(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        target = _required(args, "target")
        harness = _required(args, "harness")
        sanitizer = str(args.get("sanitizer") or "address")
        expected_error_token = args.get("expected_error_token") if isinstance(args.get("expected_error_token"), str) else None
        seed_names = _string_list(args.get("seed_artifacts"), key="seed_artifacts")
        seed_artifacts = []
        for seed_name in seed_names:
            artifact = self.state.artifact_get(run_id, seed_name)
            seed_artifacts.append({"name": str(artifact["name"]), "content_b64": str(artifact["content_b64"])})

        max_iterations = _bounded_optional_int(args.get("max_iterations"), limit=100) or 25
        feedback_rounds = _bounded_optional_int(args.get("feedback_rounds"), limit=5) or 1
        dictionary = _string_list(args.get("dictionary"), key="dictionary")
        command = _command_arg(args.get("harness_command"))
        timeout_seconds = args.get("timeout_seconds", 10)
        repetitions = int(args.get("repetitions", 3))
        record_findings = bool(args.get("record_findings", True))
        stop_on_first_finding = bool(args.get("stop_on_first_finding", False))

        known_features: set[str] = set()
        executed_hashes: set[str] = set()
        promoted: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        iterations: list[dict[str, Any]] = []
        round_summaries: list[dict[str, Any]] = []
        round_parents = seed_artifacts or [{"name": "empty-seed", "content_b64": ""}]
        stopped = False
        for round_index in range(feedback_rounds):
            remaining = max_iterations - len(iterations)
            if remaining <= 0 or not round_parents:
                break
            rounds_left = feedback_rounds - round_index
            round_budget = max(1, remaining // rounds_left)
            candidates = build_fuzz_candidates(
                round_parents,
                dictionary_tokens=dictionary,
                max_iterations=round_budget,
                exclude_sha256=executed_hashes,
            )
            next_parents: list[dict[str, str]] = []
            round_summary = {
                "round": round_index,
                "parents": [parent["name"] for parent in round_parents],
                "scheduled": len(candidates),
                "executed": 0,
                "promoted": [],
                "new_features": [],
            }
            if not candidates:
                round_summaries.append(round_summary)
                break

            for candidate in candidates:
                executed_hashes.add(str(candidate["sha256"]))
                index = len(iterations)
                artifact_name = _fuzz_artifact_name(target, harness, index, str(candidate["family"]))
                artifact = self.state.artifact_put(run_id, artifact_name, str(candidate["content_b64"]))
                run = run_harness_artifact(
                    artifact_name=str(artifact["name"]),
                    content_b64=str(candidate["content_b64"]),
                    command=command,
                    timeout_seconds=timeout_seconds,
                    repetitions=repetitions,
                    workdir=args.get("workdir") if isinstance(args.get("workdir"), str) else None,
                    expected_error_token=expected_error_token,
                )
                features = extract_coverage_features(run)
                new_features = sorted(set(features) - known_features)
                known_features.update(new_features)
                promoted_entry = None
                if new_features:
                    promoted_entry = {
                        "artifact": artifact["name"],
                        "sha256": artifact["sha256"],
                        "new_features": new_features,
                        "family": candidate["family"],
                        "mutation": candidate["mutation"],
                        "round": round_index,
                    }
                    promoted.append(promoted_entry)
                    round_summary["promoted"].append(promoted_entry)
                    round_summary["new_features"].extend(new_features)
                    next_parents.append({"name": str(artifact["name"]), "content_b64": str(candidate["content_b64"])})

                finding = None
                classification = None
                if run["verified"] and record_findings:
                    recorded = self._classify_verify_and_record(
                        run_id,
                        {
                            "target": target,
                            "harness": harness,
                            "sanitizer": sanitizer,
                            "error_token": str(expected_error_token or run["observed_error_token"] or "AddressSanitizer"),
                            "crash_output": str(run["crash_output"]),
                            "poc_artifact": str(artifact["name"]),
                            "reproductions": int(run["matches_expected"] if expected_error_token else run["crashes"]),
                            "verified": bool(run["verified"]),
                        },
                        source="fuzz_campaign",
                        record=True,
                    )
                    classification = recorded["classification"]
                    finding = recorded["finding"]
                    if finding is not None:
                        findings.append(finding)

                iterations.append(
                    {
                        "index": index,
                        "round": round_index,
                        "artifact": artifact,
                        "family": candidate["family"],
                        "mutation": candidate["mutation"],
                        "parent_artifacts": candidate["parent_artifacts"],
                        "features": features,
                        "new_features": new_features,
                        "promoted": promoted_entry is not None,
                        "run": summarize_harness_run(run),
                        "classification": classification,
                        "finding": finding,
                    }
                )
                round_summary["executed"] += 1
                if finding is not None and stop_on_first_finding:
                    stopped = True
                    break

            round_summary["new_features"] = sorted(set(round_summary["new_features"]))
            round_summaries.append(round_summary)
            if stopped:
                break
            round_parents = next_parents

        summary = {
            "run_id": run_id,
            "target": target,
            "harness": harness,
            "sanitizer": sanitizer,
            "seed_artifacts": seed_names,
            "scheduler": {"mode": "coverage-feedback", "feedback_rounds": feedback_rounds, "dictionary_tokens": len(dictionary)},
            "generated": sum(round_info["scheduled"] for round_info in round_summaries),
            "executed": len(iterations),
            "rounds_executed": len(round_summaries),
            "coverage_features": sorted(known_features),
            "promoted_corpus": len(promoted),
            "crashes": sum(1 for item in iterations if item["run"]["crashes"] > 0),
            "verified_findings": len(findings),
            "stopped_on_first_finding": bool(iterations and iterations[-1].get("finding") and stop_on_first_finding),
        }
        self.state.event_append(run_id, "fuzz_campaign", {**summary, "rounds": round_summaries, "promoted": promoted})
        return {**summary, "rounds": round_summaries, "promoted": promoted, "findings": findings, "iterations": iterations}

    def _patch_grade(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        patch_artifact_name = _required(args, "patch_artifact")
        pov_artifact_name = _required(args, "pov_artifact")
        patch_artifact = self.state.artifact_get(run_id, patch_artifact_name)
        pov_artifact = self.state.artifact_get(run_id, pov_artifact_name)
        reattack_artifacts = []
        for artifact_name in args.get("reattack_artifacts") or []:
            if not isinstance(artifact_name, str):
                raise ValueError("reattack_artifacts must contain artifact names")
            artifact = self.state.artifact_get(run_id, artifact_name)
            reattack_artifacts.append({"name": artifact_name, "content_b64": str(artifact["content_b64"])})
        result = grade_patch_artifact(
            patch_name=patch_artifact_name,
            patch_content_b64=str(patch_artifact["content_b64"]),
            source_dir=_required(args, "source_dir"),
            pov_name=pov_artifact_name,
            pov_content_b64=str(pov_artifact["content_b64"]),
            harness_command=_command_arg(args.get("harness_command")),
            expected_error_token=_required(args, "expected_error_token"),
            build_command=_optional_command(args.get("build_command")),
            test_command=_optional_command(args.get("test_command")),
            reattack_artifacts=reattack_artifacts,
            reattack_command=_optional_command(args.get("reattack_command")),
            timeout_seconds=args.get("timeout_seconds", 10),
            repetitions=int(args.get("repetitions", 3)),
        )
        self.state.event_append(
            run_id,
            "patch_grade",
            {
                "patch_artifact": patch_artifact_name,
                "pov_artifact": pov_artifact_name,
                "passed": result["passed"],
                "tier": result["tier"],
            },
        )
        return {**result, "run_id": run_id}

    def _patch_candidate_record(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = _required(args, "run_id")
        finding_id = args.get("finding_id") if isinstance(args.get("finding_id"), str) and args.get("finding_id") else None
        artifact_name = args.get("artifact_name")
        candidate = prepare_patch_candidate(
            patch_content_b64=_required(args, "patch_content_b64"),
            artifact_name=str(artifact_name) if isinstance(artifact_name, str) and artifact_name else f"patches/{finding_id or 'candidate'}.diff",
            finding_id=finding_id,
            rationale=str(args.get("rationale") or ""),
            variants_checked=_string_list(args.get("variants_checked"), key="variants_checked"),
        )
        patch_artifact = self.state.artifact_put(run_id, str(candidate["artifact_name"]), str(candidate["content_b64"]))
        metadata_artifact = self.state.artifact_put(
            run_id,
            str(candidate["metadata_artifact_name"]),
            str(candidate["metadata_content_b64"]),
        )
        result = {
            "run_id": run_id,
            "patch_artifact": patch_artifact,
            "metadata_artifact": metadata_artifact,
            "candidate": candidate["metadata"],
        }
        self.state.event_append(
            run_id,
            "patch_candidate_recorded",
            {
                "finding_id": finding_id,
                "patch_artifact": patch_artifact["name"],
                "metadata_artifact": metadata_artifact["name"],
                "changed_paths": candidate["metadata"]["changed_paths"],
            },
        )
        return result

    def _runtime_guard_audit(self, _args: dict[str, Any]) -> dict[str, Any]:
        findings = audit_runtime_guard_runtime_calls(self.audit_roots)
        return {"ok": not findings, "findings": [finding.to_dict() for finding in findings]}

    def _engine_parity_audit(self, _args: dict[str, Any]) -> dict[str, Any]:
        repo_root = Path(__file__).resolve().parents[2]
        plugin_root = repo_root / "claude-plugin" / "agentic-fuzz-engine"
        engine_root = Path(__file__).resolve().parent
        return audit_engine_parity(
            tool_specs=self.tool_specs(),
            plugin_root=plugin_root,
            engine_root=engine_root,
            audit_roots=self.audit_roots or (engine_root, plugin_root),
        )

    def _store_runtime_output_files(
        self,
        run_id: str,
        files: list[dict[str, Any]],
        *,
        artifact_prefix: str,
    ) -> list[dict[str, Any]]:
        stored = []
        seen: set[str] = set()
        for item in files:
            path_value = item.get("path")
            if not isinstance(path_value, str):
                continue
            path = Path(path_value)
            if not path.is_file():
                continue
            digest = str(item.get("sha256") or "")
            if digest and digest in seen:
                continue
            data = path.read_bytes()
            seen.add(sha256(data).hexdigest())
            artifact_name = f"{artifact_prefix}/{path.name}"
            stored.append(self.state.artifact_put(run_id, artifact_name, base64.b64encode(data).decode("ascii")))
        return stored


def _required(args: dict[str, Any], key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing required argument: {key}")
    return value


def _command_arg(value: Any) -> list[str] | str:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise ValueError("missing required argument: command")


def _optional_command(value: Any) -> list[str] | str | None:
    if value in (None, "", []):
        return None
    return _command_arg(value)


def _command_sequence_arg(value: Any) -> list[list[str]] | None:
    if value in (None, "", []):
        return None
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return [value]
    if isinstance(value, list) and all(isinstance(item, list) and all(isinstance(arg, str) for arg in item) for item in value):
        return value
    raise ValueError("build_commands must be an argv list or a list of argv lists")


def _command_for_harness(command_map: dict[str, Any], harness: str, default_command: Any) -> list[str] | str | None:
    value = command_map.get(harness)
    if value is None:
        value = default_command
    if value is None:
        return None
    return _command_arg(value)


def _string_list(value: Any, *, key: str) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise ValueError(f"{key} must be a list of strings")


def _bounded_optional_int(value: Any, *, limit: int) -> int | None:
    if value in (None, ""):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("max_cases must be an integer") from exc
    if parsed <= 0 or parsed > limit:
        raise ValueError(f"max_cases must be between 1 and {limit}")
    return parsed


def _fuzz_artifact_name(target: str, harness: str, index: int, family: str) -> str:
    name = f"fuzz_{target}_{harness}_{index:04d}_{family}.bin"
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in name)[:180]


def _artifact_sizes(artifact_list: dict[str, Any]) -> dict[str, int]:
    sizes = {}
    for artifact in artifact_list.get("artifacts", []):
        if isinstance(artifact, dict) and isinstance(artifact.get("name"), str):
            sizes[str(artifact["name"])] = int(artifact.get("size") or 0)
    return sizes


def _tool(name: str, description: str, properties: dict[str, str]) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": {key: {"type": value} for key, value in properties.items()},
            "additionalProperties": True,
        },
    }

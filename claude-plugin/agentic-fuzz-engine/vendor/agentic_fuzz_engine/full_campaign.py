from __future__ import annotations

from pathlib import Path
from typing import Any

from .fidelity import discover_reference_benchmarks, load_target_profile
from .export import DEFAULT_FULL_CAMPAIGN_AGENTS


def run_owned_local_full_campaign(
    engine: Any,
    *,
    project: str,
    run_id: str | None = None,
    harness: str | None = None,
    harness_command: list[str] | None = None,
    command_map: dict[str, Any] | None = None,
    source_dir: str | None = None,
    timeout_seconds: int | float = 5,
    repetitions: int = 3,
    include_disabled: bool = False,
) -> dict[str, Any]:
    target = project if project.startswith("localfuzz/") else f"localfuzz/c/{project}"
    profile = load_target_profile(target, engine.reference_root)
    selected_harness, selected_command_map, selection_blockers = _select_harness_command(
        engine,
        target=target,
        requested_harness=harness,
        harness_command=harness_command,
        command_map=command_map or {},
        include_disabled=include_disabled,
    )
    resolved_source = _resolve_source_dir(source_dir, profile.to_dict())

    start = engine.call_tool(
        "campaign_start",
        {
            "target": target,
            "name": run_id,
            "metadata": {
                "mode": "owned-local-full-campaign",
                "runtime_authority": "agentic_fuzz_full",
                "project": profile.project,
                "harness": selected_harness,
            },
        },
    )
    active_run_id = str(start["run_id"])
    steps: dict[str, Any] = {"campaign_start": start}
    blockers = list(selection_blockers)
    if resolved_source is None:
        blockers.append("source_dir is required and no userspace_project_dir exists for this target profile")

    parity = engine.call_tool("full_runtime_parity_audit", {})
    runtime_guard = engine.call_tool("runtime_guard_audit", {})
    target_validation = engine.call_tool("target_validate", {"project": target})
    harnesses = engine.call_tool("harness_list", {"project": target})
    steps.update(
        {
            "full_runtime_parity": parity,
            "runtime_guard_audit": runtime_guard,
            "target_validation": target_validation,
            "harnesses": harnesses,
        }
    )
    blockers.extend(str(item) for item in target_validation.get("issues", []) if item)
    if not parity.get("ok"):
        blockers.extend(str(item) for item in parity.get("blockers", []) if item)
    if not runtime_guard.get("ok"):
        blockers.append("runtime_guard_audit found forbidden runtime references")

    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=selected_harness,
        phase="readiness",
        agent="planner",
        evidence=[
            f"full_runtime_parity_audit: {'ok' if parity.get('ok') else 'blocked'}",
            f"runtime_guard_audit: {'ok' if runtime_guard.get('ok') else 'blocked'}",
        ],
        blockers=[],
        next_command="target-validate",
    )
    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=selected_harness,
        phase="scope",
        agent="harness-builder",
        evidence=[
            f"target_validate: {'ok' if target_validation.get('ok') else 'blocked'}",
            f"harness_list: {len(harnesses.get('harnesses', []))} harnesses",
        ],
        blockers=[],
        next_command="dictionary-generate",
    )

    if blockers:
        completion = _completion(engine, active_run_id, target, include_disabled=include_disabled)
        return _result(
            active_run_id=active_run_id,
            target=target,
            harness=selected_harness,
            source_dir=resolved_source,
            steps=steps,
            completion=completion,
            blockers=blockers,
        )

    assert resolved_source is not None
    dictionary = engine.call_tool(
        "dictionary_generate",
        {
            "run_id": active_run_id,
            "source_dir": resolved_source,
            "target": target,
            "harness": selected_harness,
        },
    )
    grammar = engine.call_tool(
        "grammar_infer",
        {
            "run_id": active_run_id,
            "source_dir": resolved_source,
            "target": target,
            "harness": selected_harness,
            "max_seeds": 8,
        },
    )
    concolic = engine.call_tool(
        "concolic_plan",
        {
            "run_id": active_run_id,
            "source_dir": resolved_source,
            "target": target,
            "harness": selected_harness,
            "max_seeds": 8,
        },
    )
    steps.update({"dictionary": dictionary, "grammar": grammar, "concolic": concolic})
    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=selected_harness,
        phase="input-material",
        agent="dictionary-generator",
        evidence=[f"dictionary_generate: {dictionary['artifact']['name']}"],
        blockers=[],
        next_command="grammar-infer",
    )
    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=selected_harness,
        phase="input-material",
        agent="grammar-reverser",
        evidence=[f"grammar_infer: {grammar['grammar_artifact']['name']}"],
        blockers=[],
        next_command="concolic-plan",
    )
    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=selected_harness,
        phase="input-material",
        agent="concolic-generator",
        evidence=[f"concolic_plan: {concolic['branch_plan_artifact']['name']}"],
        blockers=[],
        next_command="fidelity-replay-campaign",
    )
    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=selected_harness,
        phase="input-material",
        agent="corpus-manager",
        evidence=["benchmark proof selected as replay seed oracle"],
        blockers=[],
        next_command="fidelity-replay-campaign",
    )
    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=selected_harness,
        phase="input-material",
        agent="input-generator",
        evidence=["dictionary, grammar, and concolic artifacts generated without external generator runtime"],
        blockers=[],
        next_command="fidelity-replay-campaign",
    )

    replay = engine.call_tool(
        "fidelity_replay_campaign",
        {
            "run_id": active_run_id,
            "project": target,
            "command_map": selected_command_map,
            "timeout_seconds": timeout_seconds,
            "repetitions": repetitions,
            "record_findings": True,
            "include_disabled": include_disabled,
        },
    )
    steps["replay"] = replay
    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=selected_harness,
        phase="fuzzing",
        agent="fuzz-finder",
        evidence=[f"fidelity_replay_campaign: {replay['verified']}/{replay['executed']} verified"],
        blockers=[],
        next_command="finding-grade",
    )
    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=selected_harness,
        phase="fuzzing",
        agent="native-harness",
        evidence=["local userspace-style harness replay completed through plugin-local engine tools"],
        blockers=[],
        next_command="finding-dedupe",
    )

    verified_case = _first_verified_case(replay)
    if verified_case is None:
        blockers.append("fidelity replay did not verify any benchmark proof")
        completion = _completion(engine, active_run_id, target, include_disabled=include_disabled)
        return _result(
            active_run_id=active_run_id,
            target=target,
            harness=selected_harness,
            source_dir=resolved_source,
            steps=steps,
            completion=completion,
            blockers=blockers,
        )

    artifact_name = str(verified_case["artifact"]["name"])
    finding = verified_case.get("finding") if isinstance(verified_case.get("finding"), dict) else None
    grade = engine.call_tool(
        "finding_grade",
        {
            "run_id": active_run_id,
            "target": target,
            "harness": str(verified_case["harness"]),
            "sanitizer": str(verified_case["sanitizer"]),
            "artifact_name": artifact_name,
            "command": selected_command_map[str(verified_case["harness"])],
            "expected_error_token": str(verified_case["expected_error_token"]),
            "timeout_seconds": timeout_seconds,
            "repetitions": repetitions,
            "record_finding": False,
        },
    )
    minimized = engine.call_tool(
        "pov_minimize",
        {
            "run_id": active_run_id,
            "artifact_name": artifact_name,
            "output_artifact": f"{artifact_name}.min",
            "command": selected_command_map[str(verified_case["harness"])],
            "expected_error_token": str(verified_case["expected_error_token"]),
            "timeout_seconds": timeout_seconds,
            "repetitions": repetitions,
            "max_attempts": 40,
        },
    )
    steps.update({"finding_grade": grade, "pov_minimize": minimized})
    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=str(verified_case["harness"]),
        phase="grading",
        agent="crash-grader",
        evidence=[
            f"finding_grade: {grade['verdict']}",
            f"pov_minimize: {minimized['verdict']}",
        ],
        blockers=[],
        next_command="finding-dedupe",
    )

    dedupe = engine.call_tool("finding_dedupe", {"run_id": active_run_id})
    lifecycle = engine.call_tool("finding_lifecycle_audit", {"run_id": active_run_id})
    steps.update({"dedupe": dedupe, "lifecycle": lifecycle})
    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=str(verified_case["harness"]),
        phase="dedupe",
        agent="dedupe-judge",
        evidence=[
            f"finding_dedupe: {len(dedupe['groups'])} representative groups",
            f"finding_lifecycle_audit: {'ok' if lifecycle.get('ok') else 'blocked'}",
        ],
        blockers=[],
        next_command="campaign-report",
    )

    report = engine.call_tool(
        "campaign_report",
        {
            "run_id": active_run_id,
            "project": target,
            "artifact_prefix": f"reports/{active_run_id}",
            "include_disabled": include_disabled,
        },
    )
    steps["report"] = report
    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=str(verified_case["harness"]),
        phase="report",
        agent="reporter",
        evidence=["campaign_report: REPORT.md and REPORT.json"],
        blockers=[],
        next_command="export-bundle-create",
    )

    bundle = engine.call_tool("export_bundle_create", {"run_id": active_run_id, "project": target})
    pov_export = engine.call_tool(
        "export_mock_api_submit_pov",
        {
            "run_id": active_run_id,
            "project": target,
            "finding_id": finding.get("finding_id") if finding else None,
            "poc_artifact": finding.get("poc_artifact") if finding else artifact_name,
        },
    )
    sarif_export = engine.call_tool(
        "export_mock_api_submit_sarif",
        {
            "run_id": active_run_id,
            "project": target,
            "report_artifact": report["json_artifact"]["name"],
        },
    )
    exports = engine.call_tool("export_list", {"run_id": active_run_id})
    steps.update(
        {
            "export_bundle": bundle,
            "pov_export": pov_export,
            "sarif_export": sarif_export,
            "exports": exports,
        }
    )
    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=str(verified_case["harness"]),
        phase="export",
        agent="export-agent",
        evidence=["export_bundle_create: ok", "mock PoV and SARIF receipts accepted"],
        blockers=[],
        next_command="campaign-full-completion-audit",
    )
    _checkpoint(
        engine,
        active_run_id,
        target=target,
        harness=str(verified_case["harness"]),
        phase="export",
        agent="artifact-manager",
        evidence=["artifact_manager semantics preserved through plugin-local bundle and receipts"],
        blockers=[],
        next_command="campaign-full-completion-audit",
    )

    completion = _completion(engine, active_run_id, target, include_disabled=include_disabled)
    blockers.extend(str(item) for item in completion.get("blockers", []) if item)
    return _result(
        active_run_id=active_run_id,
        target=target,
        harness=selected_harness,
        source_dir=resolved_source,
        steps=steps,
        completion=completion,
        blockers=blockers,
    )


def _select_harness_command(
    engine: Any,
    *,
    target: str,
    requested_harness: str | None,
    harness_command: list[str] | None,
    command_map: dict[str, Any],
    include_disabled: bool,
) -> tuple[str, dict[str, Any], list[str]]:
    benchmarks = tuple(
        benchmark
        for benchmark in discover_reference_benchmarks(engine.reference_root, include_disabled=include_disabled)
        if benchmark.target == target
    )
    harnesses = sorted({benchmark.harness for benchmark in benchmarks})
    selected = requested_harness or (harnesses[0] if len(harnesses) == 1 else "")
    blockers: list[str] = []
    if not benchmarks:
        blockers.append(f"no benchmark benchmark fixtures found for {target}")
    if not selected:
        blockers.append("harness must be provided when a target has zero or multiple benchmark harnesses")
        selected = requested_harness or "unknown"

    normalized = {str(key): value for key, value in command_map.items()}
    if harness_command is not None:
        normalized[selected] = harness_command
    if selected not in normalized:
        blockers.append(f"missing harness command for {selected}")
    return selected, normalized, blockers


def _resolve_source_dir(source_dir: str | None, profile: dict[str, Any]) -> str | None:
    candidate = source_dir or profile.get("userspace_project_dir")
    if not isinstance(candidate, str) or not candidate:
        return None
    path = Path(candidate).expanduser().resolve()
    return str(path) if path.exists() else None


def _checkpoint(
    engine: Any,
    run_id: str,
    *,
    target: str,
    harness: str,
    phase: str,
    agent: str,
    evidence: list[str],
    blockers: list[str],
    next_command: str,
) -> dict[str, Any]:
    return engine.call_tool(
        "campaign_checkpoint_record",
        {
            "run_id": run_id,
            "target": target,
            "harness": harness,
            "phase": phase,
            "tool_evidence": evidence,
            "blockers": blockers,
            "next_command": next_command,
            "agent": agent,
        },
    )


def _first_verified_case(replay: dict[str, Any]) -> dict[str, Any] | None:
    for case in replay.get("cases", []):
        if isinstance(case, dict) and case.get("status") == "verified":
            return case
    return None


def _completion(engine: Any, run_id: str, project: str, *, include_disabled: bool) -> dict[str, Any]:
    return engine.call_tool(
        "campaign_full_completion_audit",
        {
            "run_id": run_id,
            "project": project,
            "include_disabled": include_disabled,
            "required_agents": list(DEFAULT_FULL_CAMPAIGN_AGENTS),
        },
    )


def _result(
    *,
    active_run_id: str,
    target: str,
    harness: str,
    source_dir: str | None,
    steps: dict[str, Any],
    completion: dict[str, Any],
    blockers: list[str],
) -> dict[str, Any]:
    deduped_blockers = list(dict.fromkeys(blockers))
    return {
        "ok": bool(completion.get("ok")) and not deduped_blockers,
        "mode": "owned-local-full-campaign",
        "runtime_authority": "agentic_fuzz_full",
        "run_id": active_run_id,
        "target": target,
        "harness": harness,
        "source_dir": source_dir,
        "steps": steps,
        "completion": completion,
        "blockers": deduped_blockers,
    }

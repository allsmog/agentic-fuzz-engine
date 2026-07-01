from __future__ import annotations

from typing import Any


DEFAULT_REQUIRED_PHASES = ("readiness", "scope", "input-material", "fuzzing", "grading", "dedupe", "report")


def audit_campaign_completion(
    *,
    run_id: str,
    project: str | None,
    engine_parity: dict[str, Any],
    runtime_guard: dict[str, Any],
    fixture_validation: dict[str, Any],
    finding_lifecycle: dict[str, Any],
    phase_audit: dict[str, Any],
    fidelity_audit: dict[str, Any],
    artifacts: list[dict[str, Any]],
    events: list[dict[str, Any]],
    require_report: bool = True,
    required_phases: tuple[str, ...] | list[str] | None = None,
) -> dict[str, Any]:
    required = _required_phases(phase_audit, required_phases)
    gates = {
        "engine_parity": _engine_parity_gate(engine_parity),
        "runtime_guard_runtime": _runtime_guard_gate(runtime_guard),
        "fixture_validation": _fixture_gate(fixture_validation),
        "finding_lifecycle": _finding_lifecycle_gate(finding_lifecycle),
        "phase_coverage": _phase_gate(phase_audit, required_phases=required),
        "fixture_fidelity": _fidelity_gate(fidelity_audit),
        "report_artifacts": _report_gate(artifacts, events, require_report=require_report),
    }
    blockers = [
        f"{name}: {blocker}"
        for name, gate in gates.items()
        for blocker in gate.get("blockers", [])
    ]
    return {
        "run_id": run_id,
        "project": project,
        "ok": all(bool(gate.get("ok")) for gate in gates.values()),
        "gates": gates,
        "blockers": blockers,
    }


def _engine_parity_gate(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": bool(result.get("ok")),
        "score": result.get("score", {}),
        "tool_count": result.get("tool_count", 0),
        "agent_count": result.get("agent_count", 0),
        "skill_count": result.get("skill_count", 0),
        "blockers": _string_items(result.get("blockers")) or _missing_guardrail_blockers(result),
    }


def _runtime_guard_gate(result: dict[str, Any]) -> dict[str, Any]:
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    blockers = []
    for finding in findings:
        if isinstance(finding, dict):
            path = finding.get("path") or finding.get("file") or "unknown"
            line = finding.get("line") or finding.get("line_number")
            reason = finding.get("reason") or finding.get("match") or "forbidden runtime reference"
            location = f"{path}:{line}" if line else str(path)
            blockers.append(f"{location} {reason}")
    return {
        "ok": bool(result.get("ok")),
        "finding_count": len(findings),
        "blockers": blockers,
    }


def _fixture_gate(result: dict[str, Any]) -> dict[str, Any]:
    blockers = []
    if int(result.get("total_fixtures") or 0) <= 0:
        blockers.append("no benchmark Fixture fixtures discovered")
    for missing in result.get("missing") or []:
        if isinstance(missing, dict):
            blockers.append(
                f"{missing.get('project')}:{missing.get('fixture')} missing {missing.get('field')}"
            )
    for invalid in result.get("invalid_patches") or []:
        if isinstance(invalid, dict):
            blockers.append(
                f"{invalid.get('project')}:{invalid.get('fixture')} invalid patch.diff: {invalid.get('error')}"
            )
    return {
        "ok": bool(result.get("ok")) and not blockers,
        "total_fixtures": result.get("total_fixtures", 0),
        "enabled_fixtures": result.get("enabled_fixtures", 0),
        "disabled_fixtures": result.get("disabled_fixtures", 0),
        "projects": result.get("projects", []),
        "blockers": blockers,
    }


def _phase_gate(result: dict[str, Any], *, required_phases: tuple[str, ...]) -> dict[str, Any]:
    blockers = _string_items(result.get("blockers"))
    attempted = result.get("attempted_phases") if isinstance(result.get("attempted_phases"), list) else []
    checkpointed = result.get("checkpointed_phases") if isinstance(result.get("checkpointed_phases"), list) else []
    missing_required = [phase for phase in required_phases if phase not in checkpointed]
    for phase in missing_required:
        blockers.append(f"required phase missing checkpoint: {phase}")
    if not attempted and not checkpointed:
        blockers.append("no campaign phase evidence recorded")
    if attempted and not checkpointed:
        blockers.append("no phase checkpoints recorded")
    return {
        "ok": bool(result.get("ok")) and not blockers,
        "coverage_ok": bool(result.get("coverage_ok")),
        "required_phases": list(required_phases),
        "missing_required_phases": missing_required,
        "attempted_phases": attempted,
        "checkpointed_phases": checkpointed,
        "missing_checkpoint_phases": result.get("missing_checkpoint_phases", []),
        "stale_checkpoint_phases": result.get("stale_checkpoint_phases", []),
        "blocked_phases": result.get("blocked_phases", []),
        "blockers": blockers,
    }


def _required_phases(result: dict[str, Any], configured: tuple[str, ...] | list[str] | None) -> tuple[str, ...]:
    if configured:
        phases = (*DEFAULT_REQUIRED_PHASES, *(str(phase) for phase in configured if phase))
    else:
        phases = DEFAULT_REQUIRED_PHASES
    attempted = set(result.get("attempted_phases") if isinstance(result.get("attempted_phases"), list) else [])
    checkpointed = set(result.get("checkpointed_phases") if isinstance(result.get("checkpointed_phases"), list) else [])
    if "patch" in attempted or "patch" in checkpointed:
        phases = (*phases, "patch")
    return _dedupe_phases(phases)


def _dedupe_phases(phases: tuple[str, ...]) -> tuple[str, ...]:
    order = ("readiness", "scope", "input-material", "fuzzing", "grading", "dedupe", "patch", "report", "export")
    values = set(phases)
    return tuple(phase for phase in order if phase in values) + tuple(sorted(values - set(order)))


def _finding_lifecycle_gate(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": bool(result.get("ok")),
        "score": result.get("score", {}),
        "dedupe": result.get("dedupe", {}),
        "blockers": _string_items(result.get("blockers")),
    }


def _fidelity_gate(result: dict[str, Any]) -> dict[str, Any]:
    score = result.get("score") if isinstance(result.get("score"), dict) else {}
    blockers = _string_items(result.get("blockers"))
    if int(score.get("enabled_fixtures") or 0) <= 0:
        blockers.append("no enabled Fixtures in audit scope")
    return {
        "ok": bool(result.get("ok")) and not blockers,
        "score": score,
        "harness_coverage": result.get("harness_coverage", {}),
        "unmatched_findings": result.get("unmatched_findings", []),
        "blockers": blockers,
    }


def _report_gate(
    artifacts: list[dict[str, Any]],
    events: list[dict[str, Any]],
    *,
    require_report: bool,
) -> dict[str, Any]:
    names = sorted(str(item.get("name")) for item in artifacts if isinstance(item, dict) and item.get("name"))
    markdown = [name for name in names if name.endswith("REPORT.md")]
    json_reports = [name for name in names if name.endswith("REPORT.json")]
    report_events = [event for event in events if event.get("type") == "campaign_report"]
    blockers = []
    if require_report:
        if not markdown:
            blockers.append("missing Markdown REPORT.md artifact")
        if not json_reports:
            blockers.append("missing JSON REPORT.json artifact")
        if not report_events:
            blockers.append("missing campaign_report event")
    return {
        "ok": not blockers,
        "required": require_report,
        "markdown_artifacts": markdown,
        "json_artifacts": json_reports,
        "campaign_report_events": len(report_events),
        "blockers": blockers,
    }


def _missing_guardrail_blockers(result: dict[str, Any]) -> list[str]:
    guardrails = result.get("guardrails") if isinstance(result.get("guardrails"), dict) else {}
    if guardrails and not guardrails.get("ok"):
        findings = guardrails.get("findings") if isinstance(guardrails.get("findings"), list) else []
        return [f"{len(findings)} forbidden runtime references"]
    return []


def _string_items(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item]

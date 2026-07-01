from __future__ import annotations

from typing import Any


EVENT_PHASES: dict[str, tuple[str, ...]] = {
    "target_build_probe": ("scope",),
    "corpus_import": ("input-material",),
    "dictionary_generate": ("input-material",),
    "grammar_infer": ("input-material",),
    "concolic_plan": ("input-material",),
    "crash_import": ("fuzzing",),
    "fidelity_replay_campaign": ("fuzzing",),
    "fuzz_campaign": ("fuzzing",),
    "harness_run": ("grading",),
    "finding_grade": ("grading",),
    "finding_graded": ("grading",),
    "pov_minimize": ("grading",),
    "finding_recorded": ("grading",),
    "finding_classified": ("dedupe",),
    "finding_dedupe": ("dedupe",),
    "patch_candidate_recorded": ("patch",),
    "patch_grade": ("patch",),
    "campaign_fidelity_audit": ("report",),
    "campaign_report": ("report",),
    "export_bundle_created": ("export",),
    "export_accepted": ("export",),
    "export_rejected": ("export",),
}


def audit_campaign_phases(
    *,
    run_id: str,
    events: list[dict[str, Any]],
    checkpoints: list[dict[str, Any]],
) -> dict[str, Any]:
    attempted = _attempted_phases(events)
    checkpointed = _checkpointed_phases(checkpoints)
    phases = []
    blockers: list[str] = []
    missing: list[str] = []
    stale: list[str] = []
    blocked: list[str] = []

    for phase in _ordered(set(attempted) | set(checkpointed)):
        latest_event = attempted.get(phase)
        latest_checkpoint = checkpointed.get(phase)
        status = "checkpointed"
        phase_blockers: list[str] = []
        if latest_event and not latest_checkpoint:
            status = "missing_checkpoint"
            missing.append(phase)
            phase_blockers.append(f"{phase} has tool evidence but no checkpoint")
        elif latest_event and latest_checkpoint and str(latest_checkpoint.get("created_at", "")) < str(latest_event.get("ts", "")):
            status = "stale_checkpoint"
            stale.append(phase)
            phase_blockers.append(f"{phase} checkpoint predates latest tool evidence")
        if latest_checkpoint and latest_checkpoint.get("blocked"):
            if status == "checkpointed":
                status = "blocked"
            blocked.append(phase)
            phase_blockers.extend(str(item) for item in latest_checkpoint.get("blockers", []) if item)
        blockers.extend(phase_blockers)
        phases.append(
            {
                "phase": phase,
                "status": status,
                "latest_event": _event_summary(latest_event) if latest_event else None,
                "latest_checkpoint": _checkpoint_summary(latest_checkpoint) if latest_checkpoint else None,
                "blockers": phase_blockers,
            }
        )

    coverage_ok = not missing and not stale
    return {
        "run_id": run_id,
        "ok": coverage_ok and not blocked,
        "coverage_ok": coverage_ok,
        "attempted_phases": _ordered(attempted),
        "checkpointed_phases": _ordered(checkpointed),
        "missing_checkpoint_phases": missing,
        "stale_checkpoint_phases": stale,
        "blocked_phases": blocked,
        "phases": phases,
        "blockers": blockers,
    }


def _attempted_phases(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    phases: dict[str, dict[str, Any]] = {}
    for event in events:
        for phase in EVENT_PHASES.get(str(event.get("type") or ""), ()):
            phases[phase] = event
    return phases


def _checkpointed_phases(checkpoints: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    phases: dict[str, dict[str, Any]] = {}
    for checkpoint in checkpoints:
        phase = str(checkpoint.get("phase") or "")
        if phase:
            phases[phase] = checkpoint
    return phases


def _ordered(phases: set[str] | dict[str, Any]) -> list[str]:
    order = ["readiness", "scope", "input-material", "fuzzing", "grading", "dedupe", "patch", "report", "export"]
    values = set(phases)
    return [phase for phase in order if phase in values] + sorted(values - set(order))


def _event_summary(event: dict[str, Any] | None) -> dict[str, Any] | None:
    if event is None:
        return None
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    return {
        "ts": event.get("ts"),
        "type": event.get("type"),
        "target": payload.get("target") or payload.get("project"),
        "harness": payload.get("harness"),
        "artifact": payload.get("artifact") or payload.get("patch_artifact") or payload.get("pov_artifact"),
        "ok": payload.get("ok"),
        "blocked": payload.get("blocked"),
        "verified": payload.get("verified"),
    }


def _checkpoint_summary(checkpoint: dict[str, Any] | None) -> dict[str, Any] | None:
    if checkpoint is None:
        return None
    return {
        "checkpoint_id": checkpoint.get("checkpoint_id"),
        "created_at": checkpoint.get("created_at"),
        "harness": checkpoint.get("harness"),
        "blocked": checkpoint.get("blocked"),
        "next_command": checkpoint.get("next_command"),
        "agent": checkpoint.get("agent"),
    }

from __future__ import annotations

import base64
import json
from hashlib import sha256
from typing import Any


MOCK_API_NAME = "plugin-local-mock-evaluation-framework"
DEFAULT_FULL_CAMPAIGN_AGENTS = (
    "planner",
    "native-harness",
    "input-generator",
    "artifact-manager",
    "harness-builder",
    "corpus-manager",
    "dictionary-generator",
    "grammar-reverser",
    "concolic-generator",
    "fuzz-finder",
    "crash-grader",
    "dedupe-judge",
    "reporter",
    "export-agent",
)


def create_export_bundle(
    *,
    run_id: str,
    project: str | None,
    findings: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    events: list[dict[str, Any]],
    dedupe: dict[str, Any],
    artifact_name: str | None = None,
) -> dict[str, Any]:
    artifact_names = _artifact_names(artifacts)
    povs = _pov_candidates(findings, artifacts=artifacts, dedupe=dedupe)
    patches = _passed_patch_candidates(events, artifact_names=artifact_names)
    reports = _report_artifacts(events, artifact_names=artifact_names)
    blockers = []
    if findings and not _dedupe_representatives(dedupe):
        blockers.append("finding_dedupe must run before PoV export bundling")
    if findings and not povs:
        blockers.append("no verified dedupe-representative PoV is ready for mock export")
    if _patch_attempted(events) and not patches:
        blockers.append("patch work was attempted but no passing patch_grade evidence is available")
    if not reports["json"]:
        blockers.append("missing JSON campaign report artifact for SARIF-style mock export")
    if not reports["markdown"]:
        blockers.append("missing Markdown campaign report artifact for human review")

    bundle = {
        "schema_version": "agentic-fuzz.mock-export-bundle.v1",
        "api": MOCK_API_NAME,
        "run_id": run_id,
        "project": project,
        "ok": not blockers,
        "pov_exports": povs,
        "patch_exports": patches,
        "sarif_exports": [
            {
                "artifact": name,
                "format": _report_format(name),
            }
            for name in reports["json"]
        ],
        "report_artifacts": reports,
        "blockers": blockers,
    }
    return _bundle_payload(run_id, artifact_name or f"exports/{run_id}/bundle.json", bundle)


def mock_submit_pov(
    *,
    run_id: str,
    project: str | None,
    findings: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    events: list[dict[str, Any]],
    dedupe: dict[str, Any],
    finding_id: str | None = None,
    poc_artifact: str | None = None,
) -> dict[str, Any]:
    candidates = _pov_candidates(findings, artifacts=artifacts, dedupe=dedupe)
    if finding_id:
        candidates = [item for item in candidates if item["finding_id"] == finding_id]
    if poc_artifact:
        candidates = [item for item in candidates if item["poc_artifact"] == poc_artifact]
    blockers = []
    if not _dedupe_representatives(dedupe):
        blockers.append("finding_dedupe must run before PoV export")
    if not candidates:
        blockers.append("no matching verified dedupe-representative PoV artifact is ready")
    if blockers:
        return _rejected("pov", run_id=run_id, project=project, blockers=blockers)

    selected = candidates[0]
    receipt = {
        "schema_version": "agentic-fuzz.mock-export-receipt.v1",
        "api": MOCK_API_NAME,
        "kind": "pov",
        "run_id": run_id,
        "project": project,
        "accepted": True,
        "finding_id": selected["finding_id"],
        "signature": selected["signature"],
        "target": selected["target"],
        "harness": selected["harness"],
        "sanitizer": selected["sanitizer"],
        "error_token": selected["error_token"],
        "poc_artifact": selected["poc_artifact"],
        "poc_sha256": selected["poc_sha256"],
    }
    return _accepted(receipt)


def mock_submit_patch(
    *,
    run_id: str,
    project: str | None,
    artifacts: list[dict[str, Any]],
    events: list[dict[str, Any]],
    patch_artifact: str | None = None,
) -> dict[str, Any]:
    artifact_names = _artifact_names(artifacts)
    candidates = _passed_patch_candidates(events, artifact_names=artifact_names)
    if patch_artifact:
        candidates = [item for item in candidates if item["patch_artifact"] == patch_artifact]
    blockers = []
    if patch_artifact and patch_artifact not in artifact_names:
        blockers.append(f"patch artifact not found: {patch_artifact}")
    if not candidates:
        blockers.append("no matching patch artifact has passing patch_grade evidence")
    if blockers:
        return _rejected("patch", run_id=run_id, project=project, blockers=blockers)

    selected = candidates[-1]
    receipt = {
        "schema_version": "agentic-fuzz.mock-export-receipt.v1",
        "api": MOCK_API_NAME,
        "kind": "patch",
        "run_id": run_id,
        "project": project,
        "accepted": True,
        "patch_artifact": selected["patch_artifact"],
        "patch_sha256": _artifact_sha(artifacts, selected["patch_artifact"]),
        "pov_artifact": selected["pov_artifact"],
        "tier": selected["tier"],
        "grade_event_ts": selected["grade_event_ts"],
    }
    return _accepted(receipt)


def mock_submit_sarif(
    *,
    run_id: str,
    project: str | None,
    artifacts: list[dict[str, Any]],
    events: list[dict[str, Any]],
    report_artifact: str | None = None,
) -> dict[str, Any]:
    artifact_names = _artifact_names(artifacts)
    reports = _report_artifacts(events, artifact_names=artifact_names)
    candidates = list(reports["json"])
    if report_artifact:
        candidates = [name for name in candidates if name == report_artifact]
        if report_artifact not in artifact_names:
            candidates = []
    blockers = []
    if not _events_by_type(events, "campaign_report"):
        blockers.append("campaign_report must run before SARIF-style mock export")
    if report_artifact and report_artifact not in artifact_names:
        blockers.append(f"report artifact not found: {report_artifact}")
    if not candidates:
        blockers.append("no JSON report or SARIF artifact is ready for mock export")
    if blockers:
        return _rejected("sarif", run_id=run_id, project=project, blockers=blockers)

    selected = candidates[-1]
    receipt = {
        "schema_version": "agentic-fuzz.mock-export-receipt.v1",
        "api": MOCK_API_NAME,
        "kind": "sarif",
        "run_id": run_id,
        "project": project,
        "accepted": True,
        "report_artifact": selected,
        "report_sha256": _artifact_sha(artifacts, selected),
        "format": _report_format(selected),
    }
    return _accepted(receipt)


def list_export_receipts(events: list[dict[str, Any]]) -> dict[str, Any]:
    accepted = _events_by_type(events, "export_accepted")
    rejected = _events_by_type(events, "export_rejected")
    bundles = _events_by_type(events, "export_bundle_created")
    return {
        "bundles": [_event_payload(event) for event in bundles],
        "accepted": [_event_payload(event) for event in accepted],
        "rejected": [_event_payload(event) for event in rejected],
        "counts": {
            "bundles": len(bundles),
            "accepted": len(accepted),
            "rejected": len(rejected),
            "pov": sum(1 for event in accepted if _event_payload(event).get("kind") == "pov"),
            "patch": sum(1 for event in accepted if _event_payload(event).get("kind") == "patch"),
            "sarif": sum(1 for event in accepted if _event_payload(event).get("kind") == "sarif"),
        },
    }


def audit_export_completion(
    *,
    findings: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    receipts = list_export_receipts(events)
    accepted = receipts["accepted"]
    blockers = []
    if not receipts["bundles"]:
        blockers.append("missing export_bundle_created event")
    if findings and not any(item.get("kind") == "pov" and item.get("accepted") is True for item in accepted):
        blockers.append("missing accepted PoV mock export receipt")
    if _passed_patch_attempted(events) and not any(item.get("kind") == "patch" and item.get("accepted") is True for item in accepted):
        blockers.append("missing accepted patch mock export receipt for passing patch_grade")
    if _events_by_type(events, "campaign_report") and not any(item.get("kind") == "sarif" and item.get("accepted") is True for item in accepted):
        blockers.append("missing accepted SARIF-style mock export receipt")
    return {
        "ok": not blockers,
        "receipt_counts": receipts["counts"],
        "accepted_receipts": accepted,
        "blockers": blockers,
    }


def audit_subagent_orchestration(
    *,
    checkpoints: list[dict[str, Any]],
    events: list[dict[str, Any]],
    required_agents: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    agents = sorted(
        {
            str(checkpoint.get("agent"))
            for checkpoint in checkpoints
            if isinstance(checkpoint.get("agent"), str) and checkpoint.get("agent")
        }
    )
    required = tuple(required_agents or DEFAULT_FULL_CAMPAIGN_AGENTS)
    if _patch_attempted(events) or _checkpointed_phase(checkpoints, "patch"):
        required = (*required, "patcher", "patch-grader")
    missing = [agent for agent in _dedupe(required) if agent not in agents]
    blockers = [f"missing required subagent checkpoint: {agent}" for agent in missing]
    return {
        "ok": not blockers,
        "required_agents": list(_dedupe(required)),
        "checkpoint_agents": agents,
        "missing_agents": missing,
        "blockers": blockers,
    }


def _pov_candidates(
    findings: list[dict[str, Any]],
    *,
    artifacts: list[dict[str, Any]],
    dedupe: dict[str, Any],
) -> list[dict[str, Any]]:
    artifact_by_name = _artifact_by_name(artifacts)
    representatives = _dedupe_representatives(dedupe)
    representative_ids = {str(item.get("finding_id")) for item in representatives if item.get("finding_id")}
    source = representatives if representatives else findings
    candidates = []
    for finding in source:
        poc_artifact = finding.get("poc_artifact")
        if not isinstance(poc_artifact, str) or not poc_artifact:
            continue
        artifact = artifact_by_name.get(poc_artifact)
        if artifact is None:
            continue
        if finding.get("verified") is not True:
            continue
        finding_id = str(finding.get("finding_id") or "")
        if representative_ids and finding_id not in representative_ids:
            continue
        candidates.append(
            {
                "finding_id": finding_id,
                "signature": finding.get("signature"),
                "target": finding.get("target"),
                "harness": finding.get("harness"),
                "sanitizer": finding.get("sanitizer"),
                "error_token": finding.get("error_token"),
                "poc_artifact": poc_artifact,
                "poc_sha256": artifact.get("sha256"),
                "reproductions": finding.get("reproductions"),
            }
        )
    return candidates


def _passed_patch_candidates(events: list[dict[str, Any]], *, artifact_names: set[str]) -> list[dict[str, Any]]:
    candidates = []
    for event in events:
        if event.get("type") != "patch_grade":
            continue
        payload = _event_payload(event)
        patch_artifact = payload.get("patch_artifact")
        if payload.get("passed") is not True or not isinstance(patch_artifact, str):
            continue
        if patch_artifact not in artifact_names:
            continue
        candidates.append(
            {
                "patch_artifact": patch_artifact,
                "pov_artifact": payload.get("pov_artifact"),
                "tier": payload.get("tier"),
                "grade_event_ts": event.get("ts"),
            }
        )
    return candidates


def _report_artifacts(events: list[dict[str, Any]], *, artifact_names: set[str]) -> dict[str, list[str]]:
    markdown: list[str] = []
    json_reports: list[str] = []
    for event in events:
        if event.get("type") != "campaign_report":
            continue
        payload = _event_payload(event)
        for key, destination in (("markdown_artifact", markdown), ("json_artifact", json_reports)):
            artifact = payload.get(key)
            if isinstance(artifact, dict) and isinstance(artifact.get("name"), str):
                name = str(artifact["name"])
                if name in artifact_names:
                    destination.append(name)
    markdown.extend(name for name in sorted(artifact_names) if name.endswith("REPORT.md") and name not in markdown)
    json_reports.extend(
        name
        for name in sorted(artifact_names)
        if (name.endswith("REPORT.json") or name.endswith(".sarif") or name.endswith(".sarif.json")) and name not in json_reports
    )
    return {"markdown": markdown, "json": json_reports}


def _bundle_payload(run_id: str, artifact_name: str, bundle: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(bundle, indent=2, sort_keys=True).encode("utf-8")
    return {
        "run_id": run_id,
        "ok": bool(bundle.get("ok")),
        "artifact_name": artifact_name,
        "bundle": bundle,
        "content_b64": base64.b64encode(data).decode("ascii"),
    }


def _accepted(receipt: dict[str, Any]) -> dict[str, Any]:
    receipt_id = _receipt_id(receipt)
    receipt = {**receipt, "receipt_id": receipt_id}
    data = json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8")
    return {
        "ok": True,
        "accepted": True,
        "receipt": receipt,
        "artifact_name": f"exports/{receipt['run_id']}/{receipt_id}.json",
        "content_b64": base64.b64encode(data).decode("ascii"),
    }


def _rejected(kind: str, *, run_id: str, project: str | None, blockers: list[str]) -> dict[str, Any]:
    return {
        "ok": False,
        "accepted": False,
        "receipt": {
            "schema_version": "agentic-fuzz.mock-export-receipt.v1",
            "api": MOCK_API_NAME,
            "kind": kind,
            "run_id": run_id,
            "project": project,
            "accepted": False,
            "blockers": blockers,
        },
        "blockers": blockers,
    }


def _receipt_id(receipt: dict[str, Any]) -> str:
    data = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"mock-cf-{receipt['kind']}-{sha256(data).hexdigest()[:16]}"


def _dedupe_representatives(dedupe: dict[str, Any]) -> list[dict[str, Any]]:
    groups = dedupe.get("groups") if isinstance(dedupe.get("groups"), list) else []
    representatives = []
    for group in groups:
        if isinstance(group, dict) and isinstance(group.get("representative"), dict):
            representatives.append(group["representative"])
    return representatives


def _artifact_names(artifacts: list[dict[str, Any]]) -> set[str]:
    return {str(item.get("name")) for item in artifacts if isinstance(item, dict) and item.get("name")}


def _artifact_by_name(artifacts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item.get("name")): item for item in artifacts if isinstance(item, dict) and item.get("name")}


def _artifact_sha(artifacts: list[dict[str, Any]], name: str) -> str | None:
    artifact = _artifact_by_name(artifacts).get(name)
    value = artifact.get("sha256") if artifact else None
    return str(value) if value else None


def _events_by_type(events: list[dict[str, Any]], event_type: str) -> list[dict[str, Any]]:
    return [event for event in events if event.get("type") == event_type]


def _event_payload(event: dict[str, Any]) -> dict[str, Any]:
    payload = event.get("payload")
    return payload if isinstance(payload, dict) else {}


def _patch_attempted(events: list[dict[str, Any]]) -> bool:
    return any(event.get("type") in {"patch_candidate_recorded", "patch_grade"} for event in events)


def _passed_patch_attempted(events: list[dict[str, Any]]) -> bool:
    return any(event.get("type") == "patch_grade" and _event_payload(event).get("passed") is True for event in events)


def _checkpointed_phase(checkpoints: list[dict[str, Any]], phase: str) -> bool:
    return any(checkpoint.get("phase") == phase for checkpoint in checkpoints)


def _report_format(name: str) -> str:
    if name.endswith(".sarif") or name.endswith(".sarif.json"):
        return "sarif"
    return "campaign-report-json"


def _dedupe(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    deduped = []
    for value in values:
        if value not in seen:
            seen.add(value)
            deduped.append(value)
    return tuple(deduped)

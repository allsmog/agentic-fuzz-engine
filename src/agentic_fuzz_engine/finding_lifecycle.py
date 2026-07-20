from __future__ import annotations

from typing import Any


def audit_finding_lifecycle(
    *,
    run_id: str,
    findings: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    artifact_names = {str(item.get("name")) for item in artifacts if isinstance(item, dict) and item.get("name")}
    classification_events = _events_by_type(events, "finding_classified")
    verification_events = _verification_events(events)
    dedupe_events = _events_by_type(events, "finding_dedupe")
    latest_finding_recorded = _latest_ts(_events_by_type(events, "finding_recorded"))
    latest_dedupe = _latest_ts(dedupe_events)

    finding_results = [
        _audit_finding(
            finding,
            artifact_names=artifact_names,
            classification_events=classification_events,
            verification_events=verification_events,
        )
        for finding in findings
    ]
    blockers = [
        f"{item['finding_id']}: {blocker}"
        for item in finding_results
        for blocker in item["blockers"]
    ]
    dedupe_blockers: list[str] = []
    if findings and not dedupe_events:
        dedupe_blockers.append("finding_dedupe was not run")
    elif latest_finding_recorded and latest_dedupe and latest_dedupe < latest_finding_recorded:
        dedupe_blockers.append("finding_dedupe predates the latest recorded finding")
    blockers.extend(dedupe_blockers)

    return {
        "run_id": run_id,
        "ok": not blockers,
        "score": {
            "findings": len(findings),
            "classified_findings": sum(1 for item in finding_results if item["classified"]),
            "verified_findings": sum(1 for item in finding_results if item["verification_evidence"]),
            "artifact_backed_findings": sum(1 for item in finding_results if item["artifact_present"]),
            "dedupe_events": len(dedupe_events),
        },
        "dedupe": {
            "events": len(dedupe_events),
            "latest_finding_recorded": latest_finding_recorded,
            "latest_dedupe": latest_dedupe,
            "blockers": dedupe_blockers,
        },
        "findings": finding_results,
        "blockers": blockers,
    }


def _audit_finding(
    finding: dict[str, Any],
    *,
    artifact_names: set[str],
    classification_events: list[dict[str, Any]],
    verification_events: list[dict[str, Any]],
) -> dict[str, Any]:
    finding_id = str(finding.get("finding_id") or finding.get("signature") or "unknown-finding")
    poc_artifact = str(finding.get("poc_artifact") or "")
    matching_classification = [
        event for event in classification_events if _event_matches_finding(event, finding)
    ]
    matching_verification = [
        event for event in verification_events if _event_matches_finding(event, finding) and _event_is_verified(event)
    ]
    blockers = []
    if not poc_artifact:
        blockers.append("missing PoV artifact")
    elif poc_artifact not in artifact_names:
        blockers.append(f"PoV artifact not found: {poc_artifact}")
    if finding.get("verified") is not True:
        blockers.append("finding is not marked verified")
    if not matching_verification:
        blockers.append("missing executable verification event before record")
    if not matching_classification:
        blockers.append("missing finding_classified event before record")
    else:
        verdicts = {str(event.get("payload", {}).get("verdict") or "") for event in matching_classification}
        if not verdicts.intersection({"NEW", "DUP_BETTER", "FIXTURE_REPLAY"}):
            blockers.append(f"classification verdict is not recordable: {', '.join(sorted(verdicts))}")
    return {
        "finding_id": finding_id,
        "signature": finding.get("signature"),
        "target": finding.get("target"),
        "harness": finding.get("harness"),
        "poc_artifact": finding.get("poc_artifact"),
        "artifact_present": bool(poc_artifact and poc_artifact in artifact_names),
        "verified": finding.get("verified"),
        "classified": bool(matching_classification),
        "classification_verdicts": sorted(
            str(event.get("payload", {}).get("verdict") or "") for event in matching_classification
        ),
        "verification_evidence": [_verification_summary(event) for event in matching_verification],
        "blockers": blockers,
    }


def _event_matches_finding(event: dict[str, Any], finding: dict[str, Any]) -> bool:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    if finding.get("created_at") and event.get("ts") and str(event.get("ts")) > str(finding.get("created_at")):
        return False
    if payload.get("signature") and finding.get("signature") and payload.get("signature") != finding.get("signature"):
        return False
    payload_artifact = payload.get("poc_artifact") or payload.get("artifact")
    if payload_artifact and finding.get("poc_artifact") and payload_artifact != finding.get("poc_artifact"):
        return False
    if payload.get("target") and finding.get("target") and payload.get("target") != finding.get("target"):
        return False
    if payload.get("harness") and finding.get("harness") and payload.get("harness") != finding.get("harness"):
        return False
    return bool(payload.get("signature") or payload_artifact)


def _verification_summary(event: dict[str, Any]) -> dict[str, Any]:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    return {
        "ts": event.get("ts"),
        "source": payload.get("source"),
        "target": payload.get("target"),
        "harness": payload.get("harness"),
        "poc_artifact": payload.get("poc_artifact") or payload.get("artifact"),
        "reproductions": payload.get("reproductions") or payload.get("matches_expected"),
    }


def _events_by_type(events: list[dict[str, Any]], event_type: str) -> list[dict[str, Any]]:
    return [event for event in events if event.get("type") == event_type]


def _verification_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        event
        for event in events
        if event.get("type") in {"finding_verified", "harness_run", "finding_graded"}
    ]


def _event_is_verified(event: dict[str, Any]) -> bool:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    event_type = event.get("type")
    if event_type == "finding_verified":
        return payload.get("verified") is True
    if event_type == "harness_run":
        return payload.get("verified") is True
    if event_type == "finding_graded":
        return payload.get("verdict") == "PASS"
    return False


def _latest_ts(events: list[dict[str, Any]]) -> str | None:
    timestamps = [str(event.get("ts")) for event in events if event.get("ts")]
    return max(timestamps) if timestamps else None


# Public aliases: the constructive-verification guard on finding_record needs
# the same matching rules the audit applies, so a record accepted at the tool
# boundary can never fail the lifecycle audit on evidence grounds.
event_matches_finding = _event_matches_finding
event_is_verified = _event_is_verified
verification_events = _verification_events

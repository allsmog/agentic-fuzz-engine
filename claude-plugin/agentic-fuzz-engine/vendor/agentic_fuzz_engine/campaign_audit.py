from __future__ import annotations

from typing import Any

from .fidelity import FixtureBenchmark


def audit_campaign_fidelity(
    *,
    run_id: str,
    project: str | None,
    benchmarks: tuple[FixtureBenchmark, ...],
    findings: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    project_name = project.removeprefix("localfuzz/c/") if project else None
    scoped = tuple(benchmark for benchmark in benchmarks if project_name is None or benchmark.project == project_name)
    enabled = tuple(benchmark for benchmark in scoped if not benchmark.disabled_project)
    disabled = tuple(benchmark for benchmark in scoped if benchmark.disabled_project)
    artifact_by_name = {str(item["name"]): item for item in artifacts if isinstance(item, dict) and item.get("name")}

    fixture_results = [_audit_fixture(benchmark, findings, artifact_by_name) for benchmark in scoped]
    enabled_results = [item for item in fixture_results if not item["disabled_project"]]
    represented = [item for item in enabled_results if item["status"] == "represented"]
    missing = [item for item in enabled_results if item["status"] == "missing"]
    partial = [item for item in enabled_results if item["status"] == "partial"]
    harness_expected = sorted({benchmark.harness for benchmark in enabled})
    harness_represented = sorted({item["harness"] for item in represented})
    replay_events = [event for event in events if event.get("type") == "fidelity_replay_campaign"]
    unmatched_findings = _unmatched_findings(findings, fixture_results)
    blockers = []
    for item in missing:
        blockers.append(f"{item['project']}:{item['fixture']} has no verified matching finding")
    for item in partial:
        blockers.append(f"{item['project']}:{item['fixture']} has only partial fixture/finding evidence")

    return {
        "run_id": run_id,
        "project": project,
        "ok": not blockers and len(enabled_results) > 0,
        "score": {
            "enabled_fixtures": len(enabled_results),
            "represented_fixtures": len(represented),
            "partial_fixtures": len(partial),
            "missing_fixtures": len(missing),
            "disabled_fixtures": len(disabled),
            "coverage_ratio": len(represented) / len(enabled_results) if enabled_results else 0.0,
        },
        "harness_coverage": {
            "expected": harness_expected,
            "represented": harness_represented,
            "missing": sorted(set(harness_expected) - set(harness_represented)),
        },
        "replay_summary": {
            "events": len(replay_events),
            "executed": sum(int(event.get("payload", {}).get("executed", 0)) for event in replay_events),
            "verified": sum(int(event.get("payload", {}).get("verified", 0)) for event in replay_events),
            "blocked": sum(int(event.get("payload", {}).get("blocked", 0)) for event in replay_events),
        },
        "fixtures": fixture_results,
        "unmatched_findings": unmatched_findings,
        "blockers": blockers,
    }


def _audit_fixture(
    benchmark: FixtureBenchmark,
    findings: list[dict[str, Any]],
    artifact_by_name: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    fixture_artifact = f"fixtures_{benchmark.project}_{benchmark.fixture}_{benchmark.harness}_proof.bin"
    artifact = artifact_by_name.get(fixture_artifact)
    artifact_matches = bool(artifact and artifact.get("sha256") == benchmark.proof_sha256)
    semantic_findings = [
        finding
        for finding in findings
        if finding.get("target") == benchmark.target
        and finding.get("harness") == benchmark.harness
        and finding.get("sanitizer") == benchmark.sanitizer
        and finding.get("error_token") == benchmark.error_token
    ]
    verified_semantic = [
        finding for finding in semantic_findings if finding.get("verified") is True or finding.get("verified") is None
    ]
    exact_findings = [finding for finding in verified_semantic if finding.get("poc_artifact") == fixture_artifact]
    if benchmark.disabled_project:
        status = "disabled"
    elif exact_findings and artifact_matches:
        status = "represented"
    elif verified_semantic:
        status = "represented"
    elif artifact_matches or semantic_findings:
        status = "partial"
    else:
        status = "missing"
    return {
        "project": benchmark.project,
        "fixture": benchmark.fixture,
        "target": benchmark.target,
        "harness": benchmark.harness,
        "sanitizer": benchmark.sanitizer,
        "error_token": benchmark.error_token,
        "proof_sha256": benchmark.proof_sha256,
        "fixture_artifact": fixture_artifact,
        "fixture_artifact_present": bool(artifact),
        "fixture_artifact_sha256_match": artifact_matches,
        "finding_ids": [str(finding.get("finding_id")) for finding in verified_semantic],
        "exact_fixture_finding_ids": [str(finding.get("finding_id")) for finding in exact_findings],
        "disabled_project": benchmark.disabled_project,
        "status": status,
        "evidence_level": "fixture-proof" if exact_findings and artifact_matches else "semantic" if verified_semantic else "artifact-only" if artifact_matches else "none",
    }


def _unmatched_findings(findings: list[dict[str, Any]], fixture_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matched_ids = {finding_id for item in fixture_results for finding_id in item["finding_ids"]}
    return [
        {
            "finding_id": finding.get("finding_id"),
            "target": finding.get("target"),
            "harness": finding.get("harness"),
            "error_token": finding.get("error_token"),
            "poc_artifact": finding.get("poc_artifact"),
        }
        for finding in findings
        if finding.get("finding_id") not in matched_ids
    ]

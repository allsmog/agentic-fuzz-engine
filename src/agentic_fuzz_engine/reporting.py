from __future__ import annotations

import base64
import json
from typing import Any

from .asan import parse_asan_signal
from .dedupe import finding_quality


def build_campaign_report(
    *,
    run_id: str,
    project: str | None,
    campaign: dict[str, Any],
    findings: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    checkpoints: list[dict[str, Any]],
    phase_audit: dict[str, Any],
    finding_lifecycle_audit: dict[str, Any],
    fidelity_audit: dict[str, Any],
    dedupe: dict[str, Any],
) -> dict[str, Any]:
    artifact_sizes = {str(item["name"]): int(item["size"]) for item in artifacts if item.get("name")}
    report_findings = [_finding_entry(group, artifact_sizes) for group in dedupe.get("groups", [])]
    phase_summary = _phase_summary(checkpoints)
    report = {
        "run_id": run_id,
        "project": project,
        "target": campaign.get("target"),
        "status": campaign.get("status"),
        "summary": {
            "total_findings": len(findings),
            "dedupe_groups": len(report_findings),
            "verified_representatives": sum(1 for item in report_findings if item["verified"] is True),
            "artifact_count": len(artifacts),
            "checkpoint_count": len(checkpoints),
            "checkpoint_phases": phase_summary["phases"],
            "blocked_checkpoint_phases": phase_summary["blocked_phases"],
            "phase_coverage_ok": bool(phase_audit.get("coverage_ok")),
            "phase_missing_checkpoints": phase_audit.get("missing_checkpoint_phases", []),
            "phase_stale_checkpoints": phase_audit.get("stale_checkpoint_phases", []),
            "phase_blocked_phases": phase_audit.get("blocked_phases", []),
            "finding_lifecycle_ok": bool(finding_lifecycle_audit.get("ok")),
            "finding_lifecycle_blockers": finding_lifecycle_audit.get("blockers", []),
            "fidelity_ok": bool(fidelity_audit.get("ok")),
            "fidelity_coverage_ratio": fidelity_audit.get("score", {}).get("coverage_ratio", 0.0),
            "fidelity_blockers": fidelity_audit.get("blockers", []),
        },
        "checkpoints": phase_summary,
        "phase_audit": phase_audit,
        "finding_lifecycle": finding_lifecycle_audit,
        "fidelity": {
            "score": fidelity_audit.get("score", {}),
            "harness_coverage": fidelity_audit.get("harness_coverage", {}),
            "blockers": fidelity_audit.get("blockers", []),
            "fixtures": fidelity_audit.get("fixtures", []),
        },
        "findings": report_findings,
        "reporting_policy": {
            "representatives_only": True,
            "dedupe_source": "finding_dedupe quality-ranked groups",
            "requires_verified_evidence": True,
            "reference_fixtures_are_oracles": True,
        },
    }
    markdown = _markdown_report(report)
    return {
        "report": report,
        "markdown": markdown,
        "markdown_content_b64": base64.b64encode(markdown.encode("utf-8")).decode("ascii"),
        "json_content_b64": base64.b64encode(
            (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
        ).decode("ascii"),
    }


def _finding_entry(group: dict[str, Any], artifact_sizes: dict[str, int]) -> dict[str, Any]:
    finding = group.get("representative", {})
    signal = parse_asan_signal(str(finding.get("crash_output") or ""))
    quality = group.get("representative_quality") or finding_quality(finding, artifact_sizes=artifact_sizes)
    return {
        "finding_id": finding.get("finding_id"),
        "signature": finding.get("signature"),
        "target": finding.get("target"),
        "harness": finding.get("harness"),
        "sanitizer": finding.get("sanitizer"),
        "error_token": finding.get("error_token"),
        "poc_artifact": finding.get("poc_artifact"),
        "poc_size": quality.get("poc_size"),
        "reproductions": finding.get("reproductions"),
        "verified": finding.get("verified"),
        "crash_type": signal.crash_type if signal else quality.get("crash_type"),
        "top_function": signal.top_function if signal else quality.get("top_function"),
        "top_file": signal.top_file if signal else quality.get("top_file"),
        "quality": quality,
        "duplicate_count": max(0, int(group.get("count", 1)) - 1),
        "duplicate_finding_ids": [
            item.get("finding_id")
            for item in group.get("duplicates", [])
            if isinstance(item, dict)
        ],
        "crash_excerpt": _excerpt(str(finding.get("crash_output") or "")),
    }


def _markdown_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        f"# Agentic Fuzz Campaign Report: {report['run_id']}",
        "",
        "## Summary",
        "",
        f"- Target: `{report.get('target')}`",
        f"- Project: `{report.get('project')}`",
        f"- Representative findings: {summary['dedupe_groups']}",
        f"- Total recorded findings: {summary['total_findings']}",
        f"- Phase checkpoints: {summary['checkpoint_count']}",
        f"- Phase coverage OK: {summary['phase_coverage_ok']}",
        f"- Finding lifecycle OK: {summary['finding_lifecycle_ok']}",
        f"- Fidelity coverage ratio: {summary['fidelity_coverage_ratio']}",
        f"- Fidelity OK: {summary['fidelity_ok']}",
        "",
        "## Checkpoints",
        "",
    ]
    checkpoint_phases = summary.get("checkpoint_phases") or []
    if checkpoint_phases:
        lines.append(f"- Phases checkpointed: {', '.join(f'`{phase}`' for phase in checkpoint_phases)}")
    else:
        lines.append("- Phases checkpointed: none")
    blocked_phases = summary.get("blocked_checkpoint_phases") or []
    if blocked_phases:
        lines.append(f"- Blocked phases: {', '.join(f'`{phase}`' for phase in blocked_phases)}")
    else:
        lines.append("- Blocked phases: none")
    missing_phases = summary.get("phase_missing_checkpoints") or []
    if missing_phases:
        lines.append(f"- Missing phase checkpoints: {', '.join(f'`{phase}`' for phase in missing_phases)}")
    else:
        lines.append("- Missing phase checkpoints: none")
    stale_phases = summary.get("phase_stale_checkpoints") or []
    if stale_phases:
        lines.append(f"- Stale phase checkpoints: {', '.join(f'`{phase}`' for phase in stale_phases)}")
    else:
        lines.append("- Stale phase checkpoints: none")
    lines.extend([
        "",
        "## Finding Lifecycle",
        "",
    ])
    lifecycle_blockers = summary.get("finding_lifecycle_blockers") or []
    if lifecycle_blockers:
        lines.append("Blockers:")
        lines.extend(f"- {blocker}" for blocker in lifecycle_blockers)
    else:
        lines.append("No finding lifecycle blockers recorded.")
    lines.extend([
        "",
        "## Fidelity",
        "",
    ])
    blockers = summary.get("fidelity_blockers") or []
    if blockers:
        lines.append("Blockers:")
        lines.extend(f"- {blocker}" for blocker in blockers)
    else:
        lines.append("No fidelity blockers recorded.")
    lines.extend(["", "## Findings", ""])
    findings = report.get("findings", [])
    if not findings:
        lines.append("No representative findings recorded.")
    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"### Finding {index}: {finding.get('crash_type') or finding.get('error_token')}",
                "",
                f"- Finding id: `{finding.get('finding_id')}`",
                f"- Signature: `{finding.get('signature')}`",
                f"- Harness: `{finding.get('harness')}`",
                f"- PoV artifact: `{finding.get('poc_artifact')}` ({finding.get('poc_size')} bytes)",
                f"- Reproductions: {finding.get('reproductions')}",
                f"- Top frame: `{finding.get('top_function')}` in `{finding.get('top_file')}`",
                f"- Duplicate findings collapsed: {finding.get('duplicate_count')}",
                "",
                "Crash excerpt:",
                "",
                "```text",
                finding.get("crash_excerpt") or "",
                "```",
                "",
            ]
        )
    lines.extend(
        [
            "## Policy",
            "",
            "This report uses quality-ranked dedupe representatives only. benchmark files are fidelity oracles, not runtime dependencies.",
            "",
        ]
    )
    return "\n".join(lines)


def _excerpt(value: str) -> str:
    lines = [line for line in value.splitlines() if line.strip()]
    return "\n".join(lines[:12])[:4000]


def _phase_summary(checkpoints: list[dict[str, Any]]) -> dict[str, Any]:
    phases: list[str] = []
    blocked_phases: list[str] = []
    latest_by_phase: dict[str, dict[str, Any]] = {}
    for checkpoint in checkpoints:
        phase = str(checkpoint.get("phase") or "")
        if not phase:
            continue
        if phase not in phases:
            phases.append(phase)
        latest_by_phase[phase] = checkpoint
        if checkpoint.get("blocked") and phase not in blocked_phases:
            blocked_phases.append(phase)
    return {
        "count": len(checkpoints),
        "phases": phases,
        "blocked_phases": blocked_phases,
        "latest_by_phase": latest_by_phase,
    }

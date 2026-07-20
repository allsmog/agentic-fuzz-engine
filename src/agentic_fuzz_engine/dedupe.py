from __future__ import annotations

import json
from hashlib import sha256
from math import log2
from typing import Any

from .asan import parse_asan_signal
from .crash_identity import (
    consolidate_signature_groups,
    crash_states_similar,
    parse_crash_output,
    root_signature,
)


SEVERITY_SCORE = {
    "heap-use-after-free": 100,
    "double-free": 98,
    "heap-buffer-overflow": 92,
    "stack-buffer-overflow": 88,
    "global-buffer-overflow": 84,
    "dynamic-stack-buffer-overflow": 82,
    "use-after-poison": 78,
}

# A WRITE access is a corruption primitive; a READ of the same crash type is
# disclosure/DoS. The bonus keeps write findings as dedupe representatives
# and floats them above reads in report ordering.
WRITE_ACCESS_BONUS = 20


def finding_signature(
    *,
    target: str,
    harness: str,
    sanitizer: str,
    error_token: str,
    crash_output: str,
) -> str:
    # Schema 2: identity comes from the normalized crash state (interceptor
    # frames dropped, DEDUP_TOKENs preferred) instead of the raw top-4 frames,
    # so inlining flap and sanitizer runtime frames no longer split one root
    # cause into many signatures. The schema tag guarantees v1/v2 signatures
    # can never collide; old findings regroup at dedupe read time.
    signal = parse_crash_output(crash_output)
    if signal is not None and signal.dedup_tokens:
        crash_material: dict[str, Any] = {"dedup_tokens": list(signal.dedup_tokens)}
    elif signal is not None:
        crash_material = {"crash_type": signal.crash_type, "crash_state": list(signal.crash_state)}
    else:
        crash_material = {"crash_type": "", "crash_state": []}
    material = {
        "schema": 2,
        "target": target,
        "harness": harness,
        "sanitizer": sanitizer,
        "error_token": error_token,
        **crash_material,
    }
    return sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:24]


def dedupe_findings(
    findings: list[dict[str, Any]],
    *,
    artifact_sizes: dict[str, int],
) -> list[dict[str, Any]]:
    """Group findings by recomputed v2 signature, then run the fuzzy
    consolidation tier.

    Signatures are recomputed from each row's stored fields so findings
    recorded under the v1 schema regroup correctly without ever rewriting
    ``findings.jsonl``; each row keeps its stored value as
    ``recorded_signature``.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        recomputed = finding_signature(
            target=str(finding.get("target") or ""),
            harness=str(finding.get("harness") or ""),
            sanitizer=str(finding.get("sanitizer") or ""),
            error_token=str(finding.get("error_token") or ""),
            crash_output=str(finding.get("crash_output") or ""),
        )
        row = dict(finding)
        row["recorded_signature"] = finding.get("signature")
        row["signature"] = recomputed
        groups.setdefault(recomputed, []).append(row)

    ranked_groups: list[dict[str, Any]] = []
    for signature, items in sorted(groups.items()):
        ranked = sorted(
            items,
            key=lambda item: finding_quality(item, artifact_sizes=artifact_sizes)["score"],
            reverse=True,
        )
        representative = ranked[0]
        ranked_groups.append(
            {
                "signature": signature,
                "count": len(items),
                "representative": representative,
                "representative_quality": finding_quality(representative, artifact_sizes=artifact_sizes),
                "duplicates": ranked[1:],
                "duplicate_qualities": [
                    finding_quality(item, artifact_sizes=artifact_sizes) for item in ranked[1:]
                ],
            }
        )
    return consolidate_signature_groups(ranked_groups)


def classify_finding_candidate(
    *,
    existing_findings: list[dict[str, Any]],
    candidate: dict[str, Any],
    artifact_sizes: dict[str, int],
) -> dict[str, Any]:
    signature = finding_signature(
        target=str(candidate["target"]),
        harness=str(candidate["harness"]),
        sanitizer=str(candidate["sanitizer"]),
        error_token=str(candidate["error_token"]),
        crash_output=str(candidate["crash_output"]),
    )
    candidate = {**candidate, "signature": signature}
    candidate_quality = finding_quality(candidate, artifact_sizes=artifact_sizes)
    duplicates = [finding for finding in existing_findings if finding.get("signature") == signature]
    if not duplicates:
        return {
            "verdict": "NEW",
            "signature": signature,
            "candidate_quality": candidate_quality,
            "representative": None,
            "representative_quality": None,
            "duplicates": [],
            "similar_signatures": _similar_existing_signatures(candidate, existing_findings),
            "reason": "no existing finding has the same sanitizer/root-cause signature",
        }

    ranked = sorted(
        (
            (finding_quality(finding, artifact_sizes=artifact_sizes), finding)
            for finding in duplicates
        ),
        key=lambda item: item[0]["score"],
        reverse=True,
    )
    representative_quality, representative = ranked[0]
    better = _materially_better(candidate_quality, representative_quality)
    return {
        "verdict": "DUP_BETTER" if better else "DUP_SKIP",
        "signature": signature,
        "candidate_quality": candidate_quality,
        "representative": representative,
        "representative_quality": representative_quality,
        "duplicates": [finding for _quality, finding in ranked],
        "reason": _reason(candidate_quality, representative_quality, better),
    }


def _similar_existing_signatures(
    candidate: dict[str, Any],
    existing_findings: list[dict[str, Any]],
    *,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Advisory near-duplicates for a NEW verdict: existing findings whose
    crash state is fuzzily similar (or root_signature identical) even though
    the exact signature differs. Informational only — the fuzzy merge tier
    lives in dedupe consolidation, not classification."""
    candidate_signal = parse_crash_output(str(candidate.get("crash_output") or ""))
    if candidate_signal is None:
        return []
    candidate_root = root_signature(candidate_signal)
    similar: list[dict[str, Any]] = []
    for finding in existing_findings:
        signal = parse_crash_output(str(finding.get("crash_output") or ""))
        if signal is None:
            continue
        same_root = root_signature(signal) == candidate_root
        fuzzy = (
            signal.crash_type == candidate_signal.crash_type
            and crash_states_similar(signal.crash_state, candidate_signal.crash_state)
        )
        if same_root or fuzzy:
            similar.append(
                {
                    "signature": finding.get("signature"),
                    "finding_id": finding.get("finding_id"),
                    "harness": finding.get("harness"),
                    "match": "root_signature" if same_root else "crash_state",
                }
            )
        if len(similar) >= limit:
            break
    return similar


def finding_quality(finding: dict[str, Any], *, artifact_sizes: dict[str, int]) -> dict[str, Any]:
    signal = parse_asan_signal(str(finding.get("crash_output") or ""))
    crash_type = signal.crash_type if signal else ""
    severity = SEVERITY_SCORE.get(crash_type, 60 if crash_type else 0)
    access = signal.access if signal else None
    access_score = WRITE_ACCESS_BONUS if access == "WRITE" else 0
    artifact_name = finding.get("poc_artifact")
    size = artifact_sizes.get(str(artifact_name), 0) if artifact_name else 0
    size_score = _size_score(size)
    reproductions = int(finding.get("reproductions") or finding.get("matches_expected") or (3 if finding.get("verified") else 0) or 0)
    reproducibility_score = min(30, reproductions * 10)
    frame_score = 15 if signal and signal.top_function and signal.top_file else 0
    score = severity + access_score + size_score + reproducibility_score + frame_score
    return {
        "score": score,
        "crash_type": crash_type or None,
        "access": access,
        "top_function": signal.top_function if signal else None,
        "top_file": signal.top_file if signal else None,
        "poc_artifact": artifact_name,
        "poc_size": size,
        "size_score": size_score,
        "reproducibility_score": reproducibility_score,
        "severity_score": severity,
        "access_score": access_score,
        "frame_score": frame_score,
    }


def _size_score(size: int) -> int:
    if size <= 0:
        return 0
    return max(0, 40 - int(log2(size + 1) * 4))


def _materially_better(candidate: dict[str, Any], representative: dict[str, Any]) -> bool:
    if int(candidate["score"]) >= int(representative["score"]) + 10:
        return True
    candidate_size = int(candidate.get("poc_size") or 0)
    representative_size = int(representative.get("poc_size") or 0)
    if candidate_size and representative_size and candidate_size * 2 <= representative_size:
        return True
    return False


def _reason(candidate: dict[str, Any], representative: dict[str, Any], better: bool) -> str:
    if better:
        if candidate.get("poc_size") and representative.get("poc_size") and int(candidate["poc_size"]) < int(representative["poc_size"]):
            return "same root-cause signature, but the candidate PoV is materially smaller"
        return "same root-cause signature, but the candidate has stronger reproducibility or signal quality"
    return "same root-cause signature and the existing representative is at least as useful"

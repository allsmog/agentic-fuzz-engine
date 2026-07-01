from __future__ import annotations

import json
from hashlib import sha256
from math import log2
from typing import Any

from .asan import parse_asan_signal


SEVERITY_SCORE = {
    "heap-use-after-free": 100,
    "double-free": 98,
    "heap-buffer-overflow": 92,
    "stack-buffer-overflow": 88,
    "global-buffer-overflow": 84,
    "dynamic-stack-buffer-overflow": 82,
    "use-after-poison": 78,
}


def finding_signature(
    *,
    target: str,
    harness: str,
    sanitizer: str,
    error_token: str,
    crash_output: str,
) -> str:
    signal = parse_asan_signal(crash_output)
    material = {
        "target": target,
        "harness": harness,
        "sanitizer": sanitizer,
        "error_token": error_token,
        "asan_signature": signal.to_dict()["signature"] if signal else "",
    }
    return sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:24]


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


def finding_quality(finding: dict[str, Any], *, artifact_sizes: dict[str, int]) -> dict[str, Any]:
    signal = parse_asan_signal(str(finding.get("crash_output") or ""))
    crash_type = signal.crash_type if signal else ""
    severity = SEVERITY_SCORE.get(crash_type, 60 if crash_type else 0)
    artifact_name = finding.get("poc_artifact")
    size = artifact_sizes.get(str(artifact_name), 0) if artifact_name else 0
    size_score = _size_score(size)
    reproductions = int(finding.get("reproductions") or finding.get("matches_expected") or (3 if finding.get("verified") else 0) or 0)
    reproducibility_score = min(30, reproductions * 10)
    frame_score = 15 if signal and signal.top_function and signal.top_file else 0
    score = severity + size_score + reproducibility_score + frame_score
    return {
        "score": score,
        "crash_type": crash_type or None,
        "top_function": signal.top_function if signal else None,
        "top_file": signal.top_file if signal else None,
        "poc_artifact": artifact_name,
        "poc_size": size,
        "size_score": size_score,
        "reproducibility_score": reproducibility_score,
        "severity_score": severity,
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

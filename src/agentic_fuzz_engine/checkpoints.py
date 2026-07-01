from __future__ import annotations

from typing import Any


ALLOWED_PHASES = (
    "readiness",
    "scope",
    "input-material",
    "fuzzing",
    "grading",
    "dedupe",
    "patch",
    "report",
    "export",
)

MAX_CHECKPOINT_ITEMS = 64
MAX_CHECKPOINT_TEXT_BYTES = 4096


def prepare_campaign_checkpoint(
    *,
    target: str,
    harness: str | None,
    phase: str,
    tool_evidence: list[str],
    blockers: list[str] | None,
    next_command: str,
    agent: str | None = None,
) -> dict[str, Any]:
    normalized_phase = _clean_text(phase, "phase")
    if normalized_phase not in ALLOWED_PHASES:
        raise ValueError(f"phase must be one of: {', '.join(ALLOWED_PHASES)}")

    evidence = _clean_list(tool_evidence, "tool_evidence")
    if not evidence:
        raise ValueError("tool_evidence must include at least one completed tool call or artifact")

    normalized_blockers = [
        blocker
        for blocker in _clean_list(blockers or [], "blockers", required=False)
        if blocker.lower() not in {"none", "no blockers", "n/a"}
    ]

    return {
        "target": _clean_text(target, "target"),
        "harness": _clean_text(harness or "campaign", "harness"),
        "phase": normalized_phase,
        "tool_evidence": evidence,
        "blockers": normalized_blockers,
        "blocked": bool(normalized_blockers),
        "next_command": _clean_text(next_command, "next_command"),
        "agent": _clean_optional_text(agent, "agent"),
    }


def _clean_list(values: list[str], field: str, *, required: bool = True) -> list[str]:
    if len(values) > MAX_CHECKPOINT_ITEMS:
        raise ValueError(f"{field} must contain at most {MAX_CHECKPOINT_ITEMS} entries")
    cleaned = [_clean_text(value, field) for value in values]
    cleaned = [value for value in cleaned if value]
    if required and not cleaned:
        raise ValueError(f"{field} must not be empty")
    return cleaned


def _clean_optional_text(value: str | None, field: str) -> str | None:
    if value is None or value == "":
        return None
    return _clean_text(value, field)


def _clean_text(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    cleaned = " ".join(value.strip().split())
    if not cleaned:
        raise ValueError(f"{field} must not be empty")
    if len(cleaned.encode("utf-8")) > MAX_CHECKPOINT_TEXT_BYTES:
        raise ValueError(f"{field} exceeds {MAX_CHECKPOINT_TEXT_BYTES} bytes")
    return cleaned

"""Deterministic, advisory scoring for multi-lens candidate judgments.

Scores summarize a fixed set of named judgments.  They never suppress work or
change lifecycle state: central scheduling may display the recommendation,
but the evidence and threshold remain visible.  Judgment sets are stored as
content-addressed records, so retries are idempotent and quantiles are rebuilt
exactly from the current highest revision for every candidate.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import os
import re
import fcntl
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .managed_persistence import (
    atomic_write_text,
    managed_path,
    read_json,
    safe_read_text,
    validate_target_slug,
)
from .workspace import resolve_workspace_root

JUDGMENTS_RELATIVE = Path("data/candidate-judgments")
MAX_JUDGMENTS = 20_000
MAX_JUDGMENT_TOTAL_BYTES = 64 * 1024 * 1024
MAX_CALIBRATION_LABELS = 10_000
MAX_REASON_CHARS = 1000
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}\Z")
DEFAULT_LENSES = ("reachability", "input-control", "guarding", "impact", "evidence")


@dataclass(frozen=True)
class ScoringPolicy:
    quantile: float = 0.75
    min_score: float = 0.5
    lenses: tuple[str, ...] = DEFAULT_LENSES
    mode: str = "advisory"

    @property
    def votes(self) -> int:
        return len(self.lenses)

    def as_dict(self) -> dict[str, Any]:
        return {
            "quantile": self.quantile,
            "min_score": self.min_score,
            "lenses": list(self.lenses),
            "votes": self.votes,
            "mode": self.mode,
        }


def default_scoring_policy() -> dict[str, Any]:
    return ScoringPolicy().as_dict()


def _finite_fraction(value: Any, *, exclusive: bool = False) -> float:
    if type(value) not in (int, float):
        raise ValueError("scoring threshold must be an exact numeric type")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("scoring threshold must be numeric") from exc
    if not math.isfinite(number):
        raise ValueError("scoring threshold must be finite")
    valid = 0 < number < 1 if exclusive else 0 <= number <= 1
    if not valid:
        interval = "(0, 1)" if exclusive else "[0, 1]"
        raise ValueError(f"scoring threshold must be in {interval}")
    return number


def _policy(root: Path) -> ScoringPolicy:
    try:
        document = read_json(root, "campaign-policy.json", max_bytes=1024 * 1024)
    except (OSError, ValueError, json.JSONDecodeError, RecursionError, OverflowError) as exc:
        raise ValueError(f"malformed campaign scoring policy: {exc}") from exc
    if document is None:
        document = {}
    if not isinstance(document, dict):
        raise ValueError("campaign policy must be a JSON object")
    section = document.get("scoring", {})
    if not isinstance(section, dict):
        raise ValueError("campaign scoring policy must be a JSON object")
    if "lenses" in section and "votes" in section:
        raise ValueError("scoring policy cannot declare both lenses and votes")
    declared_lenses = section.get("lenses")
    lenses = DEFAULT_LENSES
    if "lenses" in section:
        if not isinstance(declared_lenses, list):
            raise ValueError("scoring.lenses must be a list")
        if not all(type(item) is str for item in declared_lenses):
            raise ValueError("scoring lens names must be exact strings")
        cleaned = tuple(declared_lenses)
        if not 2 <= len(cleaned) <= 12:
            raise ValueError("scoring.lenses must contain 2 to 12 entries")
        if not all(_ID_RE.fullmatch(item) for item in cleaned):
            raise ValueError("scoring lens name contains unsupported characters")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("scoring lens names must be unique")
        lenses = cleaned
    elif "votes" in section:
        if type(section["votes"]) is not int:
            raise ValueError("scoring.votes must be an exact integer")
        count = section["votes"]
        if not 2 <= count <= 12:
            raise ValueError("scoring.votes must be between 2 and 12")
        lenses = tuple(f"lens-{index + 1}" for index in range(count))
    return ScoringPolicy(
        quantile=_finite_fraction(section["quantile"], exclusive=True) if "quantile" in section else 0.75,
        min_score=_finite_fraction(section["min_score"]) if "min_score" in section else 0.5,
        lenses=lenses,
    )


def _policy_generation(policy: ScoringPolicy) -> str:
    return hashlib.sha256(
        json.dumps(policy.as_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def scoring_policy(root: Path, *, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    del env
    return _policy(Path(root)).as_dict()


def _clean_reason(value: Any) -> str:
    text = str(value or "").replace("\x00", " ").replace("\r", " ").replace("\n", " ")
    return text[:MAX_REASON_CHARS]


def _normalize_judgments(votes: Iterable[Any], policy: ScoringPolicy) -> list[dict[str, str]]:
    raw = list(itertools.islice(iter(votes), policy.votes + 1))
    if len(raw) != policy.votes:
        raise ValueError(f"expected exactly {policy.votes} judgments")
    normalized: list[dict[str, str]] = []
    for index, item in enumerate(raw):
        if isinstance(item, str):
            lens = policy.lenses[index]
            verdict = item
            reason = ""
        elif isinstance(item, Mapping):
            declared_lens = item.get("lens", policy.lenses[index])
            declared_verdict = item.get("verdict")
            if type(declared_lens) is not str or type(declared_verdict) is not str:
                raise ValueError("judgment lens and verdict must be exact strings")
            lens = declared_lens
            verdict = declared_verdict
            reason = _clean_reason(item.get("reason") or item.get("rationale"))
        else:
            raise ValueError("each judgment must be a verdict string or mapping")
        verdict = verdict.strip().lower()
        if verdict not in ("likely", "unlikely"):
            raise ValueError("judgment verdict must be 'likely' or 'unlikely'")
        normalized.append({"lens": lens, "verdict": verdict, "reason": reason})
    by_lens = {row["lens"]: row for row in normalized}
    if set(by_lens) != set(policy.lenses) or len(by_lens) != len(normalized):
        raise ValueError("judgments must contain each configured lens exactly once")
    return [by_lens[lens] for lens in policy.lenses]


def normalize_votes(votes: Iterable[Any]) -> tuple[int, int]:
    """Compatibility fold for callers that only need verdict counts."""
    raw = list(itertools.islice(iter(votes), 13))
    if not raw:
        raise ValueError("at least one judgment is required")
    if len(raw) > 12:
        raise ValueError("judgment count exceeds cap")
    likely = 0
    for item in raw:
        verdict = item if isinstance(item, str) else item.get("verdict") if isinstance(item, Mapping) else None
        text = str(verdict or "").strip().lower()
        if text not in ("likely", "unlikely"):
            raise ValueError("judgment verdict must be 'likely' or 'unlikely'")
        likely += int(text == "likely")
    return likely, len(raw)


def _validate_hypothesis_id(value: str) -> str:
    text = str(value)
    if not _ID_RE.fullmatch(text):
        raise ValueError("hypothesis id contains unsupported characters")
    return text


def _validated_record(row: dict[str, Any], file_digest: str) -> str | None:
    try:
        expected_keys = {
            "version", "policy_generation", "target", "hypothesis_id", "stream",
            "revision", "judgments", "votes_likely", "votes_total", "score",
            "rationale", "digest",
        }
        if set(row) != expected_keys:
            return "unexpected record schema"
        if type(row["version"]) is not int or row["version"] != 1:
            return "invalid version"
        if type(row["policy_generation"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", row["policy_generation"]):
            return "invalid policy generation"
        if type(row["target"]) is not str or type(row["hypothesis_id"]) is not str or type(row["stream"]) is not str:
            return "identifiers must be exact strings"
        validate_target_slug(row["target"])
        _validate_hypothesis_id(row["hypothesis_id"])
        if not _ID_RE.fullmatch(row["stream"]):
            return "invalid stream"
        if type(row["rationale"]) is not str:
            return "rationale must be an exact string"
        revision = row["revision"]
        if isinstance(revision, bool) or not isinstance(revision, int) or not 1 <= revision <= 1_000_000:
            return "invalid revision"
        judgments = row["judgments"]
        if not isinstance(judgments, list) or not 2 <= len(judgments) <= 12:
            return "invalid judgments"
        lenses: list[str] = []
        likely = 0
        for judgment in judgments:
            if not isinstance(judgment, dict) or set(judgment) != {"lens", "verdict", "reason"}:
                return "invalid judgment schema"
            if type(judgment["lens"]) is not str or not _ID_RE.fullmatch(judgment["lens"]):
                return "invalid judgment lens"
            if type(judgment["reason"]) is not str:
                return "judgment reason must be an exact string"
            verdict = judgment["verdict"]
            if type(verdict) is not str:
                return "judgment verdict must be an exact string"
            if verdict not in ("likely", "unlikely"):
                return "invalid judgment verdict"
            lenses.append(judgment["lens"])
            likely += int(verdict == "likely")
        if len(lenses) != len(set(lenses)):
            return "duplicate judgment lens"
        total = row["votes_total"]
        likely_count = row["votes_likely"]
        if type(total) is not int or type(likely_count) is not int:
            return "vote counts must be exact integers"
        if total != len(judgments) or likely_count != likely:
            return "inconsistent vote counts"
        if type(row["score"]) not in (int, float):
            return "score must be an exact numeric type"
        score = float(row["score"])
        if not math.isfinite(score) or not math.isclose(score, likely / total, rel_tol=0.0, abs_tol=1e-12):
            return "inconsistent score"
        if type(row["digest"]) is not str:
            return "digest must be an exact string"
        digest = row["digest"]
        base = {key: value for key, value in row.items() if key != "digest"}
        expected = hashlib.sha256(
            json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if digest != file_digest or digest != expected:
            return "content digest mismatch"
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return "invalid record structure"
    return None


@contextmanager
def _judgment_lock(root: Path):
    lock_path = managed_path(root, JUDGMENTS_RELATIVE / ".lock", create_parent=True)
    if lock_path.is_symlink():
        raise ValueError("judgment lock must not be a symbolic link")
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _records(root: Path) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    directory = managed_path(root, JUDGMENTS_RELATIVE)
    if not directory.exists():
        return [], [], []
    warnings: list[str] = []
    blockers: list[str] = []
    records: list[dict[str, Any]] = []
    paths: list[Path] = []
    total_bytes = 0
    with os.scandir(directory) as entries:
        for index, entry in enumerate(entries, 1):
            if index > MAX_JUDGMENTS:
                raise ValueError("judgment directory entry count exceeds cap")
            path = Path(entry.path)
            if entry.is_symlink():
                raise ValueError(f"judgment record is a symbolic link: {path}")
            if entry.is_file(follow_symlinks=False) and re.fullmatch(r"[0-9a-f]{64}\.json", entry.name):
                total_bytes += entry.stat(follow_symlinks=False).st_size
                if total_bytes > MAX_JUDGMENT_TOTAL_BYTES:
                    raise ValueError("judgment records exceed aggregate byte cap")
                paths.append(path)
    for path in sorted(paths, key=lambda item: item.name):
        try:
            text = safe_read_text(root, JUDGMENTS_RELATIVE / path.name, max_bytes=64 * 1024)
            row = json.loads(text or "")
        except (OSError, ValueError, json.JSONDecodeError, RecursionError, OverflowError):
            blockers.append(f"unreadable judgment record {path.name}")
            continue
        if not isinstance(row, dict):
            blockers.append(f"malformed judgment record {path.name}")
            continue
        reason = _validated_record(row, path.stem)
        if reason:
            blockers.append(f"tampered judgment record {path.name}: {reason}")
            continue
        records.append(row)
    return records, warnings, blockers


def _current(
    records: Iterable[dict[str, Any]],
) -> tuple[dict[tuple[str, str], dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    for row in records:
        key = (str(row["target"]), str(row["hypothesis_id"]), int(row["revision"]))
        grouped.setdefault(key, []).append(row)
    conflicts = [
        {"target": key[0], "hypothesis_id": key[1], "revision": key[2], "digests": sorted({row["digest"] for row in rows})}
        for key, rows in sorted(grouped.items())
        if len({row["digest"] for row in rows}) > 1
    ]
    conflicted = {(row["target"], row["hypothesis_id"]) for row in conflicts}
    current: dict[tuple[str, str], dict[str, Any]] = {}
    for key, rows in grouped.items():
        pair = key[:2]
        if pair in conflicted:
            continue
        row = rows[0]
        previous = current.get(pair)
        if previous is None or int(row["revision"]) > int(previous["revision"]):
            current[pair] = row
    return current, conflicts


def _exact_threshold(scores: list[float], quantile: float) -> float:
    if not scores:
        return 0.0
    ordered = sorted(scores)
    index = max(0, math.ceil(quantile * len(ordered)) - 1)
    return ordered[index]


def _decorate(current: dict[tuple[str, str], dict[str, Any]], policy: ScoringPolicy) -> list[dict[str, Any]]:
    by_stream: dict[str, list[float]] = {}
    for row in current.values():
        by_stream.setdefault(str(row.get("stream") or "default"), []).append(float(row["score"]))
    thresholds = {stream: _exact_threshold(values, policy.quantile) for stream, values in by_stream.items()}
    decorated: list[dict[str, Any]] = []
    for row in current.values():
        stream = str(row.get("stream") or "default")
        threshold = thresholds[stream]
        score = float(row["score"])
        decorated.append(
            {
                **row,
                "threshold": threshold,
                "quantile_passed": score >= threshold,
                "floor_passed": score >= policy.min_score,
                "recommended": score >= threshold and score >= policy.min_score,
                "advisory_only": True,
            }
        )
    return sorted(decorated, key=lambda row: (str(row["target"]), str(row["hypothesis_id"])))


def record_score(
    root: Path,
    *,
    target: str,
    hypothesis_id: str,
    votes: Iterable[Any],
    stream: str = "default",
    rationale: str | None = None,
    revision: int = 1,
) -> dict[str, Any]:
    workspace = Path(root)
    slug = validate_target_slug(target)
    if type(hypothesis_id) is not str:
        raise ValueError("hypothesis id must be an exact string")
    hypothesis = _validate_hypothesis_id(hypothesis_id)
    if type(stream) is not str:
        raise ValueError("stream must be an exact string")
    if not _ID_RE.fullmatch(stream):
        raise ValueError("stream contains unsupported characters")
    if isinstance(revision, bool) or not isinstance(revision, int) or not 1 <= revision <= 1_000_000:
        raise ValueError("revision must be between 1 and 1000000")
    policy = _policy(workspace)
    judgments = _normalize_judgments(votes, policy)
    likely = sum(row["verdict"] == "likely" for row in judgments)
    base = {
        "version": 1,
        "policy_generation": _policy_generation(policy),
        "target": slug,
        "hypothesis_id": hypothesis,
        "stream": stream,
        "revision": revision,
        "judgments": judgments,
        "votes_likely": likely,
        "votes_total": policy.votes,
        "score": likely / policy.votes,
        "rationale": _clean_reason(rationale),
    }
    digest = hashlib.sha256(json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    record = {**base, "digest": digest}
    relative = JUDGMENTS_RELATIVE / f"{digest}.json"
    with _judgment_lock(workspace):
        existing = safe_read_text(workspace, relative, max_bytes=64 * 1024)
        created = existing is None
        if existing is not None:
            if existing != json.dumps(record, indent=2, sort_keys=True) + "\n":
                raise ValueError("content-addressed judgment record mismatch")
        else:
            records, _, blockers = _records(workspace)
            if blockers:
                raise ValueError("cannot record score while stored judgments are invalid")
            for prior in records:
                if (
                    prior["target"] == slug
                    and prior["hypothesis_id"] == hypothesis
                    and prior["revision"] == revision
                    and prior["digest"] != digest
                ):
                    raise ValueError("conflicting judgment set for the same candidate revision")
            atomic_write_text(
                workspace,
                relative,
                json.dumps(record, indent=2, sort_keys=True) + "\n",
                max_bytes=64 * 1024,
            )
    report = scoring_report(workspace_root=workspace)
    if not report.get("ok"):
        raise ValueError(f"stored judgment validation failed: {report.get('blockers')}")
    if any(
        row["target"] == slug and row["hypothesis_id"] == hypothesis
        for row in report.get("conflicts", [])
    ):
        raise ValueError("conflicting judgment set for the same candidate revision")
    selected = next(
        row for row in report["scores"] if row["target"] == slug and row["hypothesis_id"] == hypothesis
    )
    return {"ok": True, "created": created, **selected, "blockers": []}


def hypothesis_scores(root: Path, target: str) -> dict[str, Any]:
    slug = validate_target_slug(target)
    report = scoring_report(workspace_root=root)
    if not report.get("ok"):
        return {
            "ok": False,
            "target": slug,
            "scores": {},
            "warnings": report.get("warnings", []),
            "blockers": report.get("blockers", ["stored scoring state is invalid"]),
        }
    return {
        "ok": True,
        "target": slug,
        "scores": {
            row["hypothesis_id"]: row
            for row in report["scores"]
            if row["target"] == slug
        },
        "warnings": report.get("warnings", []),
        "blockers": [],
    }


def scoring_report(
    *,
    workspace_root: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = resolve_workspace_root(workspace_root, env=env)
    try:
        records, warnings, blockers = _records(root)
    except (OSError, ValueError, RecursionError, OverflowError) as exc:
        return {"ok": False, "mode": "candidate-scoring", "scores": [], "blockers": [str(exc)]}
    try:
        policy = _policy(root)
    except ValueError as exc:
        return {"ok": False, "mode": "candidate-scoring", "scores": [], "blockers": [str(exc)]}
    if blockers:
        return {
            "ok": False,
            "mode": "candidate-scoring",
            "scores": [],
            "conflicts": [],
            "warnings": warnings,
            "advisory_only": True,
            "blockers": blockers,
        }
    generation = _policy_generation(policy)
    compatible = []
    for record in records:
        judgments = record.get("judgments")
        lenses = {
            row["lens"]
            for row in judgments
            if isinstance(row, Mapping)
        } if isinstance(judgments, list) else set()
        if (
            record.get("policy_generation") != generation
            or len(judgments or []) != policy.votes
            or lenses != set(policy.lenses)
        ):
            warnings.append(f"ignored judgment {record.get('digest', '?')} from a different scoring policy generation")
            continue
        compatible.append(record)
    current, conflicts = _current(compatible)
    if conflicts:
        return {
            "ok": False,
            "mode": "candidate-scoring",
            "policy": policy.as_dict(),
            "scores": [],
            "conflicts": conflicts,
            "streams": {},
            "warnings": warnings,
            "advisory_only": True,
            "blockers": ["conflicting judgment records exist for the same candidate revision"],
        }
    rows = _decorate(current, policy)
    streams: dict[str, dict[str, Any]] = {}
    for stream in sorted({str(row["stream"]) for row in rows}):
        members = [row for row in rows if row["stream"] == stream]
        streams[stream] = {
            "count": len(members),
            "threshold": _exact_threshold([float(row["score"]) for row in members], policy.quantile),
        }
    return {
        "ok": True,
        "mode": "candidate-scoring",
        "policy": policy.as_dict(),
        "scores": rows,
        "conflicts": conflicts,
        "streams": streams,
        "warnings": warnings,
        "advisory_only": True,
        "blockers": [],
    }


def calibrate(*, labels: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Exact floor sweep over explicitly supplied, generic labeled scores."""
    rows: list[tuple[float, bool]] = []
    for index, label in enumerate(labels, 1):
        if index > MAX_CALIBRATION_LABELS:
            return {"ok": False, "blockers": ["calibration label count exceeds cap"]}
        if not isinstance(label, Mapping) or type(label.get("positive")) is not bool:
            return {"ok": False, "blockers": ["each calibration label needs a strict boolean positive field"]}
        if "score" not in label or type(label["score"]) not in (int, float):
            return {"ok": False, "blockers": ["each calibration label needs a numeric score"]}
        score = float(label["score"])
        if not math.isfinite(score) or not 0 <= score <= 1:
            return {"ok": False, "blockers": ["calibration scores must be finite and in [0, 1]"]}
        rows.append((score, label["positive"]))
    positives = [score for score, positive in rows if positive]
    if not positives:
        return {"ok": False, "blockers": ["at least one positive labeled score is required"]}
    floors = sorted({0.0, 1.0, *(score for score, _ in rows)})
    sweep = []
    for floor in floors:
        sweep.append(
            {
                "floor": floor,
                "false_negatives": sum(positive and score < floor for score, positive in rows),
                "negatives_rejected": sum((not positive) and score < floor for score, positive in rows),
            }
        )
    eligible = [row for row in sweep if row["false_negatives"] == 0]
    best = max(eligible, key=lambda row: (row["negatives_rejected"], row["floor"]))
    return {
        "ok": True,
        "recommended_floor": best["floor"],
        "floor_sweep": sweep,
        "advisory_only": True,
        "blockers": [],
    }

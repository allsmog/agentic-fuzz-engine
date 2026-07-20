"""Deterministic success predicates for fleet jobs.

A worker (interactive session or headless dispatcher) claims a job, authors
artifacts, and finishes; the engine — never the worker — decides whether the
job succeeded, by executing or reading the same state the campaign trusts:
generate.json validation, coverage replays, codec/bits/dict state, recorded
verified findings. The verdict is appended to the job ledger as a
``predicate`` block without changing the job's state; the caller (dispatcher
or session) applies the done/failed transition.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Mapping

from .jobs import append_event, fold_events, load_events
from .workspace import load_policy, resolve_workspace_root


def evaluate_job(
    *,
    job_id: str,
    workspace_root: str | Path | None = None,
    engine: Any = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = resolve_workspace_root(workspace_root, env=env)
    folded = fold_events(load_events(root))
    entry = folded.get(job_id)
    if entry is None:
        return {"ok": False, "blockers": [f"unknown job id: {job_id}"]}
    job_type = str(entry.get("type"))
    handler = _PREDICATES.get(job_type)
    if handler is None:
        return {"ok": False, "blockers": [f"no predicate for job type: {job_type}"]}
    verdict = handler(root, entry, engine)
    predicate = {
        "ok": bool(verdict.get("ok")),
        "command": verdict.get("command"),
        "detail": verdict.get("detail"),
        "ts": time.time(),
    }
    append_event(root, {"id": job_id, "predicate": predicate})
    return {"ok": True, "mode": "jobs-predicate", "job": job_id, "predicate": predicate}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _target_of(entry: Mapping[str, Any]) -> str:
    return str(entry.get("target") or "")


def _harness_author(root: Path, entry: Mapping[str, Any], engine: Any) -> dict[str, Any]:
    name = _target_of(entry)
    manifest_path = root / "targets" / "c" / name / ".localfuzz" / "generate.json"
    manifest = _read_json(manifest_path)
    fuzzer = root / "bin" / name / "fuzzer"
    validated = bool(manifest.get("validated"))
    binary_ok = fuzzer.is_file() and os.access(fuzzer, os.X_OK)
    return {
        "ok": validated and binary_ok,
        "command": f"target-generate {name} --validate",
        "detail": (
            f"generate.json validated={validated} ({manifest_path}); "
            f"fuzzer binary {'present' if binary_ok else 'missing'} ({fuzzer})"
        ),
    }


def _coverage_flip(root: Path, entry: Mapping[str, Any], engine: Any) -> dict[str, Any]:
    """frontier_seed / solver_assist: the qualifier method must appear covered
    after a fresh coverage replay (the COVERED_FUNC flip)."""
    name = _target_of(entry)
    method = str(entry.get("qualifier") or "")
    if not method:
        return {"ok": False, "detail": "job has no qualifier method", "command": None}
    command = f"sink-coverage --target {name}"
    report: dict[str, Any] = {}
    if engine is not None:
        try:
            report = engine.call_tool("sink_coverage", {"target": name, "workspace_root": str(root)})
        except Exception as exc:  # replay failure = predicate failure with evidence
            return {"ok": False, "command": command, "detail": f"coverage replay failed: {exc}"}
    if not report:
        report = _read_json(root / "work" / name / "sink-coverage.json")
        command += " (stale file read; no engine)"
    covered = {str(row.get("method")) for row in report.get("covered", []) if isinstance(row, dict)}
    uncovered = {str(row.get("method")) for row in report.get("uncovered", []) if isinstance(row, dict)}
    ok = method in covered
    return {
        "ok": ok,
        "command": command,
        "detail": (
            f"method {method} {'in COVERED' if ok else 'still uncovered' if method in uncovered else 'not observed'}; "
            f"covered={len(covered)} uncovered={len(uncovered)}"
        ),
    }


def _steering(root: Path, entry: Mapping[str, Any], engine: Any) -> dict[str, Any]:
    from .seed_weights import build_function_universe, load_bits

    name = _target_of(entry)
    qualifier = str(entry.get("qualifier") or "")
    work_dir = root / "work" / name
    if qualifier == "bits":
        bits, blockers = load_bits(work_dir)
        if not bits or blockers:
            return {"ok": False, "command": "load_bits", "detail": f"bits={len(bits)} blockers={blockers}"}
        universe, _, _, uni_blockers = build_function_universe(
            root=root, name=name, work_dir=work_dir, policy=load_policy(root)
        )
        ok = bool(universe) and not uni_blockers
        return {"ok": ok, "command": "build_function_universe", "detail": f"bits={len(bits)} universe={len(universe)} blockers={uni_blockers}"}
    if qualifier == "dict":
        dict_path = root / "targets" / "c" / name / f"{name}.dict"
        if not dict_path.is_file():
            return {"ok": False, "command": "dict lint", "detail": f"missing {dict_path}"}
        tokens = 0
        for line in dict_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and '"' in line:
                tokens += 1
        return {"ok": tokens > 0, "command": "dict lint", "detail": f"{tokens} tokens in {dict_path}"}
    if qualifier == "codec":
        status = _read_json(work_dir / "codec-status.json")
        ok = bool(status.get("validated"))
        return {"ok": ok, "command": f"codec-run {name} --mode validate", "detail": f"codec-status validated={ok}"}
    return {"ok": False, "command": None, "detail": f"unknown steering qualifier: {qualifier!r}"}


def _allowlist_build(root: Path, entry: Mapping[str, Any], engine: Any) -> dict[str, Any]:
    from .directed import load_queue

    name = _target_of(entry)
    task_id = (entry.get("evidence") or {}).get("task_id") if isinstance(entry.get("evidence"), dict) else None
    binaries: list[Path] = []
    for task in load_queue(root).get("tasks", []):
        if task.get("target") != name:
            continue
        if task_id and task.get("id") != task_id:
            continue
        if task.get("binary"):
            binaries.append(Path(str(task["binary"])))
    bin_dir = root / "bin" / name
    if not binaries and not task_id and bin_dir.is_dir():
        # No queue linkage to check against: any directed binary counts.
        binaries = sorted(bin_dir.glob("fuzzer-directed*"))
    live = [p for p in binaries if p.is_file() and os.access(p, os.X_OK)]
    return {
        "ok": bool(live),
        "command": f"directed-build {name}",
        "detail": f"directed binaries: {[str(p) for p in live] or 'none'}",
    }


def _triage(root: Path, entry: Mapping[str, Any], engine: Any) -> dict[str, Any]:
    name = _target_of(entry)
    sig12 = str(entry.get("qualifier") or "")
    report_dir = root / "data" / "reports" / name / sig12
    report_ok = report_dir.is_dir() and any(report_dir.iterdir())
    verified = _verified_finding_for(root, name, sig12)
    return {
        "ok": report_ok and verified is not None,
        "command": "finding-grade (worker) + verified finding scan",
        "detail": (
            f"report {'present' if report_ok else 'missing'} ({report_dir}); "
            f"verified finding {verified or 'not found'} for root_signature {sig12}*"
        ),
    }


def _row_matches_target(row: Mapping[str, Any], name: str, run_dir_name: str) -> bool:
    """Match a finding row to a target by its own fields, not the run-dir
    name — import/recon runs (e.g. ``archive-reimport``) hold verified
    findings for targets whose slug never appears in the directory name.
    Rows without harness/target fields fall back to the dir-name heuristic."""
    slug = name.replace("/", "_")
    harness = str(row.get("harness") or "")
    target = str(row.get("target") or "").replace("/", "_")
    if not harness and not target:
        return slug in run_dir_name
    return harness == name or slug == target or target.endswith("_" + slug)


def _verified_finding_for(root: Path, name: str, sig12: str) -> str | None:
    runs_dir = root / "data" / "runs"
    if not runs_dir.is_dir():
        return None
    for run_dir in sorted(runs_dir.iterdir(), reverse=True):
        if not run_dir.is_dir():
            continue
        findings = run_dir / "findings.jsonl"
        if not findings.is_file():
            continue
        try:
            with findings.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if (
                        str(row.get("root_signature") or "").startswith(sig12)
                        and row.get("verified")
                        and _row_matches_target(row, name, run_dir.name)
                    ):
                        return str(row.get("finding_id"))
        except OSError:
            continue
    return None


def _fleet_plan(root: Path, entry: Mapping[str, Any], engine: Any) -> dict[str, Any]:
    from .campaign_metrics import _ledger_current_state
    from .jobs import FLEET_PLAN_RELATIVE, fleet_policy

    plan_path = root / FLEET_PLAN_RELATIVE
    plan = _read_json(plan_path)
    rows = plan.get("targets")
    if not isinstance(rows, list) or not rows:
        return {"ok": False, "command": "fleet-plan parse", "detail": f"{plan_path} missing or has no targets list"}
    planned = {str(row.get("target")) for row in rows if isinstance(row, dict)}
    candidates = _ledger_current_state(root)
    required = {
        name for name, state in candidates.items()
        if str(state.get("status")) != "dead"
    }
    missing = sorted(required - planned)
    cap = float(fleet_policy(root).get("daily_usd_cap", 150.0))
    budget_total = 0.0
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("budget_usd"), (int, float)):
            budget_total += float(row["budget_usd"])
    ok = not missing and budget_total <= cap
    return {
        "ok": ok,
        "command": "fleet-plan parse",
        "detail": (
            f"{len(rows)} rows; missing non-dead candidates: {missing or 'none'}; "
            f"budget total ${budget_total:.2f} vs daily cap ${cap:.2f}"
        ),
    }


REQUIRED_HYPOTHESIS_KEYS = ("id", "function", "file", "line", "bug_class", "predicate_in_english")


def _vuln_hunt(root: Path, entry: Mapping[str, Any], engine: Any) -> dict[str, Any]:
    """Artifact-quality gate only: schema-valid hypotheses whose citations
    point at real files. Truth about the bugs comes from pov_produce/fuzzing."""
    name = _target_of(entry)
    path = root / "work" / name / "hypotheses.json"
    payload = _read_json(path)
    rows = payload.get("hypotheses")
    if not isinstance(rows, list) or not rows:
        return {"ok": False, "command": "hypotheses schema check", "detail": f"{path} missing or has no hypotheses list"}
    known_files = _sink_files(root, name)
    source_dir = _source_dir(root)
    problems: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            problems.append(f"row {index} not an object")
            continue
        missing = [key for key in REQUIRED_HYPOTHESIS_KEYS if not row.get(key)]
        if missing:
            problems.append(f"{row.get('id') or index}: missing {missing}")
            continue
        cited = str(row["file"])
        exists = (
            Path(cited).is_file()
            or (source_dir is not None and (source_dir / cited).is_file())
            or cited in known_files
        )
        if not exists:
            problems.append(f"{row['id']}: cited file not found: {cited}")
    ok = not problems
    return {
        "ok": ok,
        "command": "hypotheses schema + citation check",
        "detail": f"{len(rows)} hypotheses; problems: {problems or 'none'}",
    }


def _sink_files(root: Path, name: str) -> set[str]:
    from .seed_weights import resolve_sinks_jsonl
    from .sink_coverage import _load_sink_rows

    try:
        path = resolve_sinks_jsonl(root, name, load_policy(root))
        if path.is_file():
            return {str(row.get("file")) for row in _load_sink_rows(path) if row.get("file")}
    except Exception:
        pass
    return set()


def _source_dir(root: Path) -> Path | None:
    config = _read_json(root / "workspace.json")
    source = config.get("source_dir")
    return Path(source) if isinstance(source, str) and source else None


def _pov_produce(root: Path, entry: Mapping[str, Any], engine: Any) -> dict[str, Any]:
    """PASS = an engine-verified finding recorded for this target after the
    job was queued (finding-grade/harness-run record path). A hypothesis
    marked refuted WITH guard evidence also passes: a solid refutation is a
    valid job outcome, not a failure to retry."""
    name = _target_of(entry)
    queued_ts = float(entry.get("ts") or 0)
    finding = _verified_finding_after(root, name, queued_ts)
    if finding:
        return {"ok": True, "command": "verified finding scan", "detail": f"engine-verified finding {finding} recorded after job start"}
    hyp_id = str(entry.get("qualifier") or "")
    payload = _read_json(root / "work" / name / "hypotheses.json")
    for row in payload.get("hypotheses", []):
        if isinstance(row, dict) and str(row.get("id")) == hyp_id:
            if str(row.get("status")) == "refuted" and row.get("refutation_attempted"):
                return {"ok": True, "command": "hypothesis status check", "detail": f"{hyp_id} refuted with evidence: {str(row['refutation_attempted'])[:200]}"}
            return {"ok": False, "command": "hypothesis status check", "detail": f"{hyp_id} still {row.get('status')}; no verified finding since job start"}
    return {"ok": False, "command": "verified finding scan", "detail": f"no verified finding for {name} after job start and no matching hypothesis {hyp_id!r}"}


def _verified_finding_after(root: Path, name: str, ts: float) -> str | None:
    runs_dir = root / "data" / "runs"
    if not runs_dir.is_dir():
        return None
    for run_dir in sorted(runs_dir.iterdir(), reverse=True):
        if not run_dir.is_dir():
            continue
        findings = run_dir / "findings.jsonl"
        if not findings.is_file():
            continue
        try:
            with findings.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not row.get("verified") or not _row_matches_target(row, name, run_dir.name):
                        continue
                    created = _parse_ts(row.get("created_at"))
                    if created is None or created >= ts:
                        return str(row.get("finding_id"))
        except OSError:
            continue
    return None


def _parse_ts(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value:
        from datetime import datetime

        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


_PREDICATES = {
    "harness_author": _harness_author,
    "frontier_seed": _coverage_flip,
    "solver_assist": _coverage_flip,
    "steering": _steering,
    "allowlist_build": _allowlist_build,
    "triage": _triage,
    "fleet_plan": _fleet_plan,
    "vuln_hunt": _vuln_hunt,
    "pov_produce": _pov_produce,
}

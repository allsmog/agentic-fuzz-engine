"""Coverage-vs-sink frontier report (``sink-coverage``).

Answers the question plateau detection cannot: *which dangerous sinks has
the corpus never executed?* Coverage growth can look healthy for rounds
while the highest-value code (write-primitive sinks gated behind structured
input features) sits at zero coverage — the report makes that gap explicit
so aimed seed construction or the directed rungs get a concrete work order.

Mechanism: run the target's existing libFuzzer binary over the persistent
corpus with ``-runs=0 -print_coverage=1`` (execute corpus, mutate nothing),
tokenize the ``COVERED_FUNC`` lines, and intersect the covered function
names with the sinks JSONL produced by ``sink-scan``. Uncovered sinks are
ranked write/exec-first. Everything is bounded: one child process, wall
clock capped, output truncated before parsing.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Mapping

from .campaign_rounds import default_asan_options
from .seed_weights import covered_function_names
from .sink_scan import PRIMITIVE_WEIGHT, SINK_PRIMITIVES
from .workspace import load_policy, resolve_workspace_root

MAX_TIMEOUT_SECONDS = 600.0
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_UNCOVERED_ROWS = 200
MAX_COVERED_ROWS = 5_000
MAX_SINK_ROWS = 50_000

# Back-compat alias: the tokenizer moved to seed_weights so the per-seed
# index, close-seed sampling, and codec qualifying share one implementation.
_covered_function_names = covered_function_names


def sink_coverage(
    *,
    target: str,
    sinks_jsonl: str | Path | None = None,
    workspace_root: str | Path | None = None,
    timeout_seconds: int | float = 120,
    top: int = MAX_UNCOVERED_ROWS,
    max_inputs: int | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(os.environ if env is None else env)
    root = resolve_workspace_root(workspace_root, env=environment)
    name = target.removeprefix("localfuzz/c/")

    # An explicit max_inputs wins; otherwise honor the workspace policy so
    # the standalone verb samples the same way campaign rounds do.
    if max_inputs is None:
        frontier_policy = load_policy(root, env=environment).get("frontier", {})
        if isinstance(frontier_policy, dict):
            policy_max = frontier_policy.get("coverage_max_inputs")
            if policy_max is not None:
                max_inputs = int(policy_max)

    fuzzer = root / "bin" / name / "fuzzer"
    corpus = root / "work" / name / "seeds"
    sinks_path = Path(sinks_jsonl).expanduser().resolve() if sinks_jsonl else root / "data" / "sink-scan.jsonl"

    blockers: list[str] = []
    if not fuzzer.is_file() or not os.access(fuzzer, os.X_OK):
        blockers.append(f"missing fuzzer binary (run target-build first): {fuzzer}")
    if not sinks_path.is_file():
        blockers.append(f"missing sinks JSONL (run sink-scan first): {sinks_path}")
    corpus_size = sum(1 for entry in corpus.iterdir() if entry.is_file()) if corpus.is_dir() else 0
    if corpus_size == 0:
        blockers.append(f"empty corpus (nothing to measure coverage over): {corpus}")
    if blockers:
        return _result(target, fuzzer, sinks_path, corpus_size, blockers=blockers)

    sinks = _load_sink_rows(sinks_path)
    if not sinks:
        return _result(target, fuzzer, sinks_path, corpus_size, blockers=[f"no sink rows in {sinks_path}"])

    timeout = min(max(float(timeout_seconds), 1.0), MAX_TIMEOUT_SECONDS)
    environment.setdefault("ASAN_OPTIONS", default_asan_options(root))
    # -print_coverage=1 resolves COVERED_FUNC names through the sanitizer
    # symbolizer; the campaign default symbolize=0 would leave the dump empty.
    environment["ASAN_OPTIONS"] = re.sub(
        r"symbolize=0", "symbolize=1", environment["ASAN_OPTIONS"]
    )
    # Distro llvm-symbolizer builds may query remote debuginfod servers per
    # PC; without that egress every lookup stalls until the TCP timeout.
    environment.setdefault("DEBUGINFOD_URLS", "")
    # Slow-unit targets (e.g. filesystem images) cannot replay thousands of
    # corpus entries in bounded time: sample the newest max_inputs entries
    # into a staging dir instead. Coverage is cumulative across a corpus of
    # variants, so the newest slice is a good bounded approximation.
    corpus_arg = corpus
    sampled = 0
    if max_inputs is not None and corpus_size > int(max_inputs):
        sample_dir = root / "work" / name / "coverage-sample"
        if sample_dir.exists():
            shutil.rmtree(sample_dir)
        sample_dir.mkdir(parents=True)
        newest = sorted(
            (entry for entry in corpus.iterdir() if entry.is_file()),
            key=lambda entry: entry.stat().st_mtime,
            reverse=True,
        )[: max(1, int(max_inputs))]
        for entry in newest:
            try:
                os.link(entry, sample_dir / entry.name)
            except OSError:
                shutil.copy2(entry, sample_dir / entry.name)
        sampled = len(newest)
        corpus_arg = sample_dir
    try:
        completed = subprocess.run(
            [str(fuzzer), "-runs=0", "-print_coverage=1", str(corpus_arg)],
            capture_output=True,
            timeout=timeout,
            env=environment,
            cwd=str(root),
        )
    except subprocess.TimeoutExpired:
        return _result(
            target, fuzzer, sinks_path, corpus_size,
            blockers=[
                f"coverage run exceeded {timeout:.0f}s over "
                f"{sampled or corpus_size} corpus entries"
                + ("" if sampled else " (set frontier.coverage_max_inputs to sample)")
            ],
        )
    finally:
        if sampled:
            shutil.rmtree(root / "work" / name / "coverage-sample", ignore_errors=True)
    output = (completed.stderr + b"\n" + completed.stdout)[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    covered_names = _covered_function_names(output)
    if not covered_names:
        return _result(
            target, fuzzer, sinks_path, corpus_size,
            blockers=["no COVERED_FUNC lines in fuzzer output (binary not built with libFuzzer coverage?)"],
        )

    covered_rows: list[dict[str, Any]] = []
    uncovered_rows: list[dict[str, Any]] = []
    for row in sinks:
        (covered_rows if row["method"] in covered_names else uncovered_rows).append(row)
    uncovered_rows.sort(
        key=lambda row: (
            -PRIMITIVE_WEIGHT.get(row.get("primitive") or "", 1),
            row.get("file") or "",
            row.get("line") or 0,
        )
    )

    result = _result(
        target, fuzzer, sinks_path, corpus_size,
        blockers=[],
        sinks_total=len(sinks),
        sinks_covered=len(covered_rows),
        sinks_uncovered=len(uncovered_rows),
        covered_by_primitive=_count_by_primitive(covered_rows),
        uncovered_by_primitive=_count_by_primitive(uncovered_rows),
        uncovered=uncovered_rows[: max(1, int(top))],
        covered=covered_rows[:MAX_COVERED_ROWS],
        covered_functions_observed=len(covered_names),
    )
    report_path = root / "work" / name / "sink-coverage.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result["report"] = str(report_path)
    return result


def _load_sink_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            if index >= MAX_SINK_ROWS:
                break
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("kind") != "sink" or not row.get("method"):
                continue
            primitive = row.get("primitive") or SINK_PRIMITIVES.get(str(row.get("callee") or ""))
            rows.append(
                {
                    "tag": row.get("tag"),
                    "file": row.get("file"),
                    "line": row.get("line"),
                    "method": str(row["method"]),
                    "callee": row.get("callee"),
                    "primitive": primitive,
                }
            )
    return rows


def _count_by_primitive(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get("primitive") or "other")
        counts[key] = counts.get(key, 0) + 1
    return counts


def _result(
    target: str,
    fuzzer: Path,
    sinks_path: Path,
    corpus_size: int,
    *,
    blockers: list[str],
    **extra: Any,
) -> dict[str, Any]:
    return {
        "ok": not blockers,
        "mode": "sink-coverage",
        "target": target,
        "fuzzer": str(fuzzer),
        "sinks_jsonl": str(sinks_path),
        "corpus_size": corpus_size,
        "blockers": blockers,
        **extra,
    }

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

from .checkpoints import ALLOWED_PHASES
from .engine import AgenticFuzzEngine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agentic Fuzz Engine utility")
    parser.add_argument("--data-root", default=os.environ.get("CLAUDE_PLUGIN_DATA", "runs/agentic-fuzz-engine"))
    parser.add_argument(
        "--reference-root",
        default=os.environ.get("AGENTIC_FUZZ_REFERENCE_ROOT"),
    )
    parser.add_argument("--audit-root", action="append", default=[])
    subcommands = parser.add_subparsers(dest="command", required=True)

    list_fixtures = subcommands.add_parser("fidelity-list-fixtures", aliases=["fidelity-list-fixtures"])
    list_fixtures.add_argument("--include-disabled", action="store_true")
    validate = subcommands.add_parser("fidelity-validate-fixtures")
    validate.add_argument("--include-disabled", action="store_true", default=True)
    target = subcommands.add_parser("target-describe")
    target.add_argument("project")
    target_discover = subcommands.add_parser("target-discover")
    target_discover.add_argument("source_dir")
    target_discover.add_argument("--project", default=None)
    target_build_probe = subcommands.add_parser("target-build-probe")
    target_build_probe.add_argument("run_id")
    target_build_probe.add_argument("source_dir")
    target_build_probe.add_argument("--project", default=None)
    target_build_probe.add_argument("--build-id", default="build-probe")
    target_build_probe.add_argument("--build-command-json", default=None)
    target_build_probe.add_argument("--timeout-seconds", type=float, default=30)
    target_validate = subcommands.add_parser("target-validate")
    target_validate.add_argument("project")
    harness = subcommands.add_parser("harness-list")
    harness.add_argument("project")
    campaign = subcommands.add_parser("campaign-start")
    campaign.add_argument("target")
    campaign.add_argument("--name", default=None)
    status = subcommands.add_parser("campaign-status")
    status.add_argument("run_id")
    phase_audit = subcommands.add_parser("campaign-phase-audit")
    phase_audit.add_argument("run_id")
    checkpoint_record = subcommands.add_parser("campaign-checkpoint-record")
    checkpoint_record.add_argument("run_id")
    checkpoint_record.add_argument("--target", required=True)
    checkpoint_record.add_argument("--harness", default=None)
    checkpoint_record.add_argument("--phase", required=True, choices=ALLOWED_PHASES)
    checkpoint_record.add_argument("--tool-evidence", action="append", required=True)
    checkpoint_record.add_argument("--blocker", action="append", default=[])
    checkpoint_record.add_argument("--next-command", required=True)
    checkpoint_record.add_argument("--agent", default=None)
    checkpoint_list = subcommands.add_parser("campaign-checkpoint-list")
    checkpoint_list.add_argument("run_id")
    campaign_audit = subcommands.add_parser("campaign-fidelity-audit")
    campaign_audit.add_argument("run_id")
    campaign_audit.add_argument("--project", default=None)
    campaign_audit.add_argument("--include-disabled", action="store_true")
    campaign_report = subcommands.add_parser("campaign-report")
    campaign_report.add_argument("run_id")
    campaign_report.add_argument("--project", default=None)
    campaign_report.add_argument("--artifact-prefix", default=None)
    campaign_report.add_argument("--include-disabled", action="store_true")
    completion = subcommands.add_parser("campaign-completion-audit")
    completion.add_argument("run_id")
    completion.add_argument("--project", default=None)
    completion.add_argument("--include-disabled", action="store_true", default=True)
    completion.add_argument("--require-report", dest="require_report", action="store_true", default=True)
    completion.add_argument("--no-require-report", dest="require_report", action="store_false")
    completion.add_argument("--required-phase", choices=ALLOWED_PHASES, action="append", dest="required_phases", default=None)
    completion.add_argument("--strict", action="store_true")
    full_completion = subcommands.add_parser("campaign-full-completion-audit")
    full_completion.add_argument("run_id")
    full_completion.add_argument("--project", default=None)
    full_completion.add_argument("--include-disabled", action="store_true", default=True)
    full_completion.add_argument("--require-report", dest="require_report", action="store_true", default=True)
    full_completion.add_argument("--no-require-report", dest="require_report", action="store_false")
    full_completion.add_argument("--required-agent", action="append", dest="required_agents", default=None)
    full_completion.add_argument("--strict", action="store_true")
    export_bundle = subcommands.add_parser("export-bundle-create", aliases=["export-bundle-create"])
    export_bundle.add_argument("run_id")
    export_bundle.add_argument("--project", default=None)
    export_bundle.add_argument("--artifact-name", default=None)
    export_pov = subcommands.add_parser("export-mock-api-submit-pov", aliases=["export-mock-api-submit-pov"])
    export_pov.add_argument("run_id")
    export_pov.add_argument("--project", default=None)
    export_pov.add_argument("--finding-id", default=None)
    export_pov.add_argument("--poc-artifact", default=None)
    export_patch = subcommands.add_parser("export-mock-api-submit-patch", aliases=["export-mock-api-submit-patch"])
    export_patch.add_argument("run_id")
    export_patch.add_argument("--project", default=None)
    export_patch.add_argument("--patch-artifact", default=None)
    export_sarif = subcommands.add_parser("export-mock-api-submit-sarif", aliases=["export-mock-api-submit-sarif"])
    export_sarif.add_argument("run_id")
    export_sarif.add_argument("--project", default=None)
    export_sarif.add_argument("--report-artifact", default=None)
    export_list = subcommands.add_parser("export-list", aliases=["export-list"])
    export_list.add_argument("run_id")
    artifact_put = subcommands.add_parser("artifact-put")
    artifact_put.add_argument("run_id")
    artifact_put.add_argument("name")
    artifact_put.add_argument("--file", required=True)
    artifact_list = subcommands.add_parser("artifact-list")
    artifact_list.add_argument("run_id")
    artifact_get = subcommands.add_parser("artifact-get")
    artifact_get.add_argument("run_id")
    artifact_get.add_argument("name")
    corpus_import = subcommands.add_parser("corpus-import")
    corpus_import.add_argument("run_id")
    corpus_import.add_argument("source_path")
    corpus_import.add_argument("--kind", choices=("auto", "seed", "dictionary"), default="auto")
    corpus_import.add_argument("--artifact-prefix", default="corpus")
    corpus_import.add_argument("--max-files", type=int, default=100)
    corpus_import.add_argument("--max-file-bytes", type=int, default=262144)
    crash_import = subcommands.add_parser("crash-import")
    crash_import.add_argument("run_id")
    crash_import.add_argument("source_path")
    crash_import.add_argument("--target", required=True)
    crash_import.add_argument("--harness", required=True)
    crash_import.add_argument("--sanitizer", default="address")
    crash_import.add_argument("--artifact-prefix", default=None)
    crash_import.add_argument("--harness-command-json", default=None)
    crash_import.add_argument("--expected-error-token", default=None)
    crash_import.add_argument("--timeout-seconds", type=float, default=10)
    crash_import.add_argument("--repetitions", type=int, default=3)
    crash_import.add_argument("--no-record-findings", action="store_true")
    crash_import.add_argument("--max-files", type=int, default=100)
    crash_import.add_argument("--max-file-bytes", type=int, default=1048576)
    dictionary_generate = subcommands.add_parser("dictionary-generate")
    dictionary_generate.add_argument("run_id")
    dictionary_generate.add_argument("source_dir")
    dictionary_generate.add_argument("--target", required=True)
    dictionary_generate.add_argument("--harness", required=True)
    dictionary_generate.add_argument("--artifact-name", default=None)
    dictionary_generate.add_argument("--max-files", type=int, default=500)
    dictionary_generate.add_argument("--max-file-bytes", type=int, default=262144)
    dictionary_generate.add_argument("--max-tokens", type=int, default=64)
    grammar_infer = subcommands.add_parser("grammar-infer")
    grammar_infer.add_argument("run_id")
    grammar_infer.add_argument("source_dir")
    grammar_infer.add_argument("--target", required=True)
    grammar_infer.add_argument("--harness", required=True)
    grammar_infer.add_argument("--artifact-prefix", default=None)
    grammar_infer.add_argument("--max-files", type=int, default=500)
    grammar_infer.add_argument("--max-file-bytes", type=int, default=262144)
    grammar_infer.add_argument("--max-tokens", type=int, default=32)
    grammar_infer.add_argument("--max-seeds", type=int, default=32)
    concolic_plan = subcommands.add_parser("concolic-plan")
    concolic_plan.add_argument("run_id")
    concolic_plan.add_argument("source_dir")
    concolic_plan.add_argument("--target", required=True)
    concolic_plan.add_argument("--harness", required=True)
    concolic_plan.add_argument("--artifact-prefix", default=None)
    concolic_plan.add_argument("--max-files", type=int, default=500)
    concolic_plan.add_argument("--max-file-bytes", type=int, default=262144)
    concolic_plan.add_argument("--max-tokens", type=int, default=32)
    concolic_plan.add_argument("--max-seeds", type=int, default=32)
    finding_dedupe = subcommands.add_parser("finding-dedupe")
    finding_dedupe.add_argument("run_id")
    finding_lifecycle = subcommands.add_parser("finding-lifecycle-audit")
    finding_lifecycle.add_argument("run_id")
    finding_lifecycle.add_argument("--strict", action="store_true")
    finding_grade = subcommands.add_parser("finding-grade")
    finding_grade.add_argument("run_id")
    finding_grade.add_argument("artifact_name")
    finding_grade.add_argument("--target", required=True)
    finding_grade.add_argument("--harness", required=True)
    finding_grade.add_argument("--sanitizer", default="address")
    finding_grade.add_argument("--harness-command-json", required=True)
    finding_grade.add_argument("--expected-error-token", default=None)
    finding_grade.add_argument("--timeout-seconds", type=float, default=10)
    finding_grade.add_argument("--repetitions", type=int, default=3)
    finding_grade.add_argument("--record-finding", action="store_true")
    finding_classify = subcommands.add_parser("finding-classify")
    finding_classify.add_argument("run_id")
    finding_classify.add_argument("--target", required=True)
    finding_classify.add_argument("--harness", required=True)
    finding_classify.add_argument("--sanitizer", default="address")
    finding_classify.add_argument("--error-token", required=True)
    finding_classify.add_argument("--crash-output-file", required=True)
    finding_classify.add_argument("--poc-artifact", default=None)
    finding_classify.add_argument("--reproductions", type=int, default=None)
    finding_classify.add_argument("--verified", action="store_true")
    harness_run = subcommands.add_parser("harness-run")
    harness_run.add_argument("run_id")
    harness_run.add_argument("artifact_name")
    harness_run.add_argument("--target", required=True)
    harness_run.add_argument("--harness", required=True)
    harness_run.add_argument("--sanitizer", default="address")
    harness_run.add_argument("--expected-error-token", default=None)
    harness_run.add_argument("--timeout-seconds", type=float, default=10)
    harness_run.add_argument("--repetitions", type=int, default=3)
    harness_run.add_argument("--record-finding", action="store_true")
    harness_run.add_argument("harness_command", nargs=argparse.REMAINDER)
    pov_minimize = subcommands.add_parser("pov-minimize")
    pov_minimize.add_argument("run_id")
    pov_minimize.add_argument("artifact_name")
    pov_minimize.add_argument("--output-artifact", default=None)
    pov_minimize.add_argument("--harness-command-json", required=True)
    pov_minimize.add_argument("--expected-error-token", default=None)
    pov_minimize.add_argument("--timeout-seconds", type=float, default=10)
    pov_minimize.add_argument("--repetitions", type=int, default=3)
    pov_minimize.add_argument("--max-attempts", type=int, default=80)
    pov_minimize.add_argument("--no-preserve-signal", action="store_true")
    replay = subcommands.add_parser("fidelity-replay-campaign")
    replay.add_argument("run_id")
    replay.add_argument("--project", default=None)
    replay.add_argument("--include-disabled", action="store_true")
    replay.add_argument("--command-map-json", default=None)
    replay.add_argument("--command-map-file", default=None)
    replay.add_argument("--default-command-json", default=None)
    replay.add_argument("--timeout-seconds", type=float, default=10)
    replay.add_argument("--repetitions", type=int, default=3)
    replay.add_argument("--no-record-findings", action="store_true")
    replay.add_argument("--max-cases", type=int, default=None)
    owned_replay = subcommands.add_parser("fidelity-owned-build-replay")
    owned_replay.add_argument("--run-id", default=None)
    owned_replay.add_argument("--project", default=None)
    owned_replay.add_argument("--include-disabled", action="store_true")
    owned_replay.add_argument("--max-cases", type=int, default=None)
    owned_replay.add_argument("--compile-timeout-seconds", type=float, default=30)
    owned_replay.add_argument("--replay-timeout-seconds", type=float, default=10)
    owned_replay.add_argument("--repetitions", type=int, default=1)
    owned_replay.add_argument("--summary-only", action="store_true")
    owned_replay.add_argument("--require-all", action="store_true")
    oss_fuzz_build = subcommands.add_parser("fidelity-oss-fuzz-build")
    oss_fuzz_build.add_argument("project")
    oss_fuzz_build.add_argument("--run-id", default=None)
    oss_fuzz_build.add_argument("--oss-fuzz-root", default=None)
    oss_fuzz_build.add_argument("--docker-host", default=None)
    oss_fuzz_build.add_argument("--docker-platform", default="linux/amd64")
    oss_fuzz_build.add_argument("--sanitizer", default="address")
    oss_fuzz_build.add_argument("--engine", default="libfuzzer")
    oss_fuzz_build.add_argument("--timeout-seconds", type=float, default=900)
    oss_fuzz_build.add_argument("--summary-only", action="store_true")
    oss_fuzz_replay = subcommands.add_parser("fidelity-oss-fuzz-build-replay")
    oss_fuzz_replay.add_argument("project")
    oss_fuzz_replay.add_argument("--run-id", default=None)
    oss_fuzz_replay.add_argument("--oss-fuzz-root", default=None)
    oss_fuzz_replay.add_argument("--docker-host", default=None)
    oss_fuzz_replay.add_argument("--docker-platform", default="linux/amd64")
    oss_fuzz_replay.add_argument("--sanitizer", default="address")
    oss_fuzz_replay.add_argument("--engine", default="libfuzzer")
    oss_fuzz_replay.add_argument("--build-timeout-seconds", type=float, default=900)
    oss_fuzz_replay.add_argument("--replay-timeout-seconds", type=float, default=30)
    oss_fuzz_replay.add_argument("--repetitions", type=int, default=1)
    oss_fuzz_replay.add_argument("--runner-image", default="ghcr.io/agentic-fuzz/base-runner:v1.3.0")
    oss_fuzz_replay.add_argument("--include-disabled", action="store_true")
    oss_fuzz_replay.add_argument("--no-record-findings", action="store_true")
    oss_fuzz_replay.add_argument("--summary-only", action="store_true")
    oss_fuzz_replay.add_argument("--require-all", action="store_true")
    fuzz = subcommands.add_parser("fuzz-campaign")
    fuzz.add_argument("run_id")
    fuzz.add_argument("--target", required=True)
    fuzz.add_argument("--harness", required=True)
    fuzz.add_argument("--sanitizer", default="address")
    fuzz.add_argument("--seed-artifact", action="append", default=[])
    fuzz.add_argument("--dictionary-token", action="append", default=[])
    fuzz.add_argument("--dictionary-json", default=None)
    fuzz.add_argument("--harness-command-json", required=True)
    fuzz.add_argument("--expected-error-token", default=None)
    fuzz.add_argument("--timeout-seconds", type=float, default=10)
    fuzz.add_argument("--repetitions", type=int, default=3)
    fuzz.add_argument("--max-iterations", type=int, default=25)
    fuzz.add_argument("--feedback-rounds", type=int, default=1)
    fuzz.add_argument("--no-record-findings", action="store_true")
    fuzz.add_argument("--stop-on-first-finding", action="store_true")
    patch_candidate = subcommands.add_parser("patch-candidate-record")
    patch_candidate.add_argument("run_id")
    patch_candidate.add_argument("--patch-file", required=True)
    patch_candidate.add_argument("--artifact-name", default=None)
    patch_candidate.add_argument("--finding-id", default=None)
    patch_candidate.add_argument("--rationale", default=None)
    patch_candidate.add_argument("--variant-checked", action="append", default=[])
    patch_grade = subcommands.add_parser("patch-grade")
    patch_grade.add_argument("run_id")
    patch_grade.add_argument("--source-dir", required=True)
    patch_grade.add_argument("--patch-artifact", required=True)
    patch_grade.add_argument("--pov-artifact", required=True)
    patch_grade.add_argument("--harness-command-json", required=True)
    patch_grade.add_argument("--expected-error-token", required=True)
    patch_grade.add_argument("--build-command-json", default=None)
    patch_grade.add_argument("--test-command-json", default=None)
    patch_grade.add_argument("--reattack-artifact", action="append", default=[])
    patch_grade.add_argument("--reattack-command-json", default=None)
    patch_grade.add_argument("--timeout-seconds", type=float, default=10)
    patch_grade.add_argument("--repetitions", type=int, default=3)
    audit = subcommands.add_parser("runtime-guard-audit", aliases=["runtime-guard-audit"])
    audit.add_argument("--strict", action="store_true")
    parity = subcommands.add_parser("engine-parity-audit")
    parity.add_argument("--strict", action="store_true")
    runtime_doctor = subcommands.add_parser("runtime-doctor")
    runtime_doctor.add_argument("--strict", action="store_true")
    runtime_backend_status = subcommands.add_parser("runtime-backend-status")
    runtime_backend_status.add_argument("--strict", action="store_true")
    workspace_init_parser = subcommands.add_parser("workspace-init")
    workspace_init_parser.add_argument("--root", default=None)
    workspace_init_parser.add_argument("--map", action="append", dest="path_maps", default=[], metavar="HOST=OUTER")
    workspace_init_parser.add_argument("--source-dir", default=None)
    workspace_init_parser.add_argument("--klee-image", default=None)
    workspace_init_parser.add_argument("--build-container", default=None)
    workspace_init_parser.add_argument("--mount", action="append", dest="extra_mounts", default=[], metavar="HOST=CONTAINER[:ro]")
    workspace_init_parser.add_argument("--copy", action="append", dest="copies", default=[], metavar="SRC=DEST_REL")
    target_select_parser = subcommands.add_parser("target-select")
    target_select_parser.add_argument("--sinks-jsonl", required=True)
    target_select_parser.add_argument("--top", type=int, default=25)
    target_select_parser.add_argument("--workspace-root", default=None)
    target_scaffold_parser = subcommands.add_parser("target-scaffold")
    target_scaffold_parser.add_argument("name")
    target_scaffold_parser.add_argument("--sinks-jsonl", default=None)
    target_scaffold_parser.add_argument("--sink-tag", default=None)
    target_scaffold_parser.add_argument("--max-sink-refs", type=int, default=20)
    target_scaffold_parser.add_argument("--force", action="store_true")
    target_scaffold_parser.add_argument("--workspace-root", default=None)
    target_generate_parser = subcommands.add_parser("target-generate")
    target_generate_parser.add_argument("name")
    target_generate_parser.add_argument("--spec", required=True)
    target_generate_parser.add_argument("--sinks-jsonl", default=None)
    target_generate_parser.add_argument("--sink-tag", default=None)
    target_generate_parser.add_argument("--validate", action="store_true")
    target_generate_parser.add_argument("--workspace-root", default=None)
    target_build_parser = subcommands.add_parser("target-build")
    target_build_parser.add_argument("project")
    target_build_parser.add_argument("--only-step", action="append", dest="only_steps", default=[])
    target_build_parser.add_argument("--timeout-seconds", type=float, default=900)
    target_build_parser.add_argument("--workspace-root", default=None)
    round_run_parser = subcommands.add_parser("campaign-round-run")
    round_run_parser.add_argument("project")
    round_run_parser.add_argument("--run-id", default=None)
    round_run_parser.add_argument("--rounds", type=int, default=1)
    round_run_parser.add_argument("--fuzz-seconds", type=float, default=600)
    round_run_parser.add_argument("--rss-limit-mb", type=int, default=2048)
    round_run_parser.add_argument("--sync-max-inputs", type=int, default=32)
    round_run_parser.add_argument("--sync-seconds", type=float, default=600)
    round_run_parser.add_argument("--sync-memory-mb", type=int, default=4096)
    round_run_parser.add_argument("--klee-config", default=None)
    round_run_parser.add_argument("--klee-every", type=int, default=4)
    round_run_parser.add_argument("--klee-seconds", type=float, default=900)
    round_run_parser.add_argument("--workspace-root", default=None)
    round_run_parser.add_argument("--min-free-gb", type=float, default=10.0)
    corpus_sync_parser = subcommands.add_parser("symbolic-corpus-sync")
    corpus_sync_parser.add_argument("--corpus-dir", required=True)
    corpus_sync_parser.add_argument("--symcc-binary", required=True)
    corpus_sync_parser.add_argument("--state-dir", default=None)
    corpus_sync_parser.add_argument("--max-inputs", type=int, default=32)
    corpus_sync_parser.add_argument("--max-seconds", type=float, default=600)
    corpus_sync_parser.add_argument("--per-input-timeout", type=float, default=90)
    corpus_sync_parser.add_argument("--max-memory-mb", type=int, default=4096)
    corpus_sync_parser.add_argument("--max-new-files", type=int, default=500)
    fuzz_ensemble = subcommands.add_parser("fuzz-ensemble-run")
    fuzz_ensemble.add_argument("run_id")
    fuzz_ensemble.add_argument("--target", required=True)
    fuzz_ensemble.add_argument("--harness", required=True)
    fuzz_ensemble.add_argument("--harness-command-json", default=None)
    fuzz_ensemble.add_argument("--seed-artifact", action="append", default=[])
    fuzz_ensemble.add_argument("--worker", choices=("libfuzzer", "afl", "libafl"), action="append", dest="workers", default=None)
    fuzz_ensemble.add_argument("--libafl-command-json", default=None)
    fuzz_ensemble.add_argument("--runs", type=int, default=128)
    fuzz_ensemble.add_argument("--timeout-seconds", type=float, default=60)
    fuzz_ensemble.add_argument("--artifact-prefix", default=None)
    symbolic_worker = subcommands.add_parser("symbolic-worker-run")
    symbolic_worker.add_argument("run_id")
    symbolic_worker.add_argument("--mode", choices=("symcc", "symqemu", "z3", "klee"), default="symcc")
    symbolic_worker.add_argument("--command-json", default=None)
    symbolic_worker.add_argument("--constraints-smt2-b64", default=None)
    symbolic_worker.add_argument("--constraints-smt2-file", default=None)
    symbolic_worker.add_argument("--klee-config", default=None)
    symbolic_worker.add_argument("--workspace-root", default=None)
    symbolic_worker.add_argument("--timeout-seconds", type=float, default=60)
    symbolic_worker.add_argument("--artifact-prefix", default=None)
    sarif_reachability = subcommands.add_parser("sarif-reachability-run")
    sarif_reachability.add_argument("run_id")
    sarif_reachability.add_argument("--source-dir", required=True)
    sarif_reachability.add_argument("--sarif-file", required=True)
    sarif_reachability.add_argument("--language", default="c-cpp")
    sarif_reachability.add_argument("--database-dir", default=None)
    sarif_reachability.add_argument("--create-database", action="store_true")
    sarif_reachability.add_argument("--codeql-query-suite", default=None)
    sarif_reachability.add_argument("--joern-command-json", default=None)
    sarif_reachability.add_argument("--sootup-command-json", default=None)
    sarif_reachability.add_argument("--no-codeql", action="store_true")
    sarif_reachability.add_argument("--no-joern", action="store_true")
    sarif_reachability.add_argument("--no-sootup", action="store_true")
    sarif_reachability.add_argument("--timeout-seconds", type=float, default=300)
    sarif_reachability.add_argument("--artifact-prefix", default=None)
    patch_env = subcommands.add_parser("patch-environment-prepare")
    patch_env.add_argument("run_id")
    patch_env.add_argument("--source-dir", required=True)
    patch_env.add_argument("--env-name", default="patch-env")
    patch_env.add_argument("--patch-artifact", default=None)
    patch_env.add_argument("--build-command-json", default=None)
    patch_env.add_argument("--test-command-json", default=None)
    patch_env.add_argument("--timeout-seconds", type=float, default=300)
    parity_full = subcommands.add_parser("parity-full")
    parity_full.add_argument("--strict", action="store_true")
    campaign_full = subcommands.add_parser("campaign-full")
    campaign_full.add_argument("target")
    campaign_full.add_argument("--task-id", default="task-full-runtime")
    campaign_full.add_argument("--language", default="c-cpp")
    campaign_full.add_argument("--seconds", type=int, default=300)
    campaign_full_run = subcommands.add_parser("campaign-full-run")
    campaign_full_run.add_argument("project")
    campaign_full_run.add_argument("--run-id", default=None)
    campaign_full_run.add_argument("--harness", default=None)
    campaign_full_run.add_argument("--harness-command-json", default=None)
    campaign_full_run.add_argument("--command-map-json", default=None)
    campaign_full_run.add_argument("--command-map-file", default=None)
    campaign_full_run.add_argument("--source-dir", default=None)
    campaign_full_run.add_argument("--timeout-seconds", type=float, default=5)
    campaign_full_run.add_argument("--repetitions", type=int, default=3)
    campaign_full_run.add_argument("--include-disabled", action="store_true")
    campaign_full_run.add_argument("--summary-only", action="store_true")
    campaign_full_run.add_argument("--strict", action="store_true")
    deploy_local = subcommands.add_parser("deploy-local")
    deploy_local.add_argument("--namespace", default="agentic-fuzz")
    deploy_k8s = subcommands.add_parser("deploy-k8s")
    deploy_k8s.add_argument("--namespace", default="agentic-fuzz")
    benchmark = subcommands.add_parser("benchmark-fixtures", aliases=["benchmark-reference-fixtures"])
    benchmark.add_argument("--include-disabled", action="store_true")
    benchmark.add_argument("--strict", action="store_true")

    args = parser.parse_args(argv)
    engine = AgenticFuzzEngine(
        data_root=args.data_root,
        reference_root=args.reference_root,
        audit_roots=tuple(args.audit_root) or _default_audit_roots(),
    )
    payload: dict[str, Any]
    if args.command in {"fidelity-list-fixtures", "fidelity-list-fixtures"}:
        payload = engine.call_tool("fidelity_list_fixtures", {"include_disabled": args.include_disabled})
    elif args.command == "fidelity-validate-fixtures":
        payload = engine.call_tool("fidelity_validate_fixtures", {"include_disabled": args.include_disabled})
    elif args.command == "target-describe":
        payload = engine.call_tool("target_describe", {"project": args.project})
    elif args.command == "target-discover":
        payload = engine.call_tool("target_discover", {"source_dir": args.source_dir, "project": args.project})
    elif args.command == "target-build-probe":
        payload = engine.call_tool(
            "target_build_probe",
            {
                "run_id": args.run_id,
                "source_dir": args.source_dir,
                "project": args.project,
                "build_id": args.build_id,
                "build_commands": _load_json_arg(args.build_command_json, None, default=None),
                "timeout_seconds": args.timeout_seconds,
            },
        )
    elif args.command == "target-validate":
        payload = engine.call_tool("target_validate", {"project": args.project})
    elif args.command == "harness-list":
        payload = engine.call_tool("harness_list", {"project": args.project})
    elif args.command == "campaign-start":
        payload = engine.call_tool("campaign_start", {"target": args.target, "name": args.name})
    elif args.command == "campaign-status":
        payload = engine.call_tool("campaign_status", {"run_id": args.run_id})
    elif args.command == "campaign-phase-audit":
        payload = engine.call_tool("campaign_phase_audit", {"run_id": args.run_id})
    elif args.command == "campaign-checkpoint-record":
        payload = engine.call_tool(
            "campaign_checkpoint_record",
            {
                "run_id": args.run_id,
                "target": args.target,
                "harness": args.harness,
                "phase": args.phase,
                "tool_evidence": args.tool_evidence,
                "blockers": args.blocker,
                "next_command": args.next_command,
                "agent": args.agent,
            },
        )
    elif args.command == "campaign-checkpoint-list":
        payload = engine.call_tool("campaign_checkpoint_list", {"run_id": args.run_id})
    elif args.command == "campaign-fidelity-audit":
        payload = engine.call_tool(
            "campaign_fidelity_audit",
            {"run_id": args.run_id, "project": args.project, "include_disabled": args.include_disabled},
        )
    elif args.command == "campaign-report":
        payload = engine.call_tool(
            "campaign_report",
            {
                "run_id": args.run_id,
                "project": args.project,
                "artifact_prefix": args.artifact_prefix,
                "include_disabled": args.include_disabled,
            },
        )
    elif args.command == "campaign-completion-audit":
        payload = engine.call_tool(
            "campaign_completion_audit",
            {
                "run_id": args.run_id,
                "project": args.project,
                "include_disabled": args.include_disabled,
                "require_report": args.require_report,
                "required_phases": args.required_phases,
            },
        )
        if args.strict and not payload.get("ok"):
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1
    elif args.command == "campaign-full-completion-audit":
        payload = engine.call_tool(
            "campaign_full_completion_audit",
            {
                "run_id": args.run_id,
                "project": args.project,
                "include_disabled": args.include_disabled,
                "require_report": args.require_report,
                "required_agents": args.required_agents,
            },
        )
        if args.strict and not payload.get("ok"):
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1
    elif args.command in {"export-bundle-create", "export-bundle-create"}:
        payload = engine.call_tool(
            "export_bundle_create",
            {"run_id": args.run_id, "project": args.project, "artifact_name": args.artifact_name},
        )
    elif args.command in {"export-mock-api-submit-pov", "export-mock-api-submit-pov"}:
        payload = engine.call_tool(
            "export_mock_api_submit_pov",
            {
                "run_id": args.run_id,
                "project": args.project,
                "finding_id": args.finding_id,
                "poc_artifact": args.poc_artifact,
            },
        )
    elif args.command in {"export-mock-api-submit-patch", "export-mock-api-submit-patch"}:
        payload = engine.call_tool(
            "export_mock_api_submit_patch",
            {"run_id": args.run_id, "project": args.project, "patch_artifact": args.patch_artifact},
        )
    elif args.command in {"export-mock-api-submit-sarif", "export-mock-api-submit-sarif"}:
        payload = engine.call_tool(
            "export_mock_api_submit_sarif",
            {"run_id": args.run_id, "project": args.project, "report_artifact": args.report_artifact},
        )
    elif args.command in {"export-list", "export-list"}:
        payload = engine.call_tool("export_list", {"run_id": args.run_id})
    elif args.command == "artifact-put":
        content = Path(args.file).read_bytes()
        payload = engine.call_tool(
            "artifact_put",
            {"run_id": args.run_id, "name": args.name, "content_b64": base64.b64encode(content).decode("ascii")},
        )
    elif args.command == "artifact-list":
        payload = engine.call_tool("artifact_list", {"run_id": args.run_id})
    elif args.command == "artifact-get":
        payload = engine.call_tool("artifact_get", {"run_id": args.run_id, "name": args.name})
    elif args.command == "corpus-import":
        payload = engine.call_tool(
            "corpus_import",
            {
                "run_id": args.run_id,
                "source_path": args.source_path,
                "kind": args.kind,
                "artifact_prefix": args.artifact_prefix,
                "max_files": args.max_files,
                "max_file_bytes": args.max_file_bytes,
            },
        )
    elif args.command == "crash-import":
        payload = engine.call_tool(
            "crash_import",
            {
                "run_id": args.run_id,
                "source_path": args.source_path,
                "target": args.target,
                "harness": args.harness,
                "sanitizer": args.sanitizer,
                "artifact_prefix": args.artifact_prefix,
                "harness_command": _load_json_arg(args.harness_command_json, None, default=None),
                "expected_error_token": args.expected_error_token,
                "timeout_seconds": args.timeout_seconds,
                "repetitions": args.repetitions,
                "record_findings": not args.no_record_findings,
                "max_files": args.max_files,
                "max_file_bytes": args.max_file_bytes,
            },
        )
    elif args.command == "dictionary-generate":
        payload = engine.call_tool(
            "dictionary_generate",
            {
                "run_id": args.run_id,
                "source_dir": args.source_dir,
                "target": args.target,
                "harness": args.harness,
                "artifact_name": args.artifact_name,
                "max_files": args.max_files,
                "max_file_bytes": args.max_file_bytes,
                "max_tokens": args.max_tokens,
            },
        )
    elif args.command == "grammar-infer":
        payload = engine.call_tool(
            "grammar_infer",
            {
                "run_id": args.run_id,
                "source_dir": args.source_dir,
                "target": args.target,
                "harness": args.harness,
                "artifact_prefix": args.artifact_prefix,
                "max_files": args.max_files,
                "max_file_bytes": args.max_file_bytes,
                "max_tokens": args.max_tokens,
                "max_seeds": args.max_seeds,
            },
        )
    elif args.command == "concolic-plan":
        payload = engine.call_tool(
            "concolic_plan",
            {
                "run_id": args.run_id,
                "source_dir": args.source_dir,
                "target": args.target,
                "harness": args.harness,
                "artifact_prefix": args.artifact_prefix,
                "max_files": args.max_files,
                "max_file_bytes": args.max_file_bytes,
                "max_tokens": args.max_tokens,
                "max_seeds": args.max_seeds,
            },
        )
    elif args.command == "finding-dedupe":
        payload = engine.call_tool("finding_dedupe", {"run_id": args.run_id})
    elif args.command == "finding-lifecycle-audit":
        payload = engine.call_tool("finding_lifecycle_audit", {"run_id": args.run_id})
        if args.strict and not payload.get("ok"):
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1
    elif args.command == "finding-grade":
        payload = engine.call_tool(
            "finding_grade",
            {
                "run_id": args.run_id,
                "artifact_name": args.artifact_name,
                "target": args.target,
                "harness": args.harness,
                "sanitizer": args.sanitizer,
                "command": _load_json_arg(args.harness_command_json, None, default=[]),
                "expected_error_token": args.expected_error_token,
                "timeout_seconds": args.timeout_seconds,
                "repetitions": args.repetitions,
                "record_finding": args.record_finding,
            },
        )
    elif args.command == "finding-classify":
        payload = engine.call_tool(
            "finding_classify",
            {
                "run_id": args.run_id,
                "target": args.target,
                "harness": args.harness,
                "sanitizer": args.sanitizer,
                "error_token": args.error_token,
                "crash_output": Path(args.crash_output_file).read_text(encoding="utf-8"),
                "poc_artifact": args.poc_artifact,
                "reproductions": args.reproductions,
                "verified": args.verified,
            },
        )
    elif args.command == "harness-run":
        command = args.harness_command
        if command and command[0] == "--":
            command = command[1:]
        payload = engine.call_tool(
            "harness_run",
            {
                "run_id": args.run_id,
                "target": args.target,
                "harness": args.harness,
                "sanitizer": args.sanitizer,
                "artifact_name": args.artifact_name,
                "command": command,
                "expected_error_token": args.expected_error_token,
                "timeout_seconds": args.timeout_seconds,
                "repetitions": args.repetitions,
                "record_finding": args.record_finding,
            },
        )
    elif args.command == "pov-minimize":
        payload = engine.call_tool(
            "pov_minimize",
            {
                "run_id": args.run_id,
                "artifact_name": args.artifact_name,
                "output_artifact": args.output_artifact,
                "command": _load_json_arg(args.harness_command_json, None, default=[]),
                "expected_error_token": args.expected_error_token,
                "timeout_seconds": args.timeout_seconds,
                "repetitions": args.repetitions,
                "max_attempts": args.max_attempts,
                "preserve_signal": not args.no_preserve_signal,
            },
        )
    elif args.command == "fidelity-replay-campaign":
        payload = engine.call_tool(
            "fidelity_replay_campaign",
            {
                "run_id": args.run_id,
                "project": args.project,
                "include_disabled": args.include_disabled,
                "command_map": _load_json_arg(args.command_map_json, args.command_map_file, default={}),
                "default_command": _load_json_arg(args.default_command_json, None, default=None),
                "timeout_seconds": args.timeout_seconds,
                "repetitions": args.repetitions,
                "record_findings": not args.no_record_findings,
                "max_cases": args.max_cases,
            },
        )
    elif args.command == "fidelity-owned-build-replay":
        payload = engine.call_tool(
            "fidelity_owned_build_replay",
            {
                "run_id": args.run_id,
                "project": args.project,
                "include_disabled": args.include_disabled,
                "max_cases": args.max_cases,
                "compile_timeout_seconds": args.compile_timeout_seconds,
                "replay_timeout_seconds": args.replay_timeout_seconds,
                "repetitions": args.repetitions,
            },
        )
        if args.summary_only:
            payload = _owned_replay_summary(payload)
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else payload
        if args.require_all and float(summary.get("coverage_ratio") or 0) < 1.0:
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1
    elif args.command == "fidelity-oss-fuzz-build":
        payload = engine.call_tool(
            "fidelity_oss_fuzz_build",
            {
                "project": args.project,
                "run_id": args.run_id,
                "oss_fuzz_root": args.oss_fuzz_root,
                "docker_host": args.docker_host,
                "docker_platform": args.docker_platform,
                "sanitizer": args.sanitizer,
                "engine": args.engine,
                "timeout_seconds": args.timeout_seconds,
            },
        )
        if args.summary_only:
            payload = _oss_fuzz_build_summary(payload)
    elif args.command == "fidelity-oss-fuzz-build-replay":
        payload = engine.call_tool(
            "fidelity_oss_fuzz_build_replay",
            {
                "project": args.project,
                "run_id": args.run_id,
                "oss_fuzz_root": args.oss_fuzz_root,
                "docker_host": args.docker_host,
                "docker_platform": args.docker_platform,
                "sanitizer": args.sanitizer,
                "engine": args.engine,
                "build_timeout_seconds": args.build_timeout_seconds,
                "replay_timeout_seconds": args.replay_timeout_seconds,
                "repetitions": args.repetitions,
                "runner_image": args.runner_image,
                "record_findings": not args.no_record_findings,
                "include_disabled": args.include_disabled,
            },
        )
        if args.summary_only:
            payload = _oss_fuzz_replay_summary(payload)
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else payload
        if args.require_all and float(summary.get("coverage_ratio") or 0) < 1.0:
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1
    elif args.command == "fuzz-campaign":
        dictionary = list(args.dictionary_token)
        dictionary.extend(_load_json_arg(args.dictionary_json, None, default=[]))
        payload = engine.call_tool(
            "fuzz_campaign",
            {
                "run_id": args.run_id,
                "target": args.target,
                "harness": args.harness,
                "sanitizer": args.sanitizer,
                "seed_artifacts": args.seed_artifact,
                "dictionary": dictionary,
                "harness_command": _load_json_arg(args.harness_command_json, None, default=[]),
                "expected_error_token": args.expected_error_token,
                "timeout_seconds": args.timeout_seconds,
                "repetitions": args.repetitions,
                "max_iterations": args.max_iterations,
                "feedback_rounds": args.feedback_rounds,
                "record_findings": not args.no_record_findings,
                "stop_on_first_finding": args.stop_on_first_finding,
            },
        )
    elif args.command == "patch-candidate-record":
        content = Path(args.patch_file).read_bytes()
        payload = engine.call_tool(
            "patch_candidate_record",
            {
                "run_id": args.run_id,
                "patch_content_b64": base64.b64encode(content).decode("ascii"),
                "artifact_name": args.artifact_name,
                "finding_id": args.finding_id,
                "rationale": args.rationale,
                "variants_checked": args.variant_checked,
            },
        )
    elif args.command == "patch-grade":
        payload = engine.call_tool(
            "patch_grade",
            {
                "run_id": args.run_id,
                "source_dir": args.source_dir,
                "patch_artifact": args.patch_artifact,
                "pov_artifact": args.pov_artifact,
                "harness_command": _load_json_arg(args.harness_command_json, None, default=[]),
                "expected_error_token": args.expected_error_token,
                "build_command": _load_json_arg(args.build_command_json, None, default=None),
                "test_command": _load_json_arg(args.test_command_json, None, default=None),
                "reattack_artifacts": args.reattack_artifact,
                "reattack_command": _load_json_arg(args.reattack_command_json, None, default=None),
                "timeout_seconds": args.timeout_seconds,
                "repetitions": args.repetitions,
            },
        )
    elif args.command in {"runtime-guard-audit", "runtime-guard-audit"}:
        payload = engine.call_tool("runtime_guard_audit", {})
        if args.strict and not payload.get("ok"):
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1
    elif args.command == "engine-parity-audit":
        payload = engine.call_tool("engine_parity_audit", {})
        if args.strict and not payload.get("ok"):
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1
    elif args.command == "runtime-doctor":
        payload = engine.call_tool("full_runtime_doctor", {})
        if args.strict and not payload.get("ok"):
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1
    elif args.command == "runtime-backend-status":
        payload = engine.call_tool("runtime_backend_status", {})
        if args.strict and not payload.get("ok"):
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1
    elif args.command == "workspace-init":
        payload = engine.call_tool(
            "workspace_init",
            {
                "root": args.root,
                "path_maps": args.path_maps,
                "source_dir": args.source_dir,
                "klee_image": args.klee_image,
                "build_container": args.build_container,
                "extra_mounts": args.extra_mounts,
                "copies": args.copies,
            },
        )
    elif args.command == "target-select":
        payload = engine.call_tool(
            "target_select",
            {"sinks_jsonl": args.sinks_jsonl, "top": args.top, "workspace_root": args.workspace_root},
        )
    elif args.command == "target-scaffold":
        payload = engine.call_tool(
            "target_scaffold",
            {
                "name": args.name,
                "sinks_jsonl": args.sinks_jsonl,
                "sink_tag": args.sink_tag,
                "max_sink_refs": args.max_sink_refs,
                "force": args.force,
                "workspace_root": args.workspace_root,
            },
        )
    elif args.command == "target-generate":
        payload = engine.call_tool(
            "target_generate",
            {
                "name": args.name,
                "spec": args.spec,
                "sinks_jsonl": args.sinks_jsonl,
                "sink_tag": args.sink_tag,
                "validate": args.validate,
                "workspace_root": args.workspace_root,
            },
        )
    elif args.command == "target-build":
        payload = engine.call_tool(
            "target_build",
            {
                "project": args.project,
                "only_steps": args.only_steps,
                "timeout_seconds": args.timeout_seconds,
                "workspace_root": args.workspace_root,
            },
        )
    elif args.command == "campaign-round-run":
        payload = engine.call_tool(
            "campaign_round_run",
            {
                "project": args.project,
                "run_id": args.run_id,
                "rounds": args.rounds,
                "fuzz_seconds": args.fuzz_seconds,
                "rss_limit_mb": args.rss_limit_mb,
                "sync_max_inputs": args.sync_max_inputs,
                "sync_seconds": args.sync_seconds,
                "sync_memory_mb": args.sync_memory_mb,
                "klee_config": args.klee_config,
                "klee_every": args.klee_every,
                "klee_seconds": args.klee_seconds,
                "workspace_root": args.workspace_root,
                "min_free_gb": args.min_free_gb,
            },
        )
    elif args.command == "symbolic-corpus-sync":
        payload = engine.call_tool(
            "symbolic_corpus_sync",
            {
                "corpus_dir": args.corpus_dir,
                "symcc_binary": args.symcc_binary,
                "state_dir": args.state_dir,
                "max_inputs": args.max_inputs,
                "max_seconds": args.max_seconds,
                "per_input_timeout": args.per_input_timeout,
                "max_memory_mb": args.max_memory_mb,
                "max_new_files": args.max_new_files,
            },
        )
    elif args.command == "fuzz-ensemble-run":
        payload = engine.call_tool(
            "fuzz_ensemble_run",
            {
                "run_id": args.run_id,
                "target": args.target,
                "harness": args.harness,
                "harness_command": _load_json_arg(args.harness_command_json, None, default=None),
                "seed_artifacts": args.seed_artifact,
                "workers": args.workers,
                "libafl_command": _load_json_arg(args.libafl_command_json, None, default=None),
                "runs": args.runs,
                "timeout_seconds": args.timeout_seconds,
                "artifact_prefix": args.artifact_prefix,
            },
        )
    elif args.command == "symbolic-worker-run":
        constraints_smt2_b64 = args.constraints_smt2_b64
        if args.constraints_smt2_file:
            constraints_smt2_b64 = base64.b64encode(Path(args.constraints_smt2_file).read_bytes()).decode("ascii")
        payload = engine.call_tool(
            "symbolic_worker_run",
            {
                "run_id": args.run_id,
                "mode": args.mode,
                "command": _load_json_arg(args.command_json, None, default=None),
                "constraints_smt2_b64": constraints_smt2_b64,
                "klee_config": args.klee_config,
                "workspace_root": args.workspace_root,
                "timeout_seconds": args.timeout_seconds,
                "artifact_prefix": args.artifact_prefix,
            },
        )
    elif args.command == "sarif-reachability-run":
        payload = engine.call_tool(
            "sarif_reachability_run",
            {
                "run_id": args.run_id,
                "source_dir": args.source_dir,
                "sarif_file": args.sarif_file,
                "language": args.language,
                "database_dir": args.database_dir,
                "create_database": args.create_database,
                "codeql_query_suite": args.codeql_query_suite,
                "joern_command": _load_json_arg(args.joern_command_json, None, default=None),
                "sootup_command": _load_json_arg(args.sootup_command_json, None, default=None),
                "run_codeql": not args.no_codeql,
                "run_joern": not args.no_joern,
                "run_sootup": not args.no_sootup,
                "timeout_seconds": args.timeout_seconds,
                "artifact_prefix": args.artifact_prefix,
            },
        )
    elif args.command == "patch-environment-prepare":
        payload = engine.call_tool(
            "patch_environment_prepare",
            {
                "run_id": args.run_id,
                "source_dir": args.source_dir,
                "env_name": args.env_name,
                "patch_artifact": args.patch_artifact,
                "build_command": _load_json_arg(args.build_command_json, None, default=None),
                "test_command": _load_json_arg(args.test_command_json, None, default=None),
                "timeout_seconds": args.timeout_seconds,
            },
        )
    elif args.command == "parity-full":
        payload = engine.call_tool("full_runtime_parity_audit", {})
        if args.strict and not payload.get("ok"):
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1
    elif args.command == "campaign-full":
        payload = engine.call_tool(
            "full_runtime_campaign_plan",
            {
                "task_id": args.task_id,
                "target": args.target,
                "language": args.language,
                "seconds": args.seconds,
            },
        )
    elif args.command == "campaign-full-run":
        payload = engine.call_tool(
            "full_runtime_local_campaign",
            {
                "project": args.project,
                "run_id": args.run_id,
                "harness": args.harness,
                "harness_command": _load_json_arg(args.harness_command_json, None, default=None),
                "command_map": _load_json_arg(args.command_map_json, args.command_map_file, default={}),
                "source_dir": args.source_dir,
                "timeout_seconds": args.timeout_seconds,
                "repetitions": args.repetitions,
                "include_disabled": args.include_disabled,
            },
        )
        if args.summary_only:
            payload = _full_campaign_summary(payload)
        if args.strict and not payload.get("ok"):
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1
    elif args.command == "deploy-local":
        payload = engine.call_tool("full_runtime_deploy_plan", {"target": "local", "namespace": args.namespace})
    elif args.command == "deploy-k8s":
        payload = engine.call_tool("full_runtime_deploy_plan", {"target": "k8s", "namespace": args.namespace})
    elif args.command in {"benchmark-fixtures", "benchmark-reference-fixtures"}:
        fixture_payload = engine.call_tool("fidelity_validate_fixtures", {"include_disabled": args.include_disabled})
        parity_payload = engine.call_tool("full_runtime_parity_audit", {})
        payload = {
            "ok": bool(fixture_payload.get("ok")) and bool(parity_payload.get("ok")),
            "fixtures": fixture_payload,
            "full_runtime_parity": parity_payload,
        }
        if args.strict and not payload.get("ok"):
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1
    else:  # pragma: no cover
        parser.error(f"unhandled command: {args.command}")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _default_audit_roots() -> tuple[str, ...]:
    repo_root = Path(__file__).resolve().parents[2]
    return (
        str(repo_root / "src" / "agentic_fuzz_engine"),
        str(repo_root / "src" / "agentic_fuzz_full"),
        str(repo_root / "claude-plugin" / "agentic-fuzz-engine"),
    )


def _load_json_arg(value: str | None, path: str | None, *, default: Any) -> Any:
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    if value:
        return json.loads(value)
    return default


def _full_campaign_summary(payload: dict[str, Any]) -> dict[str, Any]:
    steps = payload.get("steps") if isinstance(payload.get("steps"), dict) else {}
    replay = steps.get("replay") if isinstance(steps.get("replay"), dict) else {}
    grade = steps.get("finding_grade") if isinstance(steps.get("finding_grade"), dict) else {}
    minimized = steps.get("pov_minimize") if isinstance(steps.get("pov_minimize"), dict) else {}
    dedupe = steps.get("dedupe") if isinstance(steps.get("dedupe"), dict) else {}
    lifecycle = steps.get("lifecycle") if isinstance(steps.get("lifecycle"), dict) else {}
    report = steps.get("report") if isinstance(steps.get("report"), dict) else {}
    bundle = steps.get("export_bundle") if isinstance(steps.get("export_bundle"), dict) else {}
    exports = steps.get("exports") if isinstance(steps.get("exports"), dict) else {}
    completion = payload.get("completion") if isinstance(payload.get("completion"), dict) else {}
    completion_gates = completion.get("gates") if isinstance(completion.get("gates"), dict) else {}
    phase_coverage = completion_gates.get("phase_coverage") if isinstance(completion_gates.get("phase_coverage"), dict) else {}
    subagents = (
        completion_gates.get("subagent_orchestration")
        if isinstance(completion_gates.get("subagent_orchestration"), dict)
        else {}
    )

    receipts = exports.get("accepted") if isinstance(exports.get("accepted"), list) else []
    accepted_by_kind: dict[str, int] = {}
    for receipt in receipts:
        if not isinstance(receipt, dict):
            continue
        kind = str(receipt.get("kind") or "unknown")
        accepted_by_kind[kind] = accepted_by_kind.get(kind, 0) + 1
    counts = exports.get("counts") if isinstance(exports.get("counts"), dict) else {}
    executed = int(replay.get("executed") or 0)
    verified = int(replay.get("verified") or 0)
    coverage_ratio = verified / executed if executed else 0.0

    report_body = report.get("report") if isinstance(report.get("report"), dict) else {}
    report_summary = report_body.get("summary") if isinstance(report_body.get("summary"), dict) else {}
    failed_gates = []
    for name, gate in completion_gates.items():
        if isinstance(gate, dict):
            if not gate.get("ok"):
                failed_gates.append(name)
        elif not gate:
            failed_gates.append(name)
    return {
        "ok": bool(payload.get("ok")),
        "mode": payload.get("mode"),
        "runtime_authority": payload.get("runtime_authority"),
        "run_id": payload.get("run_id"),
        "target": payload.get("target"),
        "harness": payload.get("harness"),
        "source_dir": payload.get("source_dir"),
        "blockers": payload.get("blockers") or [],
        "fixture_fidelity": {
            "expected_proofs_executed": executed,
            "verified": verified,
            "failed": replay.get("failed", 0),
            "coverage_ratio": coverage_ratio,
            "ok": bool(executed and verified == executed and not int(replay.get("failed") or 0)),
        },
        "finding": {
            "grade_verdict": grade.get("verdict"),
            "minimize_verdict": minimized.get("verdict"),
            "dedupe_groups": len(dedupe.get("groups") or []),
            "lifecycle_ok": bool(lifecycle.get("ok")),
        },
        "report_artifacts": {
            "json": (report.get("json_artifact") or {}).get("name") if isinstance(report.get("json_artifact"), dict) else None,
            "markdown": (report.get("markdown_artifact") or {}).get("name") if isinstance(report.get("markdown_artifact"), dict) else None,
            "export_bundle": (bundle.get("bundle_artifact") or {}).get("name") if isinstance(bundle.get("bundle_artifact"), dict) else None,
            "total_recorded_findings": report_summary.get("total_findings"),
        },
        "exports": {
            "total": counts.get("accepted", len(receipts)),
            "accepted_by_kind": {
                "pov": counts.get("pov", accepted_by_kind.get("pov", 0)),
                "sarif": counts.get("sarif", accepted_by_kind.get("sarif", 0)),
                "patch": counts.get("patch", accepted_by_kind.get("patch", 0)),
            },
        },
        "completion": {
            "ok": bool(completion.get("ok")),
            "phase_coverage_ok": bool(phase_coverage.get("ok")),
            "subagent_orchestration_ok": bool(subagents.get("ok")),
            "missing_agents": subagents.get("missing_agents") or [],
            "failed_gates": failed_gates,
            "blockers": completion.get("blockers") or [],
        },
    }


def _owned_replay_summary(payload: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    builds = payload.get("builds") if isinstance(payload.get("builds"), list) else []
    compiled = [
        {
            "project": build.get("project"),
            "harness": build.get("harness"),
            "binary": build.get("binary"),
        }
        for build in builds
        if isinstance(build, dict) and build.get("ok")
    ]
    blocked = [
        {
            "project": build.get("project"),
            "harness": build.get("harness"),
            "blocker": build.get("blocker"),
        }
        for build in builds
        if isinstance(build, dict) and not build.get("ok")
    ]
    audit = payload.get("audit") if isinstance(payload.get("audit"), dict) else {}
    score = audit.get("score") if isinstance(audit.get("score"), dict) else {}
    return {
        "ok": bool(payload.get("ok")),
        "mode": payload.get("mode"),
        "runtime_authority": payload.get("runtime_authority"),
        "run_id": payload.get("run_id"),
        "target": payload.get("target"),
        "selected_fixtures": summary.get("selected_fixtures", 0),
        "enabled_fixtures": summary.get("enabled_fixtures", 0),
        "disabled_fixtures": summary.get("disabled_fixtures", 0),
        "compiled_harnesses": summary.get("compiled_harnesses", 0),
        "blocked_harnesses": summary.get("blocked_harnesses", 0),
        "executed_proofs": summary.get("executed_proofs", 0),
        "verified_proofs": summary.get("verified_proofs", 0),
        "represented_fixtures": summary.get("represented_fixtures", 0),
        "missing_fixtures": summary.get("missing_fixtures", 0),
        "coverage_ratio": summary.get("coverage_ratio", 0),
        "compiled": compiled,
        "blocked": blocked[:20],
        "audit_score": score,
        "blocker_count": len(payload.get("blockers") or []),
    }


def _oss_fuzz_build_summary(payload: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    commands = payload.get("commands") if isinstance(payload.get("commands"), list) else []
    return {
        "ok": bool(payload.get("ok")),
        "mode": payload.get("mode"),
        "runtime_authority": payload.get("runtime_authority"),
        "run_id": payload.get("run_id"),
        "target": payload.get("target"),
        "project": summary.get("project"),
        "docker_platform": summary.get("docker_platform"),
        "fuzzer_count": summary.get("fuzzer_count", 0),
        "matched_harness_count": summary.get("matched_harness_count", 0),
        "missing_harness_count": summary.get("missing_harness_count", 0),
        "fuzzers": [item.get("name") for item in payload.get("fuzzers", []) if isinstance(item, dict)],
        "matched_harnesses": summary.get("matched_harnesses") or [],
        "missing_harnesses": summary.get("missing_harnesses") or [],
        "source_dir": summary.get("source_dir"),
        "out_dir": summary.get("out_dir"),
        "blockers": payload.get("blockers") or [],
        "commands": [
            {
                "ok": bool(command.get("ok")),
                "stage": (command.get("command") or [None, None, "unknown"])[2]
                if isinstance(command.get("command"), list)
                else "unknown",
                "exit_code": command.get("exit_code"),
                "timed_out": bool(command.get("timed_out")),
            }
            for command in commands
            if isinstance(command, dict)
        ],
    }


def _oss_fuzz_replay_summary(payload: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    audit = payload.get("audit") if isinstance(payload.get("audit"), dict) else {}
    score = audit.get("score") if isinstance(audit.get("score"), dict) else {}
    build = payload.get("build") if isinstance(payload.get("build"), dict) else {}
    build_commands = build.get("commands") if isinstance(build.get("commands"), list) else []
    cases = payload.get("cases") if isinstance(payload.get("cases"), list) else []
    return {
        "ok": bool(payload.get("ok")),
        "mode": payload.get("mode"),
        "runtime_authority": payload.get("runtime_authority"),
        "run_id": payload.get("run_id"),
        "target": payload.get("target"),
        "docker_platform": summary.get("docker_platform"),
        "runner_image": summary.get("runner_image"),
        "build_ok": bool(summary.get("build_ok")),
        "fuzzer_count": summary.get("fuzzer_count", 0),
        "matched_harness_count": summary.get("matched_harness_count", 0),
        "missing_harness_count": summary.get("missing_harness_count", 0),
        "total_cases": summary.get("total_cases", 0),
        "executed_proofs": summary.get("executed", 0),
        "verified_proofs": summary.get("verified", 0),
        "failed_proofs": summary.get("failed", 0),
        "blocked_proofs": summary.get("blocked", 0),
        "findings_recorded": summary.get("findings_recorded", 0),
        "represented_fixtures": summary.get("represented_fixtures", score.get("represented_fixtures", 0)),
        "partial_fixtures": summary.get("partial_fixtures", score.get("partial_fixtures", 0)),
        "missing_fixtures": summary.get("missing_fixtures", score.get("missing_fixtures", 0)),
        "coverage_ratio": summary.get("coverage_ratio", score.get("coverage_ratio", 0)),
        "build_blockers": build.get("blockers") or [],
        "build_commands": [
            {
                "ok": bool(command.get("ok")),
                "stage": (command.get("command") or [None, None, "unknown"])[2]
                if isinstance(command.get("command"), list)
                else "unknown",
                "exit_code": command.get("exit_code"),
                "timed_out": bool(command.get("timed_out")),
                "stderr_tail": str(command.get("stderr") or "")[-2000:],
                "stdout_tail": str(command.get("stdout") or "")[-2000:],
            }
            for command in build_commands
            if isinstance(command, dict)
        ],
        "cases": [
            {
                "project": case.get("project"),
                "fixture": case.get("fixture"),
                "harness": case.get("harness"),
                "status": case.get("status"),
                "blocker": case.get("blocker"),
                "observed_error_token": (case.get("run") or {}).get("observed_error_token")
                if isinstance(case.get("run"), dict)
                else None,
                "exit_codes": sorted(
                    {
                        run.get("exit_code")
                        for run in ((case.get("run") or {}).get("runs") or [])
                        if isinstance(run, dict)
                    }
                )
                if isinstance(case.get("run"), dict)
                else [],
            }
            for case in cases
            if isinstance(case, dict)
        ],
        "blockers": payload.get("blockers") or [],
    }


if __name__ == "__main__":
    raise SystemExit(main())

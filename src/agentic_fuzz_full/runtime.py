from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


LLM_ENV_GROUP = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY", "GROK_API_KEY")


@dataclass(frozen=True, slots=True)
class RequirementGroup:
    name: str
    kind: str
    alternatives: tuple[str, ...]
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RuntimeSubsystem:
    identifier: str
    title: str
    description: str
    mcp_server: str
    subagents: tuple[str, ...]
    workers: tuple[str, ...]
    requirements: tuple[RequirementGroup, ...]
    fidelity_paths: tuple[str, ...] = ()
    topics: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["requirements"] = [requirement.to_dict() for requirement in self.requirements]
        return data


FULL_RUNTIME_SUBSYSTEMS: tuple[RuntimeSubsystem, ...] = (
    RuntimeSubsystem(
        identifier="k8s_node_allocator",
        title="Kubernetes node allocator",
        description="Owns worker leases, pod/job templates, namespace bounds, sandbox runtime checks, and local/cloud cluster placement.",
        mcp_server="fuzz-k8s-allocator-mcp",
        subagents=("allocator-agent", "infra-agent"),
        workers=("scheduler", "lease-reaper", "pod-template-renderer"),
        requirements=(
            RequirementGroup("kubernetes_cli", "binary", ("kubectl",), "Kubernetes API access through kubectl."),
            RequirementGroup("container_runtime", "binary", ("docker", "podman"), "Container runtime for local worker images."),
            RequirementGroup("local_cluster", "binary_any", ("kind", "colima", "k3d", "minikube"), "At least one local cluster backend for development."),
        ),
    ),
    RuntimeSubsystem(
        identifier="model_budget_runtime",
        title="Claude-native model budget runtime",
        description="Uses Claude Code or explicit provider credentials as the model-call surface and records per-task budget metadata without requiring a proxy package.",
        mcp_server="fuzz-model-budget-mcp",
        subagents=("model-budget-agent",),
        workers=("claude-code-model-runtime", "usage-reconciler"),
        requirements=(
            RequirementGroup("model_runtime", "env_any", LLM_ENV_GROUP, "Claude Code model runtime or at least one supported provider credential."),
        ),
    ),
    RuntimeSubsystem(
        identifier="distributed_bus",
        title="Redis/Kafka/ZeroMQ distributed fuzzing bus",
        description="Provides durable task state, topiced work queues, crash/coverage streams, locks, and high-rate seed injection.",
        mcp_server="fuzz-bus-mcp",
        subagents=("bus-agent", "monitor-agent"),
        workers=("redis-state", "kafka-router", "zeromq-seed-forwarder"),
        topics=("tasks", "agent.commands", "coverage", "crashes", "seeds", "patches", "sarif"),
        requirements=(
            RequirementGroup("redis_cli", "binary_any", ("redis-cli", "redis-server"), "Redis client/server tooling."),
            RequirementGroup("kafka_cli", "binary_any", ("kafka-topics", "kafka-topics.sh"), "Kafka topic administration tooling."),
            RequirementGroup("zeromq_module", "python_module", ("zmq",), "pyzmq seed bus bindings."),
        ),
    ),
    RuntimeSubsystem(
        identifier="fuzz_ensemble",
        title="LibAFL/AFL++/libFuzzer ensemble",
        description="Builds instrumented targets, runs coordinated fuzzers, imports/promotes seeds, captures coverage, and records crashes.",
        mcp_server="fuzz-ensemble-mcp",
        subagents=("native-harness", "fuzzer-campaign-agent", "corpus-manager", "crash-grader"),
        workers=("libfuzzer-worker", "afl-worker", "libafl-worker", "coverage-worker", "crash-collector"),
        requirements=(
            RequirementGroup("clang_toolchain", "binary", ("clang",), "Clang/LLVM compiler for sanitizer and libFuzzer builds."),
            RequirementGroup("llvm_symbolizer", "binary", ("llvm-symbolizer",), "Symbolization for sanitizer stack traces."),
            RequirementGroup("aflplusplus", "binary", ("afl-fuzz",), "AFL++ fuzzing worker."),
            RequirementGroup("rust_toolchain", "binary", ("cargo",), "Rust toolchain for LibAFL workers."),
        ),
    ),
    RuntimeSubsystem(
        identifier="symbolic_execution",
        title="SymCC/SymQEMU execution engine",
        description="Runs bounded concolic jobs over interesting seeds and returns solver-derived inputs to the corpus.",
        mcp_server="fuzz-symbolic-mcp",
        subagents=("concolic-generator", "symbolic-agent"),
        workers=("symcc-worker", "symqemu-worker", "z3-solver-worker"),
        requirements=(
            RequirementGroup("symcc", "binary", ("symcc",), "SymCC compiler/runtime."),
            RequirementGroup("symqemu", "binary_any", ("symqemu", "symqemu-x86_64"), "SymQEMU runtime."),
            RequirementGroup("z3_module", "python_module", ("z3",), "Z3 solver Python bindings."),
        ),
    ),
    RuntimeSubsystem(
        identifier="model_generation_agents",
        title="Model-assisted generation agents",
        description="Provides harness understanding, call graph analysis, blob generation, mutation, sanitizer selection, and prompt-update loops.",
        mcp_server="fuzz-generator-mcp",
        subagents=("code-planner-agent", "path-analysis-agent", "mutation-generator-agent", "coverage-agent", "blob-generator-agent", "input-generator"),
        workers=("code_planner", "path_analyzer", "mutation_generator", "coverage_analyzer", "blob_generator", "blobgen", "mutator"),
        requirements=(
            RequirementGroup("model_credentials", "env_any", LLM_ENV_GROUP, "At least one supported model provider credential."),
            RequirementGroup("tree_sitter", "python_module", ("tree_sitter",), "Tree-sitter parsing for code understanding."),
            RequirementGroup("joern_cli", "binary", ("joern",), "Joern code graph access for deep call graph workflows."),
        ),
    ),
    RuntimeSubsystem(
        identifier="java_fuzzing",
        title="Java fuzzing",
        description="Runs Jazzer campaigns, Java sinkpoint analysis, Java dictionary generation, concolic PoV generation, and Java triage.",
        mcp_server="fuzz-java-mcp",
        subagents=("java-coordinator", "java-sinkpoint-agent"),
        workers=("jazzer-worker", "java-sinkpoint-worker", "java-pov-worker"),
        requirements=(
            RequirementGroup("java_runtime", "binary", ("java",), "Java runtime."),
            RequirementGroup("java_compiler", "binary", ("javac",), "Java compiler."),
            RequirementGroup("java_build_tool", "binary_any", ("mvn", "gradle"), "Java build tool."),
            RequirementGroup("jazzer", "binary", ("jazzer",), "Jazzer fuzzer."),
            RequirementGroup("codeql", "binary", ("codeql",), "CodeQL for Java analysis."),
            RequirementGroup("joern_cli", "binary", ("joern",), "Joern code graph analysis."),
        ),
    ),
    RuntimeSubsystem(
        identifier="cached_patching",
        title="Cached patching framework",
        description="Owns environment pools, cache-everywhere build/test reuse, patch agents, fault localization, grading, and regression checks.",
        mcp_server="fuzz-patch-mcp",
        subagents=("patcher", "patch-grader", "patch-agent"),
        workers=("environment-pool", "fault-localizer", "patch-agent-pool", "patch-grader"),
        requirements=(
            RequirementGroup("container_runtime", "binary", ("docker",), "Container runtime for patch sandboxes."),
            RequirementGroup("git", "binary", ("git",), "Patch application and diff operations."),
            RequirementGroup("uv", "binary", ("uv",), "Python environment runner used by local tooling."),
            RequirementGroup("model_credentials", "env_any", LLM_ENV_GROUP, "At least one supported model provider credential."),
        ),
    ),
    RuntimeSubsystem(
        identifier="sarif_reachability",
        title="SARIF reachability engine",
        description="Runs CodeQL/Joern/SootUp reachability, validates SARIF against crash/patch/source context, and emits conservative verdicts.",
        mcp_server="fuzz-sarif-mcp",
        subagents=("sarif-agent",),
        workers=("codeql-worker", "joern-worker", "sootup-worker", "sarif-validator"),
        requirements=(
            RequirementGroup("codeql", "binary", ("codeql",), "CodeQL database and query runner."),
            RequirementGroup("joern_cli", "binary", ("joern",), "Joern code graph analysis."),
            RequirementGroup("java_runtime", "binary", ("java",), "SootUp runtime."),
            RequirementGroup("sootup", "binary_or_env_any", ("sootup", "SOOTUP_JAR"), "SootUp CLI or jar for Java reachability."),
            RequirementGroup("model_credentials", "env_any", LLM_ENV_GROUP, "At least one supported model provider credential."),
        ),
    ),
    RuntimeSubsystem(
        identifier="artifact_manager",
        title="Owned artifact manager",
        description="Coordinates task intake, budgets, campaign orchestration, artifact routing, dedupe, bundling, and gated exports.",
        mcp_server="fuzz-export-mcp",
        subagents=("artifact-manager", "export-agent", "monitor"),
        workers=("task-router", "bundle-manager", "export-gateway", "dedupe-indexer"),
        requirements=(
            RequirementGroup("redis_cli", "binary_any", ("redis-cli", "redis-server"), "State backend access."),
            RequirementGroup("export_endpoint", "env_optional", ("AGENTIC_FUZZ_EXPORT_URL",), "Optional real export endpoint; mock mode is default."),
        ),
    ),
)


def build_full_runtime_doctor(
    *,
    reference_root: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = env if env is not None else os.environ
    reference = Path(reference_root).expanduser().resolve() if reference_root else None
    reports = [_subsystem_report(subsystem, reference_root=reference, env=environment) for subsystem in FULL_RUNTIME_SUBSYSTEMS]
    blockers = [
        f"{report['identifier']}: {missing['name']}"
        for report in reports
        for missing in report["missing_required"]
    ]
    ready = sum(1 for report in reports if report["ready"])
    return {
        "ok": not blockers,
        "mode": "owned-full-runtime",
        "runtime_authority": "agentic_fuzz_full",
        "subsystem_count": len(reports),
        "ready_subsystems": ready,
        "missing_subsystems": len(reports) - ready,
        "subsystems": reports,
        "blockers": blockers,
    }


def build_full_runtime_parity_audit(
    *,
    tool_names: Iterable[str],
    plugin_root: str | Path,
    reference_root: str | Path | None = None,
) -> dict[str, Any]:
    tools = set(tool_names)
    plugin = Path(plugin_root)
    expected_tools = {
        "full_runtime_doctor",
        "runtime_backend_status",
        "fuzz_ensemble_run",
        "symbolic_worker_run",
        "sarif_reachability_run",
        "patch_environment_prepare",
        "full_runtime_parity_audit",
        "full_runtime_campaign_plan",
        "full_runtime_local_campaign",
        "fidelity_owned_build_replay",
        "fidelity_oss_fuzz_build",
        "fidelity_oss_fuzz_build_replay",
        "full_runtime_deploy_plan",
    }
    command_files = {
        "campaign-full": plugin / "commands" / "campaign-full.md",
        "campaign-full-run": plugin / "commands" / "campaign-full-run.md",
        "fidelity-owned-build-replay": plugin / "commands" / "fidelity-owned-build-replay.md",
        "fidelity-oss-fuzz-build": plugin / "commands" / "fidelity-oss-fuzz-build.md",
        "fidelity-oss-fuzz-build-replay": plugin / "commands" / "fidelity-oss-fuzz-build-replay.md",
        "fidelity-remote-amd64-replay": plugin / "commands" / "fidelity-remote-amd64-replay.md",
        "runtime-doctor": plugin / "commands" / "runtime-doctor.md",
        "runtime-backend-status": plugin / "commands" / "runtime-backend-status.md",
        "fuzz-ensemble-run": plugin / "commands" / "fuzz-ensemble-run.md",
        "symbolic-worker-run": plugin / "commands" / "symbolic-worker-run.md",
        "sarif-reachability-run": plugin / "commands" / "sarif-reachability-run.md",
        "patch-environment-prepare": plugin / "commands" / "patch-environment-prepare.md",
        "ready": plugin / "commands" / "ready.md",
        "fuzz": plugin / "commands" / "fuzz.md",
        "sym": plugin / "commands" / "sym.md",
        "reach": plugin / "commands" / "reach.md",
        "patch-env": plugin / "commands" / "patch-env.md",
        "deploy-local": plugin / "commands" / "deploy-local.md",
        "deploy-k8s": plugin / "commands" / "deploy-k8s.md",
        "parity-full": plugin / "commands" / "parity-full.md",
        "benchmark-fixtures": plugin / "commands" / "benchmark-fixtures.md",
    }
    subsystems = [subsystem.to_dict() for subsystem in FULL_RUNTIME_SUBSYSTEMS]
    mcp_servers = {subsystem.mcp_server for subsystem in FULL_RUNTIME_SUBSYSTEMS}
    subagents = {agent for subsystem in FULL_RUNTIME_SUBSYSTEMS for agent in subsystem.subagents}
    missing_tools = sorted(expected_tools - tools)
    missing_commands = sorted(name for name, path in command_files.items() if not path.exists())
    reference = Path(reference_root).expanduser().resolve() if reference_root else None
    fidelity = _fidelity_report(reference)
    blockers = []
    if missing_tools:
        blockers.append(f"missing full-runtime MCP tools: {', '.join(missing_tools)}")
    if missing_commands:
        blockers.append(f"missing plugin commands: {', '.join(missing_commands)}")
    if not fidelity["ok"]:
        blockers.append("missing full-runtime prompt fidelity fixtures")
    return {
        "ok": not blockers,
        "mode": "owned-full-runtime",
        "subsystem_count": len(FULL_RUNTIME_SUBSYSTEMS),
        "subsystems": subsystems,
        "mcp_servers": sorted(mcp_servers),
        "subagents": sorted(subagents),
        "missing_tools": missing_tools,
        "missing_commands": missing_commands,
        "fidelity": fidelity,
        "blockers": blockers,
    }


def build_owned_campaign_plan(
    *,
    task_id: str,
    target: str,
    language: str = "c-cpp",
    seconds: int = 300,
) -> dict[str, Any]:
    phases = (
        "accept-task",
        "allocate-budget-and-workers",
        "build-and-instrument",
        "seed-and-dictionary-ingest",
        "ensemble-fuzz",
        "symbolic-generation",
        "model-generation",
        "crash-triage-and-dedupe",
        "sarif-reachability",
        "patch-generation-and-grading",
        "export-bundling",
    )
    required = _required_subsystems_for_language(language)
    return {
        "ok": True,
        "task_id": task_id,
        "target": target,
        "language": language,
        "seconds": seconds,
        "runtime_authority": "agentic_fuzz_full",
        "required_subsystems": required,
        "phases": [
            {
                "order": index + 1,
                "name": phase,
                "checkpoint": f"{task_id}:{phase}",
                "mcp_tools": _phase_tools(phase),
            }
            for index, phase in enumerate(phases)
        ],
        "execution_default": "plan-only",
        "execute_gate": "requires full_runtime_doctor ok plus explicit operator mutation approval",
    }


def build_owned_deploy_plan(*, target: str = "local", namespace: str = "agentic-fuzz") -> dict[str, Any]:
    if target not in {"local", "k8s"}:
        raise ValueError("target must be 'local' or 'k8s'")
    if target == "local":
        steps = (
            "create or select dedicated Colima/kind cluster",
            "install Redis, Kafka, and ZeroMQ sidecars",
            "build local worker images",
            "run runtime-doctor until all local prerequisites are ready",
        )
        required = ("k8s_node_allocator", "distributed_bus", "fuzz_ensemble", "model_budget_runtime")
    else:
        steps = (
            "create namespace and service accounts",
            "apply Redis/Kafka/worker manifests",
            "apply scheduler and budget proxy deployments",
            "run bounded readiness probes before any campaign launch",
        )
        required = tuple(subsystem.identifier for subsystem in FULL_RUNTIME_SUBSYSTEMS)
    return {
        "ok": True,
        "target": target,
        "namespace": namespace,
        "runtime_authority": "agentic_fuzz_full",
        "required_subsystems": list(required),
        "steps": [{"order": index + 1, "action": step} for index, step in enumerate(steps)],
        "execution_default": "plan-only",
        "mutation_gate": "AGENTIC_FUZZ_ALLOW_MUTATION=1 plus command-specific confirmation token",
    }


def _subsystem_report(
    subsystem: RuntimeSubsystem,
    *,
    reference_root: Path | None,
    env: Mapping[str, str],
) -> dict[str, Any]:
    checks = [_check_requirement(requirement, env=env) for requirement in subsystem.requirements]
    fidelity = _subsystem_fidelity(subsystem, reference_root)
    missing_required = [check for check in checks if check["required"] and not check["ok"]]
    if not fidelity["ok"] and subsystem.fidelity_paths:
        missing_required.append(
            {
                "name": "prompt_fidelity_fixtures",
                "kind": "path",
                "required": True,
                "ok": False,
                "alternatives": list(subsystem.fidelity_paths),
                "present": [],
                "missing": fidelity["missing_paths"],
                "description": "Benchmark prompt fixtures needed for high-fidelity agent prompts.",
            }
        )
    return {
        "identifier": subsystem.identifier,
        "title": subsystem.title,
        "mcp_server": subsystem.mcp_server,
        "subagents": list(subsystem.subagents),
        "workers": list(subsystem.workers),
        "topics": list(subsystem.topics),
        "checks": checks,
        "fidelity": fidelity,
        "ready": not missing_required,
        "missing_required": missing_required,
    }


def _check_requirement(requirement: RequirementGroup, *, env: Mapping[str, str]) -> dict[str, Any]:
    required = requirement.kind != "env_optional"
    present: list[str] = []
    missing: list[str] = []
    if requirement.kind == "binary":
        present = [item for item in requirement.alternatives if _binary_requirement_ok(item, env)]
        missing = [] if present else list(requirement.alternatives)
        ok = bool(present)
    elif requirement.kind == "binary_any":
        present = [item for item in requirement.alternatives if _binary_requirement_ok(item, env)]
        missing = [] if present else list(requirement.alternatives)
        ok = bool(present)
    elif requirement.kind == "python_module":
        present = [item for item in requirement.alternatives if importlib.util.find_spec(item) is not None]
        missing = [] if present else list(requirement.alternatives)
        ok = bool(present)
    elif requirement.kind == "env_any":
        present = [item for item in requirement.alternatives if env.get(item)]
        if (env.get("AGENTIC_FUZZ_CLAUDE_CODE_MODEL") == "1" or env.get("AGENTIC_FUZZ_CLAUDE_CODE_MODEL") == "1") and _which("claude", env):
            present.append("CLAUDE_CODE_MODEL_RUNTIME")
        missing = [] if present else list(requirement.alternatives)
        ok = bool(present)
    elif requirement.kind == "env_optional":
        present = [item for item in requirement.alternatives if env.get(item)]
        missing = [item for item in requirement.alternatives if not env.get(item)]
        ok = True
    elif requirement.kind == "binary_or_env_any":
        present = [item for item in requirement.alternatives if _binary_requirement_ok(item, env) or env.get(item)]
        missing = [] if present else list(requirement.alternatives)
        ok = bool(present)
    else:
        raise ValueError(f"unsupported requirement kind: {requirement.kind}")
    return {
        "name": requirement.name,
        "kind": requirement.kind,
        "required": required,
        "ok": ok,
        "alternatives": list(requirement.alternatives),
        "present": present,
        "missing": missing,
        "description": requirement.description,
    }


def _binary_requirement_ok(name: str, env: Mapping[str, str]) -> bool:
    path = _which(name, env)
    if not path:
        return False
    if name in {"symcc", "sym++"}:
        return _docker_wrapper_image_ok(path, env, default_image="eurecoms3/symcc:latest", env_name="AGENTIC_FUZZ_SYMCC_IMAGE", fallback_env_name="AGENTIC_FUZZ_SYMCC_IMAGE")
    if name in {"symqemu", "symqemu-x86_64"}:
        return _docker_wrapper_image_ok(path, env, default_image="agentic-fuzz/symqemu:latest", env_name="AGENTIC_FUZZ_SYMQEMU_IMAGE", fallback_env_name="AGENTIC_FUZZ_SYMQEMU_IMAGE")
    return True


def _docker_wrapper_image_ok(
    path: str,
    env: Mapping[str, str],
    *,
    default_image: str,
    env_name: str,
    fallback_env_name: str | None = None,
) -> bool:
    try:
        resolved = Path(path).resolve()
        resolved.relative_to((Path(__file__).resolve().parents[2] / "tools" / "bin").resolve())
    except (OSError, ValueError):
        return True
    docker = _which("docker", env)
    if not docker:
        return False
    image = env.get(env_name) or (env.get(fallback_env_name) if fallback_env_name else None) or default_image
    try:
        proc = subprocess.run(
            [docker, "image", "inspect", image],
            env=dict(env),
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _which(name: str, env: Mapping[str, str]) -> str | None:
    path = shutil.which(name, path=env.get("PATH"))
    if path:
        return path
    for directory in _tool_search_dirs(env):
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _tool_search_dirs(env: Mapping[str, str]) -> tuple[Path, ...]:
    repo_root = Path(__file__).resolve().parents[2]
    custom_home = env.get("AGENTIC_FUZZ_TOOL_HOME") or env.get("AGENTIC_FUZZ_TOOL_HOME")
    custom_dirs = (Path(custom_home).expanduser() / "bin",) if custom_home else ()
    return (
        *custom_dirs,
        repo_root / "tools" / "bin",
        Path("/opt/homebrew/opt/llvm/bin"),
        Path("/usr/local/opt/llvm/bin"),
        Path("/opt/homebrew/bin"),
        Path("/usr/local/bin"),
    )


def _fidelity_report(reference_root: Path | None) -> dict[str, Any]:
    reports = [_subsystem_fidelity(subsystem, reference_root) for subsystem in FULL_RUNTIME_SUBSYSTEMS if subsystem.fidelity_paths]
    missing = [path for report in reports for path in report["missing_paths"]]
    present = [path for report in reports for path in report["present_paths"]]
    return {
        "ok": not missing,
        "reference_root_configured": reference_root is not None,
        "present_paths": present,
        "missing_paths": missing,
    }


def _subsystem_fidelity(subsystem: RuntimeSubsystem, reference_root: Path | None) -> dict[str, Any]:
    if not subsystem.fidelity_paths:
        return {"ok": True, "present_paths": [], "missing_paths": []}
    if reference_root is None:
        return {"ok": False, "present_paths": [], "missing_paths": list(subsystem.fidelity_paths)}
    present = []
    missing = []
    for relative in subsystem.fidelity_paths:
        path = reference_root / relative
        if path.exists():
            present.append(relative)
        else:
            missing.append(relative)
    return {"ok": not missing, "present_paths": present, "missing_paths": missing}


def _required_subsystems_for_language(language: str) -> list[str]:
    common = ["k8s_node_allocator", "model_budget_runtime", "distributed_bus", "artifact_manager"]
    if language.lower() in {"java", "jvm"}:
        return common + ["java_fuzzing", "model_generation_agents", "sarif_reachability", "cached_patching"]
    return common + ["fuzz_ensemble", "symbolic_execution", "model_generation_agents", "sarif_reachability", "cached_patching"]


def _phase_tools(phase: str) -> list[str]:
    mapping = {
        "accept-task": ["full_runtime_campaign_plan"],
        "allocate-budget-and-workers": ["full_runtime_doctor", "fuzz-k8s-allocator-mcp", "fuzz-model-budget-mcp"],
        "build-and-instrument": ["fuzz-ensemble-mcp", "fuzz-java-mcp"],
        "seed-and-dictionary-ingest": ["corpus_import", "dictionary_generate"],
        "ensemble-fuzz": ["fuzz-ensemble-mcp"],
        "symbolic-generation": ["fuzz-symbolic-mcp"],
        "model-generation": ["fuzz-generator-mcp"],
        "crash-triage-and-dedupe": ["finding_grade", "finding_dedupe"],
        "sarif-reachability": ["fuzz-sarif-mcp"],
        "patch-generation-and-grading": ["fuzz-patch-mcp", "patch_grade"],
        "export-bundling": ["fuzz-export-mcp", "export_bundle_create"],
    }
    return mapping.get(phase, [])

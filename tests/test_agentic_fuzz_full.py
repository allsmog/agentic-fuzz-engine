from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.engine import AgenticFuzzEngine
from agentic_fuzz_engine.mcp_stdio import AgenticFuzzMcpServer
from agentic_fuzz_engine.oss_fuzz_build import (
    MOSQUITTO_LIB_FILES,
    PHP_BUILD_FILES,
    PHP_BUILD_EXECUTABLE_FILES,
    PHP_DATE_LIB_FILES,
    _apply_project_compatibility_shims,
)
from agentic_fuzz_engine.runtime_backends import (
    prepare_patch_environment,
    run_fuzz_ensemble,
    run_sarif_reachability,
    run_symbolic_worker,
    runtime_backend_status,
)
from agentic_fuzz_full.runtime import (
    FULL_RUNTIME_SUBSYSTEMS,
    build_full_runtime_doctor,
    build_full_runtime_parity_audit,
    build_owned_campaign_plan,
    build_owned_deploy_plan,
)


class AgenticFuzzFullRuntimeTests(unittest.TestCase):
    def test_full_runtime_subsystem_model_covers_requested_gaps(self) -> None:
        identifiers = {subsystem.identifier for subsystem in FULL_RUNTIME_SUBSYSTEMS}

        self.assertEqual(len(FULL_RUNTIME_SUBSYSTEMS), 10)
        self.assertIn("k8s_node_allocator", identifiers)
        self.assertIn("model_budget_runtime", identifiers)
        self.assertIn("distributed_bus", identifiers)
        self.assertIn("fuzz_ensemble", identifiers)
        self.assertIn("symbolic_execution", identifiers)
        self.assertIn("model_generation_agents", identifiers)
        self.assertIn("java_fuzzing", identifiers)
        self.assertIn("cached_patching", identifiers)
        self.assertIn("sarif_reachability", identifiers)
        self.assertIn("artifact_manager", identifiers)

    def test_runtime_doctor_fails_closed_with_missing_credentials_and_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = build_full_runtime_doctor(reference_root=tmp, env={})

        self.assertFalse(report["ok"])
        self.assertEqual(report["mode"], "owned-full-runtime")
        self.assertEqual(report["subsystem_count"], len(FULL_RUNTIME_SUBSYSTEMS))
        blockers = "\n".join(report["blockers"])
        self.assertIn("model_credentials", blockers)

    def test_full_runtime_parity_passes_when_plugin_commands_and_prompt_fixtures_exist(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            reference = Path(tmp)
            _write_prompt_fixture_tree(reference)
            tool_names = {tool["name"] for tool in AgenticFuzzEngine(data_root=reference / "state").tool_specs()}
            report = build_full_runtime_parity_audit(
                tool_names=tool_names,
                plugin_root=plugin,
                reference_root=reference,
            )

        self.assertTrue(report["ok"], report["blockers"])
        self.assertIn("fuzz-ensemble-mcp", report["mcp_servers"])
        self.assertIn("artifact-manager", report["subagents"])
        self.assertFalse(report["missing_tools"])
        self.assertFalse(report["missing_commands"])

    def test_owned_campaign_and_deploy_plans_are_non_mutating_phase_graphs(self) -> None:
        campaign = build_owned_campaign_plan(
            task_id="task-1",
            target="localfuzz/c/mongoose",
            language="c-cpp",
            seconds=60,
        )
        local_deploy = build_owned_deploy_plan(target="local", namespace="agentic-fuzz-test")
        k8s_deploy = build_owned_deploy_plan(target="k8s", namespace="agentic-fuzz-test")

        self.assertEqual(campaign["execution_default"], "plan-only")
        self.assertIn("fuzz_ensemble", campaign["required_subsystems"])
        self.assertIn("symbolic_execution", campaign["required_subsystems"])
        self.assertIn("export-bundling", {phase["name"] for phase in campaign["phases"]})
        self.assertEqual(local_deploy["target"], "local")
        self.assertEqual(k8s_deploy["target"], "k8s")
        self.assertEqual(local_deploy["execution_default"], "plan-only")
        self.assertIn("AGENTIC_FUZZ_ALLOW_MUTATION=1", k8s_deploy["mutation_gate"])

    def test_engine_and_mcp_expose_full_runtime_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = AgenticFuzzEngine(data_root=tmp)
            tool_names = {tool["name"] for tool in engine.tool_specs()}
            server = AgenticFuzzMcpServer(data_root=tmp)
            response = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "full_runtime_campaign_plan", "arguments": {"target": "localfuzz/c/mongoose"}},
                }
            )

        self.assertIn("full_runtime_doctor", tool_names)
        self.assertIn("runtime_backend_status", tool_names)
        self.assertIn("fuzz_ensemble_run", tool_names)
        self.assertIn("symbolic_worker_run", tool_names)
        self.assertIn("sarif_reachability_run", tool_names)
        self.assertIn("patch_environment_prepare", tool_names)
        self.assertIn("full_runtime_parity_audit", tool_names)
        self.assertIn("full_runtime_campaign_plan", tool_names)
        self.assertIn("full_runtime_local_campaign", tool_names)
        self.assertIn("fidelity_owned_build_replay", tool_names)
        self.assertIn("fidelity_oss_fuzz_build", tool_names)
        self.assertIn("fidelity_oss_fuzz_build_replay", tool_names)
        self.assertIn("full_runtime_deploy_plan", tool_names)
        body = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(body["runtime_authority"], "agentic_fuzz_full")
        self.assertEqual(body["execution_default"], "plan-only")

    def test_full_runtime_local_campaign_runs_end_to_end_over_reference_fixture(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = root / "claude-plugin" / "agentic-fuzz-engine"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            reference = tmp_path / "reference"
            harness_script = tmp_path / "mongoose_harness.py"
            source = tmp_path / "source"
            _write_live_campaign_fixture_reference(reference, project="mongoose", error_token="dynamic-stack-buffer-overflow")
            _write_live_harness_script(harness_script, crash_type="dynamic-stack-buffer-overflow")
            _write_dictionary_generation_source(source)
            engine = AgenticFuzzEngine(
                data_root=tmp_path / "state",
                reference_root=reference,
                audit_roots=(root / "src" / "agentic_fuzz_engine", root / "src" / "agentic_fuzz_full", plugin),
            )

            result = engine.call_tool(
                "full_runtime_local_campaign",
                {
                    "project": "localfuzz/c/mongoose",
                    "run_id": "owned-full-e2e",
                    "harness": "fuzz",
                    "harness_command": [sys.executable, str(harness_script), "{poc}"],
                    "source_dir": str(source),
                    "timeout_seconds": 5,
                    "repetitions": 3,
                },
            )

        self.assertTrue(result["ok"], result["blockers"])
        self.assertEqual(result["mode"], "owned-local-full-campaign")
        self.assertEqual(result["steps"]["replay"]["verified"], 1)
        self.assertEqual(result["steps"]["finding_grade"]["verdict"], "PASS")
        self.assertTrue(result["steps"]["lifecycle"]["ok"], result["steps"]["lifecycle"]["blockers"])
        self.assertEqual(result["steps"]["exports"]["counts"]["pov"], 1)
        self.assertEqual(result["steps"]["exports"]["counts"]["sarif"], 1)
        self.assertTrue(result["completion"]["ok"], result["completion"]["blockers"])
        self.assertEqual(result["completion"]["gates"]["fixture_fidelity"]["score"]["coverage_ratio"], 1.0)
        checkpoint_agents = set(result["completion"]["gates"]["subagent_orchestration"]["checkpoint_agents"])
        self.assertIn("native-harness", checkpoint_agents)
        self.assertIn("input-generator", checkpoint_agents)
        self.assertIn("artifact-manager", checkpoint_agents)

    def test_plugin_command_files_exist_for_full_runtime_surfaces(self) -> None:
        root = Path(__file__).resolve().parents[1]
        commands = root / "claude-plugin" / "agentic-fuzz-engine" / "commands"

        expected = {
            "campaign-full.md",
            "campaign-full-run.md",
            "fidelity-owned-build-replay.md",
            "fidelity-oss-fuzz-build.md",
            "fidelity-oss-fuzz-build-replay.md",
            "fidelity-remote-amd64-replay.md",
            "runtime-doctor.md",
            "runtime-backend-status.md",
            "fuzz-ensemble-run.md",
            "fuzz.md",
            "symbolic-worker-run.md",
            "sym.md",
            "sarif-reachability-run.md",
            "reach.md",
            "patch-environment-prepare.md",
            "patch-env.md",
            "ready.md",
            "deploy-local.md",
            "deploy-k8s.md",
            "parity-full.md",
            "benchmark-fixtures.md",
        }
        self.assertTrue(expected.issubset({path.name for path in commands.glob("*.md")}))

    def test_runtime_backend_status_reports_real_tool_visibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp) / "bin"
            bin_dir.mkdir()
            for name in ("clang", "llvm-symbolizer", "afl-fuzz", "cargo", "symcc", "symqemu", "codeql", "joern", "java", "docker", "git", "uv", "sootup"):
                _write_fake_executable(bin_dir / name)
            env = {
                "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                "ANTHROPIC_API_KEY": "test-key",
            }

            result = runtime_backend_status(env=env)

        self.assertTrue(result["groups"]["fuzz_ensemble"]["checks"]["afl-fuzz"]["ok"])
        self.assertTrue(result["groups"]["symbolic_stack"]["checks"]["symcc"]["ok"])
        self.assertTrue(result["groups"]["sarif_reachability"]["checks"]["codeql"]["ok"])
        self.assertTrue(result["groups"]["cached_patch_pool"]["checks"]["model_credentials"]["ok"])

    def test_real_fuzz_ensemble_runs_bounded_fake_local_workers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            _write_fake_executable(bin_dir / "clang")
            _write_fake_executable(bin_dir / "cargo")
            _write_fake_afl_fuzz(bin_dir / "afl-fuzz")
            libfuzzer = tmp_path / "libfuzzer_worker.py"
            libafl = tmp_path / "libafl_worker.py"
            _write_fake_libfuzzer_worker(libfuzzer)
            _write_fake_crash_writer(libafl)
            env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"}

            result = run_fuzz_ensemble(
                work_dir=tmp_path / "work",
                target="localfuzz/c/tiny",
                harness="fuzz",
                harness_command=[sys.executable, str(libfuzzer), "{seed_corpus}", "{crash_dir}"],
                seed_artifacts=[{"name": "seed.bin", "content_b64": base64.b64encode(b"seed").decode("ascii")}],
                workers=["libfuzzer", "afl", "libafl"],
                libafl_command=[sys.executable, str(libafl), "{crash_dir}"],
                runs=2,
                timeout_seconds=5,
                env=env,
            )

        self.assertTrue(result["ok"], result["blockers"])
        self.assertEqual(result["workers_executed"], 3)
        self.assertGreaterEqual(len(result["crash_files"]), 3)

    def test_afl_worker_defaults_to_autoresume_for_repeat_rounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            _write_fake_executable(bin_dir / "clang")
            _write_fake_env_dump_afl_fuzz(bin_dir / "afl-fuzz")
            env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"}

            result = run_fuzz_ensemble(
                work_dir=tmp_path / "work",
                target="localfuzz/c/tiny",
                harness="fuzz",
                harness_command=["/bin/true", "{poc}"],
                workers=["afl"],
                runs=2,
                timeout_seconds=5,
                env=env,
            )

            afl_result = result["worker_results"][0]
            self.assertTrue(afl_result["executed"])
            env_dump = Path(afl_result["crash_dir"]) / "env.json"
            recorded = json.loads(env_dump.read_text(encoding="utf-8"))
        self.assertEqual(recorded.get("AFL_AUTORESUME"), "1")

    def test_symbolic_worker_runs_bounded_fake_symcc_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            _write_fake_executable(bin_dir / "symcc")
            writer = tmp_path / "symcc_writer.py"
            _write_fake_crash_writer(writer)
            env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"}

            result = run_symbolic_worker(
                work_dir=tmp_path / "work",
                mode="symcc",
                command=[sys.executable, str(writer), "{output_dir}"],
                timeout_seconds=5,
                env=env,
            )

        self.assertTrue(result["ok"], result["blockers"])
        self.assertEqual(len(result["output_files"]), 1)

    def test_sarif_reachability_runs_bounded_fake_codeql(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            source = tmp_path / "src"
            source.mkdir()
            (source / "bug.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            sarif = tmp_path / "input.sarif.json"
            _write_minimal_sarif(sarif)
            bin_dir.mkdir()
            _write_fake_codeql(bin_dir / "codeql")
            env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"}

            result = run_sarif_reachability(
                work_dir=tmp_path / "sarif-work",
                source_dir=source,
                sarif_file=sarif,
                create_database=True,
                codeql_query_suite="test-suite",
                run_joern=False,
                run_sootup=False,
                timeout_seconds=5,
                env=env,
            )

        self.assertTrue(result["ok"], result["blockers"])
        self.assertEqual(result["verdict"], "analyzed")
        self.assertEqual(result["input_sarif"]["source_location_hits"], 1)
        self.assertTrue(any(item["relative_path"] == "codeql-results.sarif" for item in result["output_files"]))

    def test_patch_environment_prepare_uses_source_cache_pool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "source"
            source.mkdir()
            (source / "parser.c").write_text("int parse(void) { return 0; }\n", encoding="utf-8")
            first = prepare_patch_environment(source_dir=source, pool_root=tmp_path / "pool", env_name="bug-1")
            second = prepare_patch_environment(source_dir=source, pool_root=tmp_path / "pool", env_name="bug-1")
            second_env_exists = Path(second["env_dir"]).is_dir()

        self.assertTrue(first["ok"], first["blockers"])
        self.assertFalse(first["cache_hit"])
        self.assertTrue(second["ok"], second["blockers"])
        self.assertTrue(second["cache_hit"])
        self.assertTrue(second_env_exists)

    def test_remote_amd64_replay_script_is_execution_only_not_cloud_provisioning(self) -> None:
        root = Path(__file__).resolve().parents[1]
        script = root / "scripts" / "remote-amd64-oss-fuzz-replay.sh"
        content = script.read_text(encoding="utf-8")

        self.assertTrue(script.exists())
        self.assertIn("fidelity-oss-fuzz-build-replay", content)
        self.assertIn("runs/remote-amd64", content)
        self.assertIn("bash -s --", content)
        self.assertIn("docker image inspect ghcr.io/agentic-fuzz/base-runner:v1.3.0", content)
        self.assertNotIn("docker pull", content)
        self.assertNotIn("--delete", content)
        self.assertNotIn("hcloud server create", content)
        self.assertNotIn("gcloud compute instances create", content)

    def test_cli_campaign_full_outputs_owned_runtime_plan(self) -> None:
        root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agentic_fuzz_engine.cli",
                    "--data-root",
                    tmp,
                    "campaign-full",
                    "localfuzz/c/mongoose",
                    "--task-id",
                    "task-cli",
                    "--seconds",
                    "60",
                ],
                cwd=root,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        body = json.loads(result.stdout)
        self.assertEqual(body["task_id"], "task-cli")
        self.assertEqual(body["target"], "localfuzz/c/mongoose")
        self.assertEqual(body["execution_default"], "plan-only")

    def test_cli_campaign_full_run_summary_reports_fixture_comparison(self) -> None:
        root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            reference = tmp_path / "reference"
            harness_script = tmp_path / "mongoose_harness.py"
            source = tmp_path / "source"
            _write_live_campaign_fixture_reference(reference, project="mongoose", error_token="dynamic-stack-buffer-overflow")
            _write_live_harness_script(harness_script, crash_type="dynamic-stack-buffer-overflow")
            _write_dictionary_generation_source(source)
            env["AGENTIC_FUZZ_REFERENCE_ROOT"] = str(reference)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agentic_fuzz_engine.cli",
                    "--data-root",
                    str(tmp_path / "state"),
                    "campaign-full-run",
                    "localfuzz/c/mongoose",
                    "--run-id",
                    "summary-full-e2e",
                    "--harness",
                    "fuzz",
                    "--harness-command-json",
                    json.dumps([sys.executable, str(harness_script), "{poc}"]),
                    "--source-dir",
                    str(source),
                    "--timeout-seconds",
                    "5",
                    "--repetitions",
                    "3",
                    "--summary-only",
                    "--strict",
                ],
                cwd=root,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        body = json.loads(result.stdout)
        self.assertTrue(body["ok"], body["blockers"])
        self.assertEqual(body["fixture_fidelity"]["expected_proofs_executed"], 1)
        self.assertEqual(body["fixture_fidelity"]["verified"], 1)
        self.assertEqual(body["fixture_fidelity"]["coverage_ratio"], 1.0)
        self.assertTrue(body["fixture_fidelity"]["ok"])
        self.assertEqual(body["finding"]["grade_verdict"], "PASS")
        self.assertEqual(body["exports"]["accepted_by_kind"]["pov"], 1)
        self.assertEqual(body["exports"]["accepted_by_kind"]["sarif"], 1)
        self.assertTrue(body["completion"]["subagent_orchestration_ok"])

    def test_owned_build_replay_compiles_source_snapshot_and_verifies_fixture(self) -> None:
        if shutil.which("clang") is None:
            self.skipTest("clang is required for owned direct-ASAN replay")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            reference = tmp_path / "reference"
            _write_direct_asan_fixture_reference(reference)
            engine = AgenticFuzzEngine(data_root=tmp_path / "state", reference_root=reference)

            result = engine.call_tool(
                "fidelity_owned_build_replay",
                {
                    "run_id": "direct-owned-e2e",
                    "project": "localfuzz/c/tiny",
                    "compile_timeout_seconds": 30,
                    "replay_timeout_seconds": 5,
                    "repetitions": 1,
                },
            )

        self.assertTrue(result["ok"], result["blockers"])
        self.assertEqual(result["summary"]["selected_fixtures"], 1)
        self.assertEqual(result["summary"]["compiled_harnesses"], 1)
        self.assertEqual(result["summary"]["executed_proofs"], 1)
        self.assertEqual(result["summary"]["verified_proofs"], 1)
        self.assertEqual(result["summary"]["represented_fixtures"], 1)
        self.assertEqual(result["summary"]["coverage_ratio"], 1.0)
        self.assertEqual(result["audit"]["fixtures"][0]["status"], "represented")

    def test_oss_fuzz_build_uses_owned_external_project_and_counts_harnesses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            reference = tmp_path / "reference"
            oss_fuzz_root = tmp_path / "oss-fuzz"
            bin_dir = tmp_path / "bin"
            _write_oss_fuzz_fixture_reference(reference)
            _write_fake_oss_fuzz_helper(oss_fuzz_root)
            _write_fake_binary(bin_dir / "docker")
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}"
            try:
                engine = AgenticFuzzEngine(data_root=tmp_path / "state", reference_root=reference)

                result = engine.call_tool(
                    "fidelity_oss_fuzz_build",
                    {
                        "run_id": "fake-oss-fuzz-build",
                        "project": "localfuzz/c/tiny",
                        "oss_fuzz_root": str(oss_fuzz_root),
                        "docker_platform": "linux/amd64",
                        "timeout_seconds": 10,
                    },
                )
                owned_source_exists = Path(result["summary"]["source_dir"]).is_dir()
            finally:
                os.environ["PATH"] = old_path

        self.assertTrue(result["ok"], result["blockers"])
        self.assertEqual(result["mode"], "owned-oss-fuzz-build")
        self.assertEqual(result["summary"]["fuzzer_count"], 1)
        self.assertEqual(result["summary"]["matched_harness_count"], 1)
        self.assertEqual(result["summary"]["missing_harness_count"], 0)
        self.assertEqual([item["name"] for item in result["fuzzers"]], ["fuzz"])
        self.assertTrue(all(command["ok"] for command in result["commands"]))
        self.assertEqual(result["summary"]["source_preparation"]["mode"], "owned-copy")
        self.assertNotEqual(
            Path(result["summary"]["source_dir"]).resolve(),
            Path(result["summary"]["reference_source_dir"]).resolve(),
        )
        self.assertTrue(owned_source_exists)

    def test_oss_fuzz_build_replay_records_fixture_finding_from_container_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            reference = tmp_path / "reference"
            oss_fuzz_root = tmp_path / "oss-fuzz"
            bin_dir = tmp_path / "bin"
            _write_oss_fuzz_fixture_reference(reference)
            _write_fake_oss_fuzz_helper(oss_fuzz_root)
            _write_fake_docker_replay_binary(bin_dir / "docker")
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{bin_dir}{os.pathsep}{old_path}"
            try:
                engine = AgenticFuzzEngine(data_root=tmp_path / "state", reference_root=reference)

                result = engine.call_tool(
                    "fidelity_oss_fuzz_build_replay",
                    {
                        "run_id": "fake-oss-fuzz-build-replay",
                        "project": "localfuzz/c/tiny",
                        "oss_fuzz_root": str(oss_fuzz_root),
                        "docker_platform": "linux/amd64",
                        "build_timeout_seconds": 10,
                        "replay_timeout_seconds": 10,
                        "repetitions": 1,
                        "runner_image": "fake-runner:latest",
                    },
                )
            finally:
                os.environ["PATH"] = old_path

        self.assertTrue(result["ok"], result["blockers"])
        self.assertEqual(result["mode"], "owned-oss-fuzz-build-replay")
        self.assertEqual(result["summary"]["verified"], 1)
        self.assertEqual(result["summary"]["findings_recorded"], 1)
        self.assertEqual(result["summary"]["represented_fixtures"], 1)
        self.assertEqual(result["summary"]["coverage_ratio"], 1.0)
        self.assertEqual(result["cases"][0]["status"], "verified")
        self.assertEqual(result["audit"]["fixtures"][0]["status"], "represented")

    def test_project_compatibility_shims_patch_only_owned_build_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "owned-source" / "target-c-mosquitto-src"
            external = tmp_path / "external"
            source.mkdir(parents=True)
            external.mkdir()
            (source / "libcommon").mkdir()
            (external / "build.sh").write_text(
                "make $MAKE_FLAGS WITH_STATIC_LIBRARIES=yes WITH_DOCS=no WITH_FUZZING=yes WITH_EDITLINE=no > /dev/null",
                encoding="utf-8",
            )

            shims = _apply_project_compatibility_shims("mosquitto", source, external)
            lib_is_symlink = (source / "lib").is_symlink()
            patched = (external / "build.sh").read_text(encoding="utf-8")

        self.assertEqual({shim["kind"] for shim in shims}, {"source-layout", "build-script"})
        self.assertTrue(lib_is_symlink)
        self.assertNotIn('DIRS="libcommon plugins src"', patched)
        self.assertIn("make $MAKE_FLAGS -C libcommon", patched)
        self.assertIn("make $MAKE_FLAGS -C src", patched)
        self.assertIn("make $MAKE_FLAGS -C plugins/dynamic-security", patched)
        self.assertIn("make $MAKE_FLAGS -C fuzzing/broker broker_fuzz_test_config", patched)
        self.assertIn("make $MAKE_FLAGS -C fuzzing/libcommon libcommon_fuzz_utf8", patched)
        self.assertIn("make $MAKE_FLAGS -C fuzzing/plugins/dynamic-security dynsec_fuzz_load", patched)

    def test_project_compatibility_shims_restore_mosquitto_lib_tree_for_real_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "owned-source" / "target-c-mosquitto-src"
            external = tmp_path / "external"
            lib_fixture = tmp_path / "public-lib"
            (source / "src").mkdir(parents=True)
            (source / "include" / "mosquitto").mkdir(parents=True)
            (source / "libcommon").mkdir()
            external.mkdir()
            lib_fixture.mkdir()
            (source / "config.mk").write_text("VERSION=2.1.0\n", encoding="utf-8")
            (source / "src" / "Makefile").write_text("all:\n", encoding="utf-8")
            (source / "include" / "mosquitto" / "mqtt_protocol.h").write_text(
                "#define CMD_CONNECT 0x10U\n",
                encoding="utf-8",
            )
            for name in MOSQUITTO_LIB_FILES:
                (lib_fixture / name).write_text(f"fixture {name}\n", encoding="utf-8")
            (external / "build.sh").write_text(
                "make $MAKE_FLAGS WITH_STATIC_LIBRARIES=yes WITH_DOCS=no WITH_FUZZING=yes WITH_EDITLINE=no > /dev/null\n",
                encoding="utf-8",
            )
            previous = os.environ.get("AGENTIC_FUZZ_MOSQUITTO_LIB_SOURCE")
            os.environ["AGENTIC_FUZZ_MOSQUITTO_LIB_SOURCE"] = str(lib_fixture)
            try:
                shims = _apply_project_compatibility_shims("mosquitto", source, external)
            finally:
                if previous is None:
                    os.environ.pop("AGENTIC_FUZZ_MOSQUITTO_LIB_SOURCE", None)
                else:
                    os.environ["AGENTIC_FUZZ_MOSQUITTO_LIB_SOURCE"] = previous
            patched = (external / "build.sh").read_text(encoding="utf-8")
            lib_is_symlink = (source / "lib").is_symlink()
            restored_alias = (source / "lib" / "alias_mosq.c").read_text(encoding="utf-8")
            protocol_header = (source / "include" / "mosquitto" / "mqtt_protocol.h").read_text(encoding="utf-8")

        self.assertFalse(lib_is_symlink)
        self.assertEqual(restored_alias, "fixture alias_mosq.c\n")
        self.assertIn("restored missing public Mosquitto", "\n".join(shim["detail"] for shim in shims))
        self.assertIn("source-header", {shim["kind"] for shim in shims})
        self.assertIn("#define CMD_RESERVED 0x00U\n#define CMD_CONNECT", protocol_header)
        self.assertIn("make $MAKE_FLAGS -C fuzzing/plugins/dynamic-security dynsec_fuzz_load", patched)

    def test_project_compatibility_shims_restore_php_build_tree_for_real_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "owned-source" / "target-c-php"
            external = tmp_path / "external"
            build_fixture = tmp_path / "public-build"
            date_lib_fixture = tmp_path / "public-date-lib"
            (source / "main").mkdir(parents=True)
            (source / "ext" / "date" / "lib").mkdir(parents=True)
            external.mkdir()
            build_fixture.mkdir()
            date_lib_fixture.mkdir()
            (source / "buildconf").write_text("#!/bin/sh\n", encoding="utf-8")
            (source / "main" / "php_version.h").write_text(
                '#define PHP_VERSION "8.5.0-dev"\n',
                encoding="utf-8",
            )
            (source / "ext" / "date" / "lib" / "timelib_config.h").write_text(
                "fixture timelib_config.h\n",
                encoding="utf-8",
            )
            for name in PHP_BUILD_FILES:
                (build_fixture / name).write_text(f"fixture {name}\n", encoding="utf-8")
            for name in PHP_DATE_LIB_FILES:
                (date_lib_fixture / name).write_text(f"fixture {name}\n", encoding="utf-8")
            previous = os.environ.get("AGENTIC_FUZZ_PHP_BUILD_SOURCE")
            previous_date_lib = os.environ.get("AGENTIC_FUZZ_PHP_DATE_LIB_SOURCE")
            os.environ["AGENTIC_FUZZ_PHP_BUILD_SOURCE"] = str(build_fixture)
            os.environ["AGENTIC_FUZZ_PHP_DATE_LIB_SOURCE"] = str(date_lib_fixture)
            try:
                shims = _apply_project_compatibility_shims("php", source, external)
            finally:
                if previous is None:
                    os.environ.pop("AGENTIC_FUZZ_PHP_BUILD_SOURCE", None)
                else:
                    os.environ["AGENTIC_FUZZ_PHP_BUILD_SOURCE"] = previous
                if previous_date_lib is None:
                    os.environ.pop("AGENTIC_FUZZ_PHP_DATE_LIB_SOURCE", None)
                else:
                    os.environ["AGENTIC_FUZZ_PHP_DATE_LIB_SOURCE"] = previous_date_lib
            restored_php_m4 = (source / "build" / "php.m4").read_text(encoding="utf-8")
            restored_timelib = (source / "ext" / "date" / "lib" / "timelib.h").read_text(encoding="utf-8")
            preserved_timelib_config = (source / "ext" / "date" / "lib" / "timelib_config.h").read_text(
                encoding="utf-8"
            )
            executable_modes = {
                name: bool((source / "build" / name).stat().st_mode & 0o111)
                for name in PHP_BUILD_EXECUTABLE_FILES
            }

        self.assertEqual(restored_php_m4, "fixture php.m4\n")
        self.assertEqual(restored_timelib, "fixture timelib.h\n")
        self.assertEqual(preserved_timelib_config, "fixture timelib_config.h\n")
        self.assertTrue(all(executable_modes.values()), executable_modes)
        self.assertIn("restored missing public PHP 8.5", "\n".join(shim["detail"] for shim in shims))

    def test_project_compatibility_shims_patch_sleuthkit_bootstrap_and_wireshark_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sleuth_source = tmp_path / "owned-source" / "target-c-sleuthkit"
            sleuth_external = tmp_path / "sleuth-external"
            sleuth_source.mkdir(parents=True)
            sleuth_external.mkdir()
            (sleuth_source / "bootstrap").write_text(
                "#!/bin/sh\n"
                "aclocal \\\n"
                "    && (libtoolize --force || glibtoolize --force) \\\n"
                "    && automake --foreign --add-missing --copy \\\n"
                "    && autoconf\n",
                encoding="utf-8",
            )
            (sleuth_external / "build.sh").write_text(
                "./bootstrap\n./configure --enable-static\nmake -j$(nproc)\n",
                encoding="utf-8",
            )

            wireshark_source = tmp_path / "owned-source" / "target-c-wireshark"
            wireshark_external = tmp_path / "wireshark-external"
            wireshark_source.mkdir(parents=True)
            wireshark_external.mkdir()
            (wireshark_external / "build.sh").write_text(
                'CMAKE_DEFINES="-DBUILD_fuzzshark=ON"\n'
                "ninja all-fuzzers\n\n"
                "$SRC/target-c-wireshark/tools/oss-fuzzshark/build.sh all\n",
                encoding="utf-8",
            )

            sleuth_shims = _apply_project_compatibility_shims("sleuthkit", sleuth_source, sleuth_external)
            wireshark_shims = _apply_project_compatibility_shims("wireshark", wireshark_source, wireshark_external)
            sleuth_bootstrap = (sleuth_source / "bootstrap").read_text(encoding="utf-8")
            sleuth_build = (sleuth_external / "build.sh").read_text(encoding="utf-8")
            wireshark_build = (wireshark_external / "build.sh").read_text(encoding="utf-8")

        self.assertIn("source-bootstrap", {shim["kind"] for shim in sleuth_shims})
        self.assertIn("&& autoheader", sleuth_bootstrap)
        self.assertIn("make -C tsk -j$(nproc) || test -f tsk/.libs/libtsk.a", sleuth_build)
        self.assertIn('CMAKE_DEFINES="-DBUILD_fuzzshark=OFF"', wireshark_build)
        self.assertIn("ninja -j1 fuzzshark_ip", wireshark_build)
        self.assertIn('install run/fuzzshark_ip "$OUT/fuzzshark_ip"', wireshark_build)
        self.assertEqual([shim["project"] for shim in wireshark_shims], ["wireshark", "wireshark"])


def _write_prompt_fixture_tree(reference: Path) -> None:
    for subsystem in FULL_RUNTIME_SUBSYSTEMS:
        for relative in subsystem.fidelity_paths:
            path = reference / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("prompt fixture\n", encoding="utf-8")


def _write_live_harness_script(path: Path, *, crash_type: str) -> None:
    path.write_text(
        "\n".join(
            [
                "import sys",
                "data = open(sys.argv[1], 'rb').read()",
                "if data:",
                f"    sys.stderr.write('==9==ERROR: AddressSanitizer: {crash_type} on address 0x41414141\\n')",
                "    sys.stderr.write('    #0 0xaaaa in live_parse /src/live/parser.c:7\\n')",
                "    sys.stderr.write('    #1 0xbbbb in LLVMFuzzerTestOneInput /src/live/fuzz.c:3\\n')",
                f"    sys.stderr.write('SUMMARY: AddressSanitizer: {crash_type} /src/live/parser.c:7 in live_parse\\n')",
                "    raise SystemExit(134)",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_live_campaign_fixture_reference(reference: Path, *, project: str, error_token: str) -> None:
    project_dir = reference / "benchmark" / "projects" / project
    vuln = project_dir / "vulnerabilities" / "fixture_0"
    userspace = reference / "targets" / "c" / project / ".localfuzz"
    vuln.mkdir(parents=True)
    userspace.mkdir(parents=True)
    (project_dir / "project.yaml").write_text(
        "\n".join(
            [
                "language: c",
                "sanitizers:",
                "  - address",
                "fuzzing_engines:",
                "  - libfuzzer",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (userspace / "config.yaml").write_text(
        "\n".join(
            [
                "harness_files:",
                "  - name: fuzz",
                "    path: fuzz.c",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (vuln / "index.json").write_text(
        json.dumps(
            {
                "name": "fixture_0",
                "harness": "fuzz",
                "sanitizer": "address",
                "error_token": error_token,
                "base_commit": "abc123",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (vuln / "proof.bin").write_bytes(b"CRASH")
    (vuln / "patch.diff").write_text(
        "\n".join(
            [
                "diff --git a/fuzz.c b/fuzz.c",
                "index 1111111..2222222 100644",
                "--- a/fuzz.c",
                "+++ b/fuzz.c",
                "@@ -1,1 +1,1 @@",
                "-int vulnerable;",
                "+int fixed;",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_direct_asan_fixture_reference(reference: Path) -> None:
    project = reference / "benchmark" / "projects" / "tiny"
    source = project / "sources" / "abc123" / "src" / "target-c-tiny-src"
    vuln = project / "vulnerabilities" / "fixture_0"
    userspace = (
        reference
        / "targets"
        / "c"
        / "tiny"
        / ".localfuzz"
    )
    source.mkdir(parents=True)
    vuln.mkdir(parents=True)
    userspace.mkdir(parents=True)
    (project / "project.yaml").write_text(
        "\n".join(
            [
                "language: c",
                "sanitizers:",
                "  - address",
                "fuzzing_engines:",
                "  - libfuzzer",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (userspace / "config.yaml").write_text(
        "\n".join(
            [
                "harness_files:",
                "  - name: fuzz",
                "    path: sources/abc123/src/target-c-tiny-src/fuzz.c",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (source / "fuzz.c").write_text(
        "\n".join(
            [
                "#include <stddef.h>",
                "#include <stdint.h>",
                "#include <stdlib.h>",
                "#include <string.h>",
                "__attribute__((noinline)) static int boom(const uint8_t *data) {",
                "  char *buf = (char *) malloc(4);",
                "  volatile int idx = (int)data[0];",
                "  buf[idx] = 1;",
                "  int rc = buf[0];",
                "  free(buf);",
                "  return rc;",
                "}",
                "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {",
                "  if (size >= 5 && memcmp(data, \"CRASH\", 5) == 0) return boom(data);",
                "  return 0;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (vuln / "index.json").write_text(
        json.dumps(
            {
                "name": "fixture_0",
                "harness": "fuzz",
                "sanitizer": "address",
                "error_token": "ERROR: AddressSanitizer: heap-buffer-overflow",
                "base_commit": "abc123",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (vuln / "proof.bin").write_bytes(b"CRASH")
    (vuln / "patch.diff").write_text(
        "\n".join(
            [
                "diff --git a/fuzz.c b/fuzz.c",
                "index 1111111..2222222 100644",
                "--- a/fuzz.c",
                "+++ b/fuzz.c",
                "@@ -1,1 +1,1 @@",
                "-int vulnerable;",
                "+int fixed;",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_fake_executable(path: Path) -> None:
    path.write_text("#!/usr/bin/env python3\nimport sys\nraise SystemExit(0)\n", encoding="utf-8")
    path.chmod(0o755)


def _write_fake_afl_fuzz(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import pathlib, sys",
                "out = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])",
                "crashes = out / 'default' / 'crashes'",
                "crashes.mkdir(parents=True, exist_ok=True)",
                "(crashes / 'id:000000,sig:06,src:000000').write_bytes(b'afl-crash')",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _write_fake_env_dump_afl_fuzz(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import json, os, pathlib, sys",
                "out = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])",
                "out.mkdir(parents=True, exist_ok=True)",
                "keys = ('AFL_AUTORESUME', 'AFL_NO_UI')",
                "(out / 'env.json').write_text(json.dumps({k: os.environ.get(k) for k in keys}))",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _write_fake_libfuzzer_worker(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "import pathlib, sys",
                "crash_dir = None",
                "for arg in sys.argv[1:]:",
                "    if arg.startswith('-artifact_prefix='):",
                "        crash_dir = pathlib.Path(arg.split('=', 1)[1])",
                "if crash_dir is None:",
                "    crash_dir = pathlib.Path(sys.argv[-1])",
                "crash_dir.mkdir(parents=True, exist_ok=True)",
                "(crash_dir / 'crash-libfuzzer').write_bytes(b'libfuzzer-crash')",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_fake_crash_writer(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "import pathlib, sys",
                "out = pathlib.Path(sys.argv[1])",
                "out.mkdir(parents=True, exist_ok=True)",
                "(out / 'generated-input').write_bytes(b'generated')",
                "raise SystemExit(0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_fake_codeql(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import pathlib, sys",
                "if sys.argv[1:3] == ['database', 'create']:",
                "    pathlib.Path(sys.argv[3]).mkdir(parents=True, exist_ok=True)",
                "    raise SystemExit(0)",
                "if sys.argv[1:3] == ['database', 'analyze']:",
                "    output = next(arg.split('=', 1)[1] for arg in sys.argv if arg.startswith('--output='))",
                "    pathlib.Path(output).write_text('{\"runs\": []}\\n', encoding='utf-8')",
                "    raise SystemExit(0)",
                "raise SystemExit(2)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _write_minimal_sarif(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "unit", "rules": [{"id": "unit.rule"}]}},
                        "results": [
                            {
                                "ruleId": "unit.rule",
                                "message": {"text": "unit"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "bug.c"},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _write_oss_fuzz_fixture_reference(reference: Path) -> None:
    _write_direct_asan_fixture_reference(reference)
    project = reference / "benchmark" / "projects" / "tiny"
    (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (project / "build.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (project / "fuzz.options").write_text("[libfuzzer]\n", encoding="utf-8")


def _write_fake_oss_fuzz_helper(root: Path) -> None:
    helper = root / "infra" / "helper.py"
    helper.parent.mkdir(parents=True)
    helper.write_text(
        "\n".join(
            [
                "from pathlib import Path",
                "import os",
                "import sys",
                "",
                "root = Path(__file__).resolve().parents[1]",
                "command = sys.argv[1] if len(sys.argv) > 1 else ''",
                "if command == 'build_image':",
                "    raise SystemExit(0)",
                "if command == 'build_fuzzers':",
                "    source = Path(sys.argv[3])",
                "    project = None",
                "    for parent in source.parents:",
                "        if parent.name == 'sources':",
                "            project = parent.parent.name",
                "            break",
                "    project = project or Path(sys.argv[2]).name",
                "    out_dir = root / 'build' / 'out' / project",
                "    out_dir.mkdir(parents=True, exist_ok=True)",
                "    for name in ('fuzz', 'llvm-symbolizer'):",
                "        path = out_dir / name",
                "        path.write_text('#!/bin/sh\\nexit 0\\n', encoding='utf-8')",
                "        path.chmod(0o755)",
                "    (out_dir / 'fuzz.options').write_text('[libfuzzer]\\n', encoding='utf-8')",
                "    raise SystemExit(0)",
                "print('unexpected helper command', command, file=sys.stderr)",
                "raise SystemExit(2)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_fake_binary(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)


def _write_fake_docker_replay_binary(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "#!/bin/sh",
                "if [ \"$1\" = \"run\" ]; then",
                "  echo '==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x41414141' >&2",
                "  echo '    #0 0xaaaa in LLVMFuzzerTestOneInput /src/fuzz.c:7' >&2",
                "  echo 'SUMMARY: AddressSanitizer: heap-buffer-overflow /src/fuzz.c:7 in LLVMFuzzerTestOneInput' >&2",
                "  exit 134",
                "fi",
                "exit 0",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _write_dictionary_generation_source(path: Path) -> None:
    path.mkdir(parents=True)
    (path / "parser.c").write_text(
        "\n".join(
            [
                "#include <string.h>",
                "int parse_input(const unsigned char *data, unsigned long size) {",
                "  if (size >= 5 && memcmp(data, \"MAGIC\", 5) == 0) { return 1; }",
                "  if (size >= 5 && memmem(data, size, \"CRASH\", 5) != 0) { return 2; }",
                "  if (size >= 4 && strcmp((const char *)data, \"PING\") == 0) { return 3; }",
                "  return 0;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

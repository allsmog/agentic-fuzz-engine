from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.scaffold import scaffold_target, select_targets
from agentic_fuzz_engine.workspace import (
    WORKSPACE_CONFIG_NAME,
    _render_env_file,
    load_workspace,
    translate_host_path,
    workspace_init,
)


class WorkspaceTests(unittest.TestCase):
    def test_workspace_init_creates_layout_config_and_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ws"
            result = workspace_init(
                root=root,
                path_maps=["/home/user/.cache=/mnt/disks/data/cache"],
                source_dir=tmp,
                klee_image="klee-ng:test",
                build_container="sddev",
                env={},
            )

            self.assertTrue(result["ok"], result["blockers"])
            for relative in ("data", "targets/c", "benchmark/projects", "bin", "work", "klee"):
                self.assertTrue((root / relative).is_dir(), relative)
            config = json.loads((root / WORKSPACE_CONFIG_NAME).read_text(encoding="utf-8"))
            self.assertEqual(config["docker"]["klee_image"], "klee-ng:test")
            self.assertEqual(config["docker"]["build_container"], "sddev")
            self.assertEqual(config["path_maps"], [{"host": "/home/user/.cache", "outer": "/mnt/disks/data/cache"}])
            env_text = (root / "env.sh").read_text(encoding="utf-8")
            self.assertIn("AGENTIC_FUZZ_REFERENCE_ROOT", env_text)
            self.assertIn("CLAUDE_PLUGIN_DATA", env_text)

            loaded = load_workspace(root, env={})
            self.assertEqual(loaded["docker"]["klee_image"], "klee-ng:test")

    def test_workspace_init_copies_assets_and_reports_missing_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "legacy"
            (source / "sub").mkdir(parents=True)
            (source / "a.bin").write_bytes(b"a")
            (source / "sub" / "b.bin").write_bytes(b"b")
            (source / ".git").mkdir()
            (source / ".git" / "junk").write_bytes(b"x")

            result = workspace_init(
                root=tmp_path / "ws",
                copies=[f"{source}=klee/legacy", f"{tmp_path / 'missing'}=klee/nope"],
                env={},
            )

            self.assertFalse(result["ok"])
            copied = result["copies"][0]
            self.assertEqual(copied["copied_files"], 2)
            self.assertTrue((tmp_path / "ws" / "klee" / "legacy" / "sub" / "b.bin").is_file())
            self.assertFalse((tmp_path / "ws" / "klee" / "legacy" / ".git").exists())
            self.assertIn("copy source missing", result["copies"][1]["blocker"])

    def test_workspace_init_rejects_copy_destination_escaping_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "src"
            source.mkdir()
            result = workspace_init(root=tmp_path / "ws", copies=[f"{source}=../outside"], env={})
        self.assertFalse(result["ok"])
        self.assertIn("escapes workspace", result["blockers"][0])

    def test_workspace_copy_rejects_sibling_prefix_and_nested_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "source"
            source.mkdir()
            (source / "input").write_text("ok", encoding="utf-8")
            root = tmp_path / "workspace"
            outside = tmp_path / "workspace-escape"
            outside.mkdir()
            result = workspace_init(root=root, copies=[f"{source}=../workspace-escape/out"], env={})
            self.assertFalse(result["ok"])
            self.assertFalse((outside / "out").exists())

            (root / "klee" / "linked").symlink_to(outside, target_is_directory=True)
            result = workspace_init(root=root, copies=[f"{source}=klee/linked/out"], env={})
            self.assertFalse(result["ok"])
            self.assertFalse((outside / "out").exists())

    def test_rendered_env_quotes_shell_values_and_rejects_controls(self) -> None:
        rendered = _render_env_file(Path("/tmp/work space"), "image; $(unexpected)")
        self.assertIn("export AGENTIC_FUZZ_KLEE_IMAGE='image; $(unexpected)'", rendered)
        with self.assertRaises(ValueError):
            _render_env_file(Path("/tmp/work"), "bad\nvalue")

    def test_workspace_metadata_outputs_reject_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for name in ("workspace.json", "env.sh", "campaign-policy.json"):
                root = tmp_path / name.replace(".", "-")
                workspace_init(root=root, env={})
                victim = tmp_path / f"{name}.victim"
                victim.write_text("untouched", encoding="utf-8")
                output = root / name
                output.unlink()
                output.symlink_to(victim)
                with self.assertRaises(ValueError):
                    workspace_init(root=root, env={})
                self.assertEqual(victim.read_text(encoding="utf-8"), "untouched")

    def test_translate_host_path_uses_longest_prefix_and_identity_fallback(self) -> None:
        workspace = {
            "path_maps": [
                {"host": "/home/user", "outer": "/mnt/outer/home"},
                {"host": "/home/user/.cache", "outer": "/mnt/disks/data/cache"},
            ]
        }
        self.assertEqual(
            translate_host_path("/home/user/.cache/klee-work", workspace),
            "/mnt/disks/data/cache/klee-work",
        )
        self.assertEqual(translate_host_path("/home/user/notes", workspace), "/mnt/outer/home/notes")
        self.assertEqual(translate_host_path("/srv/other", workspace), "/srv/other")


class ContainerBuildTests(unittest.TestCase):
    def test_build_target_runs_steps_with_placeholders_and_stops_on_failure(self) -> None:
        from agentic_fuzz_engine.container_build import build_target
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, source_dir=tmp, env={})
            target_dir = ws / "targets" / "c" / "demo"
            (target_dir / ".localfuzz").mkdir(parents=True)
            (target_dir / ".localfuzz" / "build.json").write_text(
                json.dumps(
                    {
                        "steps": [
                            {"name": "ok", "argv": ["/usr/bin/touch", "{bin_dir}/fuzzer"], "env": {}},
                            {"name": "boom", "argv": [sys.executable, "-c", "raise SystemExit(1)"], "env": {}},
                            {"name": "after", "argv": ["/bin/true"], "env": {}},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = build_target(project="localfuzz/c/demo", workspace_root=ws, timeout_seconds=30, env=dict(os.environ))

        self.assertFalse(result["ok"])
        self.assertEqual([step["name"] for step in result["steps"]], ["ok", "boom", "after"])
        self.assertTrue(result["steps"][0]["ok"])
        self.assertFalse(result["steps"][1]["ok"])
        self.assertTrue(result["steps"][2]["skipped"])
        self.assertEqual(result["blockers"], ["boom: exit 1"])
        self.assertEqual(result["artifacts"][0]["path"].rsplit("/", 1)[-1], "fuzzer")


class KleeBackendTests(unittest.TestCase):
    def test_extract_klee_tests_writes_seed_bytes_and_error_reports(self) -> None:
        from agentic_fuzz_engine.runtime_backends import _extract_klee_tests

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_root = tmp_path / "klee-ng-out"
            target_out = out_root / "smoke" / "h1-demo"
            target_out.mkdir(parents=True)
            (target_out / "test000001.json").write_text(
                json.dumps(
                    {
                        "testId": 1,
                        "error": {"type": "cwe78.err", "message": "boom"},
                        "inputs": [{"name": "cmd", "size": 3, "data": [65, 66, 67]}],
                    }
                ),
                encoding="utf-8",
            )
            (target_out / "test000002.json").write_text(
                json.dumps({"testId": 2, "inputs": [{"name": "cmd", "size": 2, "data": [1, 2]}]}),
                encoding="utf-8",
            )
            output_dir = tmp_path / "outputs"

            result = _extract_klee_tests(out_root, output_dir)

            self.assertEqual(result["scanned"], 2)
            self.assertEqual(result["seeds_written"], 2)
            self.assertEqual(result["errors_written"], 1)
            seed = output_dir / "seeds" / "smoke-h1-demo-test000001-cmd.bin"
            self.assertEqual(seed.read_bytes(), b"ABC")
            self.assertTrue((output_dir / "errors" / "smoke-h1-demo-test000001.json").is_file())

    def test_klee_mode_reports_blockers_without_config_or_workspace(self) -> None:
        from agentic_fuzz_engine.runtime_backends import run_symbolic_worker

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            fake_docker = bin_dir / "docker"
            fake_docker.write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8")
            fake_docker.chmod(0o755)
            env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '')}"}

            missing_config = run_symbolic_worker(work_dir=tmp_path / "w1", mode="klee", timeout_seconds=5, env=env)
            self.assertFalse(missing_config["ok"])
            self.assertIn("missing klee_config", missing_config["blockers"][0])

            missing_workspace = run_symbolic_worker(
                work_dir=tmp_path / "w2",
                mode="klee",
                klee_config="nope.ci.json",
                workspace_root=tmp_path / "no-ws",
                timeout_seconds=5,
                env=env,
            )
            self.assertFalse(missing_workspace["ok"])
            self.assertIn("workspace config not found", missing_workspace["blockers"][0])


class CorpusSyncTests(unittest.TestCase):
    def _write_fake_symcc(self, path: Path) -> None:
        path.write_text(
            "\n".join(
                [
                    "#!/usr/bin/env python3",
                    "import os, pathlib, sys",
                    "out = pathlib.Path(os.environ['SYMCC_OUTPUT_DIR'])",
                    "seed = pathlib.Path(sys.argv[1]).read_bytes()",
                    "(out / 'variant0').write_bytes(seed)",
                    "raise SystemExit(0)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def test_corpus_sync_feeds_solved_variants_back_and_tracks_seen(self) -> None:
        from agentic_fuzz_engine.concolic_sync import run_corpus_sync

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            corpus = tmp_path / "corpus"
            corpus.mkdir()
            (corpus / "seed-a").write_bytes(b"aaaa")
            (corpus / "seed-b").write_bytes(b"bbbb")
            binary = tmp_path / "fake-symcc"
            self._write_fake_symcc(binary)

            first = run_corpus_sync(
                corpus_dir=corpus,
                symcc_binary=binary,
                max_inputs=10,
                max_seconds=30,
                per_input_timeout=10,
                env=dict(os.environ),
            )

            self.assertTrue(first["ok"], first["blockers"])
            self.assertEqual(first["inputs_processed"], 2)
            self.assertEqual(first["new_seeds_added"], 2)
            solved = [entry.name for entry in corpus.iterdir() if entry.name.startswith("symcc-")]
            self.assertEqual(len(solved), 2)

            second = run_corpus_sync(
                corpus_dir=corpus,
                symcc_binary=binary,
                max_inputs=10,
                max_seconds=30,
                per_input_timeout=10,
                env=dict(os.environ),
            )
            # solved variants are new corpus entries, so they get processed once;
            # their content-identical outputs dedupe to zero new seeds.
            self.assertEqual(second["inputs_processed"], 2)
            self.assertEqual(second["new_seeds_added"], 0)

    def test_corpus_sync_respects_input_budget(self) -> None:
        from agentic_fuzz_engine.concolic_sync import run_corpus_sync

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            corpus = tmp_path / "corpus"
            corpus.mkdir()
            for index in range(5):
                (corpus / f"seed-{index}").write_bytes(bytes([index]))
            binary = tmp_path / "fake-symcc"
            self._write_fake_symcc(binary)

            result = run_corpus_sync(
                corpus_dir=corpus,
                symcc_binary=binary,
                max_inputs=2,
                max_seconds=30,
                per_input_timeout=10,
                env=dict(os.environ),
            )

        self.assertEqual(result["inputs_processed"], 2)


class _StubEngine:
    def __init__(self, crash_dir: Path) -> None:
        self.calls: list[tuple[str, dict]] = []
        self._crash_dir = crash_dir

    def call_tool(self, name: str, args: dict) -> dict:
        self.calls.append((name, args))
        if name == "campaign_start":
            return {"run_id": "run-test"}
        if name == "fuzz_ensemble_run":
            return {
                "ok": True,
                "crash_files": [str(self._crash_dir / "crash-1")],
                "worker_results": [{"worker": "libfuzzer", "executed": True, "crash_dir": str(self._crash_dir)}],
                "blockers": [],
            }
        if name == "crash_import":
            return {"findings": [{"finding_id": "f-1"}]}
        if name == "finding_dedupe":
            return {"groups": [{"representative": {"finding_id": "f-1"}}]}
        return {"ok": True}


class CampaignRoundsTests(unittest.TestCase):
    def test_round_run_chains_lanes_and_summarizes(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            bin_dir = ws / "bin" / "demo"
            bin_dir.mkdir(parents=True)
            fuzzer = bin_dir / "fuzzer"
            fuzzer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fuzzer.chmod(0o755)
            crash_dir = Path(tmp) / "crashes"
            crash_dir.mkdir()
            (crash_dir / "crash-1").write_bytes(b"boom")
            engine = _StubEngine(crash_dir)

            result = run_campaign_rounds(
                engine,
                project="localfuzz/c/demo",
                rounds=2,
                fuzz_seconds=5,
                workspace_root=ws,
                env=dict(os.environ),
            )

        self.assertTrue(result["ok"], result["blockers"])
        self.assertEqual(result["rounds_completed"], 2)
        self.assertEqual(result["findings_recorded"], 2)
        tool_names = [name for name, _ in engine.calls]
        self.assertEqual(tool_names.count("fuzz_ensemble_run"), 2)
        self.assertEqual(tool_names.count("crash_import"), 2)
        self.assertEqual(tool_names.count("finding_dedupe"), 2)
        self.assertEqual(tool_names.count("campaign_checkpoint_record"), 2)
        # klee lane must not run without a config
        self.assertNotIn("symbolic_worker_run", tool_names)
        round_one = result["rounds"][0]
        self.assertIn("skipped", round_one["symcc_sync"])
        self.assertEqual(round_one["intake"]["findings_recorded"], 1)

    def test_round_run_imports_authored_target_seeds(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            bin_dir = ws / "bin" / "demo"
            bin_dir.mkdir(parents=True)
            fuzzer = bin_dir / "fuzzer"
            fuzzer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fuzzer.chmod(0o755)
            authored = ws / "targets" / "c" / "demo" / "seeds"
            authored.mkdir(parents=True)
            (authored / "v1-plain.bin").write_bytes(b"valid-seed-one")
            (authored / "v2-refs.bin").write_bytes(b"valid-seed-two")
            crash_dir = Path(tmp) / "crashes"
            crash_dir.mkdir()
            (crash_dir / "crash-1").write_bytes(b"boom")
            engine = _StubEngine(crash_dir)

            result = run_campaign_rounds(
                engine,
                project="localfuzz/c/demo",
                rounds=1,
                fuzz_seconds=5,
                workspace_root=ws,
                env=dict(os.environ),
            )

            self.assertTrue(result["ok"], result["blockers"])
            self.assertEqual(result["seeds_imported"], 2)
            corpus_blobs = {
                entry.read_bytes()
                for entry in (ws / "work" / "demo" / "seeds").iterdir()
            }
            self.assertIn(b"valid-seed-one", corpus_blobs)
            self.assertIn(b"valid-seed-two", corpus_blobs)

            # Re-run is idempotent: content-addressed names dedupe imports.
            result = run_campaign_rounds(
                engine,
                project="localfuzz/c/demo",
                rounds=1,
                fuzz_seconds=5,
                workspace_root=ws,
                env=dict(os.environ),
            )
            self.assertEqual(result["seeds_imported"], 0)

    def test_round_run_intake_skips_resource_class_artifacts(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            bin_dir = ws / "bin" / "demo"
            bin_dir.mkdir(parents=True)
            fuzzer = bin_dir / "fuzzer"
            fuzzer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fuzzer.chmod(0o755)
            crash_dir = Path(tmp) / "crashes"
            crash_dir.mkdir()
            # Fork-mode runs collect resource-class artifacts alongside real
            # crashes; intake must replay only the genuine crash candidates.
            (crash_dir / "crash-1").write_bytes(b"boom")
            (crash_dir / "timeout-aa").write_bytes(b"hang")
            (crash_dir / "oom-bb").write_bytes(b"big")
            (crash_dir / "slow-unit-cc").write_bytes(b"slow")
            engine = _StubEngine(crash_dir)

            result = run_campaign_rounds(
                engine,
                project="localfuzz/c/demo",
                rounds=1,
                fuzz_seconds=5,
                workspace_root=ws,
                env=dict(os.environ),
            )

            self.assertTrue(result["ok"], result["blockers"])
            intake = result["rounds"][0]["intake"]
            self.assertEqual(intake["resource_noise_skipped"], 3)
            self.assertEqual(intake["findings_recorded"], 1)
            import_args = [args for name, args in engine.calls if name == "crash_import"]
            self.assertEqual(len(import_args), 1)
            staged = Path(import_args[0]["source_path"])
            staged_names = sorted(f.name for f in staged.rglob("*") if f.is_file())
            self.assertEqual(staged_names, ["crash-1"])

    def test_round_run_intake_skips_entire_noise_only_source(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            bin_dir = ws / "bin" / "demo"
            bin_dir.mkdir(parents=True)
            fuzzer = bin_dir / "fuzzer"
            fuzzer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fuzzer.chmod(0o755)
            crash_dir = Path(tmp) / "crashes"
            crash_dir.mkdir()
            (crash_dir / "timeout-aa").write_bytes(b"hang")
            (crash_dir / "slow-unit-bb").write_bytes(b"slow")
            engine = _StubEngine(crash_dir)

            result = run_campaign_rounds(
                engine,
                project="localfuzz/c/demo",
                rounds=1,
                fuzz_seconds=5,
                workspace_root=ws,
                env=dict(os.environ),
            )

        self.assertTrue(result["ok"], result["blockers"])
        intake = result["rounds"][0]["intake"]
        self.assertEqual(intake["resource_noise_skipped"], 2)
        self.assertEqual(intake["findings_recorded"], 0)
        self.assertNotIn("crash_import", [name for name, _ in engine.calls])

    def test_round_run_intake_skip_prefixes_overridable_per_target(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            bin_dir = ws / "bin" / "demo"
            bin_dir.mkdir(parents=True)
            fuzzer = bin_dir / "fuzzer"
            fuzzer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fuzzer.chmod(0o755)
            localfuzz = ws / "targets" / "c" / "demo" / ".localfuzz"
            localfuzz.mkdir(parents=True)
            # Empty override list disables the skip entirely.
            (localfuzz / "fuzz.json").write_text(
                json.dumps({"intake_skip_prefixes": []}), encoding="utf-8"
            )
            crash_dir = Path(tmp) / "crashes"
            crash_dir.mkdir()
            (crash_dir / "crash-1").write_bytes(b"boom")
            (crash_dir / "timeout-aa").write_bytes(b"hang")
            engine = _StubEngine(crash_dir)

            result = run_campaign_rounds(
                engine,
                project="localfuzz/c/demo",
                rounds=1,
                fuzz_seconds=5,
                workspace_root=ws,
                env=dict(os.environ),
            )

        self.assertTrue(result["ok"], result["blockers"])
        intake = result["rounds"][0]["intake"]
        self.assertEqual(intake["resource_noise_skipped"], 0)
        import_args = [args for name, args in engine.calls if name == "crash_import"]
        self.assertEqual(len(import_args), 1)
        # No staging needed when nothing is filtered — raw crash dir is used.
        self.assertEqual(import_args[0]["source_path"], str(crash_dir))

    def test_round_run_blocks_unvalidated_generated_target(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            bin_dir = ws / "bin" / "gen"
            bin_dir.mkdir(parents=True)
            fuzzer = bin_dir / "fuzzer"
            fuzzer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fuzzer.chmod(0o755)
            manifest_dir = ws / "targets" / "c" / "gen" / ".localfuzz"
            manifest_dir.mkdir(parents=True)
            (manifest_dir / "generate.json").write_text(
                json.dumps({"status": "awaiting-authoring", "validated": False}), encoding="utf-8"
            )
            engine = _StubEngine(Path(tmp))

            result = run_campaign_rounds(
                engine, project="localfuzz/c/gen", workspace_root=ws, env=dict(os.environ)
            )

        self.assertFalse(result["ok"])
        self.assertIn("not validated", result["blockers"][0])
        self.assertEqual(result["rounds_completed"], 0)

    def test_round_run_blocks_without_fuzzer_binary(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds

        with tempfile.TemporaryDirectory() as tmp:
            engine = _StubEngine(Path(tmp))
            result = run_campaign_rounds(
                engine,
                project="localfuzz/c/none",
                workspace_root=Path(tmp) / "ws",
                env=dict(os.environ),
            )
        self.assertFalse(result["ok"])
        self.assertIn("missing ASAN fuzzer binary", result["blockers"][0])
        self.assertEqual(result["rounds_completed"], 0)


class ScaffoldTests(unittest.TestCase):
    def _write_sinks(self, path: Path) -> None:
        rows = [
            {"tag": "exec-L0", "file": "a.cpp", "line": 10, "method": "Run", "callee": "system", "code": "system(x)"},
            {"tag": "exec-L0", "file": "b.cpp", "line": 20, "method": "Go", "callee": "popen", "code": "popen(y)"},
            {"tag": "mem-parse", "file": "c.cpp", "line": 30, "method": "Parse", "callee": "memcpy", "code": "memcpy(d, s, n)"},
        ]
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    def test_select_targets_ranks_unharnessed_vectors_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sinks = tmp_path / "sinks.jsonl"
            self._write_sinks(sinks)
            (tmp_path / "ws" / "targets" / "c" / "mem_parse").mkdir(parents=True)
            (tmp_path / "ws" / "targets" / "c" / "_legacy").mkdir(parents=True)

            result = select_targets(sinks_jsonl=sinks, workspace_root=tmp_path / "ws", env={})

        self.assertEqual(result["existing_targets"], ["mem_parse"])
        self.assertEqual(result["unharnessed"], ["exec_l0"])
        first = result["vectors"][0]
        self.assertEqual(first["suggested_name"], "exec_l0")
        self.assertEqual(first["sink_count"], 2)
        self.assertFalse(first["harnessed"])

    def test_scaffold_target_generates_profile_config_build_and_harness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sinks = tmp_path / "sinks.jsonl"
            self._write_sinks(sinks)
            ws = tmp_path / "ws"

            result = scaffold_target(name="exec_l0", workspace_root=ws, sinks_jsonl=sinks, sink_tag="exec-L0", env={})

            self.assertTrue(result["ok"])
            self.assertEqual(result["sink_refs"], 2)
            target_dir = ws / "targets" / "c" / "exec_l0"
            config_text = (target_dir / ".localfuzz" / "config.yaml").read_text(encoding="utf-8")
            self.assertIn("- name: exec_l0", config_text)
            harness_text = (target_dir / "harness.cpp").read_text(encoding="utf-8")
            self.assertIn("TODO(human)", harness_text)
            self.assertIn("a.cpp:10", harness_text)
            self.assertIn("FUZZ_MAIN", harness_text)
            build = json.loads((target_dir / ".localfuzz" / "build.json").read_text(encoding="utf-8"))
            self.assertEqual([step["name"] for step in build["steps"]], ["libfuzzer", "symcc"])
            self.assertTrue((ws / "benchmark" / "projects" / "exec_l0" / "project.yaml").is_file())

            with self.assertRaises(FileExistsError):
                scaffold_target(name="exec_l0", workspace_root=ws, env={})

    def test_scaffold_target_rejects_bad_names(self) -> None:
        with self.assertRaises(ValueError):
            scaffold_target(name="Bad Name", workspace_root="/tmp/nowhere", env={})


if __name__ == "__main__":
    unittest.main()

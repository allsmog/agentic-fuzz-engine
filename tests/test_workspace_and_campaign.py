from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from unittest import mock

from agentic_fuzz_engine.scaffold import scaffold_target, select_targets
from agentic_fuzz_engine.workspace import (
    WORKSPACE_CONFIG_NAME,
    _render_env_file,
    load_workspace,
    translate_host_path,
    workspace_init,
)


class WorkspaceTests(unittest.TestCase):
    def test_workspace_init_leaves_klee_image_unset_without_an_immutable_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ws"

            result = workspace_init(root=root, env={})

            self.assertTrue(result["ok"], result["blockers"])
            self.assertEqual(result["docker"]["klee_image"], "")
            config = json.loads((root / WORKSPACE_CONFIG_NAME).read_text(encoding="utf-8"))
            self.assertEqual(config["docker"]["klee_image"], "")
            self.assertIn(
                "export AGENTIC_FUZZ_KLEE_IMAGE=''",
                (root / "env.sh").read_text(encoding="utf-8"),
            )

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

    def test_target_build_declares_safe_env_and_rejects_injection(self) -> None:
        from agentic_fuzz_engine.container_build import build_target
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            workspace_init(root=ws, source_dir=tmp, env={})
            target = ws / "targets" / "c" / "demo"
            target.mkdir(parents=True)
            marker = root / "marker"
            config = {"steps": [{"name": "build", "argv": [sys.executable, "-c", f"import os; open({str(marker)!r}, 'w').write(os.environ['CUSTOM_BUILD_FLAG'])"], "env": {}}]}
            result = build_target(project="localfuzz/c/demo", workspace_root=ws, config_override=config, build_env={"CUSTOM_BUILD_FLAG": "present"})
            self.assertTrue(result["ok"], result)
            self.assertEqual(marker.read_text(encoding="utf-8"), "present")
            with self.assertRaisesRegex(ValueError, "forbidden"):
                build_target(project="localfuzz/c/demo", workspace_root=ws, config_override={"steps": [{"name": "bad", "argv": [sys.executable, "-c", "raise SystemExit(0)"], "env": {"PYTHONPATH": "bad"}}]})

    def test_target_build_validates_declared_environment_before_skipped_steps(self) -> None:
        from agentic_fuzz_engine.container_build import build_target
        from agentic_fuzz_engine.workspace import workspace_init

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            workspace_init(root=ws, source_dir=tmp, env={})
            (ws / "targets" / "c" / "demo").mkdir(parents=True)
            config = {"steps": [{"name": "skipped", "argv": ["/bin/true"], "env": {"CUSTOM_BUILD_FLAG": "safe"}}]}
            with self.assertRaisesRegex(ValueError, "forbidden"):
                build_target(
                    project="localfuzz/c/demo",
                    workspace_root=ws,
                    config_override=config,
                    only_steps=["another-step"],
                    build_env={"PATH": "/not-an-ambient-path"},
                )
            with self.assertRaisesRegex(ValueError, "forbidden"):
                build_target(
                    project="localfuzz/c/demo",
                    workspace_root=ws,
                    config_override={"steps": [{"name": "skipped", "argv": ["/bin/true"], "env": {"DOCKER_AUTH_CONFIG": "blocked"}}]},
                    only_steps=["another-step"],
                )


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
            seed = next((output_dir / "seeds").glob("smoke-h1-demo-test000001-cmd-*.bin"))
            self.assertEqual(seed.read_bytes(), b"ABC")
            self.assertTrue(list((output_dir / "errors").glob("smoke-h1-demo-test000001-*.json")))

    def test_extract_klee_rejects_malformed_symlink_and_destination_symlink(self) -> None:
        from agentic_fuzz_engine.runtime_backends import _extract_klee_tests

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_root = root / "klee-ng-out"
            test_dir = out_root / "smoke" / "h1-demo"
            test_dir.mkdir(parents=True)
            payload = {"inputs": [{"name": "../../victim", "size": 2, "data": [1, 2]}]}
            test = test_dir / "test000001.json"
            test.write_text(json.dumps(payload), encoding="utf-8")
            (test_dir / "test000002.json").write_text(json.dumps({"inputs": "not-a-list"}), encoding="utf-8")
            linked = test_dir / "test000003.json"
            linked.symlink_to(test)
            output = root / "outputs"
            victim = root / "victim"
            victim.write_bytes(b"keep")
            source_tag = sha256(b"smoke/h1-demo/test000001.json").hexdigest()[:12]
            blob_tag = sha256(bytes([1, 2])).hexdigest()[:12]
            destination = output / "seeds" / f"smoke-h1-demo-test000001-_.._victim-0-{source_tag}-{blob_tag}.bin"
            destination.parent.mkdir(parents=True)
            destination.symlink_to(victim)

            result = _extract_klee_tests(out_root, output)

            self.assertEqual(result["seeds_written"], 0)
            self.assertGreaterEqual(result["rejected_tests"], 2)
            self.assertGreaterEqual(result["rejected_inputs"], 1)
            self.assertEqual(victim.read_bytes(), b"keep")

    def test_extract_klee_rejects_size_mismatch_and_non_bytes(self) -> None:
        from agentic_fuzz_engine.runtime_backends import _extract_klee_tests

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test_dir = root / "klee-ng-out" / "suite" / "case"
            test_dir.mkdir(parents=True)
            (test_dir / "test000001.json").write_text(
                json.dumps({"inputs": [{"name": "x", "size": 99, "data": [1, 2]}, {"name": "y", "size": 1, "data": [True]}, {"name": "z", "size": True, "data": [1]}]}),
                encoding="utf-8",
            )
            result = _extract_klee_tests(root / "klee-ng-out", root / "outputs")
            self.assertEqual(result["seeds_written"], 0)
            self.assertEqual(result["rejected_inputs"], 3)

    def test_extract_klee_rejects_missing_and_invalid_top_level_inputs(self) -> None:
        from agentic_fuzz_engine.runtime_backends import _extract_klee_tests

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test_dir = root / "klee-ng-out" / "suite" / "case"
            test_dir.mkdir(parents=True)
            for index, payload in enumerate(({}, [], None, "not-an-object", {"inputs": {}}), start=1):
                (test_dir / f"test{index:06d}.json").write_text(json.dumps(payload), encoding="utf-8")
            result = _extract_klee_tests(root / "klee-ng-out", root / "outputs")
            self.assertEqual(result["seeds_written"], 0)
            self.assertEqual(result["rejected_tests"], 5)

    def test_extract_klee_never_reads_past_aggregate_raw_json_budget(self) -> None:
        from agentic_fuzz_engine import runtime_backends

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test_dir = root / "klee-ng-out" / "suite" / "case"
            test_dir.mkdir(parents=True)
            payload = b'{"inputs":[]}'
            for index in range(3):
                (test_dir / f"test{index:06d}.json").write_bytes(payload)
            original_read = os.read
            bytes_read = 0

            def counted_read(descriptor, amount):
                nonlocal bytes_read
                chunk = original_read(descriptor, amount)
                bytes_read += len(chunk)
                return chunk

            with mock.patch.object(runtime_backends, "MAX_KLEE_TEST_JSON_BYTES", len(payload)), mock.patch.object(runtime_backends, "MAX_KLEE_TOTAL_TEST_JSON_BYTES", len(payload)), mock.patch.object(runtime_backends.os, "read", side_effect=counted_read):
                result = runtime_backends._extract_klee_tests(root / "klee-ng-out", root / "outputs")
            self.assertEqual(result["test_json_bytes"], len(payload))
            self.assertEqual(bytes_read, len(payload))

    def test_extract_klee_growth_rejection_consumes_shared_physical_read_budget(self) -> None:
        from agentic_fuzz_engine import runtime_backends

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test_dir = root / "klee-ng-out" / "suite" / "case"
            test_dir.mkdir(parents=True)
            payload = b'{"inputs":[]}'
            self.assertEqual(len(payload), 13)
            growing = test_dir / "test000001.json"
            growing.write_bytes(payload)
            # A stable candidate must not be read after the growth race has
            # consumed the aggregate physical-read allowance.
            (test_dir / "test000002.json").write_bytes(payload)
            original_read = os.read
            bytes_read = 0
            appended = False

            def grow_before_first_read(descriptor, amount):
                nonlocal bytes_read, appended
                if not appended:
                    appended = True
                    growing.write_bytes(payload + b"!")
                chunk = original_read(descriptor, amount)
                bytes_read += len(chunk)
                return chunk

            with mock.patch.object(runtime_backends, "MAX_KLEE_TEST_JSON_BYTES", len(payload)), mock.patch.object(runtime_backends, "MAX_KLEE_TOTAL_TEST_JSON_BYTES", len(payload)), mock.patch.object(runtime_backends.os, "read", side_effect=grow_before_first_read):
                result = runtime_backends._extract_klee_tests(root / "klee-ng-out", root / "outputs")
            self.assertEqual(result["scanned"], 1)
            self.assertEqual(result["test_json_bytes"], 0)
            self.assertEqual(result["test_json_bytes_read"], len(payload))
            self.assertLessEqual(bytes_read, len(payload))
            self.assertEqual(result["seeds_written"], 0)

    def test_klee_reader_rejects_growth_after_open(self) -> None:
        from agentic_fuzz_engine import runtime_backends

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.json"
            path.write_bytes(b"{}")
            original_read = os.read
            grown = False

            def grow_after_open(descriptor, amount):
                nonlocal grown
                chunk = original_read(descriptor, amount)
                if not grown:
                    grown = True
                    path.write_bytes(b"x" * 8)
                return chunk

            with mock.patch.object(runtime_backends.os, "read", side_effect=grow_after_open):
                self.assertIsNone(runtime_backends._read_nofollow_bounded(path, 16))

    def test_klee_reader_growth_never_reads_past_aggregate_limit(self) -> None:
        from agentic_fuzz_engine import runtime_backends

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.json"
            original = b'{"inputs":[]}'
            self.assertEqual(len(original), 13)
            path.write_bytes(original)
            original_read = os.read
            returned = 0
            appended = False

            def append_before_first_read(descriptor, amount):
                nonlocal returned, appended
                if not appended:
                    appended = True
                    path.write_bytes(original + b"!")
                chunk = original_read(descriptor, amount)
                returned += len(chunk)
                return chunk

            with mock.patch.object(runtime_backends.os, "read", side_effect=append_before_first_read):
                self.assertIsNone(runtime_backends._read_nofollow_bounded(path, len(original)))
            self.assertLessEqual(returned, len(original))

    def test_klee_reader_rejects_in_cap_path_swap(self) -> None:
        from agentic_fuzz_engine import runtime_backends

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test_dir = root / "out" / "suite" / "case"
            test_dir.mkdir(parents=True)
            path = test_dir / "test000001.json"
            path.write_bytes(b"{}")
            replacement = root / "replacement"
            replacement.write_bytes(b"[]")
            original_read = os.read
            swapped = False

            def swap_after_read(descriptor, amount):
                nonlocal swapped
                chunk = original_read(descriptor, amount)
                if not swapped:
                    swapped = True
                    replacement.replace(path)
                return chunk

            root_fd = runtime_backends._open_nofollow_directory(root / "out")
            self.assertIsNotNone(root_fd)
            try:
                with mock.patch.object(runtime_backends.os, "read", side_effect=swap_after_read):
                    self.assertIsNone(runtime_backends._read_nofollow_bounded_at(root_fd, ("suite", "case", "test000001.json"), 16))
            finally:
                os.close(root_fd)

    def test_klee_reader_rejects_symlinked_source_component(self) -> None:
        from agentic_fuzz_engine import runtime_backends

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            external = root / "external" / "case"
            external.mkdir(parents=True)
            (external / "test000001.json").write_text('{"inputs": []}', encoding="utf-8")
            out.mkdir()
            (out / "linked").symlink_to(external.parent, target_is_directory=True)
            root_fd = runtime_backends._open_nofollow_directory(out)
            self.assertIsNotNone(root_fd)
            try:
                self.assertIsNone(runtime_backends._read_nofollow_bounded_at(root_fd, ("linked", "case", "test000001.json"), 1024))
            finally:
                os.close(root_fd)

    def test_klee_output_fd_survives_destination_directory_swap(self) -> None:
        from agentic_fuzz_engine import runtime_backends

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "output"
            seeds = output / "seeds"
            seeds.mkdir(parents=True)
            victim = root / "victim"
            victim.mkdir()
            descriptor = runtime_backends._open_nofollow_directory(seeds)
            self.assertIsNotNone(descriptor)
            moved = output / "seeds-held"
            seeds.rename(moved)
            seeds.symlink_to(victim, target_is_directory=True)
            try:
                self.assertTrue(runtime_backends._write_nofollow_at(descriptor, "seed.bin", b"safe"))
            finally:
                os.close(descriptor)
            self.assertEqual((moved / "seed.bin").read_bytes(), b"safe")
            self.assertFalse((victim / "seed.bin").exists())

    def test_klee_run_failure_includes_clipped_stderr_context(self) -> None:
        from agentic_fuzz_engine import runtime_backends
        from agentic_fuzz_engine.process_safety import BoundedRun

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            klee_dir = root / "klee"
            klee_dir.mkdir()
            config = klee_dir / "demo.ci.json"
            config.write_text("{}", encoding="utf-8")
            image = "example.invalid/klee@sha256:" + "a" * 64
            failed_run = {
                "command": ["docker", "run"], "exit_code": 127,
                "timed_out": False, "elapsed_ms": 1, "stdout": "",
                "stderr": "cannot connect: no daemon",
            }
            with mock.patch.object(runtime_backends, "load_workspace", return_value={"root": str(root), "docker": {}}), mock.patch.object(runtime_backends, "check_disk_headroom", return_value={"ok": True}), mock.patch.object(runtime_backends, "_run_command", return_value=failed_run), mock.patch.object(runtime_backends, "bounded_run", return_value=BoundedRun(0, False, 1, "", "")), mock.patch.object(runtime_backends, "_extract_klee_tests", return_value={}):
                result = runtime_backends._run_klee_ng(
                    klee_config="demo.ci.json",
                    command=None,
                    output_dir=root / "out",
                    timeout_seconds=10,
                    status={"klee_ng": {"ok": True, "path": image}},
                    env={"PATH": "/bin"},
                    workspace_root=root,
                )
            self.assertFalse(result["ok"])
            self.assertIn("no daemon", result["blockers"][0])

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

    def test_klee_extraction_rejects_out_of_range_bytes_and_caps_output(self) -> None:
        from agentic_fuzz_engine import runtime_backends

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            target_out = tmp_path / "klee-ng-out" / "tier" / "target"
            target_out.mkdir(parents=True)
            (target_out / "test000001.json").write_text(json.dumps({"error": {"type": "x"}, "inputs": [{"name": "bad", "size": 3, "data": [0, 256, -1]}, {"name": "first", "size": 2, "data": [1, 2]}, {"name": "aggregate", "size": 2, "data": [3, 4]}, {"name": "large", "size": 3, "data": [1, 2, 3]}]}), encoding="utf-8")
            with mock.patch.object(runtime_backends, "MAX_KLEE_SEED_BYTES", 2), mock.patch.object(runtime_backends, "MAX_KLEE_TOTAL_SEED_BYTES", 2), mock.patch.object(runtime_backends, "MAX_KLEE_ERROR_REPORT_BYTES", 32):
                result = runtime_backends._extract_klee_tests(tmp_path / "klee-ng-out", tmp_path / "out")
            self.assertEqual(result["seeds_written"], 1)
            self.assertEqual(result["errors_written"], 0)
            self.assertEqual(result["rejected_inputs"], 3)

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

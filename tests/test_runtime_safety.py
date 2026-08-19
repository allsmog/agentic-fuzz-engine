"""Regression tests for the bounded process envelope and authored-script gate."""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

from agentic_fuzz_engine.process_safety import BoundedRun, bounded_run, sanitized_env, tool_env, validate_command_shape
from agentic_fuzz_engine.codec import _copy_bounded_codec_inputs, _validate_codec_report, run_codec
from agentic_fuzz_engine.oss_fuzz_build import _run_docker_once
from agentic_fuzz_engine.oss_fuzz_build import _run_command as run_container_build
from agentic_fuzz_engine.patching import _run_command as run_patch_build
from agentic_fuzz_engine.runtime_backends import prepare_patch_environment
from agentic_fuzz_engine.seedgen import run_seedgen


class ProcessSafetyTests(unittest.TestCase):
    def test_output_flood_is_drained_and_clipped(self) -> None:
        run = bounded_run([sys.executable, "-c", "import sys; sys.stdout.write('x'*1000000)"], timeout_seconds=5, max_output_chars=128)
        self.assertEqual(run.exit_code, 0)
        self.assertLessEqual(len(run.stdout), 140)
        self.assertIn("[truncated]", run.stdout)

    def test_timeout_reaps_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = Path(tmp) / "child.pid"
            child = "import time; time.sleep(30)"
            parent = f"import subprocess,sys,time; p=subprocess.Popen([sys.executable, '-c', {child!r}]); open({str(pid_file)!r}, 'w').write(str(p.pid)); time.sleep(30)"
            run = bounded_run([sys.executable, "-c", parent], timeout_seconds=0.2)
            self.assertTrue(run.timed_out)
            pid = int(pid_file.read_text())
            time.sleep(0.1)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_successful_parent_cannot_leave_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = Path(tmp) / "child.pid"
            child = "import time; time.sleep(30)"
            parent = f"import subprocess,sys; p=subprocess.Popen([sys.executable, '-c', {child!r}]); open({str(pid_file)!r}, 'w').write(str(p.pid))"
            run = bounded_run([sys.executable, "-c", parent], timeout_seconds=5)
            self.assertEqual(run.exit_code, 0)
            pid = int(pid_file.read_text())
            time.sleep(0.1)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_command_shape_rejects_shell_and_wrapper_primaries(self) -> None:
        for argv in (["sh", "-c", "true"], ["env", "X=1", "tool"]):
            with self.assertRaises(ValueError):
                validate_command_shape(argv, context="test")

    def test_authored_seedgen_gets_no_secret_or_python_injection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "gen.py"
            script.write_text(
                "import os\ndef generate(rnd): return (os.getenv('TOP_SECRET','no') + os.getenv('PYTHONPATH','no')).encode()\n",
                encoding="utf-8",
            )
            result = run_seedgen(
                target="demo", script_path=str(script), count=1, workspace_root=root / "ws",
                env={"AGENTIC_FUZZ_ALLOW_AUTHORED_SCRIPTS": "1", "TOP_SECRET": "leaked", "PYTHONPATH": "injected"},
            )
            self.assertTrue(result["ok"], result)
            blobs = list(Path(result["seeds_dir"]).iterdir())
            self.assertEqual(blobs[0].read_bytes(), b"nono")

    def test_forged_success_before_codec_load_exit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seeds = root / "ws" / "work" / "demo" / "seeds"
            seeds.mkdir(parents=True)
            (seeds / "one").write_bytes(b"x")
            script = root / "codec.py"
            script.write_text(f"import atexit\nfrom pathlib import Path\ndef forge():\n  [p.write_text('{{\\\"samples\\\":1}}') for p in Path({str(root / 'ws')!r}).rglob('.codec-report-*')]\n  print('{{\\\"samples\\\":1,\\\"parsed\\\":1,\\\"encode_present\\\":false}}')\natexit.register(forge)\nraise SystemExit(0)\n", encoding="utf-8")
            result = run_codec(target="demo", mode="validate", script_path=script, workspace_root=root / "ws", env={"AGENTIC_FUZZ_ALLOW_AUTHORED_SCRIPTS": "1"})
            self.assertFalse(result["ok"])
            self.assertTrue(any("script load failed" in blocker for blocker in result["blockers"]))

    def test_codec_fd_forged_exit_report_is_schema_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seeds = root / "ws" / "work" / "demo" / "seeds"
            seeds.mkdir(parents=True)
            (seeds / "one").write_bytes(b"x")
            script = root / "codec.py"
            forged = b'{"samples":-1,"parsed":0,"failed":0,"encode_present":false,"roundtrip_ok":0,"roundtrip_failed":0,"probe_written":false,"errors":[]}'
            script.write_text("import os\nfor fd in range(3, 256):\n  try: os.write(fd, " + repr(forged) + ")\n  except OSError: pass\nos._exit(0)\n", encoding="utf-8")
            result = run_codec(target="demo", mode="validate", script_path=script, workspace_root=root / "ws", env={"AGENTIC_FUZZ_ALLOW_AUTHORED_SCRIPTS": "1"})
            self.assertFalse(result["ok"])
            self.assertTrue(any("counter" in blocker or "authoritative" in blocker for blocker in result["blockers"]))

    def test_codec_rejects_decode_symlink_and_staging_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / "victim"
            victim.mkdir()
            linked = root / "linked.bin"
            linked.symlink_to(victim, target_is_directory=True)
            script = root / "codec.py"
            script.write_text("def decode(data): return {}", encoding="utf-8")
            result = run_codec(target="demo", mode="decode", script_path=script, paths=[str(linked)], workspace_root=root / "ws", env={"AGENTIC_FUZZ_ALLOW_AUTHORED_SCRIPTS": "1"})
            self.assertFalse(result["ok"])
            staging = root / "ws" / "work" / "demo" / "codec-staging"
            staging.parent.mkdir(parents=True, exist_ok=True)
            staging.symlink_to(victim, target_is_directory=True)
            (root / "ws" / "work" / "demo" / "seeds").mkdir()
            (root / "ws" / "work" / "demo" / "seeds" / "x").write_bytes(b"x")
            result = run_codec(target="demo", mode="validate", script_path=script, workspace_root=root / "ws", env={"AGENTIC_FUZZ_ALLOW_AUTHORED_SCRIPTS": "1"})
            self.assertFalse(result["ok"])
            self.assertTrue(victim.is_dir())

    def test_codec_status_symlink_does_not_overwrite_victim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "ws" / "work" / "demo"
            seeds = work / "seeds"
            seeds.mkdir(parents=True)
            (seeds / "seed").write_bytes(b"x")
            victim = root / "victim"
            victim.write_text("keep", encoding="utf-8")
            (work / "codec-status.json").symlink_to(victim)
            script = root / "codec.py"
            script.write_text("def decode(data): return {}", encoding="utf-8")
            result = run_codec(target="demo", mode="validate", script_path=script, workspace_root=root / "ws", env={"AGENTIC_FUZZ_ALLOW_AUTHORED_SCRIPTS": "1"})
            self.assertFalse(result["ok"])
            self.assertTrue(any("status destination" in blocker for blocker in result["blockers"]))
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep")

    def test_codec_copy_growth_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.write_bytes(b"x")
            staging = root / "staging"
            staging.mkdir()
            original_read = os.read
            grown = False

            def growing_read(descriptor, amount):
                nonlocal grown
                chunk = original_read(descriptor, amount)
                if not grown:
                    grown = True
                    source.write_bytes(b"grown")
                return chunk

            with mock.patch("agentic_fuzz_engine.codec.os.read", side_effect=growing_read):
                blockers = _copy_bounded_codec_inputs([source], staging)
            self.assertTrue(any("changed" in blocker for blocker in blockers))

    def test_codec_copy_holds_source_fd_across_path_swap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            secret = root / "secret"
            source.write_bytes(b"original")
            secret.write_bytes(b"external-secret")
            staging = root / "staging"
            staging.mkdir()
            original_read = os.read
            swapped = False

            def swap_after_open(descriptor, amount):
                nonlocal swapped
                chunk = original_read(descriptor, amount)
                if not swapped:
                    swapped = True
                    source.unlink()
                    source.symlink_to(secret)
                return chunk

            with mock.patch("agentic_fuzz_engine.codec.os.read", side_effect=swap_after_open):
                blockers = _copy_bounded_codec_inputs([source], staging)
            self.assertEqual(blockers, [])
            self.assertEqual((staging / "source").read_bytes(), b"original")

    def test_forged_success_before_seedgen_load_exit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "gen.py"
            script.write_text("print('{\"written\":1,\"errors\":0}')\nraise SystemExit(0)\n", encoding="utf-8")
            result = run_seedgen(target="demo", script_path=str(script), workspace_root=root / "ws", env={"AGENTIC_FUZZ_ALLOW_AUTHORED_SCRIPTS": "1"})
            self.assertFalse(result["ok"])
            self.assertTrue(any("script load failed" in blocker for blocker in result["blockers"]))

    def test_seedgen_parent_rejects_forged_oversize_staging_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "gen.py"
            script.write_text("def generate(rnd): return b'x'", encoding="utf-8")

            def forged(argv, **_kwargs):
                staging = Path(argv[4])
                (staging / "seedgen-deadbeefdeadbeef").write_bytes(b"x" * 4097)
                return BoundedRun(0, False, 1, '{"written": 1}', "")

            with mock.patch("agentic_fuzz_engine.seedgen.bounded_run", side_effect=forged):
                result = run_seedgen(target="demo", script_path=str(script), max_blob_bytes=1024, workspace_root=root / "ws", env={"AGENTIC_FUZZ_ALLOW_AUTHORED_SCRIPTS": "1"})
            self.assertFalse(result["ok"])
            self.assertTrue(any("blob-size cap" in blocker for blocker in result["blockers"]))

    def test_docker_success_exit_does_not_match_crash_text(self) -> None:
        results = [
            BoundedRun(0, False, 1, "", "ERROR: AddressSanitizer: heap-buffer-overflow"),
            BoundedRun(0, False, 1, "", ""),
        ]
        with mock.patch("agentic_fuzz_engine.oss_fuzz_build.bounded_run", side_effect=results):
            run = _run_docker_once(["docker", "run", "example"], container_name="test-container", env={"PATH": "/bin"}, timeout_seconds=1, expected_error_token="AddressSanitizer: heap-buffer-overflow")
        self.assertFalse(run["matched_expected"])
        self.assertFalse(run["crashed"])

    def test_sanitized_env_drops_credentials_and_loader_knobs(self) -> None:
        result = sanitized_env({"PATH": "/bin", "OPENAI_API_KEY": "secret", "LD_PRELOAD": "bad", "PYTHONINSPECT": "1"})
        self.assertEqual(result, {"PATH": "/bin"})
        with self.assertRaises(ValueError):
            sanitized_env({"PATH": "/bin"}, extra={"LD_PRELOAD": "injected"})

    def test_tool_env_separates_ambient_and_declared_values(self) -> None:
        result = tool_env(
            {"PATH": "/bin", "GITHUB_PAT": "secret", "DATABASE_URL": "secret", "SSH_AUTH_SOCK": "/tmp/agent", "DOCKER_HOST": "unix:///tmp/docker"},
            declared={"FUZZ_FLAG_PROFILE": "fast"},
        )
        self.assertEqual(result["FUZZ_FLAG_PROFILE"], "fast")
        self.assertEqual(result["DOCKER_HOST"], "unix:///tmp/docker")
        self.assertNotIn("GITHUB_PAT", result)
        self.assertNotIn("DATABASE_URL", result)
        self.assertNotIn("SSH_AUTH_SOCK", result)
        with self.assertRaises(ValueError):
            tool_env({"PATH": "/bin"}, declared={"PYTHONPATH": "injected"})

    def test_declared_environment_rejects_authentication_and_path_overrides(self) -> None:
        # PATH is valid as an ambient tool lookup setting, but no explicit
        # build/tool declaration can replace it or inject credential controls.
        self.assertEqual(tool_env({"PATH": "/bin"})["PATH"], "/bin")
        for name in (
            "PATH", "MYSQL_PWD", "DOCKER_AUTH_CONFIG", "GIT_ASKPASS",
            "AUTH", "CI_AUTHORIZATION", "REQUEST_TOKEN", "SERVICE_APIKEY",
            "AUTHORIZATION_HEADER", "CI_AUTHORIZATION_HEADER", "TOKEN_FILE",
            "REQUEST_TOKEN_FILE", "APIKEY_FILE", "SERVICE_APIKEY_FILE",
            "SESSION_COOKIE", "REQUEST_JWT", "SIGNING_PRIVATE_KEY",
            "SSH_ASKPASS", "SUDO_ASKPASS", "BASH_ENV", "ENV", "PERL5OPT",
            "RUBYOPT", "NODE_OPTIONS", "JAVA_TOOL_OPTIONS", "GLIBC_TUNABLES",
            "NODE_PATH", "RUBYLIB", "PERL5LIB", "CLASSPATH", "SSLKEYLOGFILE",
            "NETRC", "SECRET", "TEAM_SECRET", "SECRET_FILE", "TEAM_SECRET_FILE",
            "PASSWORD", "TEAM_PASSWORD", "PASSWORD_FILE", "PASSWD", "TEAM_PASSWD_FILE",
            "CREDENTIAL", "CREDENTIALS", "TEAM_CREDENTIAL_FILE", "DATABASE_URL",
            "TEAM_DATABASE_URL", "DATABASE_URL_FILE",
        ):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "forbidden"):
                tool_env({"PATH": "/bin"}, declared={name: "blocked"})
        for name in (
            "USE_PRIVATE_HEADERS", "HTTP_AUTH_MODE", "CUSTOM_BUILD_FLAG",
            "SECRETARY_MODE", "PASSWORD_POLICY", "CREDENTIAL_PROVIDER",
            "DATABASE_URL_REQUIRED",
        ):
            with self.subTest(name=name):
                self.assertEqual(tool_env({"PATH": "/bin"}, declared={name: "allowed"})[name], "allowed")

    def test_docker_run_and_cleanup_share_daemon_selection(self) -> None:
        environments: list[dict[str, str]] = []

        def fake(_argv, **kwargs):
            environments.append(dict(kwargs["env"]))
            return BoundedRun(0, False, 1, "", "")

        with mock.patch("agentic_fuzz_engine.oss_fuzz_build.bounded_run", side_effect=fake):
            _run_docker_once(["docker", "run", "example"], container_name="unit", env={"PATH": "/bin", "DOCKER_CONTEXT": "unit-context"}, timeout_seconds=1, expected_error_token="boom")
        self.assertEqual(len(environments), 2)
        self.assertTrue(all(item.get("DOCKER_CONTEXT") == "unit-context" for item in environments))

    def test_docker_success_cleanup_and_cleanup_failure_are_distinguished(self) -> None:
        with mock.patch(
            "agentic_fuzz_engine.oss_fuzz_build.bounded_run",
            side_effect=[BoundedRun(0, False, 1, "", ""), BoundedRun(0, False, 1, "", "")],
        ):
            success = _run_docker_once(["docker", "run", "example"], container_name="unit", env={"PATH": "/bin"}, timeout_seconds=1, expected_error_token="boom")
        self.assertEqual(success["blockers"], [])
        with mock.patch(
            "agentic_fuzz_engine.oss_fuzz_build.bounded_run",
            side_effect=[BoundedRun(127, False, 1, "", "no docker daemon"), BoundedRun(1, False, 1, "", "No such container")],
        ):
            failed = _run_docker_once(["docker", "run", "example"], container_name="unit", env={"PATH": "/bin"}, timeout_seconds=1, expected_error_token="boom")
        self.assertTrue(any("launch failed" in blocker for blocker in failed["blockers"]))
        self.assertTrue(any("cleanup failed" in blocker for blocker in failed["blockers"]))
        self.assertIn("No such container", failed["cleanup"]["stderr"])

    def test_z3_rejects_oversized_encoded_input_before_launch(self) -> None:
        from agentic_fuzz_engine.runtime_backends import MAX_Z3_ENCODED_BYTES, _run_z3_solver

        with mock.patch("agentic_fuzz_engine.runtime_backends.bounded_run") as launch:
            result = _run_z3_solver(constraints_smt2_b64="A" * (MAX_Z3_ENCODED_BYTES + 1), status={"z3": {"ok": True}})
        self.assertFalse(result["ok"])
        self.assertIn("encoded SMT-LIB", result["blockers"][0])
        launch.assert_not_called()

    def test_custom_build_flags_propagate_without_secrets_or_injection(self) -> None:
        source_env = {"FUZZ_FLAG_PROFILE": "fast", "CUSTOM_BUILD_FLAG": "yes"}
        captured: list[dict[str, str]] = []

        def fake(_argv, **kwargs):
            captured.append(dict(kwargs["env"]))
            return BoundedRun(0, False, 1, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("agentic_fuzz_engine.oss_fuzz_build.bounded_run", side_effect=fake):
                run_container_build(["tool"], cwd=Path(tmp), env={"PATH": "/bin", "GITHUB_PAT": "ambient"}, timeout_seconds=1, declared_env=source_env)
            with mock.patch.dict(os.environ, {"PATH": "/bin", "GITHUB_PAT": "ambient"}, clear=True):
                with mock.patch("agentic_fuzz_engine.patching.bounded_run", side_effect=fake):
                    run_patch_build(["tool"], cwd=Path(tmp), timeout_seconds=1, declared_env=source_env)
        self.assertEqual(len(captured), 2)
        for environment in captured:
            self.assertEqual(environment["FUZZ_FLAG_PROFILE"], "fast")
            self.assertEqual(environment["CUSTOM_BUILD_FLAG"], "yes")
            self.assertNotIn("OPENAI_API_KEY", environment)
            self.assertNotIn("PYTHONPATH", environment)
            self.assertNotIn("LD_PRELOAD", environment)
            self.assertNotIn("GITHUB_PAT", environment)
        with self.assertRaises(ValueError):
            run_container_build(["tool"], cwd=Path.cwd(), env={"PATH": "/bin"}, timeout_seconds=1, declared_env={"OPENAI_API_KEY": "secret"})

    def test_patch_environment_declares_build_and_test_controls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            marker = root / "marker"
            command = [sys.executable, "-c", f"import os; open({str(marker)!r}, 'a').write(os.environ['CUSTOM_BUILD_FLAG'])"]
            result = prepare_patch_environment(
                source_dir=source,
                pool_root=root / "pool",
                build_command=command,
                test_command=command,
                build_env={"CUSTOM_BUILD_FLAG": "B"},
                test_env={"CUSTOM_BUILD_FLAG": "T"},
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(marker.read_text(encoding="utf-8"), "BT")
            with self.assertRaises(ValueError):
                prepare_patch_environment(source_dir=source, pool_root=root / "pool2", build_command=command, build_env={"LD_PRELOAD": "bad"})

    def test_patch_environment_rejects_declared_injection_before_noop_setup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            with self.assertRaisesRegex(ValueError, "forbidden"):
                prepare_patch_environment(
                    source_dir=source,
                    pool_root=root / "pool",
                    # No patch/build/test command must not bypass validation.
                    declared_env={"GIT_ASKPASS": "askpass"},
                )

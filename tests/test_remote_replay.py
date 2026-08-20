from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "remote-amd64-oss-fuzz-replay.sh"


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _fixture_root(tmp_path: Path) -> Path:
    root = tmp_path / "reference"
    (root / "benchmark" / "projects" / "mongoose").mkdir(parents=True)
    (root / "fixtures" / "reference" / "oss-fuzz").mkdir(parents=True)
    return root


def _environment(tmp_path: Path) -> tuple[dict[str, str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    call_log = tmp_path / "calls.log"
    remote_base = tmp_path / "remote-base"
    remote_base.mkdir()
    remote_user = subprocess.check_output(["id", "-un"], text=True).strip()
    _write_executable(
        bin_dir / "ssh",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf '%s\\n' \"$0 $*\" >> \"$CALL_LOG\"\n"
        "if [[ \"$#\" -eq 7 && \"$2\" == bash && \"$3\" == -s && \"$4\" == -- ]]; then\n"
        "  shift 4\n"
        "  bash -s -- \"$@\"\n"
        "fi\n",
    )
    _write_executable(
        bin_dir / "rsync",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf '%s\\n' \"$0 $*\" >> \"$CALL_LOG\"\n"
        "target=\"${!#}\"\n"
        "if [[ \"$target\" == *:* ]]; then\n"
        "  remote_path=\"${target#*:}\"\n"
        "  test -d \"$(dirname \"${remote_path%/}\")\"\n"
        "fi\n",
    )
    _write_executable(bin_dir / "docker", "#!/usr/bin/env bash\nexit 0\n")
    _write_executable(bin_dir / "uname", "#!/usr/bin/env bash\necho x86_64\n")
    environment = dict(os.environ)
    environment.update(
        {
            "PATH": f"{bin_dir}:{environment['PATH']}",
            "CALL_LOG": str(call_log),
            "REMOTE_HOST": "runner.example",
            "REMOTE_USER": remote_user,
            "REMOTE_DIR": str(remote_base),
            "REFERENCE_ROOT": str(_fixture_root(tmp_path)),
        }
    )
    return environment, call_log


def _run(tmp_path: Path, *args: str, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env, _ = _environment(tmp_path) if environment is None else (environment, tmp_path / "calls.log")
    return subprocess.run(
        [str(SCRIPT), *args],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_rejects_hostile_input_before_connecting(tmp_path: Path) -> None:
    environment, call_log = _environment(tmp_path)
    environment["REMOTE_HOST"] = "operator@runner.example"

    result = _run(tmp_path, environment=environment)

    assert result.returncode == 2
    assert "REMOTE_HOST" in result.stderr
    assert not call_log.exists()


def test_requires_non_root_user_before_connecting(tmp_path: Path) -> None:
    environment, call_log = _environment(tmp_path)
    environment["REMOTE_USER"] = "root"

    result = _run(tmp_path, environment=environment)

    assert result.returncode == 2
    assert "must not be root" in result.stderr
    assert not call_log.exists()


def test_rejects_free_form_ssh_options_before_connecting(tmp_path: Path) -> None:
    environment, call_log = _environment(tmp_path)
    environment["SSH_OPTS"] = "-o ProxyCommand=unexpected"

    result = _run(tmp_path, environment=environment)

    assert result.returncode == 2
    assert "not supported" in result.stderr
    assert not call_log.exists()


@pytest.mark.parametrize(
    "remote_dir",
    [
        "/srv/agentic fuzz",
        '/srv/"agentic"',
        "/srv/agentic;next",
        "/srv/agentic\nnext",
        "/srv/$(agentic)",
        "/srv/`agentic`",
        "/srv//agentic",
        "/srv/./agentic",
        "/srv/../agentic",
        "/",
    ],
)
def test_rejects_malicious_remote_directory_before_connecting(tmp_path: Path, remote_dir: str) -> None:
    environment, call_log = _environment(tmp_path)
    environment["REMOTE_DIR"] = remote_dir

    result = _run(tmp_path, environment=environment)

    assert result.returncode == 2
    assert "REMOTE_DIR" in result.stderr
    assert not call_log.exists()


def test_uses_explicit_destination_and_fresh_run_directory(tmp_path: Path) -> None:
    environment, call_log = _environment(tmp_path)
    remote_base = environment["REMOTE_DIR"]
    remote_user = environment["REMOTE_USER"]

    result = _run(tmp_path, "localfuzz/c/mongoose", "review-run-17", environment=environment)

    assert result.returncode == 0, result.stderr
    calls = call_log.read_text(encoding="utf-8")
    assert f"{remote_user}@runner.example bash -s -- {remote_base} review-run-17 {remote_user}" in calls
    assert f"{remote_base}/review-run-17/repo/" in calls
    assert (Path(remote_base) / "review-run-17" / "reference" / "benchmark" / "projects").is_dir()
    assert (Path(remote_base) / "review-run-17" / "reference" / "fixtures" / "reference").is_dir()
    assert "--delete" not in calls

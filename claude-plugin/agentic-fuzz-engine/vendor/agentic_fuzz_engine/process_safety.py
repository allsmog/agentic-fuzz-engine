"""Small, defensive process envelope for untrusted or long-running commands.

The command-shape checks here are a guardrail against accidental shell/wrapper
launches.  They are *not* a security boundary: callers still need an isolated
runtime when executing untrusted native code.
"""
from __future__ import annotations

import os
import signal
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Mapping, Sequence

MAX_CAPTURE_CHARS = 12_000
AUTHORED_SCRIPTS_OPT_IN = "AGENTIC_FUZZ_ALLOW_AUTHORED_SCRIPTS"
_SHELLS = frozenset({"sh", "bash", "zsh", "fish", "dash", "csh", "tcsh", "ksh"})
_WRAPPERS = frozenset({"env", "sudo", "su", "command", "xargs", "nice", "nohup", "setsid", "timeout"})
_SAFE_ENV_NAMES = frozenset({"PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "LC_CTYPE", "TZ"})
_SENSITIVE_ENV_SUFFIXES = ("_KEY", "_TOKEN", "_PWD", "_PASS", "_COOKIE", "_JWT")
_CREDENTIAL_EXACT_OR_SUFFIXES = ("AUTHORIZATION", "AUTH", "TOKEN", "APIKEY")
_SECRET_BEARING_EXACT_OR_SUFFIXES = ("SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "CREDENTIALS", "DATABASE_URL")
_RUNTIME_INJECTION_NAMES = frozenset({
    "BASH_ENV", "ENV", "PERL5OPT", "RUBYOPT", "NODE_OPTIONS",
    "JAVA_TOOL_OPTIONS", "GLIBC_TUNABLES", "NODE_PATH", "RUBYLIB",
    "PERL5LIB", "CLASSPATH",
})


@dataclass(frozen=True)
class BoundedRun:
    exit_code: int
    timed_out: bool
    elapsed_ms: int
    stdout: str
    stderr: str


def validate_command_shape(argv: Sequence[str], *, context: str) -> list[str]:
    """Validate direct argv shape; this guardrail deliberately is not a sandbox."""
    if not argv or not all(isinstance(arg, str) and arg for arg in argv):
        raise ValueError(f"{context} command must be a non-empty argv list")
    primary = Path(argv[0]).name.lower()
    if primary in _SHELLS:
        raise ValueError(f"{context} command may not use a shell primary")
    if primary in _WRAPPERS:
        raise ValueError(f"{context} command may not use a wrapper primary")
    return list(argv)


def sanitized_env(environment: Mapping[str, str] | None = None, *, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Pass only operational locale/path settings; credentials and loader/Python knobs never cross."""
    source = os.environ if environment is None else environment
    result = {name: value for name, value in source.items() if name in _SAFE_ENV_NAMES and isinstance(value, str)}
    if extra:
        validate_declared_env(extra)
        result.update({name: value for name, value in extra.items() if isinstance(value, str)})
    return result


def tool_env(ambient: Mapping[str, str] | None = None, *, declared: Mapping[str, str] | None = None, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Use a tight ambient base; only explicitly declared safe tool flags propagate."""
    source = os.environ if ambient is None else ambient
    result = {
        name: value for name, value in source.items()
        if isinstance(value, str) and (name in _SAFE_ENV_NAMES or name in {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_DEFAULT_PLATFORM"})
    }
    if declared:
        validate_declared_env(declared)
        result.update({name: value for name, value in declared.items() if isinstance(value, str)})
    if extra:
        validate_declared_env(extra)
        result.update({name: value for name, value in extra.items() if isinstance(value, str)})
    return result


def validate_declared_env(values: Mapping[str, str] | None) -> dict[str, str]:
    """Reject unsafe explicit controls before a public tool flow does any work.

    Ambient operational settings are intentionally kept separate: ``PATH`` is
    needed to locate tools from the ambient allowlist, but a caller may not
    replace it through a declared tool/build environment.
    """
    if values is None:
        return {}
    invalid = sorted(str(name) for name, value in values.items() if not isinstance(name, str) or not isinstance(value, str))
    if invalid:
        raise ValueError(f"declared environment must contain string keys and values: {', '.join(invalid)}")
    blocked = sorted(name for name in values if _blocked_tool_env_name(name))
    if blocked:
        raise ValueError(f"declared environment contains forbidden keys: {', '.join(blocked)}")
    return dict(values)


def _blocked_tool_env_name(name: str) -> bool:
    upper = name.upper()
    credential_tokens = _CREDENTIAL_EXACT_OR_SUFFIXES + _SECRET_BEARING_EXACT_OR_SUFFIXES
    exact_or_suffix = upper in credential_tokens or upper.endswith(tuple(f"_{token}" for token in credential_tokens))
    file_tokens = tuple(f"{token}_FILE" for token in credential_tokens)
    file_variant = upper in file_tokens or upper.endswith(tuple(f"_{token}" for token in file_tokens))
    return (
        upper == "PATH"
        or upper.startswith(("PYTHON", "LD_", "DYLD_"))
        or upper.endswith(_SENSITIVE_ENV_SUFFIXES)
        or upper in _RUNTIME_INJECTION_NAMES
        or exact_or_suffix
        or file_variant
        or upper == "AUTHORIZATION_HEADER"
        or upper.endswith("_AUTHORIZATION_HEADER")
        or upper.endswith("_PRIVATE_KEY")
        or upper.endswith("_KEY_FILE")
        or upper in {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY", "GROK_API_KEY", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_PAT", "SSH_AUTH_SOCK", "MYSQL_PWD", "DOCKER_AUTH_CONFIG", "GIT_ASKPASS", "SSH_ASKPASS", "SUDO_ASKPASS", "SSLKEYLOGFILE", "NETRC"}
    )


def docker_client_env(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    """Keep Docker daemon/context selection identical for run and cleanup."""
    return tool_env(environment)


def authored_scripts_enabled(environment: Mapping[str, str]) -> bool:
    return environment.get(AUTHORED_SCRIPTS_OPT_IN, "").strip().lower() in {"1", "true", "yes"}


def bounded_run(
    argv: Sequence[str], *, cwd: str | Path | None = None, env: Mapping[str, str] | None = None,
    timeout_seconds: float, max_output_chars: int = MAX_CAPTURE_CHARS, pass_fds: Sequence[int] = (),
) -> BoundedRun:
    """Run an argv while draining bounded output and terminating its group on every exit path."""
    started = monotonic()
    try:
        popen_options: dict[str, object] = {}
        if os.name == "posix" and pass_fds:
            popen_options["pass_fds"] = tuple(pass_fds)
        proc = subprocess.Popen(
            list(argv), cwd=str(cwd) if cwd else None, env=dict(env) if env is not None else None,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", start_new_session=(os.name == "posix"), **popen_options,
        )
    except OSError as exc:
        return BoundedRun(127, False, int((monotonic() - started) * 1000), "", str(exc))

    captured: dict[str, list[str]] = {"stdout": [], "stderr": []}
    def drain(name: str, stream: object) -> None:
        # Iterative reads keep a flood from becoming an in-memory unbounded capture.
        handle = stream  # type: ignore[assignment]
        while True:
            chunk = handle.read(4096)  # type: ignore[union-attr]
            if not chunk:
                break
            used = sum(map(len, captured[name]))
            if used < max_output_chars:
                captured[name].append(chunk[: max_output_chars - used])

    threads = [threading.Thread(target=drain, args=(name, stream), daemon=True) for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr))]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        proc.wait(timeout=max(0.001, timeout_seconds))
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_tree(proc)
    finally:
        if proc.poll() is None:
            _terminate_process_tree(proc)
        # A parent can exit 0 while leaving descendants in its process group.
        # Kill that group before closing pipes so descendants cannot outlive a
        # successful leader.
        _terminate_process_group(proc.pid)
        for thread in threads:
            thread.join(timeout=2)
        for stream in (proc.stdout, proc.stderr):
            if stream:
                stream.close()
    stdout, stderr = (_finish_capture(captured[name], max_output_chars) for name in ("stdout", "stderr"))
    if timed_out:
        stderr = _finish_capture([stderr, "\nTIMEOUT"], max_output_chars)
    return BoundedRun(proc.returncode if not timed_out else 124, timed_out, int((monotonic() - started) * 1000), stdout, stderr)


def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(timeout=1.5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            pass


def _terminate_process_group(pgid: int) -> None:
    if os.name != "posix":
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    # No child handle is available after a successful leader exit; SIGKILL
    # ensures any surviving descendants in the isolated group are stopped.
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _finish_capture(parts: list[str], limit: int) -> str:
    value = "".join(parts)
    return value + "\n[truncated]" if len(value) >= limit else value

"""Bounded execution of authored harness codec scripts.

An input-generator agent authors a Python script exposing
``decode(data: bytes) -> dict`` (required) and optionally
``encode(obj: dict) -> bytes``. The codec makes harness inputs legible:
validate mode proves the script actually understands the live corpus (decode
rate over real entries, encode/decode round-trip, and a qualifying replay of
one re-encoded probe through the fuzzer — the RoboDuck gate that the harness
parses what the encoder emits), and decode mode renders PoV artifacts as
structured dicts for triage, failing open to a hex preview.

The child process is launched as ``python -c <bootstrap> <script> ...`` so the
authored file is loaded via importlib rather than passed as the interpreter's
script argument (endpoint protection on some hosts kills ``python file.py``).
Same envelope as seedgen: one child, wall-clock timeout, address-space cap,
output size caps. The opt-in authorizes trusted code execution with host
access; it is not a sandbox for hostile scripts. The parent-owned result pipe
and strict report checks protect the protocol from ordinary stdout, ``atexit``,
and work-directory report spoofing. They do not contain a script actively
hostile in the same Python process: it can inspect process state and needs a
real supervisor/subordinate isolation boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping

from .workspace import resolve_workspace_root
from .process_safety import AUTHORED_SCRIPTS_OPT_IN, authored_scripts_enabled, bounded_run, sanitized_env

CODEC_STATUS_FILE = "codec-status.json"
MAX_VALIDATE_SAMPLES = 256
MAX_DECODE_PATHS = 8
MAX_SECONDS_CAP = 600.0
MAX_DECODE_BYTES_CAP = 1024 * 1024
HEX_PREVIEW_BYTES = 256
MAX_CODEC_INPUT_BYTES = 8 * 1024 * 1024
MAX_CODEC_INPUT_TOTAL_BYTES = 32 * 1024 * 1024
MAX_CODEC_REPORT_BYTES = 512 * 1024
MAX_CODEC_REPORT_DECODE_BYTES = (MAX_CODEC_REPORT_BYTES - 64 * 1024) // MAX_DECODE_PATHS

_BOOTSTRAP = r"""
import importlib.util, json, os, sys
from pathlib import Path

script, mode, input_dir, probe_out = sys.argv[1], sys.argv[2], Path(sys.argv[3]), sys.argv[4]
max_decode_bytes, memory_bytes, max_probe_bytes, result_fd = int(sys.argv[5]), int(sys.argv[6]), int(sys.argv[7]), int(sys.argv[8])
# The parent-private result FD is removed before authored code is imported and
# stdout is never authoritative. This only hardens the result protocol: opt-in
# still executes trusted host code, not a hostile-code sandbox.
del sys.argv[7:]
def _emit(payload, exit_code=0):
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    # Never let a decoded object or exception message turn the private result
    # channel into an unbounded output stream. The parent independently
    # applies the same cap while it drains the pipe.
    if len(encoded) > 524288:
        payload = {"fatal": "codec bootstrap report exceeds output cap"}
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        exit_code = 3
    os.write(result_fd, encoded)
    os.close(result_fd)
    os._exit(exit_code)
try:
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
except (ImportError, OSError, ValueError):
    pass
try:
    spec = importlib.util.spec_from_file_location("codec_authored", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load script")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
except BaseException as exc:
    _emit({"fatal": f"script load failed: {type(exc).__name__}: {exc}"}, 3)
decode = getattr(module, "decode", None)
if not callable(decode):
    _emit({"fatal": "script does not define decode(data: bytes) -> dict"}, 3)
encode = getattr(module, "encode", None)
encode_present = callable(encode)

def _canon(obj):
    return json.dumps(obj, sort_keys=True, default=repr)

def _write_probe(data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(probe_out, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short probe write")
            view = view[written:]
    finally:
        os.close(fd)

files = sorted(p for p in input_dir.iterdir() if p.is_file())
if mode == "validate":
    parsed, failed, roundtrip_ok, roundtrip_failed = 0, 0, 0, 0
    errors = []
    probe_written = False
    for path in files:
        data = path.read_bytes()
        try:
            obj = decode(data)
            if not isinstance(obj, dict):
                raise TypeError(f"decode returned {type(obj).__name__}, not dict")
            canonical = _canon(obj)
        except BaseException as exc:
            failed += 1
            if len(errors) < 5:
                errors.append(f"{path.name}: {type(exc).__name__}: {exc}")
            continue
        parsed += 1
        if encode_present:
            try:
                blob = encode(obj)
                if not isinstance(blob, (bytes, bytearray)):
                    raise TypeError(f"encode returned {type(blob).__name__}, not bytes")
                if len(blob) > max_probe_bytes:
                    raise ValueError("encode output exceeds probe-size cap")
                if _canon(decode(bytes(blob))) == canonical:
                    roundtrip_ok += 1
                else:
                    roundtrip_failed += 1
                if not probe_written:
                    _write_probe(bytes(blob))
                    probe_written = True
            except BaseException as exc:
                roundtrip_failed += 1
                if len(errors) < 5:
                    errors.append(f"{path.name} roundtrip: {type(exc).__name__}: {exc}")
        elif not probe_written:
            _write_probe(data)
            probe_written = True
    _emit({
        "samples": len(files), "parsed": parsed, "failed": failed,
        "encode_present": encode_present,
        "roundtrip_ok": roundtrip_ok, "roundtrip_failed": roundtrip_failed,
        "probe_written": probe_written, "errors": errors,
    })
else:
    results = []
    for path in files:
        data = path.read_bytes()
        try:
            obj = decode(data)
            if not isinstance(obj, dict):
                raise TypeError(f"decode returned {type(obj).__name__}, not dict")
            rendered = json.dumps(obj, indent=2, sort_keys=True, default=repr)
            truncated = len(rendered) > max_decode_bytes
            results.append({
                "name": path.name, "ok": True,
                "decoded": rendered[:max_decode_bytes], "truncated": truncated,
            })
        except BaseException as exc:
            results.append({
                "name": path.name, "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "hex_preview": data[:256].hex(),
            })
    _emit({"files": results})
"""


def default_codec_script(root: Path, name: str) -> Path:
    return root / "generators" / "codec" / f"{name}.py"


def load_codec_status(work_dir: Path) -> dict[str, Any]:
    path = work_dir / CODEC_STATUS_FILE
    if not _regular_nofollow_file(path):
        return {}
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            current = os.fstat(descriptor)
            if not stat.S_ISREG(current.st_mode) or current.st_size > MAX_CODEC_REPORT_BYTES:
                return {}
            raw = os.read(descriptor, MAX_CODEC_REPORT_BYTES + 1)
        finally:
            os.close(descriptor)
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def run_codec(
    *,
    target: str,
    mode: str = "validate",
    script_path: str | Path | None = None,
    paths: list[str] | None = None,
    max_samples: int = 64,
    qualify_functions: list[str] | None = None,
    min_parse_rate: float = 0.9,
    require_roundtrip: bool = False,
    qualify_default_from_sinks: bool = True,
    timeout_seconds: float = 60.0,
    memory_mb: int = 1024,
    max_decode_bytes: int = 65536,
    workspace_root: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(env) if env is not None else dict(os.environ)
    if not authored_scripts_enabled(environment):
        return {"ok": False, "target": str(target).strip().rstrip("/").split("/")[-1], "mode": str(mode or "validate"),
                "script": str(script_path or ""),
                "blockers": [f"authored codec execution is disabled; set {AUTHORED_SCRIPTS_OPT_IN}=1 in the server environment"]}
    root = resolve_workspace_root(workspace_root, env=environment)
    name = str(target).strip().rstrip("/").split("/")[-1]
    blockers: list[str] = []
    if not name:
        blockers.append("target name is empty")
    mode = str(mode or "validate")
    if mode not in ("validate", "decode"):
        blockers.append(f"mode must be 'validate' or 'decode', got {mode!r}")
    script = Path(script_path).expanduser().resolve() if script_path else default_codec_script(root, name)
    if not script.is_file():
        blockers.append(f"codec script not found: {script}")
    if mode == "decode" and not paths:
        blockers.append("decode mode requires at least one --path")
    if blockers:
        return {"ok": False, "target": name, "mode": mode, "script": str(script), "blockers": blockers}

    timeout_seconds = max(1.0, min(float(timeout_seconds), MAX_SECONDS_CAP))
    max_decode_bytes = max(256, min(int(max_decode_bytes), MAX_CODEC_REPORT_DECODE_BYTES))
    work_dir = root / "work" / name
    work_dir.mkdir(parents=True, exist_ok=True)
    script_digest = hashlib.sha256(script.read_bytes()).hexdigest()

    staging = work_dir / "codec-staging"
    staging_blocker = _prepare_codec_staging(staging)
    if staging_blocker:
        return {"ok": False, "target": name, "mode": mode, "script": str(script), "blockers": [staging_blocker]}
    probe_path = work_dir / "codec-probe.bin"

    if mode == "validate":
        seeds_dir = work_dir / "seeds"
        candidates = (
            sorted(
                (entry for entry in seeds_dir.iterdir() if entry.is_file()),
                key=lambda entry: entry.stat().st_mtime,
                reverse=True,
            )
            if seeds_dir.is_dir()
            else []
        )[: max(1, min(int(max_samples), MAX_VALIDATE_SAMPLES))]
        if not candidates:
            shutil.rmtree(staging, ignore_errors=True)
            return {
                "ok": False, "target": name, "mode": mode, "script": str(script),
                "blockers": [f"validate mode requires a non-empty corpus in {seeds_dir}"],
            }
        input_blockers = _copy_bounded_codec_inputs(candidates, staging)
        if input_blockers:
            shutil.rmtree(staging, ignore_errors=True)
            return {"ok": False, "target": name, "mode": mode, "script": str(script), "blockers": input_blockers}
        probe_blocker = _clear_codec_probe(probe_path)
        if probe_blocker:
            shutil.rmtree(staging, ignore_errors=True)
            return {"ok": False, "target": name, "mode": mode, "script": str(script), "blockers": [probe_blocker]}
    else:
        decode_paths = [Path(p).expanduser() for p in (paths or [])][:MAX_DECODE_PATHS]
        missing = [str(p) for p in decode_paths if not _regular_nofollow_file(p)]
        if missing:
            shutil.rmtree(staging, ignore_errors=True)
            return {
                "ok": False, "target": name, "mode": mode, "script": str(script),
                "blockers": [f"decode path not found: {p}" for p in missing],
            }
        input_blockers = _copy_bounded_codec_inputs(decode_paths, staging, numbered=True)
        if input_blockers:
            shutil.rmtree(staging, ignore_errors=True)
            return {"ok": False, "target": name, "mode": mode, "script": str(script), "blockers": input_blockers}

    staged_names = sorted(entry.name for entry in staging.iterdir() if _regular_nofollow_file(entry))

    read_fd, write_fd = os.pipe()
    report_bytes: list[bytes] = []
    def _drain_result() -> None:
        while True:
            chunk = os.read(read_fd, 65536)
            if not chunk:
                return
            if sum(map(len, report_bytes)) <= MAX_CODEC_REPORT_BYTES:
                report_bytes.append(chunk[: MAX_CODEC_REPORT_BYTES + 1 - sum(map(len, report_bytes))])
    result_reader = threading.Thread(target=_drain_result, daemon=True)
    result_reader.start()
    argv = [
        sys.executable, "-c", _BOOTSTRAP,
        str(script), mode, str(staging), str(probe_path), str(max_decode_bytes),
        str(max(64, int(memory_mb)) * 1024 * 1024),
        str(MAX_CODEC_INPUT_BYTES), str(write_fd),
    ]
    try:
        proc = bounded_run(argv, env=sanitized_env(environment), timeout_seconds=timeout_seconds, pass_fds=(write_fd,))
    finally:
        try:
            os.close(write_fd)
        except OSError:
            pass
    result_reader.join(timeout=2)
    try:
        os.close(read_fd)
    except OSError:
        pass
    timed_out, exit_code, stdout, stderr, elapsed_ms = proc.timed_out, proc.exit_code, proc.stdout, proc.stderr, proc.elapsed_ms
    shutil.rmtree(staging, ignore_errors=True)
    child_report, report_blocker = _read_codec_report(b"".join(report_bytes), exit_code=exit_code)
    if report_blocker is None and not child_report.get("fatal"):
        report_blocker = _validate_codec_report(child_report, mode=mode, staged_names=staged_names)
    if report_blocker:
        blockers.append(report_blocker)
    if child_report.get("fatal"):
        blockers.append(str(child_report["fatal"]))
    probe_exists = False
    try:
        probe_stat = probe_path.lstat()
        probe_exists = True
    except FileNotFoundError:
        probe_stat = None
    except OSError:
        probe_stat = None
        blockers.append("codec probe could not be inspected")
    if mode == "validate" and probe_exists:
        try:
            if not _regular_nofollow_file(probe_path) or probe_stat is None or probe_stat.st_size > MAX_CODEC_INPUT_BYTES:
                blockers.append("codec probe is not a regular file within its size cap")
        except OSError:
            blockers.append("codec probe could not be inspected")
    if mode == "validate" and report_blocker is None and not child_report.get("fatal"):
        if bool(child_report.get("probe_written")) != probe_exists:
            blockers.append("codec bootstrap report disagrees with probe output")
    if timed_out:
        blockers.append(f"codec script exceeded {timeout_seconds:.0f}s wall clock")
    elif exit_code != 0 and not child_report.get("fatal"):
        tail = stderr.strip().splitlines()[-3:]
        blockers.append(f"codec subprocess exited {exit_code}: {' | '.join(tail) if tail else 'no stderr'}")

    if mode == "decode":
        files = child_report.get("files") or []
        status = load_codec_status(work_dir)
        if status and status.get("script_sha256") and status["script_sha256"] != script_digest:
            blockers.append(
                "codec script changed since last validate (stale codec-status.json) — re-run --mode validate"
            )
        return {
            "ok": not blockers and bool(files),
            "target": name, "mode": mode, "script": str(script),
            "script_sha256": script_digest,
            "validated": bool(status.get("validated")),
            "files": files,
            "elapsed_ms": elapsed_ms,
            "blockers": blockers,
        }

    samples = int(child_report.get("samples") or 0)
    parsed = int(child_report.get("parsed") or 0)
    encode_present = bool(child_report.get("encode_present"))
    roundtrip_ok = int(child_report.get("roundtrip_ok") or 0)
    roundtrip_failed = int(child_report.get("roundtrip_failed") or 0)
    parse_rate = parsed / samples if samples else 0.0
    roundtrip_pass = (not encode_present) or (not require_roundtrip) or roundtrip_failed == 0
    validated = not blockers and parse_rate >= float(min_parse_rate) and roundtrip_pass
    if samples and parse_rate < float(min_parse_rate):
        blockers.append(f"parse rate {parse_rate:.2f} below min_parse_rate {float(min_parse_rate):.2f}")
    if encode_present and require_roundtrip and roundtrip_failed:
        blockers.append(f"{roundtrip_failed} sample(s) failed the encode/decode round-trip")

    # RoboDuck qualifying gate: the re-encoded probe must still drive the
    # harness into at least one function the campaign cares about — proof the
    # encoder emits bytes the harness actually parses, not a lookalike format.
    qualifying: dict[str, Any] = {"ran": False}
    if validated and child_report.get("probe_written") and _regular_nofollow_file(probe_path):
        qualifying = _qualify_probe(
            root=root, name=name, work_dir=work_dir, probe=probe_path,
            qualify_functions=qualify_functions,
            qualify_default_from_sinks=qualify_default_from_sinks,
            environment=environment,
            timeout=timeout_seconds,
        )
        if qualifying["ran"] and not qualifying["qualified"]:
            validated = False
            blockers.append(
                "qualifying gate failed: probe replay covered none of "
                f"{qualifying['functions'][:5]} — the encoder output is not being parsed"
            )

    status_payload = {
        "script": str(script),
        "script_sha256": script_digest,
        "validated": validated,
        "samples": samples,
        "parse_rate": round(parse_rate, 4),
        "encode_present": encode_present,
        "roundtrip_ok": roundtrip_ok,
        "roundtrip_failed": roundtrip_failed,
        "qualifying": qualifying,
        "errors": child_report.get("errors") or [],
        "blockers": blockers,
        "updated_ts": time.time(),
    }
    status_blocker = _write_codec_status(work_dir, status_payload)
    if status_blocker:
        blockers.append(status_blocker)
        validated = False

    return {
        "ok": validated,
        "target": name, "mode": mode, "script": str(script),
        "script_sha256": script_digest,
        "validated": validated,
        "samples": samples,
        "parse_rate": round(parse_rate, 4),
        "encode_present": encode_present,
        "roundtrip_ok": roundtrip_ok,
        "roundtrip_failed": roundtrip_failed,
        "qualifying": qualifying,
        "status_path": str(work_dir / CODEC_STATUS_FILE),
        "elapsed_ms": elapsed_ms,
        "errors": child_report.get("errors") or [],
        "blockers": blockers,
    }


def _copy_bounded_codec_inputs(paths: list[Path], staging: Path, *, numbered: bool = False) -> list[str]:
    total = 0
    blockers: list[str] = []
    for index, path in enumerate(paths):
        try:
            copied_size, reason = _copy_codec_input_nofollow(
                path,
                staging / (f"{index:02d}-{path.name}" if numbered else path.name),
            )
        except OSError:
            copied_size, reason = None, "could not be copied safely"
        if reason:
            blockers.append(f"codec input {reason}: {path}")
            continue
        assert copied_size is not None
        total += copied_size
        if total > MAX_CODEC_INPUT_TOTAL_BYTES:
            _unlink_codec_staging_file(staging / (f"{index:02d}-{path.name}" if numbered else path.name))
            blockers.append(f"codec inputs exceed {MAX_CODEC_INPUT_TOTAL_BYTES} byte aggregate cap")
    return blockers


def _copy_codec_input_nofollow(source: Path, destination: Path) -> tuple[int | None, str | None]:
    source_flags = os.O_RDONLY
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
        destination_flags |= os.O_NOFOLLOW
    try:
        source_fd = os.open(source, source_flags)
    except OSError:
        return None, "is not a regular file"
    destination_fd: int | None = None
    completed = False
    try:
        source_before = os.fstat(source_fd)
        if not stat.S_ISREG(source_before.st_mode):
            return None, "is not a regular file"
        if source_before.st_size > MAX_CODEC_INPUT_BYTES:
            return None, f"exceeds {MAX_CODEC_INPUT_BYTES} byte cap"
        destination_fd = os.open(destination, destination_flags, 0o600)
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source_fd, 65536)
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_CODEC_INPUT_BYTES or copied > source_before.st_size:
                return None, "changed while being copied"
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        source_after = os.fstat(source_fd)
        destination_after = os.fstat(destination_fd)
        if (source_after.st_size != source_before.st_size or copied != source_before.st_size
                or destination_after.st_size != source_before.st_size):
            return None, "changed while being copied"
        # Re-open through the staging pathname without following a link and
        # require it to still designate the file held by destination_fd.
        verify_fd = os.open(destination, source_flags)
        try:
            verify_stat = os.fstat(verify_fd)
            if (not stat.S_ISREG(verify_stat.st_mode)
                    or (verify_stat.st_dev, verify_stat.st_ino) != (destination_after.st_dev, destination_after.st_ino)
                    or verify_stat.st_size != source_before.st_size):
                return None, "changed while being copied"
            copied_digest = hashlib.sha256()
            while True:
                chunk = os.read(verify_fd, 65536)
                if not chunk:
                    break
                copied_digest.update(chunk)
            if copied_digest.digest() != digest.digest():
                return None, "changed while being copied"
        finally:
            os.close(verify_fd)
        completed = True
        return copied, None
    except OSError:
        return None, "could not be copied safely"
    finally:
        if destination_fd is not None:
            try:
                destination_stat = os.fstat(destination_fd)
            except OSError:
                destination_stat = None
            os.close(destination_fd)
            if destination_stat is not None and not completed:
                _unlink_codec_staging_file(destination, expected=(destination_stat.st_dev, destination_stat.st_ino))
        os.close(source_fd)


def _unlink_codec_staging_file(path: Path, *, expected: tuple[int, int] | None = None) -> None:
    try:
        current = path.lstat()
        if not stat.S_ISREG(current.st_mode) or (expected is not None and (current.st_dev, current.st_ino) != expected):
            return
        path.unlink()
    except OSError:
        pass


def _regular_nofollow_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _prepare_codec_staging(staging: Path) -> str | None:
    try:
        staging.lstat()
    except FileNotFoundError:
        staging.mkdir(parents=True)
        return None
    except OSError as exc:
        return f"codec staging path could not be inspected: {exc}"
    if staging.is_symlink() or not stat.S_ISDIR(staging.lstat().st_mode):
        return f"codec staging path is not a removable directory: {staging}"
    try:
        shutil.rmtree(staging)
        staging.mkdir(parents=True)
    except OSError as exc:
        return f"codec staging path could not be prepared: {exc}"
    return None


def _clear_codec_probe(path: Path) -> str | None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"codec probe path could not be inspected: {exc}"
    if stat.S_ISDIR(current.st_mode):
        return f"codec probe path is a directory: {path}"
    try:
        path.unlink()
    except OSError as exc:
        return f"codec probe path could not be cleared: {exc}"
    return None


def _write_codec_status(work_dir: Path, payload: dict[str, Any]) -> str | None:
    """Atomically publish status without following a staged/final symlink."""
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(work_dir, directory_flags)
    except OSError as exc:
        return f"codec status directory could not be opened safely: {exc}"
    temp_name = f".codec-status-{os.getpid()}-{secrets.token_hex(16)}.tmp"
    temp_fd: int | None = None
    try:
        directory_stat = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory_stat.st_mode):
            return "codec status directory is not a directory"
        try:
            final_stat = os.stat(CODEC_STATUS_FILE, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            final_stat = None
        if final_stat is not None and not stat.S_ISREG(final_stat.st_mode):
            return "codec status destination is not a regular file"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        temp_fd = os.open(temp_name, flags, 0o600, dir_fd=directory_fd)
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        view = memoryview(encoded)
        while view:
            written = os.write(temp_fd, view)
            if written <= 0:
                raise OSError("short codec status write")
            view = view[written:]
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None
        try:
            final_stat = os.stat(CODEC_STATUS_FILE, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            final_stat = None
        if final_stat is not None and not stat.S_ISREG(final_stat.st_mode):
            return "codec status destination changed to a non-regular file"
        os.replace(temp_name, CODEC_STATUS_FILE, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
        return None
    except OSError as exc:
        return f"codec status could not be written safely: {exc}"
    finally:
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except OSError:
                pass
        try:
            os.unlink(temp_name, dir_fd=directory_fd)
        except OSError:
            pass
        os.close(directory_fd)


def _read_codec_report(raw: bytes, *, exit_code: int) -> tuple[dict[str, Any], str | None]:
    if not raw:
        return {}, "codec bootstrap did not produce an authoritative report"
    if len(raw) > MAX_CODEC_REPORT_BYTES:
        return {}, "codec bootstrap report exceeds its output cap"
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}, "codec bootstrap report is not valid JSON"
    if not isinstance(payload, dict):
        return {}, "codec bootstrap report is not an object"
    fatal = payload.get("fatal")
    if fatal is not None:
        return (payload, None) if set(payload) == {"fatal"} and isinstance(fatal, str) and exit_code == 3 else ({}, "codec bootstrap exit/report disagreement")
    return (payload, None) if exit_code == 0 else ({}, "codec bootstrap exit/report disagreement")


def _validate_codec_report(payload: dict[str, Any], *, mode: str, staged_names: list[str]) -> str | None:
    if mode == "validate":
        required = {"samples", "parsed", "failed", "encode_present", "roundtrip_ok", "roundtrip_failed", "probe_written", "errors"}
        if set(payload) != required:
            return "codec bootstrap report has an invalid validate schema"
        integers = ("samples", "parsed", "failed", "roundtrip_ok", "roundtrip_failed")
        if any(not isinstance(payload[name], int) or isinstance(payload[name], bool) or payload[name] < 0 for name in integers):
            return "codec bootstrap report has invalid counter types"
        if not isinstance(payload["encode_present"], bool) or not isinstance(payload["probe_written"], bool):
            return "codec bootstrap report has invalid boolean types"
        if not isinstance(payload["errors"], list) or any(not isinstance(item, str) for item in payload["errors"]):
            return "codec bootstrap report has invalid errors"
        if payload["samples"] != len(staged_names) or payload["parsed"] + payload["failed"] != payload["samples"]:
            return "codec bootstrap report counters disagree with staged inputs"
        if payload["roundtrip_ok"] + payload["roundtrip_failed"] > payload["parsed"]:
            return "codec bootstrap report roundtrip counters are inconsistent"
        if not payload["encode_present"] and (payload["roundtrip_ok"] or payload["roundtrip_failed"]):
            return "codec bootstrap report includes roundtrip counts without encode"
        return None
    if set(payload) != {"files"} or not isinstance(payload["files"], list) or len(payload["files"]) != len(staged_names):
        return "codec bootstrap report has an invalid decode schema"
    seen: list[str] = []
    for item in payload["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("ok"), bool):
            return "codec bootstrap report contains an invalid decode entry"
        if item["ok"]:
            if set(item) != {"name", "ok", "decoded", "truncated"} or not isinstance(item.get("decoded"), str) or not isinstance(item.get("truncated"), bool):
                return "codec bootstrap report contains an invalid decoded entry"
        elif set(item) != {"name", "ok", "error", "hex_preview"} or not isinstance(item.get("error"), str) or not isinstance(item.get("hex_preview"), str):
            return "codec bootstrap report contains an invalid decode error"
        seen.append(item["name"])
    return None if sorted(seen) == sorted(staged_names) else "codec bootstrap report names disagree with staged inputs"


def _qualify_probe(
    *,
    root: Path,
    name: str,
    work_dir: Path,
    probe: Path,
    qualify_functions: list[str] | None,
    qualify_default_from_sinks: bool,
    environment: dict[str, str],
    timeout: float = 20.0,
) -> dict[str, Any]:
    functions = [str(f) for f in (qualify_functions or []) if str(f).strip()]
    if not functions and qualify_default_from_sinks:
        from .sink_status import load_sink_status

        status = load_sink_status(work_dir)
        functions = sorted(
            {
                str(entry.get("method"))
                for entry in status.get("sinks", {}).values()
                if entry.get("method") and str(entry.get("status")) in ("reached", "exploited")
            }
        )
    fuzzer = root / "bin" / name / "fuzzer"
    if not functions:
        return {"ran": False, "skipped": "no qualify functions (no reached sinks yet, none supplied)"}
    if not fuzzer.is_file() or not os.access(fuzzer, os.X_OK):
        return {"ran": False, "skipped": f"no fuzzer binary at {fuzzer}"}

    from .seed_weights import replay_entry_coverage

    covered = replay_entry_coverage(fuzzer=fuzzer, entry=probe, env=environment, timeout=max(20.0, float(timeout)))
    if covered is None:
        return {"ran": False, "skipped": "probe replay failed or timed out", "functions": functions}
    hit = sorted(set(functions) & covered)
    return {"ran": True, "qualified": bool(hit), "functions": functions, "covered_qualifiers": hit}

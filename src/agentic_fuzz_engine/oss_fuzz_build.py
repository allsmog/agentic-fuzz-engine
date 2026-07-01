from __future__ import annotations

import base64
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .asan import parse_asan_signal
from .fidelity import REFERENCE_PROJECTS_RELATIVE, FixtureBenchmark, discover_reference_benchmarks, resolve_reference_root


DEFAULT_OSS_FUZZ_RELATIVE = Path("fixtures/reference/oss-fuzz")
DEFAULT_RUNNER_IMAGE = "ghcr.io/agentic-fuzz/base-runner:v1.3.0"
MAX_OUTPUT_CHARS = 12000
MAX_REPLAY_TIMEOUT_SECONDS = 120.0
MAX_REPETITIONS = 5
NON_FUZZER_OUTPUTS = {
    "llvm-symbolizer",
    "llvm-cov",
    "llvm-profdata",
    "sancov",
    "jazzer_agent_deploy.jar",
    "jazzer_standalone_deploy.jar",
}
MOSQUITTO_PUBLIC_LIB_COMMIT = "4ad1286d8828c874596be216b5d442fb9508f2df"
MOSQUITTO_LIB_FILES = (
    "CMakeLists.txt",
    "Makefile",
    "actions_publish.c",
    "actions_subscribe.c",
    "actions_unsubscribe.c",
    "alias_mosq.c",
    "alias_mosq.h",
    "callbacks.c",
    "callbacks.h",
    "connect.c",
    "extended_auth.c",
    "handle_auth.c",
    "handle_connack.c",
    "handle_disconnect.c",
    "handle_ping.c",
    "handle_pubackcomp.c",
    "handle_publish.c",
    "handle_pubrec.c",
    "handle_pubrel.c",
    "handle_suback.c",
    "handle_unsuback.c",
    "helpers.c",
    "http_client.c",
    "http_client.h",
    "libmosquitto.c",
    "linker.version",
    "logging_mosq.c",
    "logging_mosq.h",
    "loop.c",
    "messages_mosq.c",
    "messages_mosq.h",
    "mosquitto_internal.h",
    "net_mosq.c",
    "net_mosq.h",
    "net_mosq_ocsp.c",
    "net_ws.c",
    "options.c",
    "packet_datatypes.c",
    "packet_mosq.c",
    "packet_mosq.h",
    "property_mosq.c",
    "property_mosq.h",
    "pthread_compat.h",
    "read_handle.c",
    "read_handle.h",
    "send_connect.c",
    "send_disconnect.c",
    "send_mosq.c",
    "send_mosq.h",
    "send_publish.c",
    "send_subscribe.c",
    "send_unsubscribe.c",
    "socks_mosq.c",
    "socks_mosq.h",
    "srv_mosq.c",
    "thread_mosq.c",
    "tls_mosq.c",
    "tls_mosq.h",
    "util_mosq.c",
    "util_mosq.h",
    "will_mosq.c",
    "will_mosq.h",
)
PHP_PUBLIC_BUILD_REF = "php-8.5.0alpha1"
PHP_BUILD_FILES = (
    "Makefile.gcov",
    "Makefile.global",
    "ax_check_compile_flag.m4",
    "ax_func_which_gethostbyname_r.m4",
    "ax_gcc_func_attribute.m4",
    "config-stubs",
    "config.guess",
    "config.sub",
    "gen_stub.php",
    "genif.sh",
    "libtool.m4",
    "ltmain.sh",
    "order_by_dep.awk",
    "php.m4",
    "php_cxx_compile_stdcxx.m4",
    "pkg.m4",
    "print_include.awk",
    "shtool",
)
PHP_BUILD_EXECUTABLE_FILES = ("config-stubs", "config.guess", "config.sub", "genif.sh", "shtool")
PHP_DATE_LIB_FILES = (
    "LICENSE.rst",
    "README.rst",
    "astro.c",
    "astro.h",
    "dow.c",
    "fallbackmap.h",
    "interval.c",
    "parse_date.c",
    "parse_date.re",
    "parse_iso_intervals.c",
    "parse_iso_intervals.re",
    "parse_posix.c",
    "parse_tz.c",
    "timelib.c",
    "timelib.h",
    "timelib_private.h",
    "timezonedb.h",
    "timezonemap.h",
    "tm2unixtime.c",
    "unixtime2tm.c",
)


def run_owned_oss_fuzz_build(
    engine: Any,
    *,
    project: str,
    run_id: str | None = None,
    oss_fuzz_root: str | None = None,
    docker_host: str | None = None,
    docker_platform: str = "linux/amd64",
    sanitizer: str = "address",
    engine_name: str = "libfuzzer",
    timeout_seconds: int | float = 900,
) -> dict[str, Any]:
    target = project if project.startswith("localfuzz/") else f"localfuzz/c/{project}"
    project_name = target.removeprefix("localfuzz/c/")
    active_run_id = run_id or f"oss-fuzz-build-{project_name}"
    root = resolve_reference_root(engine.reference_root)
    oss_root = Path(oss_fuzz_root).expanduser().resolve() if oss_fuzz_root else root / DEFAULT_OSS_FUZZ_RELATIVE
    helper = oss_root / "infra" / "helper.py"
    reference_project = root / REFERENCE_PROJECTS_RELATIVE / project_name
    benchmarks = [item for item in discover_reference_benchmarks(root, include_disabled=True) if item.project == project_name]

    engine.call_tool(
        "campaign_start",
        {
            "target": target,
            "name": active_run_id,
            "metadata": {
                "mode": "owned-oss-fuzz-build",
                "runtime_authority": "agentic_fuzz_engine",
                "oss_fuzz_root": str(oss_root),
                "docker_platform": docker_platform,
            },
        },
    )

    blockers: list[str] = []
    if not helper.exists():
        blockers.append(f"oss-fuzz helper not found: {helper}")
    if not reference_project.exists():
        blockers.append(f"benchmark project not found: {reference_project}")
    else:
        missing_project_files = [
            str(reference_project / name)
            for name in ("Dockerfile", "project.yaml")
            if not (reference_project / name).exists()
        ]
        if missing_project_files:
            blockers.append(f"benchmark project missing OSS-Fuzz files: {', '.join(missing_project_files)}")
    if shutil.which("docker") is None:
        blockers.append("docker CLI not found")
    if blockers:
        result = _result(active_run_id, target, oss_root, reference_project, [], [], {}, blockers)
        engine.state.event_append(active_run_id, "owned_oss_fuzz_build", result["summary"])
        return result

    workspace = engine.state.worktree_dir(active_run_id, f"oss-fuzz-external-{project_name}")
    external_project = _prepare_external_project(workspace, reference_project)
    reference_source_dir, source_blocker = _source_dir_for_project(reference_project, benchmarks)
    if source_blocker:
        blockers.append(source_blocker)
        result = _result(active_run_id, target, oss_root, reference_project, [], [], {}, blockers)
        engine.state.event_append(active_run_id, "owned_oss_fuzz_build", result["summary"])
        return result

    assert reference_source_dir is not None
    source_dir, source_preparation = _prepare_owned_source(
        engine,
        active_run_id=active_run_id,
        project_name=project_name,
        reference_source_dir=reference_source_dir,
        external_project=external_project,
    )
    env = os.environ.copy()
    if docker_host:
        env["DOCKER_HOST"] = docker_host
    elif Path.home().joinpath(".colima/default/docker.sock").exists():
        env.setdefault("DOCKER_HOST", f"unix://{Path.home() / '.colima/default/docker.sock'}")
    if docker_platform:
        env["DOCKER_DEFAULT_PLATFORM"] = docker_platform

    tag = f"owned-{active_run_id}".replace("/", "_")[:80]
    common = ["python3", str(helper)]
    build_image_command = [
        *common,
        "build_image",
        str(external_project),
        "--external",
        "--no-pull",
        "--docker_image_tag",
        tag,
    ]
    build_fuzzers_command = [
        *common,
        "build_fuzzers",
        str(external_project),
        str(source_dir),
        "--external",
        "--engine",
        engine_name,
        "--sanitizer",
        sanitizer,
        "--architecture",
        "x86_64" if docker_platform.endswith("amd64") else "aarch64",
        "--docker_image_tag",
        tag,
        "--clean",
    ]

    commands = [
        _run_command(build_image_command, cwd=oss_root, env=env, timeout_seconds=timeout_seconds),
        _run_command(build_fuzzers_command, cwd=oss_root, env=env, timeout_seconds=timeout_seconds),
    ]
    if not all(command["ok"] for command in commands):
        blockers.append("OSS-Fuzz helper build failed")

    out_dir = _select_out_dir(oss_root, preferred_names=(external_project.name, project_name))
    fuzzers = _built_fuzzers(out_dir)
    matched = _matched_harnesses(benchmarks, fuzzers)
    missing_harnesses = sorted({benchmark.harness for benchmark in benchmarks if benchmark.harness not in matched})
    if not fuzzers and not blockers:
        blockers.append(f"no fuzzer binaries found in {out_dir}")

    result = _result(
        active_run_id,
        target,
        oss_root,
        reference_project,
        commands,
        fuzzers,
        {
            "matched_harnesses": matched,
            "missing_harnesses": missing_harnesses,
            "source_dir": str(source_dir),
            "reference_source_dir": str(reference_source_dir),
            "source_preparation": source_preparation,
            "external_project": str(external_project),
            "out_dir": str(out_dir),
            "docker_platform": docker_platform,
        },
        blockers,
    )
    engine.state.event_append(active_run_id, "owned_oss_fuzz_build", result["summary"])
    return result


def run_owned_oss_fuzz_build_replay(
    engine: Any,
    *,
    project: str,
    run_id: str | None = None,
    oss_fuzz_root: str | None = None,
    docker_host: str | None = None,
    docker_platform: str = "linux/amd64",
    sanitizer: str = "address",
    engine_name: str = "libfuzzer",
    build_timeout_seconds: int | float = 900,
    replay_timeout_seconds: int | float = 30,
    repetitions: int = 1,
    runner_image: str = DEFAULT_RUNNER_IMAGE,
    record_findings: bool = True,
    include_disabled: bool = False,
) -> dict[str, Any]:
    target = project if project.startswith("localfuzz/") else f"localfuzz/c/{project}"
    project_name = target.removeprefix("localfuzz/c/")
    active_run_id = run_id or f"oss-fuzz-build-replay-{project_name}"
    build = run_owned_oss_fuzz_build(
        engine,
        project=target,
        run_id=active_run_id,
        oss_fuzz_root=oss_fuzz_root,
        docker_host=docker_host,
        docker_platform=docker_platform,
        sanitizer=sanitizer,
        engine_name=engine_name,
        timeout_seconds=build_timeout_seconds,
    )
    build_summary = build.get("summary") if isinstance(build.get("summary"), dict) else {}
    root = resolve_reference_root(engine.reference_root)
    selected = [
        benchmark
        for benchmark in discover_reference_benchmarks(root, include_disabled=include_disabled)
        if benchmark.project == project_name
    ]
    fuzzer_names = {str(item.get("name")) for item in build.get("fuzzers", []) if isinstance(item, dict)}
    out_dir = Path(str(build_summary.get("out_dir") or ""))
    env = _docker_env(docker_host=docker_host, docker_platform=docker_platform)
    timeout = _bounded_replay_timeout(replay_timeout_seconds)
    repeat_count = _bounded_repetitions(repetitions)

    cases: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    blockers = list(build.get("blockers") or [])
    for benchmark in selected:
        proof_bytes = Path(benchmark.proof_path).read_bytes()
        artifact_name = f"fixtures_{benchmark.project}_{benchmark.fixture}_{benchmark.harness}_proof.bin"
        artifact = engine.state.artifact_put(
            active_run_id,
            artifact_name,
            base64.b64encode(proof_bytes).decode("ascii"),
        )
        case: dict[str, Any] = {
            "project": benchmark.project,
            "target": benchmark.target,
            "fixture": benchmark.fixture,
            "harness": benchmark.harness,
            "sanitizer": benchmark.sanitizer,
            "expected_error_token": benchmark.error_token,
            "proof_sha256": benchmark.proof_sha256,
            "artifact": artifact,
            "disabled_project": benchmark.disabled_project,
            "status": "imported",
        }
        if benchmark.harness not in fuzzer_names:
            case["status"] = "blocked"
            case["blocker"] = "fuzzer binary missing from OSS-Fuzz output"
            cases.append(case)
            continue
        if not out_dir.exists():
            case["status"] = "blocked"
            case["blocker"] = f"OSS-Fuzz output directory missing: {out_dir}"
            cases.append(case)
            continue
        run = _run_docker_replay(
            out_dir=out_dir,
            benchmark=benchmark,
            docker_platform=docker_platform,
            runner_image=runner_image,
            env=env,
            timeout_seconds=timeout,
            repetitions=repeat_count,
        )
        case["run"] = run
        case["status"] = "verified" if run["verified"] else "failed"
        if run["verified"] and record_findings:
            finding = engine.state.finding_record(
                active_run_id,
                target=benchmark.target,
                harness=benchmark.harness,
                sanitizer=benchmark.sanitizer,
                error_token=benchmark.error_token,
                crash_output=str(run["crash_output"]),
                poc_artifact=str(artifact["name"]),
                reproductions=int(run["matches_expected"]),
                verified=True,
            )
            case["finding"] = finding
            findings.append(finding)
        cases.append(case)

    summary = {
        "run_id": active_run_id,
        "project": target,
        "total_cases": len(cases),
        "artifacts_imported": len(cases),
        "executed": sum(1 for case in cases if "run" in case),
        "verified": sum(1 for case in cases if case["status"] == "verified"),
        "failed": sum(1 for case in cases if case["status"] == "failed"),
        "blocked": sum(1 for case in cases if case["status"] == "blocked"),
        "findings_recorded": len(findings),
        "docker_platform": docker_platform,
        "runner_image": runner_image,
    }
    engine.state.event_append(active_run_id, "fidelity_replay_campaign", summary)
    audit = engine.call_tool(
        "campaign_fidelity_audit",
        {"run_id": active_run_id, "project": target, "include_disabled": include_disabled},
    )
    replay_blockers = _replay_blockers(cases)
    result = {
        "ok": bool(build.get("ok")) and summary["verified"] > 0 and not replay_blockers,
        "mode": "owned-oss-fuzz-build-replay",
        "runtime_authority": "agentic_fuzz_engine",
        "run_id": active_run_id,
        "target": target,
        "build": build,
        "summary": {
            **summary,
            "build_ok": bool(build.get("ok")),
            "fuzzer_count": build_summary.get("fuzzer_count", 0),
            "matched_harness_count": build_summary.get("matched_harness_count", 0),
            "missing_harness_count": build_summary.get("missing_harness_count", 0),
            "represented_fixtures": audit.get("score", {}).get("represented_fixtures", 0) if isinstance(audit.get("score"), dict) else 0,
            "partial_fixtures": audit.get("score", {}).get("partial_fixtures", 0) if isinstance(audit.get("score"), dict) else 0,
            "missing_fixtures": audit.get("score", {}).get("missing_fixtures", 0) if isinstance(audit.get("score"), dict) else 0,
            "coverage_ratio": audit.get("score", {}).get("coverage_ratio", 0) if isinstance(audit.get("score"), dict) else 0,
        },
        "cases": cases,
        "audit": audit,
        "blockers": list(dict.fromkeys([*blockers, *replay_blockers])),
    }
    engine.state.event_append(active_run_id, "owned_oss_fuzz_build_replay", result["summary"])
    return result


def _prepare_external_project(workspace: Path, reference_project: Path) -> Path:
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    integration = workspace / ".clusterfuzzlite"
    integration.mkdir()
    for name in ("Dockerfile", "project.yaml"):
        shutil.copy2(reference_project / name, integration / name)
    for path in reference_project.iterdir():
        if path.name in {"sources", "vulnerabilities", ".clusterfuzzlite"}:
            continue
        if path.is_file():
            shutil.copy2(path, workspace / path.name)
    return workspace


def _prepare_owned_source(
    engine: Any,
    *,
    active_run_id: str,
    project_name: str,
    reference_source_dir: Path,
    external_project: Path,
) -> tuple[Path, dict[str, Any]]:
    owned_root = engine.state.worktree_dir(active_run_id, "owned-source")
    owned_source = owned_root / reference_source_dir.name
    if owned_source.exists():
        shutil.rmtree(owned_source)
    owned_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(reference_source_dir, owned_source, symlinks=True)
    shims = _apply_project_compatibility_shims(project_name, owned_source, external_project)
    return owned_source.resolve(), {
        "mode": "owned-copy",
        "reference_source_dir": str(reference_source_dir),
        "owned_source_dir": str(owned_source.resolve()),
        "shims": shims,
    }


def _apply_project_compatibility_shims(project_name: str, source_dir: Path, external_project: Path) -> list[dict[str, str]]:
    shims: list[dict[str, str]] = []
    if project_name == "binutils":
        script = external_project / "build.sh"
        inserted = _insert_once(
            script,
            marker="# AGENTIC_FUZZ_SHIM: binutils build binutils object dependencies",
            needle="for fuzzer in ${!fl[@]}; do\n",
            insertion="""# AGENTIC_FUZZ_SHIM: binutils build binutils object dependencies
make MAKEINFO=true \\
  bucomm.o version.o filemode.o demanguse.o dwarf.o prdbg.o rddbg.o \\
  unwind-ia64.o debug.o stabs.o rdcoff.o elfcomm.o od-xcoff.o rename.o \\
  defparse.o deflex.o resrc.o rescoff.o resbin.o rcparse.o rclex.o wrstabs.o \\
  winduni.o resres.o || true
for obj in bucomm.o version.o filemode.o demanguse.o; do
  test -f "$obj" || echo "AGENTIC_FUZZ_SHIM: missing binutils object after targeted make: $obj" >&2
done
""",
        )
        if inserted:
            shims.append(
                {
                    "project": project_name,
                    "kind": "build-script",
                    "detail": "build required binutils object files before linking fuzz_nm/fuzz_dwarf-style harnesses",
                }
            )
    elif project_name == "mosquitto":
        restored_lib = False
        if _looks_like_mosquitto_210_fixture(source_dir) and not (source_dir / "lib").exists():
            restored_lib = _restore_mosquitto_public_lib_tree(source_dir)
            if restored_lib:
                shims.append(
                    {
                        "project": project_name,
                        "kind": "source-layout",
                        "detail": "restored missing public Mosquitto pre-2.1.0 API lib support tree into owned source",
                    }
                )
        if not restored_lib and not (source_dir / "lib").exists() and (source_dir / "libcommon").exists():
            (source_dir / "lib").symlink_to("libcommon")
            shims.append(
                {
                    "project": project_name,
                    "kind": "source-layout",
                    "detail": "created owned-source lib -> libcommon symlink for legacy fuzzing include paths",
                }
            )
        protocol_header = source_dir / "include" / "mosquitto" / "mqtt_protocol.h"
        patched_protocol = False
        if protocol_header.exists():
            patched_protocol = _insert_once(
                protocol_header,
                marker="#define CMD_RESERVED 0x00U",
                needle="#define CMD_CONNECT 0x10U\n",
                insertion="#define CMD_RESERVED 0x00U\n",
            )
        if patched_protocol:
            shims.append(
                {
                    "project": project_name,
                    "kind": "source-header",
                    "detail": "restored CMD_RESERVED protocol constant expected by the public Mosquitto lib support tree",
                }
            )
        script = external_project / "build.sh"
        replaced = _replace_once(
            script,
            old="make $MAKE_FLAGS WITH_STATIC_LIBRARIES=yes WITH_DOCS=no WITH_FUZZING=yes WITH_EDITLINE=no > /dev/null\n",
            new=(
                "make $MAKE_FLAGS -C libcommon WITH_STATIC_LIBRARIES=yes WITH_DOCS=no "
                "WITH_FUZZING=yes WITH_EDITLINE=no\n"
                "make $MAKE_FLAGS -C src WITH_STATIC_LIBRARIES=yes WITH_DOCS=no "
                "WITH_FUZZING=yes WITH_EDITLINE=no\n"
                "make $MAKE_FLAGS -C plugins/dynamic-security WITH_STATIC_LIBRARIES=yes WITH_DOCS=no "
                "WITH_FUZZING=yes WITH_EDITLINE=no\n"
                "make $MAKE_FLAGS -C fuzzing/broker broker_fuzz_test_config WITH_STATIC_LIBRARIES=yes WITH_DOCS=no "
                "WITH_FUZZING=yes WITH_EDITLINE=no\n"
                "make $MAKE_FLAGS -C fuzzing/libcommon libcommon_fuzz_utf8 WITH_STATIC_LIBRARIES=yes WITH_DOCS=no "
                "WITH_FUZZING=yes WITH_EDITLINE=no\n"
                "make $MAKE_FLAGS -C fuzzing/plugins/dynamic-security dynsec_fuzz_load WITH_STATIC_LIBRARIES=yes WITH_DOCS=no "
                "WITH_FUZZING=yes WITH_EDITLINE=no\n"
            ),
        )
        if replaced:
            shims.append(
                {
                    "project": project_name,
                    "kind": "build-script",
                    "detail": "skip absent legacy lib directory and run mosquitto fuzzing make targets",
                }
            )
    elif project_name == "php":
        if _looks_like_php_850_fixture(source_dir) and not (source_dir / "build").exists():
            restored = _restore_php_public_build_tree(source_dir)
            if restored:
                shims.append(
                    {
                        "project": project_name,
                        "kind": "source-layout",
                        "detail": "restored missing public PHP 8.5 buildconf support tree into owned source",
                    }
                )
        if _looks_like_php_850_fixture(source_dir) and not (source_dir / "ext" / "date" / "lib" / "timelib.h").exists():
            restored = _restore_php_public_date_lib_tree(source_dir)
            if restored:
                shims.append(
                    {
                        "project": project_name,
                        "kind": "source-layout",
                        "detail": "restored missing public PHP 8.5 ext/date timelib support files into owned source",
                    }
                )
    elif project_name == "sleuthkit":
        script = external_project / "build.sh"
        replaced = _replace_once(script, old="./bootstrap\n./configure ", new="./bootstrap\nautoheader\n./configure ")
        targeted_make = _replace_once(
            script,
            old="make -j$(nproc)\n",
            new="make -C tsk -j$(nproc) || test -f tsk/.libs/libtsk.a\n",
        )
        bootstrap = source_dir / "bootstrap"
        patched_bootstrap = False
        if bootstrap.exists():
            patched_bootstrap = _replace_once(
                bootstrap,
                old="&& automake --foreign --add-missing --copy \\\n    && autoconf\n",
                new="&& autoheader \\\n    && automake --foreign --add-missing --copy \\\n    && autoconf\n",
            )
        if replaced:
            shims.append(
                {
                    "project": project_name,
                    "kind": "build-script",
                    "detail": "run autoheader after bootstrap so tsk/tsk_config.h.in is generated",
                }
            )
        if targeted_make:
            shims.append(
                {
                    "project": project_name,
                    "kind": "build-script",
                    "detail": "build the libtsk static archive required by OSS-Fuzz harnesses without failing on unrelated recursive targets",
                }
            )
        if patched_bootstrap:
            shims.append(
                {
                    "project": project_name,
                    "kind": "source-bootstrap",
                    "detail": "generate tsk/tsk_config.h.in before bootstrap invokes automake",
                }
            )
    elif project_name == "wireshark":
        script = external_project / "build.sh"
        replaced = _replace_once(
            script,
            old='CMAKE_DEFINES="-DBUILD_fuzzshark=ON"\n',
            new='CMAKE_DEFINES="-DBUILD_fuzzshark=OFF"\n',
        )
        targeted = _replace_once(
            script,
            old=(
                "ninja all-fuzzers\n\n"
                "$SRC/target-c-wireshark/tools/oss-fuzzshark/build.sh all\n"
            ),
            new=(
                "ninja -j1 fuzzshark_ip\n\n"
                "install run/fuzzshark_ip \"$OUT/fuzzshark_ip\"\n"
                "echo -en \"[libfuzzer]\\nmax_len = 1024\\n\" > \"$OUT/fuzzshark_ip.options\"\n"
                "if [ -d \"$SAMPLES_DIR/ip\" ]; then\n"
                "  zip -j \"$OUT/fuzzshark_ip_seed_corpus.zip\" \"$SAMPLES_DIR/ip\"/*/*.bin || true\n"
                "fi\n"
            ),
        )
        if replaced:
            shims.append(
                {
                    "project": project_name,
                    "kind": "build-script",
                    "detail": "avoid generic fuzzshark link so target-specific fuzzshark_* harnesses can finish on 16GB runners",
                }
            )
        if targeted:
            shims.append(
                {
                    "project": project_name,
                    "kind": "build-script",
                    "detail": "build and export only fuzzshark_ip with a single ninja job for the benchmark harness",
                }
            )
    return shims


def _looks_like_mosquitto_210_fixture(source_dir: Path) -> bool:
    config = source_dir / "config.mk"
    makefile = source_dir / "src" / "Makefile"
    if not config.exists() or not makefile.exists():
        return False
    try:
        return "VERSION=2.1.0" in config.read_text(encoding="utf-8")
    except OSError:
        return False


def _restore_mosquitto_public_lib_tree(source_dir: Path) -> bool:
    target = source_dir / "lib"
    if target.exists():
        return False
    temp = source_dir / ".agentic-fuzz-mosquitto-lib"
    if temp.exists():
        shutil.rmtree(temp)
    temp.mkdir(parents=True)
    local_source = os.environ.get("AGENTIC_FUZZ_MOSQUITTO_LIB_SOURCE")
    try:
        if local_source:
            source = Path(local_source).expanduser().resolve()
            for name in MOSQUITTO_LIB_FILES:
                shutil.copy2(source / name, temp / name)
        else:
            base = f"https://raw.githubusercontent.com/eclipse-mosquitto/mosquitto/{MOSQUITTO_PUBLIC_LIB_COMMIT}/lib"
            for name in MOSQUITTO_LIB_FILES:
                with urllib.request.urlopen(f"{base}/{name}", timeout=20) as response:
                    (temp / name).write_bytes(response.read())
        temp.rename(target)
        return True
    except (OSError, urllib.error.URLError):
        shutil.rmtree(temp, ignore_errors=True)
        return False


def _looks_like_php_850_fixture(source_dir: Path) -> bool:
    version = source_dir / "main" / "php_version.h"
    buildconf = source_dir / "buildconf"
    if not version.exists() or not buildconf.exists():
        return False
    try:
        text = version.read_text(encoding="utf-8")
    except OSError:
        return False
    return 'PHP_VERSION "8.5.0-dev"' in text


def _restore_php_public_build_tree(source_dir: Path) -> bool:
    target = source_dir / "build"
    if target.exists():
        return False
    temp = source_dir / ".agentic-fuzz-php-build"
    if temp.exists():
        shutil.rmtree(temp)
    temp.mkdir(parents=True)
    local_source = os.environ.get("AGENTIC_FUZZ_PHP_BUILD_SOURCE")
    try:
        if local_source:
            source = Path(local_source).expanduser().resolve()
            for name in PHP_BUILD_FILES:
                shutil.copy2(source / name, temp / name)
        else:
            base = f"https://raw.githubusercontent.com/php/php-src/{PHP_PUBLIC_BUILD_REF}/build"
            for name in PHP_BUILD_FILES:
                with urllib.request.urlopen(f"{base}/{name}", timeout=20) as response:
                    (temp / name).write_bytes(response.read())
        for name in PHP_BUILD_EXECUTABLE_FILES:
            executable = temp / name
            executable.chmod(executable.stat().st_mode | 0o755)
        temp.rename(target)
        return True
    except (OSError, urllib.error.URLError):
        shutil.rmtree(temp, ignore_errors=True)
        return False


def _restore_php_public_date_lib_tree(source_dir: Path) -> bool:
    target = source_dir / "ext" / "date" / "lib"
    target.mkdir(parents=True, exist_ok=True)
    local_source = os.environ.get("AGENTIC_FUZZ_PHP_DATE_LIB_SOURCE")
    try:
        if local_source:
            source = Path(local_source).expanduser().resolve()
            for name in PHP_DATE_LIB_FILES:
                destination = target / name
                if not destination.exists():
                    shutil.copy2(source / name, destination)
        else:
            base = f"https://raw.githubusercontent.com/php/php-src/{PHP_PUBLIC_BUILD_REF}/ext/date/lib"
            for name in PHP_DATE_LIB_FILES:
                destination = target / name
                if destination.exists():
                    continue
                with urllib.request.urlopen(f"{base}/{name}", timeout=20) as response:
                    destination.write_bytes(response.read())
        return True
    except (OSError, urllib.error.URLError):
        for name in PHP_DATE_LIB_FILES:
            path = target / name
            if path.exists():
                path.unlink()
        return False


def _source_dir_for_project(reference_project: Path, benchmarks: list[FixtureBenchmark]) -> tuple[Path | None, str | None]:
    commits = sorted({benchmark.base_commit for benchmark in benchmarks})
    if not commits:
        return None, f"no benchmark fixtures found for {reference_project.name}"
    if len(commits) != 1:
        return None, f"multiple base commits are not supported yet: {commits}"
    source_root = reference_project / "sources" / commits[0] / "src"
    if not source_root.exists():
        return None, f"source snapshot not found: {source_root}"
    children = [path for path in source_root.iterdir() if path.is_dir()]
    if len(children) == 1:
        return children[0].resolve(), None
    return source_root.resolve(), None


def _replace_once(path: Path, *, old: str, new: str) -> bool:
    text = path.read_text(encoding="utf-8")
    new_variants = {new, new.rstrip("\n")}
    if any(variant and variant in text for variant in new_variants):
        return False
    candidates = [old]
    if old.endswith("\n"):
        candidates.append(old.rstrip("\n"))
    for candidate in candidates:
        if candidate in text:
            replacement = new if candidate.endswith("\n") else new.rstrip("\n")
            path.write_text(text.replace(candidate, replacement, 1), encoding="utf-8")
            return True
    return False


def _insert_once(path: Path, *, marker: str, needle: str, insertion: str) -> bool:
    text = path.read_text(encoding="utf-8")
    if marker in text:
        return False
    if needle not in text:
        return False
    path.write_text(text.replace(needle, insertion + needle, 1), encoding="utf-8")
    return True


def _run_command(command: list[str], *, cwd: Path, env: dict[str, str], timeout_seconds: int | float) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=float(timeout_seconds),
            check=False,
        )
        timed_out = False
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = _coerce_output(exc.stdout)
        stderr = _coerce_output(exc.stderr) + "\nTIMEOUT"
        returncode = 124
    return {
        "ok": returncode == 0,
        "command": command,
        "exit_code": returncode,
        "timed_out": timed_out,
        "stdout": _clip(stdout),
        "stderr": _clip(stderr),
    }


def _run_docker_replay(
    *,
    out_dir: Path,
    benchmark: FixtureBenchmark,
    docker_platform: str,
    runner_image: str,
    env: dict[str, str],
    timeout_seconds: float,
    repetitions: int,
) -> dict[str, Any]:
    command = [
        "docker",
        "run",
        "--rm",
        "--platform",
        docker_platform,
        "-v",
        f"{out_dir.resolve()}:/out:ro",
        "-v",
        f"{Path(benchmark.proof_path).resolve()}:/testcase/proof.bin:ro",
        runner_image,
        f"/out/{benchmark.harness}",
        "-runs=1",
        "-rss_limit_mb=0",
        "/testcase/proof.bin",
    ]
    runs = [
        _run_docker_once(command, env=env, timeout_seconds=timeout_seconds, expected_error_token=benchmark.error_token)
        for _ in range(repetitions)
    ]
    matching = [run for run in runs if run["matched_expected"]]
    first_crash = next((run for run in runs if run["asan_signal"]), None)
    first_run = runs[0] if runs else {}
    return {
        "ok": True,
        "verified": len(matching) == repetitions,
        "command": command,
        "timeout_seconds": timeout_seconds,
        "repetitions": repetitions,
        "matches_expected": len(matching),
        "expected_error_token": benchmark.error_token,
        "observed_error_token": first_crash.get("observed_error_token") if first_crash else None,
        "crash_output": str(first_crash.get("combined_output") if first_crash else first_run.get("combined_output") or ""),
        "runs": runs,
    }


def _run_docker_once(
    command: list[str],
    *,
    env: dict[str, str],
    timeout_seconds: float,
    expected_error_token: str,
) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        timed_out = False
        returncode = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = 124
        stdout = _coerce_output(exc.stdout)
        stderr = _coerce_output(exc.stderr) + "\nTIMEOUT"

    combined = _clip(stdout + stderr)
    signal = parse_asan_signal(combined)
    normalized_output = _normalize_asan_token(combined)
    expected = _normalize_asan_token(expected_error_token)
    matched_expected = expected in normalized_output
    return {
        "exit_code": returncode,
        "timed_out": timed_out,
        "crashed": returncode != 0 and signal is not None,
        "matched_expected": matched_expected,
        "observed_error_token": f"AddressSanitizer: {signal.crash_type}" if signal else None,
        "asan_signal": signal.to_dict() if signal else None,
        "stdout": _clip(stdout),
        "stderr": _clip(stderr),
        "combined_output": combined,
    }


def _built_fuzzers(out_dir: Path) -> list[dict[str, Any]]:
    if not out_dir.exists():
        return []
    fuzzers = []
    for path in sorted(out_dir.iterdir()):
        if not path.is_file() or path.suffix in {".options", ".dict", ".zip"}:
            continue
        if path.name in NON_FUZZER_OUTPUTS:
            continue
        if os.access(path, os.X_OK):
            fuzzers.append({"name": path.name, "path": str(path), "size": path.stat().st_size})
    return fuzzers


def _select_out_dir(oss_root: Path, *, preferred_names: tuple[str, ...]) -> Path:
    seen: set[str] = set()
    candidates: list[Path] = []
    for name in preferred_names:
        if name in seen:
            continue
        seen.add(name)
        candidates.append(oss_root / "build" / "out" / name)
    for candidate in candidates:
        if _built_fuzzers(candidate):
            return candidate
    return candidates[0]


def _docker_env(*, docker_host: str | None, docker_platform: str) -> dict[str, str]:
    env = os.environ.copy()
    if docker_host:
        env["DOCKER_HOST"] = docker_host
    elif Path.home().joinpath(".colima/default/docker.sock").exists():
        env.setdefault("DOCKER_HOST", f"unix://{Path.home() / '.colima/default/docker.sock'}")
    if docker_platform:
        env["DOCKER_DEFAULT_PLATFORM"] = docker_platform
    return env


def _matched_harnesses(benchmarks: list[FixtureBenchmark], fuzzers: list[dict[str, Any]]) -> list[str]:
    fuzzer_names = {str(item["name"]) for item in fuzzers}
    return sorted({benchmark.harness for benchmark in benchmarks if benchmark.harness in fuzzer_names})


def _result(
    run_id: str,
    target: str,
    oss_root: Path,
    reference_project: Path,
    commands: list[dict[str, Any]],
    fuzzers: list[dict[str, Any]],
    extra: dict[str, Any],
    blockers: list[str],
) -> dict[str, Any]:
    matched = extra.get("matched_harnesses") or []
    missing = extra.get("missing_harnesses") or []
    summary = {
        "ok": not blockers and bool(fuzzers),
        "target": target,
        "project": target.removeprefix("localfuzz/c/"),
        "oss_fuzz_root": str(oss_root),
        "reference_project": str(reference_project),
        "fuzzer_count": len(fuzzers),
        "matched_harness_count": len(matched),
        "missing_harness_count": len(missing),
        **extra,
    }
    return {
        "ok": summary["ok"],
        "mode": "owned-oss-fuzz-build",
        "runtime_authority": "agentic_fuzz_engine",
        "run_id": run_id,
        "target": target,
        "summary": summary,
        "commands": commands,
        "fuzzers": fuzzers,
        "blockers": list(dict.fromkeys(blockers)),
    }


def _clip(value: str) -> str:
    if len(value) <= MAX_OUTPUT_CHARS:
        return value
    return value[: MAX_OUTPUT_CHARS // 2] + "\n...[truncated]...\n" + value[-MAX_OUTPUT_CHARS // 2 :]


def _bounded_replay_timeout(value: int | float) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("replay_timeout_seconds must be numeric") from exc
    if timeout <= 0 or timeout > MAX_REPLAY_TIMEOUT_SECONDS:
        raise ValueError(f"replay_timeout_seconds must be between 0 and {MAX_REPLAY_TIMEOUT_SECONDS:g}")
    return timeout


def _bounded_repetitions(value: int) -> int:
    try:
        repetitions = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("repetitions must be an integer") from exc
    if repetitions <= 0 or repetitions > MAX_REPETITIONS:
        raise ValueError(f"repetitions must be between 1 and {MAX_REPETITIONS}")
    return repetitions


def _normalize_asan_token(value: str) -> str:
    return value.replace("ERROR:", "").strip()


def _replay_blockers(cases: list[dict[str, Any]]) -> list[str]:
    blockers: list[str] = []
    for case in cases:
        if case["status"] == "blocked":
            blockers.append(f"{case['project']}:{case['fixture']}:{case['harness']} blocked: {case.get('blocker')}")
            continue
        if case["status"] != "failed":
            continue
        run = case.get("run") if isinstance(case.get("run"), dict) else {}
        runs = run.get("runs") if isinstance(run.get("runs"), list) else []
        exits = sorted({str(item.get("exit_code")) for item in runs if isinstance(item, dict)})
        observed = run.get("observed_error_token") or "no ASAN signal"
        blockers.append(
            f"{case['project']}:{case['fixture']}:{case['harness']} replay failed "
            f"(exit_codes={','.join(exits) or 'none'}, observed={observed})"
        )
    return blockers


def _coerce_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value

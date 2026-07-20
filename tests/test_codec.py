"""Cached harness codec: bounded validate/decode of authored decode() scripts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentic_fuzz_engine.codec import load_codec_status, run_codec

GOOD_CODEC = """
import json

def decode(data: bytes) -> dict:
    text = data.decode("utf-8")
    kind, _, body = text.partition(":")
    if not kind:
        raise ValueError("empty kind")
    return {"kind": kind, "body": body}

def encode(obj: dict) -> bytes:
    return f"{obj['kind']}:{obj['body']}".encode("utf-8")
"""

DECODE_ONLY_CODEC = """
def decode(data: bytes) -> dict:
    return {"length": len(data), "first": data[:1].hex()}
"""

NON_DICT_CODEC = """
def decode(data: bytes):
    return [1, 2, 3]
"""

BROKEN_ROUNDTRIP_CODEC = """
def decode(data: bytes) -> dict:
    return {"length": len(data)}

def encode(obj: dict) -> bytes:
    return b"X" * (obj["length"] + 1)  # never round-trips
"""


def _workspace(tmp: Path, *, corpus_entries: dict[str, bytes] | None = None) -> Path:
    ws = tmp / "ws"
    seeds = ws / "work" / "demo" / "seeds"
    seeds.mkdir(parents=True)
    for name, blob in (corpus_entries or {}).items():
        (seeds / name).write_bytes(blob)
    return ws


def _write_script(tmp: Path, source: str) -> Path:
    script = tmp / "codec-demo.py"
    script.write_text(source, encoding="utf-8")
    return script


class CodecValidateTests(unittest.TestCase):
    def test_validate_passes_and_writes_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _workspace(tmp_path, corpus_entries={"a": b"ping:one", "b": b"pong:two"})
            script = _write_script(tmp_path, GOOD_CODEC)

            result = run_codec(target="demo", mode="validate", script_path=script, workspace_root=ws)

            self.assertTrue(result["ok"], result["blockers"])
            self.assertTrue(result["validated"])
            self.assertEqual(result["samples"], 2)
            self.assertEqual(result["parse_rate"], 1.0)
            self.assertTrue(result["encode_present"])
            self.assertEqual(result["roundtrip_failed"], 0)
            status = load_codec_status(ws / "work" / "demo")
            self.assertTrue(status["validated"])
            self.assertEqual(status["script_sha256"], result["script_sha256"])
            # qualifying gate skipped (no fuzzer, no reached sinks) but recorded
            self.assertFalse(status["qualifying"]["ran"])

    def test_validate_fails_below_parse_rate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # invalid UTF-8 entries fail decode; 1 of 3 parses -> 0.33 < 0.9
            ws = _workspace(
                tmp_path,
                corpus_entries={"a": b"ok:fine", "b": b"\xff\xfe", "c": b"\xff\xff"},
            )
            script = _write_script(tmp_path, GOOD_CODEC)

            result = run_codec(target="demo", mode="validate", script_path=script, workspace_root=ws)

            self.assertFalse(result["validated"])
            self.assertIn("parse rate", result["blockers"][0])
            self.assertFalse(load_codec_status(ws / "work" / "demo")["validated"])

    def test_validate_rejects_non_dict_decode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _workspace(tmp_path, corpus_entries={"a": b"data"})
            script = _write_script(tmp_path, NON_DICT_CODEC)

            result = run_codec(target="demo", mode="validate", script_path=script, workspace_root=ws)

            self.assertFalse(result["validated"])
            self.assertEqual(result["parse_rate"], 0.0)
            self.assertTrue(any("not dict" in e for e in result["errors"]))

    def test_roundtrip_failure_blocks_only_when_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _workspace(tmp_path, corpus_entries={"a": b"data"})
            script = _write_script(tmp_path, BROKEN_ROUNDTRIP_CODEC)

            relaxed = run_codec(target="demo", mode="validate", script_path=script, workspace_root=ws)
            self.assertTrue(relaxed["validated"], relaxed["blockers"])
            self.assertGreaterEqual(relaxed["roundtrip_failed"], 1)

            strict = run_codec(
                target="demo", mode="validate", script_path=script,
                require_roundtrip=True, workspace_root=ws,
            )
            self.assertFalse(strict["validated"])
            self.assertTrue(any("round-trip" in b for b in strict["blockers"]))

    def test_validate_without_encode_is_fine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _workspace(tmp_path, corpus_entries={"a": b"anything"})
            script = _write_script(tmp_path, DECODE_ONLY_CODEC)

            result = run_codec(target="demo", mode="validate", script_path=script, workspace_root=ws)

            self.assertTrue(result["validated"], result["blockers"])
            self.assertFalse(result["encode_present"])

    def test_validate_requires_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _workspace(tmp_path)
            (ws / "work" / "demo" / "seeds").rmdir()
            script = _write_script(tmp_path, GOOD_CODEC)

            result = run_codec(target="demo", mode="validate", script_path=script, workspace_root=ws)

            self.assertFalse(result["ok"])
            self.assertIn("non-empty corpus", result["blockers"][0])

    def test_missing_script_is_a_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _workspace(Path(tmp), corpus_entries={"a": b"x"})
            result = run_codec(target="demo", mode="validate", workspace_root=ws)
            self.assertFalse(result["ok"])
            self.assertIn("codec script not found", result["blockers"][0])


class CodecBootstrapContractTests(unittest.TestCase):
    def test_child_launched_via_dash_c_bootstrap(self) -> None:
        """EDR contract: the authored file must never be the interpreter's
        script argument — always `python -c <bootstrap>` + importlib."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _workspace(tmp_path, corpus_entries={"a": b"k:v"})
            script = _write_script(tmp_path, GOOD_CODEC)
            captured: dict = {}
            real_run = subprocess.run

            def spy(argv, **kwargs):
                captured["argv"] = list(argv)
                return real_run(argv, **kwargs)

            with mock.patch("agentic_fuzz_engine.codec.subprocess.run", side_effect=spy):
                with mock.patch("agentic_fuzz_engine.codec.shutil.which", return_value=None):
                    run_codec(target="demo", mode="validate", script_path=script, workspace_root=ws)

            self.assertEqual(captured["argv"][:2], [sys.executable, "-c"])
            self.assertNotIn(str(script), captured["argv"][:3])


class CodecDecodeTests(unittest.TestCase):
    def _validated_workspace(self, tmp_path: Path) -> tuple[Path, Path]:
        ws = _workspace(tmp_path, corpus_entries={"a": b"ping:one"})
        script = _write_script(tmp_path, GOOD_CODEC)
        result = run_codec(target="demo", mode="validate", script_path=script, workspace_root=ws)
        assert result["validated"], result
        return ws, script

    def test_decode_renders_pretty_dict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws, script = self._validated_workspace(tmp_path)
            pov = tmp_path / "pov.bin"
            pov.write_bytes(b"crash:payload")

            result = run_codec(
                target="demo", mode="decode", script_path=script,
                paths=[str(pov)], workspace_root=ws,
            )

            self.assertTrue(result["ok"], result["blockers"])
            self.assertTrue(result["validated"])
            self.assertEqual(len(result["files"]), 1)
            entry = result["files"][0]
            self.assertTrue(entry["ok"])
            decoded = json.loads(entry["decoded"])
            self.assertEqual(decoded, {"kind": "crash", "body": "payload"})

    def test_decode_fails_open_to_hex_preview(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws, script = self._validated_workspace(tmp_path)
            pov = tmp_path / "pov.bin"
            pov.write_bytes(b"\xff\xfe\xfd\xfc")

            result = run_codec(
                target="demo", mode="decode", script_path=script,
                paths=[str(pov)], workspace_root=ws,
            )

            entry = result["files"][0]
            self.assertFalse(entry["ok"])
            self.assertEqual(entry["hex_preview"], "fffefdfc")
            self.assertIn("error", entry)

    def test_decode_flags_stale_script_sha(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws, script = self._validated_workspace(tmp_path)
            script.write_text(GOOD_CODEC + "\n# edited after validate\n", encoding="utf-8")
            pov = tmp_path / "pov.bin"
            pov.write_bytes(b"k:v")

            result = run_codec(
                target="demo", mode="decode", script_path=script,
                paths=[str(pov)], workspace_root=ws,
            )

            self.assertTrue(any("stale" in b for b in result["blockers"]))

    def test_decode_requires_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws, script = self._validated_workspace(tmp_path)
            result = run_codec(target="demo", mode="decode", script_path=script, workspace_root=ws)
            self.assertFalse(result["ok"])
            self.assertIn("requires at least one", result["blockers"][0])


class CodecQualifyTests(unittest.TestCase):
    def _write_cov_fuzzer(self, path: Path) -> None:
        # Fake libFuzzer: one COVERED_FUNC line per whitespace token in the
        # replayed input, so the probe's bytes declare its coverage.
        path.write_text(
            "#!/bin/sh\n"
            "for last; do :; done\n"
            'if [ -d "$last" ]; then last=$(find "$last" -type f | head -1); fi\n'
            'if [ -f "$last" ]; then\n'
            '  for tok in $(cat "$last"); do\n'
            '    echo "COVERED_FUNC: hits: 1 edges: 1/1 in $tok /src/lib.c:1" >&2\n'
            "  done\n"
            "fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def test_qualifying_gate_passes_when_probe_covers_sink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # GOOD_CODEC's encode re-emits "ParseFrame:x" -> probe covers ParseFrame
            ws = _workspace(tmp_path, corpus_entries={"a": b"ParseFrame:x"})
            bin_dir = ws / "bin" / "demo"
            bin_dir.mkdir(parents=True)
            self._write_cov_fuzzer(bin_dir / "fuzzer")
            script = _write_script(tmp_path, GOOD_CODEC)

            result = run_codec(
                target="demo", mode="validate", script_path=script,
                qualify_functions=["ParseFrame"], workspace_root=ws,
            )

            self.assertTrue(result["validated"], result["blockers"])
            self.assertTrue(result["qualifying"]["ran"])
            self.assertTrue(result["qualifying"]["qualified"])
            self.assertEqual(result["qualifying"]["covered_qualifiers"], ["ParseFrame"])

    def test_qualifying_gate_fails_when_probe_misses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _workspace(tmp_path, corpus_entries={"a": b"Other:x"})
            bin_dir = ws / "bin" / "demo"
            bin_dir.mkdir(parents=True)
            self._write_cov_fuzzer(bin_dir / "fuzzer")
            script = _write_script(tmp_path, GOOD_CODEC)

            result = run_codec(
                target="demo", mode="validate", script_path=script,
                qualify_functions=["NeverCovered"], workspace_root=ws,
            )

            self.assertFalse(result["validated"])
            self.assertTrue(any("qualifying gate failed" in b for b in result["blockers"]))

    def test_qualify_defaults_from_reached_sinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _workspace(tmp_path, corpus_entries={"a": b"CopyBits:x"})
            bin_dir = ws / "bin" / "demo"
            bin_dir.mkdir(parents=True)
            self._write_cov_fuzzer(bin_dir / "fuzzer")
            (ws / "work" / "demo" / "sink-status.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "sinks": {
                            "a.c:1:CopyBits": {"method": "CopyBits", "status": "reached"},
                            "b.c:2:Cold": {"method": "Cold", "status": "unreached"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            script = _write_script(tmp_path, GOOD_CODEC)

            result = run_codec(target="demo", mode="validate", script_path=script, workspace_root=ws)

            self.assertTrue(result["validated"], result["blockers"])
            self.assertTrue(result["qualifying"]["ran"])
            # unreached sinks are not qualifiers
            self.assertEqual(result["qualifying"]["functions"], ["CopyBits"])


class CodecEngineWiringTests(unittest.TestCase):
    def test_tool_spec_and_dispatch(self) -> None:
        from agentic_fuzz_engine.engine import AgenticFuzzEngine

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _workspace(tmp_path, corpus_entries={"a": b"k:v"})
            script = _write_script(tmp_path, GOOD_CODEC)
            engine = AgenticFuzzEngine(data_root=str(tmp_path / "data"))

            names = [spec["name"] for spec in engine.tool_specs()]
            self.assertIn("codec_run", names)

            result = engine.call_tool(
                "codec_run",
                {"target": "demo", "mode": "validate", "script": str(script), "workspace_root": str(ws)},
            )
            self.assertTrue(result["validated"], result.get("blockers"))

    def test_cli_smoke(self) -> None:
        from agentic_fuzz_engine import cli

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _workspace(tmp_path, corpus_entries={"a": b"k:v"})
            script = _write_script(tmp_path, GOOD_CODEC)
            env_backup = dict(os.environ)
            os.environ["CLAUDE_PLUGIN_DATA"] = str(tmp_path / "data")
            try:
                exit_code = cli.main(
                    [
                        "codec-run", "demo",
                        "--mode", "validate",
                        "--script", str(script),
                        "--workspace-root", str(ws),
                    ]
                )
            finally:
                os.environ.clear()
                os.environ.update(env_backup)
            self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import base64
import json
import stat
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.flag_profiles import (
    flag_scan,
    load_flag_profiles,
    render_flag_prelude,
    write_flag_prelude,
)
from agentic_fuzz_engine.impact import finding_impact
from agentic_fuzz_engine.state import EngineState

FLAGS_JSON = {
    "profiles": {
        "production": {"use_digest_index": "true", "page_size": "65536"},
        "permissive": {"use_digest_index": "false", "page_size": "4096"},
    },
    "default_profile": "production",
    "provenance": "test",
}

CRASH = """\
==11==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010 at pc 0x400b12
READ of size 8 at 0x602000000010 thread T0
    #0 0x51fa22 in Decode /work/src/ops.cpp:30
"""

# Stub fuzzer: crashes (exit 1 + ERROR:) only when the profile is permissive.
GATED_FUZZER = """#!/bin/sh
if [ "$FUZZ_FLAG_PROFILE" = "permissive" ]; then
  echo "ERROR: AddressSanitizer: heap-buffer-overflow" >&2
  exit 1
fi
exit 0
"""


def _make_target(root: Path, name: str = "demo") -> Path:
    target_dir = root / "targets" / "c" / name
    (target_dir / ".localfuzz").mkdir(parents=True)
    (target_dir / "harness.cpp").write_text(
        'DEFINE_bool(use_digest_index, true, "gate");\n'
        "int LLVMFuzzerTestOneInput() { return 0; }\n",
        encoding="utf-8",
    )
    (target_dir / ".localfuzz" / "build.json").write_text(
        json.dumps({"steps": [{"name": "fuzzer", "argv": ["true", "harness.cpp"]}]}),
        encoding="utf-8",
    )
    return target_dir


class FlagProfilesTest(unittest.TestCase):
    def test_flag_scan_inventories_defines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_target(root)
            result = flag_scan(root=root, name="demo")
            self.assertTrue(result["ok"])
            inventory = json.loads(Path(result["out"]).read_text(encoding="utf-8"))
            flags = {item["name"]: item for item in inventory["flags"]}
            self.assertIn("use_digest_index", flags)
            self.assertEqual(flags["use_digest_index"]["default"], "true")
            self.assertEqual(flags["use_digest_index"]["type"], "bool")

    def test_prelude_render_profiles_and_noop(self) -> None:
        noop = render_flag_prelude(None)
        self.assertIn("apply_flag_profile", noop)
        self.assertIn("nothing to apply", noop)

        prelude = render_flag_prelude(FLAGS_JSON)
        self.assertIn('std::getenv("FUZZ_FLAG_PROFILE")', prelude)
        self.assertIn('profile_env ? profile_env : "production"', prelude)
        self.assertIn("FLAGS_use_digest_index = true;", prelude)
        self.assertIn("FLAGS_use_digest_index = false;", prelude)
        self.assertIn("FLAGS_page_size = 65536;", prelude)

    def test_write_prelude_from_target_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_dir = _make_target(root)
            (target_dir / ".localfuzz" / "flags.json").write_text(json.dumps(FLAGS_JSON), encoding="utf-8")
            self.assertIsNotNone(load_flag_profiles(target_dir))
            result = write_flag_prelude(root=root, name="demo")
            self.assertTrue(result["ok"])
            self.assertEqual(result["profiles"], ["permissive", "production"])
            self.assertIn("FLAGS_use_digest_index", (target_dir / "flag_profile.inc").read_text(encoding="utf-8"))

    def test_impact_flag_matrix_detects_config_gated_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_dir = _make_target(root)
            (target_dir / ".localfuzz" / "flags.json").write_text(json.dumps(FLAGS_JSON), encoding="utf-8")
            fuzzer = root / "bin" / "demo" / "fuzzer"
            fuzzer.parent.mkdir(parents=True)
            fuzzer.write_text(GATED_FUZZER, encoding="utf-8")
            fuzzer.chmod(fuzzer.stat().st_mode | stat.S_IXUSR)

            state = EngineState(root / "data")
            state.campaign_start("localfuzz/c/demo", name="run-a")
            state.artifact_put("run-a", "crash-1.bin", base64.b64encode(b"POV").decode())
            finding = state.finding_record(
                "run-a",
                target="localfuzz/c/demo",
                harness="demo",
                sanitizer="address",
                error_token="heap-buffer-overflow",
                crash_output=CRASH,
                poc_artifact="crash-1.bin",
                verified=True,
            )
            result = finding_impact(
                state=state,
                run_id="run-a",
                finding_id=finding["finding_id"],
                workspace_root=root,
            )
            impact = result["impact"]
            self.assertEqual(impact["flag_matrix"], {"permissive": "reproduces", "production": "no-repro"})
            self.assertTrue(any("config-gated" in note for note in impact["notes"]))


if __name__ == "__main__":
    unittest.main()

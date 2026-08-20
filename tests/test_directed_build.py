from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.directed import (
    directed_build,
    flag_task,
    load_queue,
    sync_queue,
)

FAKECC = """#!/bin/sh
# fake compiler: writes an executable at the -o argument, records argv.
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then out="$arg"; fi
  prev="$arg"
done
echo "$@" > "$(dirname "$0")/fakecc-argv.txt"
printf '#!/bin/sh\\nexit 0\\n' > "$out"
chmod +x "$out"
"""


def _make_workspace(root: Path) -> Path:
    target_dir = root / "targets" / "c" / "demo"
    (target_dir / ".localfuzz").mkdir(parents=True)
    (target_dir / "harness.cpp").write_text("int main(){}\n", encoding="utf-8")
    fakecc = target_dir / "fakecc"
    fakecc.write_text(FAKECC, encoding="utf-8")
    fakecc.chmod(fakecc.stat().st_mode | stat.S_IXUSR)
    config = {
        "steps": [
            {"name": "fuzzer", "argv": ["./fakecc", "-fsanitize=fuzzer,address", "harness.cpp", "-o", "{bin_dir}/fuzzer"]}
        ]
    }
    (target_dir / ".localfuzz" / "build.json").write_text(json.dumps(config), encoding="utf-8")
    return target_dir


class DirectedBuildTest(unittest.TestCase):
    def test_directed_build_appends_allowlist_and_renames_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_dir = _make_workspace(root)
            sink = "pkg/package.cpp:147:InitializeOffsetMap"
            flag_task(root=root, target="demo", sink=sink, note="test focus")

            result = directed_build(root=root, name="demo", sink=sink, env=dict(os.environ))
            self.assertTrue(result["ok"], result["blockers"])

            argv = (target_dir / "fakecc-argv.txt").read_text(encoding="utf-8")
            self.assertIn("-fsanitize-coverage-allowlist=", argv)
            self.assertIn("fuzzer-directed-", argv)

            allowlist = Path(result["allowlist"]).read_text(encoding="utf-8")
            self.assertIn("src:*pkg/package.cpp", allowlist)
            self.assertIn("fun:*", allowlist)

            binary = Path(result["binary"])
            self.assertTrue(binary.is_file())
            self.assertTrue(os.access(binary, os.X_OK))
            self.assertIn("fuzzer-directed-", binary.name)
            # Plain fuzzer name untouched by the directed build.
            self.assertFalse((root / "bin" / "demo" / "fuzzer").exists())

            # The queue task now carries the binary for the round loop.
            queue = load_queue(root)
            task = next(t for t in queue["tasks"] if t["sink"] == sink)
            self.assertEqual(task["binary"], str(binary))

    def test_directed_build_requires_recipe_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_dir = _make_workspace(root)
            config = {"steps": [{"name": "fuzzer", "argv": ["./fakecc", "-o", "{bin_dir}/other"]}]}
            (target_dir / ".localfuzz" / "build.json").write_text(json.dumps(config), encoding="utf-8")
            result = directed_build(root=root, name="demo", sink="a.cpp:1:m", env=dict(os.environ))
            self.assertFalse(result["ok"])
            self.assertTrue(any("build step" in blocker for blocker in result["blockers"]))


class DeadCandidateHygieneTest(unittest.TestCase):
    def _sinks_jsonl(self, root: Path) -> Path:
        rows = [
            {"tag": "af2", "file": "af2/af2_file_ops.cpp", "line": 292,
             "method": "MintShortUuid", "callee": "memcpy", "kind": "sink", "primitive": "write"},
            {"tag": "pkg", "file": "pkg/package.cpp", "line": 147,
             "method": "InitializeOffsetMap", "callee": "memcpy", "kind": "sink", "primitive": "write"},
        ]
        path = root / "sinks.jsonl"
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
        return path

    def test_dead_candidate_sinks_are_skipped_and_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "work" / "demo").mkdir(parents=True)
            sinks = self._sinks_jsonl(root)

            first = sync_queue(root=root, name="demo", round_index=1, sinks_jsonl=sinks)
            self.assertTrue(first["ok"])
            open_ids = {t["id"] for t in load_queue(root)["tasks"] if t["state"] in ("queued", "active")}
            self.assertEqual(len(open_ids), 2)

            # Rule the af2 candidate dead in the ledger, then re-sync.
            from agentic_fuzz_engine.campaign_metrics import ledger_append

            ledger_append(root, name="af2", status="dead", note="MintShortUuid false positive")
            second = sync_queue(root=root, name="demo", round_index=2, sinks_jsonl=sinks)
            transitions = {change["id"]: change["transition"] for change in second["changes"]}
            af2_id = next(identifier for identifier in open_ids if "MintShortUuid" in identifier)
            self.assertEqual(transitions.get(af2_id), "dropped")

            remaining = [t for t in load_queue(root)["tasks"] if t["state"] in ("queued", "active")]
            self.assertTrue(all("MintShortUuid" not in t["id"] for t in remaining))
            # And it never re-enqueues.
            third = sync_queue(root=root, name="demo", round_index=3, sinks_jsonl=sinks)
            self.assertTrue(all("MintShortUuid" not in change["id"] for change in third["changes"]))


if __name__ == "__main__":
    unittest.main()

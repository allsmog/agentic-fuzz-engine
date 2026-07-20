"""valgrind-sweep: memcheck parsing, severity ranking, and the bounded
end-to-end corpus replay loop (stub valgrind, no real binary needed)."""

from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.valgrind_replay import (
    parse_valgrind_errors,
    valgrind_sweep,
    worst_error,
)

WRITE_ERROR = """\
==1234== Invalid write of size 8
==1234==    at 0x484A54C: memcpy (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==1234==    by 0x14B2A0: fill_hardlink_names (in /tmp/fork_traverse)
==1234==    by 0x149416: ntfs_traversal_istat (in /tmp/fork_traverse)
==1234==  Address 0x4e69b48 is 0 bytes after a block of size 8 alloc'd
"""

JUMP_ERROR = """\
==5678== Jump to the invalid address stated on the next line
==5678==    at 0x0: ???
==5678==    by 0x1236AB: tsk_fs_ils_traverse (in /tmp/fork_traverse)
==5678==    by 0x112425: tsk_traverse_inodes (in /tmp/fork_traverse)
==5678== Process terminating with default action of signal 11 (SIGSEGV): dumping core
"""

READ_ERROR = """\
==9999== Invalid read of size 4
==9999==    at 0x14C000: demo_parse_records (in /tmp/fork_traverse)
==9999==    by 0x14B000: ntfs_traversal_istat (in /tmp/fork_traverse)
"""


class ParseTests(unittest.TestCase):
    def test_invalid_write_parsed_with_product_frame(self) -> None:
        errors = parse_valgrind_errors(WRITE_ERROR)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["kind"], "invalid-write")
        self.assertEqual(errors[0]["access"], "WRITE")
        self.assertEqual(errors[0]["size"], 8)
        # signature frame skips the vgpreload memcpy noise frame
        self.assertEqual(errors[0]["signature_frame"], "fill_hardlink_names")

    def test_jump_and_signal_both_recorded(self) -> None:
        errors = parse_valgrind_errors(JUMP_ERROR)
        kinds = {err["kind"] for err in errors}
        self.assertIn("invalid-jump", kinds)
        self.assertIn("fatal-signal", kinds)
        worst = worst_error(errors)
        assert worst is not None
        self.assertEqual(worst["kind"], "invalid-jump")

    def test_write_ranks_above_read(self) -> None:
        errors = parse_valgrind_errors(READ_ERROR + WRITE_ERROR)
        worst = worst_error(errors)
        assert worst is not None
        self.assertEqual(worst["kind"], "invalid-write")


STUB_VALGRIND = """\
#!/bin/sh
# stub valgrind: args are -q --error-exitcode=N <driver...> <input>
code=0
for arg in "$@"; do
  case "$arg" in --error-exitcode=*) code=${arg#--error-exitcode=} ;; esac
  last="$arg"
done
if grep -q BADWRITE "$last" 2>/dev/null; then
  echo '==1== Invalid write of size 8' >&2
  echo '==1==    at 0x1000: fill_hardlink_names (in /tmp/drv)' >&2
  exit "$code"
fi
if grep -q BADREAD "$last" 2>/dev/null; then
  echo '==1== Invalid read of size 4' >&2
  echo '==1==    at 0x2000: demo_parse_records (in /tmp/drv)' >&2
  exit "$code"
fi
exit 0
"""


class SweepTests(unittest.TestCase):
    def _workspace(self, tmp: Path) -> Path:
        seeds = tmp / "work" / "demo" / "seeds"
        seeds.mkdir(parents=True)
        (seeds / "a-clean").write_bytes(b"nothing here")
        (seeds / "b-write").write_bytes(b"BADWRITE trigger")
        (seeds / "c-read").write_bytes(b"BADREAD trigger")
        stub = tmp / "valgrind-stub"
        stub.write_text(STUB_VALGRIND, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        return tmp

    def test_sweep_flags_and_ranks_write_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._workspace(Path(tmp))
            result = valgrind_sweep(
                target="localfuzz/c/demo",
                command=["/bin/true"],
                workspace_root=root,
                valgrind_path=str(root / "valgrind-stub"),
            )
            self.assertTrue(result["ok"], result.get("blockers"))
            self.assertEqual(result["inputs_scanned"], 3)
            self.assertEqual(result["flagged"], 2)
            self.assertEqual(result["write_class_hits"], 1)
            self.assertEqual(result["hits"][0]["worst_kind"], "invalid-write")
            self.assertEqual(result["hits"][0]["signature_frame"], "fill_hardlink_names")
            self.assertEqual(result["hits"][1]["worst_kind"], "invalid-read")
            report = json.loads(Path(result["report"]).read_text(encoding="utf-8"))
            self.assertEqual(report["flagged"], 2)

    def test_missing_command_is_a_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._workspace(Path(tmp))
            result = valgrind_sweep(
                target="localfuzz/c/demo",
                command=None,
                workspace_root=root,
                valgrind_path=str(root / "valgrind-stub"),
            )
            self.assertFalse(result["ok"])
            self.assertTrue(any("command required" in b for b in result["blockers"]))


if __name__ == "__main__":
    unittest.main()

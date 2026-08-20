"""Directed-fuzzing scheduler: queue lifecycle, budgets, plateau surface."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.directed import (
    complete_task,
    flag_task,
    load_queue,
    queue_summary,
    sync_queue,
    tick_budget,
)


def _write_sinks(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def _sink_row(method: str, *, line: int = 10, primitive: str = "write") -> dict:
    return {
        "kind": "sink", "tag": "demo", "file": "a.c", "line": line,
        "method": method, "callee": "memcpy", "primitive": primitive,
    }


def _write_status(root: Path, name: str, sinks: dict[str, str]) -> None:
    work = root / "work" / name
    work.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "sinks": {
            key: {"method": key.rsplit(":", 1)[-1], "status": status}
            for key, status in sinks.items()
        },
    }
    (work / "sink-status.json").write_text(json.dumps(payload), encoding="utf-8")


class SyncQueueTests(unittest.TestCase):
    def test_sync_enqueues_uncovered_dangerous_sinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sinks = root / "sinks.jsonl"
            _write_sinks(sinks, [
                _sink_row("CopyBits", line=10, primitive="write"),
                _sink_row("RunCmd", line=20, primitive="exec"),
                _sink_row("ReadOnly", line=30, primitive="read"),
            ])

            result = sync_queue(root=root, name="demo", round_index=3, policy={}, sinks_jsonl=sinks)

            self.assertTrue(result["ok"], result["blockers"])
            queue = load_queue(root)
            ids = sorted(t["id"] for t in queue["tasks"])
            self.assertEqual(ids, ["demo:a.c:10:CopyBits", "demo:a.c:20:RunCmd"])  # read excluded
            task = queue["tasks"][0]
            self.assertEqual(task["state"], "queued")
            self.assertEqual(task["priority"], 60)  # frontier 50 + write bonus 10
            self.assertEqual(task["source"], "frontier")
            self.assertEqual(task["added_round"], 3)

    def test_sync_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sinks = root / "sinks.jsonl"
            _write_sinks(sinks, [_sink_row("CopyBits")])
            first = sync_queue(root=root, name="demo", round_index=1, policy={}, sinks_jsonl=sinks)
            second = sync_queue(root=root, name="demo", round_index=2, policy={}, sinks_jsonl=sinks)
            self.assertEqual(len(first["changes"]), 1)
            self.assertEqual(second["changes"], [])
            self.assertEqual(len(load_queue(root)["tasks"]), 1)

    def test_sync_respects_per_target_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sinks = root / "sinks.jsonl"
            _write_sinks(sinks, [_sink_row(f"Sink{i}", line=i) for i in range(10)])
            sync_queue(
                root=root, name="demo", round_index=1,
                policy={"max_tasks_per_target": 2}, sinks_jsonl=sinks,
            )
            open_tasks = [t for t in load_queue(root)["tasks"] if t["state"] == "queued"]
            self.assertEqual(len(open_tasks), 2)

    def test_sync_retires_reached_sinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sinks = root / "sinks.jsonl"
            _write_sinks(sinks, [_sink_row("CopyBits")])
            sync_queue(root=root, name="demo", round_index=1, policy={}, sinks_jsonl=sinks)

            _write_status(root, "demo", {"a.c:10:CopyBits": "reached"})
            result = sync_queue(root=root, name="demo", round_index=2, policy={}, sinks_jsonl=sinks)

            self.assertEqual(result["changes"], [{"id": "demo:a.c:10:CopyBits", "transition": "done"}])
            self.assertEqual(load_queue(root)["tasks"][0]["state"], "done")

    def test_sync_drops_vanished_sinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sinks = root / "sinks.jsonl"
            _write_sinks(sinks, [_sink_row("CopyBits")])
            sync_queue(root=root, name="demo", round_index=1, policy={}, sinks_jsonl=sinks)

            _write_sinks(sinks, [_sink_row("Other", line=99)])
            result = sync_queue(root=root, name="demo", round_index=2, policy={}, sinks_jsonl=sinks)

            transitions = {c["id"]: c["transition"] for c in result["changes"]}
            self.assertEqual(transitions["demo:a.c:10:CopyBits"], "dropped")


class BudgetTickTests(unittest.TestCase):
    def _seeded_root(self, tmp: str) -> Path:
        root = Path(tmp)
        sinks = root / "sinks.jsonl"
        _write_sinks(sinks, [
            _sink_row("HighPri", line=1, primitive="write"),
            _sink_row("LowPri", line=2, primitive="alloc"),
        ])
        sync_queue(
            root=root, name="demo", round_index=1,
            policy={"primitives": ["write", "alloc"]}, sinks_jsonl=sinks,
        )
        return root

    def test_tick_promotes_highest_priority_when_none_active(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._seeded_root(tmp)
            result = tick_budget(root=root, name="demo", round_index=2, policy={})
            self.assertEqual(result["changes"], [{"id": "demo:a.c:1:HighPri", "transition": "activated"}])
            states = {t["id"]: t["state"] for t in load_queue(root)["tasks"]}
            self.assertEqual(states["demo:a.c:1:HighPri"], "active")
            self.assertEqual(states["demo:a.c:2:LowPri"], "queued")

    def test_tick_rotates_exhausted_task_with_decay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._seeded_root(tmp)
            tick_budget(root=root, name="demo", round_index=2, policy={})
            for round_index in range(3, 3 + 6):  # burn the 6-round budget
                tick_budget(root=root, name="demo", round_index=round_index, policy={})
            tasks = {t["id"]: t for t in load_queue(root)["tasks"]}
            rotated = tasks["demo:a.c:1:HighPri"]
            # exhausted -> requeued at decayed priority; the other task took over
            self.assertEqual(rotated["priority"], 50)  # 60 - decay 10
            self.assertEqual(rotated["rounds_used"], 0)
            other = tasks["demo:a.c:2:LowPri"]
            self.assertEqual(other["state"], "active")

    def test_agent_flag_preempts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._seeded_root(tmp)
            flag_task(root=root, target="demo", sink="b.c:7:AgentPick", note="suspicious parser")
            tick_budget(root=root, name="demo", round_index=2, policy={})
            active = [t for t in load_queue(root)["tasks"] if t["state"] == "active"]
            self.assertEqual(len(active), 1)
            self.assertEqual(active[0]["id"], "demo:b.c:7:AgentPick")
            self.assertEqual(active[0]["priority"], 100)

    def test_flag_raises_priority_of_existing_task(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._seeded_root(tmp)
            result = flag_task(root=root, target="demo", sink="a.c:1:HighPri", note="focus here")
            self.assertFalse(result["created"])
            task = next(t for t in load_queue(root)["tasks"] if t["id"] == "demo:a.c:1:HighPri")
            self.assertEqual(task["priority"], 100)
            self.assertEqual(task["source"], "agent")

    def test_complete_task_closes_and_rejects_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._seeded_root(tmp)
            done = complete_task(root=root, target="demo", sink="a.c:1:HighPri", note="pov landed")
            self.assertTrue(done["ok"])
            self.assertEqual(done["task"]["state"], "done")
            missing = complete_task(root=root, target="demo", sink="nope:1:X")
            self.assertFalse(missing["ok"])

    def test_queue_summary_orders_active_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._seeded_root(tmp)
            tick_budget(root=root, name="demo", round_index=2, policy={})
            summary = queue_summary(root=root, target="demo")
            self.assertEqual(summary["counts"], {"active": 1, "queued": 1})
            self.assertEqual(summary["tasks"][0]["state"], "active")


class PlateauSurfaceTests(unittest.TestCase):
    def _flat_workspace(self, tmp: str) -> Path:
        root = Path(tmp)
        work = root / "work" / "demo"
        work.mkdir(parents=True)
        with (work / "rounds.jsonl").open("w", encoding="utf-8") as handle:
            for index in range(1, 6):
                handle.write(json.dumps({
                    "round": index, "corpus_size": 5,
                    "intake": {"findings_recorded": 0}, "fuzz": {},
                }) + "\n")
        return root

    def test_directed_surface_present_when_frontier_tried_and_task_queued(self) -> None:
        from agentic_fuzz_engine.campaign_metrics import ledger_append, plateau_status

        with tempfile.TemporaryDirectory() as tmp:
            root = self._flat_workspace(tmp)
            ledger_append(root, name="demo", status="escalated:frontier")
            sinks = root / "sinks.jsonl"
            _write_sinks(sinks, [_sink_row("CopyBits")])
            sync_queue(root=root, name="demo", round_index=1, policy={}, sinks_jsonl=sinks)

            assessment = plateau_status(workspace_root=root, target="localfuzz/c/demo")

            target = assessment["targets"][0]
            self.assertTrue(target["verdict"].startswith("plateaued"))
            self.assertIn("directed", target)
            self.assertEqual(target["directed"]["active_task"]["method"], "CopyBits")
            self.assertIn("directed-allowlist", target["directed"]["recommendation"])

    def test_directed_surface_absent_without_queue(self) -> None:
        from agentic_fuzz_engine.campaign_metrics import ledger_append, plateau_status

        with tempfile.TemporaryDirectory() as tmp:
            root = self._flat_workspace(tmp)
            ledger_append(root, name="demo", status="escalated:frontier")
            assessment = plateau_status(workspace_root=root, target="localfuzz/c/demo")
            self.assertNotIn("directed", assessment["targets"][0])

    def test_directed_surface_absent_before_frontier_rung(self) -> None:
        from agentic_fuzz_engine.campaign_metrics import plateau_status

        with tempfile.TemporaryDirectory() as tmp:
            root = self._flat_workspace(tmp)
            sinks = root / "sinks.jsonl"
            _write_sinks(sinks, [_sink_row("CopyBits")])
            sync_queue(root=root, name="demo", round_index=1, policy={}, sinks_jsonl=sinks)
            assessment = plateau_status(workspace_root=root, target="localfuzz/c/demo")
            self.assertNotIn("directed", assessment["targets"][0])


class ToolAndCliTests(unittest.TestCase):
    def test_tool_dispatch_all_actions(self) -> None:
        from agentic_fuzz_engine.engine import AgenticFuzzEngine

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sinks = root / "sinks.jsonl"
            _write_sinks(sinks, [_sink_row("CopyBits")])
            engine = AgenticFuzzEngine(data_root=str(root / "engine-data"))

            names = [spec["name"] for spec in engine.tool_specs()]
            self.assertIn("directed_queue", names)

            synced = engine.call_tool(
                "directed_queue",
                {"action": "sync", "target": "demo", "sinks_jsonl": str(sinks), "workspace_root": str(root)},
            )
            self.assertTrue(synced["ok"], synced["blockers"])

            flagged = engine.call_tool(
                "directed_queue",
                {"action": "flag", "target": "demo", "sink": "b.c:9:Hot", "workspace_root": str(root)},
            )
            self.assertTrue(flagged["ok"])

            listed = engine.call_tool(
                "directed_queue", {"action": "list", "target": "demo", "workspace_root": str(root)}
            )
            self.assertEqual(len(listed["tasks"]), 2)

            completed = engine.call_tool(
                "directed_queue",
                {"action": "complete", "target": "demo", "sink": "b.c:9:Hot", "workspace_root": str(root)},
            )
            self.assertTrue(completed["ok"])

    def test_cli_smoke(self) -> None:
        from agentic_fuzz_engine import cli

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_backup = dict(os.environ)
            os.environ["CLAUDE_PLUGIN_DATA"] = str(root / "engine-data")
            try:
                exit_code = cli.main(["directed-queue", "list", "--workspace-root", str(root)])
            finally:
                os.environ.clear()
                os.environ.update(env_backup)
            self.assertEqual(exit_code, 0)


class RoundIntegrationTests(unittest.TestCase):
    class _StubEngine:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict]] = []

        def call_tool(self, name: str, args: dict) -> dict:
            self.calls.append((name, args))
            if name == "campaign_start":
                return {"run_id": "run-test"}
            if name == "fuzz_ensemble_run":
                return {"ok": True, "crash_files": [], "worker_results": [], "blockers": []}
            if name == "finding_dedupe":
                return {"groups": []}
            return {"ok": True}

    def test_plateaued_round_populates_queue_and_summary(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            bin_dir = ws / "bin" / "demo"
            bin_dir.mkdir(parents=True)
            fuzzer = bin_dir / "fuzzer"
            # Fake libFuzzer coverage replay: covers only the token in the
            # seed ("hello"), so CopyBits stays uncovered -> enqueued.
            fuzzer.write_text(
                "#!/bin/sh\n"
                "for last; do :; done\n"
                'if [ -d "$last" ]; then\n'
                '  files=$(find "$last" -type f)\n'
                'elif [ -f "$last" ]; then\n'
                '  files="$last"\n'
                "else\n"
                '  files=""\n'
                "fi\n"
                "for f in $files; do\n"
                '  for tok in $(cat "$f"); do\n'
                '    echo "COVERED_FUNC: hits: 1 edges: 1/1 in $tok /src/lib.c:1" >&2\n'
                "  done\n"
                "done\n"
                "exit 0\n",
                encoding="utf-8",
            )
            fuzzer.chmod(0o755)
            work = ws / "work" / "demo"
            seeds = work / "seeds"
            seeds.mkdir(parents=True)
            (seeds / "unit-a").write_bytes(b"hello")
            _write_sinks(ws / "data" / "sink-scan.jsonl", [_sink_row("CopyBits")])
            # Pre-plateaued history: flat corpus_size across 4 recorded rounds.
            with (work / "rounds.jsonl").open("w", encoding="utf-8") as handle:
                for index in range(1, 5):
                    handle.write(json.dumps({
                        "round": index, "corpus_size": 1,
                        "intake": {"findings_recorded": 0}, "fuzz": {},
                    }) + "\n")
            engine = self._StubEngine()

            result = run_campaign_rounds(
                engine,
                project="localfuzz/c/demo",
                rounds=1,
                fuzz_seconds=5,
                workspace_root=ws,
                env=dict(os.environ),
            )

            self.assertTrue(result["ok"], result["blockers"])
            round_summary = result["rounds"][0]
            self.assertTrue(round_summary["plateau"]["verdict"].startswith("plateaued"))
            frontier = round_summary.get("frontier") or {}
            directed = frontier.get("directed") or {}
            self.assertTrue(directed.get("changes"), frontier)
            # tick promoted the freshly queued task in the same round
            tick = (round_summary.get("directed") or {}).get("tick") or []
            self.assertTrue(any(c["transition"] == "activated" for c in tick), round_summary.get("directed"))
            queue = load_queue(ws)
            states = {t["id"]: t["state"] for t in queue["tasks"]}
            self.assertEqual(states, {"demo:a.c:10:CopyBits": "active"})

    def test_directed_disabled_writes_nothing(self) -> None:
        from agentic_fuzz_engine.campaign_rounds import run_campaign_rounds

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            bin_dir = ws / "bin" / "demo"
            bin_dir.mkdir(parents=True)
            fuzzer = bin_dir / "fuzzer"
            fuzzer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fuzzer.chmod(0o755)
            work = ws / "work" / "demo"
            seeds = work / "seeds"
            seeds.mkdir(parents=True)
            (seeds / "unit-a").write_bytes(b"hello")
            _write_sinks(ws / "data" / "sink-scan.jsonl", [_sink_row("CopyBits")])
            (ws / "campaign-policy.json").write_text(
                json.dumps({"directed": {"enabled": False}}), encoding="utf-8"
            )
            with (work / "rounds.jsonl").open("w", encoding="utf-8") as handle:
                for index in range(1, 5):
                    handle.write(json.dumps({
                        "round": index, "corpus_size": 1,
                        "intake": {"findings_recorded": 0}, "fuzz": {},
                    }) + "\n")
            engine = self._StubEngine()

            result = run_campaign_rounds(
                engine,
                project="localfuzz/c/demo",
                rounds=1,
                fuzz_seconds=5,
                workspace_root=ws,
                env=dict(os.environ),
            )

            self.assertTrue(result["ok"], result["blockers"])
            self.assertNotIn("directed", result["rounds"][0])
            self.assertFalse((ws / "data" / "directed-queue.json").exists())


if __name__ == "__main__":
    unittest.main()

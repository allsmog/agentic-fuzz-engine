"""Fleet job predicates: engine-side PASS/FAIL judgment per job type."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from agentic_fuzz_engine.job_predicates import evaluate_job
from agentic_fuzz_engine.jobs import append_event, fold_events, load_events


def _seed_job(root: Path, job_id: str, job_type: str, target: str, qualifier: str | None = None, evidence: dict | None = None) -> None:
    event = {
        "id": job_id,
        "type": job_type,
        "target": target,
        "state": "queued",
        "attempt": 1,
        "gen": "deadbeef",
    }
    if qualifier:
        event["qualifier"] = qualifier
    if evidence:
        event["evidence"] = evidence
    append_event(root, event)


class _FakeEngine:
    def __init__(self, report: dict) -> None:
        self.report = report
        self.calls: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict) -> dict:
        self.calls.append((name, args))
        return self.report


class HarnessAuthorTests(unittest.TestCase):
    def test_pass_requires_validated_manifest_and_executable_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(root, "harness_author:demo", "harness_author", "demo")
            manifest = root / "targets" / "c" / "demo" / ".localfuzz" / "generate.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({"validated": True}), encoding="utf-8")

            result = evaluate_job(job_id="harness_author:demo", workspace_root=root)
            self.assertFalse(result["predicate"]["ok"])  # binary missing

            fuzzer = root / "bin" / "demo" / "fuzzer"
            fuzzer.parent.mkdir(parents=True)
            fuzzer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fuzzer, 0o755)

            result = evaluate_job(job_id="harness_author:demo", workspace_root=root)
            self.assertTrue(result["predicate"]["ok"], result["predicate"]["detail"])

    def test_predicate_event_appended_without_state_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(root, "harness_author:demo", "harness_author", "demo")
            evaluate_job(job_id="harness_author:demo", workspace_root=root)
            folded = fold_events(load_events(root))["harness_author:demo"]
            self.assertEqual(folded["state"], "queued")
            self.assertIn("predicate", folded)
            self.assertFalse(folded["predicate"]["ok"])


class CoverageFlipTests(unittest.TestCase):
    def test_frontier_seed_passes_when_method_covered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(root, "frontier_seed:demo:CopyBits", "frontier_seed", "demo", "CopyBits")
            engine = _FakeEngine({"covered": [{"method": "CopyBits"}], "uncovered": []})

            result = evaluate_job(job_id="frontier_seed:demo:CopyBits", workspace_root=root, engine=engine)

            self.assertTrue(result["predicate"]["ok"])
            self.assertEqual(engine.calls[0][0], "sink_coverage")

    def test_solver_assist_fails_when_still_uncovered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(root, "solver_assist:demo:CopyBits", "solver_assist", "demo", "CopyBits")
            engine = _FakeEngine({"covered": [], "uncovered": [{"method": "CopyBits"}]})

            result = evaluate_job(job_id="solver_assist:demo:CopyBits", workspace_root=root, engine=engine)

            self.assertFalse(result["predicate"]["ok"])
            self.assertIn("still uncovered", result["predicate"]["detail"])

    def test_falls_back_to_stale_file_without_engine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(root, "frontier_seed:demo:CopyBits", "frontier_seed", "demo", "CopyBits")
            work = root / "work" / "demo"
            work.mkdir(parents=True)
            (work / "sink-coverage.json").write_text(
                json.dumps({"covered": [{"method": "CopyBits"}], "uncovered": []}), encoding="utf-8"
            )
            result = evaluate_job(job_id="frontier_seed:demo:CopyBits", workspace_root=root)
            self.assertTrue(result["predicate"]["ok"])
            self.assertIn("stale file read", result["predicate"]["command"])


class SteeringTests(unittest.TestCase):
    def test_dict_lint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(root, "steering:demo:dict", "steering", "demo", "dict")
            result = evaluate_job(job_id="steering:demo:dict", workspace_root=root)
            self.assertFalse(result["predicate"]["ok"])

            dict_path = root / "targets" / "c" / "demo" / "demo.dict"
            dict_path.parent.mkdir(parents=True)
            dict_path.write_text('# comment\nmagic="\\x89PNG"\n', encoding="utf-8")
            result = evaluate_job(job_id="steering:demo:dict", workspace_root=root)
            self.assertTrue(result["predicate"]["ok"])

    def test_codec_requires_validated_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(root, "steering:demo:codec", "steering", "demo", "codec")
            work = root / "work" / "demo"
            work.mkdir(parents=True)
            (work / "codec-status.json").write_text(json.dumps({"validated": False}), encoding="utf-8")
            self.assertFalse(evaluate_job(job_id="steering:demo:codec", workspace_root=root)["predicate"]["ok"])

            (work / "codec-status.json").write_text(json.dumps({"validated": True}), encoding="utf-8")
            self.assertTrue(evaluate_job(job_id="steering:demo:codec", workspace_root=root)["predicate"]["ok"])

    def test_bits_requires_parseable_bits_and_universe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(root, "steering:demo:bits", "steering", "demo", "bits")
            work = root / "work" / "demo"
            work.mkdir(parents=True)
            self.assertFalse(evaluate_job(job_id="steering:demo:bits", workspace_root=root)["predicate"]["ok"])

            (work / "bits.json").write_text(
                json.dumps({"bits": [{"func_name": "CopyBits", "weight": 9}]}), encoding="utf-8"
            )
            sinks = root / "data" / "sink-scan.jsonl"
            sinks.parent.mkdir(parents=True, exist_ok=True)
            sinks.write_text(
                json.dumps({"kind": "sink", "tag": "demo", "file": "a.c", "line": 1, "method": "CopyBits", "callee": "memcpy", "primitive": "write"}) + "\n",
                encoding="utf-8",
            )
            result = evaluate_job(job_id="steering:demo:bits", workspace_root=root)
            self.assertTrue(result["predicate"]["ok"], result["predicate"]["detail"])


class AllowlistBuildTests(unittest.TestCase):
    def test_passes_when_directed_binary_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(
                root, "allowlist_build:demo:CopyBits", "allowlist_build", "demo", "CopyBits",
                evidence={"task_id": "demo:a.c:10:CopyBits"},
            )
            self.assertFalse(evaluate_job(job_id="allowlist_build:demo:CopyBits", workspace_root=root)["predicate"]["ok"])

            binary = root / "bin" / "demo" / "fuzzer-directed-abcd1234"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(binary, 0o755)
            queue = root / "data" / "directed-queue.json"
            queue.write_text(
                json.dumps({"version": 1, "tasks": [{"id": "demo:a.c:10:CopyBits", "target": "demo", "sink": "a.c:10:CopyBits", "state": "active", "binary": str(binary)}]}),
                encoding="utf-8",
            )
            result = evaluate_job(job_id="allowlist_build:demo:CopyBits", workspace_root=root)
            self.assertTrue(result["predicate"]["ok"], result["predicate"]["detail"])


class TriageTests(unittest.TestCase):
    def test_requires_report_and_verified_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sig = "c" * 40
            _seed_job(root, f"triage:demo:{sig[:12]}", "triage", "demo", sig[:12])
            self.assertFalse(evaluate_job(job_id=f"triage:demo:{sig[:12]}", workspace_root=root)["predicate"]["ok"])

            report_dir = root / "data" / "reports" / "demo" / sig[:12]
            report_dir.mkdir(parents=True)
            (report_dir / "report.md").write_text("triage", encoding="utf-8")
            run_dir = root / "data" / "runs" / "localfuzz_c_demo-20260101-aaaa"
            run_dir.mkdir(parents=True)
            (run_dir / "findings.jsonl").write_text(
                json.dumps({"finding_id": "f-1", "root_signature": sig, "verified": True}) + "\n",
                encoding="utf-8",
            )
            result = evaluate_job(job_id=f"triage:demo:{sig[:12]}", workspace_root=root)
            self.assertTrue(result["predicate"]["ok"], result["predicate"]["detail"])

    def test_unverified_finding_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sig = "d" * 40
            _seed_job(root, f"triage:demo:{sig[:12]}", "triage", "demo", sig[:12])
            report_dir = root / "data" / "reports" / "demo" / sig[:12]
            report_dir.mkdir(parents=True)
            (report_dir / "report.md").write_text("triage", encoding="utf-8")
            run_dir = root / "data" / "runs" / "localfuzz_c_demo-20260101-aaaa"
            run_dir.mkdir(parents=True)
            (run_dir / "findings.jsonl").write_text(
                json.dumps({"finding_id": "f-1", "root_signature": sig, "verified": False}) + "\n",
                encoding="utf-8",
            )
            self.assertFalse(evaluate_job(job_id=f"triage:demo:{sig[:12]}", workspace_root=root)["predicate"]["ok"])


class VulnHuntTests(unittest.TestCase):
    def test_schema_and_citation_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(root, "vuln_hunt:demo", "vuln_hunt", "demo")
            work = root / "work" / "demo"
            work.mkdir(parents=True)
            self.assertFalse(evaluate_job(job_id="vuln_hunt:demo", workspace_root=root)["predicate"]["ok"])

            # schema-valid but fabricated citation -> fail
            (work / "hypotheses.json").write_text(
                json.dumps({"hypotheses": [{
                    "id": "hyp-01", "function": "CopyBits", "file": "nope/missing.c", "line": 10,
                    "bug_class": "obw", "predicate_in_english": "N unbounded", "status": "open",
                }]}),
                encoding="utf-8",
            )
            result = evaluate_job(job_id="vuln_hunt:demo", workspace_root=root)
            self.assertFalse(result["predicate"]["ok"])
            self.assertIn("cited file not found", result["predicate"]["detail"])

            # citation matches the sink inventory -> pass
            sinks = root / "data" / "sink-scan.jsonl"
            sinks.parent.mkdir(parents=True, exist_ok=True)
            sinks.write_text(
                json.dumps({"kind": "sink", "tag": "demo", "file": "nope/missing.c", "line": 10,
                            "method": "CopyBits", "callee": "memcpy", "primitive": "write"}) + "\n",
                encoding="utf-8",
            )
            result = evaluate_job(job_id="vuln_hunt:demo", workspace_root=root)
            self.assertTrue(result["predicate"]["ok"], result["predicate"]["detail"])


class PovProduceTests(unittest.TestCase):
    def test_passes_on_verified_finding_after_job_start(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(root, "pov_produce:demo:hyp-01", "pov_produce", "demo", "hyp-01")
            self.assertFalse(evaluate_job(job_id="pov_produce:demo:hyp-01", workspace_root=root)["predicate"]["ok"])

            run_dir = root / "data" / "runs" / "localfuzz_c_demo-20990101-bbbb"
            run_dir.mkdir(parents=True)
            (run_dir / "findings.jsonl").write_text(
                json.dumps({"finding_id": "f-9", "root_signature": "e" * 40, "verified": True,
                            "created_at": "2099-01-01T00:00:00+00:00"}) + "\n",
                encoding="utf-8",
            )
            result = evaluate_job(job_id="pov_produce:demo:hyp-01", workspace_root=root)
            self.assertTrue(result["predicate"]["ok"], result["predicate"]["detail"])

    def test_old_finding_does_not_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "data" / "runs" / "localfuzz_c_demo-20200101-cccc"
            run_dir.mkdir(parents=True)
            (run_dir / "findings.jsonl").write_text(
                json.dumps({"finding_id": "f-old", "root_signature": "f" * 40, "verified": True,
                            "created_at": "2020-01-01T00:00:00+00:00"}) + "\n",
                encoding="utf-8",
            )
            _seed_job(root, "pov_produce:demo:hyp-01", "pov_produce", "demo", "hyp-01")
            self.assertFalse(evaluate_job(job_id="pov_produce:demo:hyp-01", workspace_root=root)["predicate"]["ok"])

    def test_refuted_with_evidence_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(root, "pov_produce:demo:hyp-01", "pov_produce", "demo", "hyp-01")
            work = root / "work" / "demo"
            work.mkdir(parents=True)
            (work / "hypotheses.json").write_text(
                json.dumps({"hypotheses": [{
                    "id": "hyp-01", "status": "refuted",
                    "refutation_attempted": "clamp at parser.c:88 bounds N to 16",
                }]}),
                encoding="utf-8",
            )
            result = evaluate_job(job_id="pov_produce:demo:hyp-01", workspace_root=root)
            self.assertTrue(result["predicate"]["ok"])
            self.assertIn("refuted with evidence", result["predicate"]["detail"])

    def test_refuted_without_evidence_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(root, "pov_produce:demo:hyp-01", "pov_produce", "demo", "hyp-01")
            work = root / "work" / "demo"
            work.mkdir(parents=True)
            (work / "hypotheses.json").write_text(
                json.dumps({"hypotheses": [{"id": "hyp-01", "status": "refuted"}]}), encoding="utf-8"
            )
            self.assertFalse(evaluate_job(job_id="pov_produce:demo:hyp-01", workspace_root=root)["predicate"]["ok"])


class FleetPlanTests(unittest.TestCase):
    def test_plan_must_cover_non_dead_candidates_within_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_job(root, "fleet_plan:_workspace:2026-07-16", "fleet_plan", "_workspace", "2026-07-16")
            ledger = root / "data" / "candidates.jsonl"
            ledger.parent.mkdir(parents=True, exist_ok=True)
            ledger.write_text(
                "\n".join([
                    json.dumps({"name": "vec_a", "status": "validated"}),
                    json.dumps({"name": "vec_b", "status": "dead"}),
                ]) + "\n",
                encoding="utf-8",
            )
            plan_path = root / "data" / "fleet-plan.json"

            self.assertFalse(evaluate_job(job_id="fleet_plan:_workspace:2026-07-16", workspace_root=root)["predicate"]["ok"])

            plan_path.write_text(
                json.dumps({"targets": [{"target": "vec_a", "budget_usd": 20.0, "rounds": 4}]}), encoding="utf-8"
            )
            result = evaluate_job(job_id="fleet_plan:_workspace:2026-07-16", workspace_root=root)
            self.assertTrue(result["predicate"]["ok"], result["predicate"]["detail"])

            # dead candidate vec_b must NOT be required
            self.assertIn("missing non-dead candidates: none", result["predicate"]["detail"])

            plan_path.write_text(
                json.dumps({"targets": [{"target": "vec_a", "budget_usd": 999.0}]}), encoding="utf-8"
            )
            self.assertFalse(evaluate_job(job_id="fleet_plan:_workspace:2026-07-16", workspace_root=root)["predicate"]["ok"])


if __name__ == "__main__":
    unittest.main()


class ImportRunMatchTests(unittest.TestCase):
    def test_triage_finds_verified_finding_in_import_run(self) -> None:
        """Verified findings recorded by import/recon runs whose dir name
        does not contain the target slug must still satisfy triage."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sig = "a1" * 20
            _seed_job(root, f"triage:demo:{sig[:12]}", "triage", "demo", sig[:12])
            report_dir = root / "data" / "reports" / "demo" / sig[:12]
            report_dir.mkdir(parents=True)
            (report_dir / "report.md").write_text("triage", encoding="utf-8")
            run_dir = root / "data" / "runs" / "demo-reimport"  # no slug match needed
            run_dir.mkdir(parents=True)
            (run_dir / "findings.jsonl").write_text(
                json.dumps({"finding_id": "f-imp", "root_signature": sig, "verified": True,
                            "harness": "demo", "target": "localfuzz/c/demo"}) + "\n",
                encoding="utf-8",
            )
            result = evaluate_job(job_id=f"triage:demo:{sig[:12]}", workspace_root=root)
            self.assertTrue(result["predicate"]["ok"], result["predicate"]["detail"])

    def test_triage_rejects_other_targets_finding(self) -> None:
        """A verified finding belonging to a DIFFERENT target must not
        satisfy this target's triage, even with a matching signature."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sig = "b2" * 20
            _seed_job(root, f"triage:demo:{sig[:12]}", "triage", "demo", sig[:12])
            report_dir = root / "data" / "reports" / "demo" / sig[:12]
            report_dir.mkdir(parents=True)
            (report_dir / "report.md").write_text("triage", encoding="utf-8")
            run_dir = root / "data" / "runs" / "other-reimport"
            run_dir.mkdir(parents=True)
            (run_dir / "findings.jsonl").write_text(
                json.dumps({"finding_id": "f-other", "root_signature": sig, "verified": True,
                            "harness": "other", "target": "localfuzz/c/other"}) + "\n",
                encoding="utf-8",
            )
            self.assertFalse(evaluate_job(job_id=f"triage:demo:{sig[:12]}", workspace_root=root)["predicate"]["ok"])

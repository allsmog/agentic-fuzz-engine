from __future__ import annotations

import json
import threading
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from unittest import mock


def _write_jsonl(path: Path, rows: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


class ManagedPersistenceTests(unittest.TestCase):
    def test_rejects_traversal_and_symlinked_parent(self) -> None:
        from agentic_fuzz_engine.managed_persistence import atomic_write_text, managed_path

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "data").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                atomic_write_text(root, "data/state.json", "{}")
            with self.assertRaisesRegex(ValueError, "forbidden"):
                managed_path(root, "../outside/state.json")
            self.assertFalse((outside / "state.json").exists())


class DerivedDatabaseTests(unittest.TestCase):
    def test_full_rebuild_tracks_same_size_rewrite_deletion_and_malformed_rows(self) -> None:
        from agentic_fuzz_engine.campaign_db import connect, db_sync

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace?name"
            source = root / "data" / "candidates.jsonl"
            _write_jsonl(source, [{"name": "demo", "status": "aaa"}])
            first = db_sync(workspace_root=root)
            self.assertTrue(first["ok"], first)
            conn = connect(root)
            try:
                self.assertEqual(conn.execute("SELECT status FROM candidates").fetchone()[0], "aaa")
            finally:
                conn.close()

            _write_jsonl(source, [{"name": "demo", "status": "bbb"}])
            second = db_sync(workspace_root=root)
            self.assertTrue(second["ok"], second)
            conn = connect(root)
            try:
                self.assertEqual(conn.execute("SELECT status FROM candidates").fetchone()[0], "bbb")
            finally:
                conn.close()

            source.write_text('{"name":"bad"\n' + json.dumps({"name": "safe", "status": "ready"}) + "\n", encoding="utf-8")
            malformed = db_sync(workspace_root=root)
            self.assertFalse(malformed["ok"], malformed)
            conn = connect(root)
            try:
                self.assertEqual([row[0] for row in conn.execute("SELECT name FROM candidates")], ["demo"])
                self.assertEqual(conn.execute("SELECT status FROM candidates").fetchone()[0], "bbb")
            finally:
                conn.close()

            _write_jsonl(source, [{"name": "safe", "status": "ready"}])
            self.assertTrue(db_sync(workspace_root=root)["ok"])
            source.unlink()
            deleted = db_sync(workspace_root=root)
            self.assertTrue(deleted["ok"], deleted)
            conn = connect(root)
            try:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0], 0)
            finally:
                conn.close()

    def test_torn_tail_is_ignored_until_complete(self) -> None:
        from agentic_fuzz_engine.campaign_db import connect, db_sync

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "data" / "jobs.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"id": "job:one", "state": "queued"}) + "\n" + '{"id":"job:two"', encoding="utf-8")
            self.assertTrue(db_sync(workspace_root=root)["ok"])
            conn = connect(root)
            try:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 1)
            finally:
                conn.close()
            with path.open("a", encoding="utf-8") as handle:
                handle.write(',"state":"queued"}\n')
            self.assertTrue(db_sync(workspace_root=root)["ok"])
            conn = connect(root)
            try:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 2)
            finally:
                conn.close()

    def test_symlinked_data_directory_preserves_outside_file(self) -> None:
        from agentic_fuzz_engine.campaign_db import db_sync

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            victim = outside / "campaign.db"
            victim.write_text("untouched", encoding="utf-8")
            (root / "data").symlink_to(outside, target_is_directory=True)
            result = db_sync(workspace_root=root)
            self.assertFalse(result["ok"])
            self.assertEqual(victim.read_text(encoding="utf-8"), "untouched")

    def test_binding_requires_target_tag_and_leaves_ambiguous_matches_unbound(self) -> None:
        from agentic_fuzz_engine.campaign_db import connect, db_sync

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_jsonl(root / "data" / "candidates.jsonl", [{"name": "demo", "status": "validated", "tag": "parser"}])
            _write_jsonl(
                root / "data" / "sink-scan.jsonl",
                [
                    {"tag": "other", "kind": "sink", "primitive": "write", "file": "src/parse.c", "line": 10, "method": "parse", "callee": "copy"},
                    {"tag": "parser", "kind": "sink", "primitive": "write", "file": "src\\parse.c", "line": 10, "method": "parse", "callee": "copy_a"},
                ],
            )
            work = root / "work" / "demo"
            work.mkdir(parents=True)
            (work / "hypotheses.json").write_text(
                json.dumps({"hypotheses": [{"id": "H1", "file": "/checkout/src/parse.c", "line": 10, "function": "parse"}]}),
                encoding="utf-8",
            )
            self.assertTrue(db_sync(workspace_root=root)["ok"])
            conn = connect(root)
            try:
                rows = conn.execute("SELECT match FROM hypothesis_sinks").fetchall()
                self.assertEqual([row[0] for row in rows], ["exact-line"])
            finally:
                conn.close()

            _write_jsonl(
                root / "data" / "candidates.jsonl",
                [
                    {"name": "demo", "status": "validated", "tag": "parser"},
                    {"name": "demo_two", "status": "validated", "tag": "parser"},
                ],
            )
            shared = db_sync(workspace_root=root)
            self.assertTrue(shared["ok"], shared)
            self.assertEqual(shared["counts"]["ambiguous_target_tags"], 1)
            conn = connect(root)
            try:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM hypothesis_sinks").fetchone()[0], 0)
            finally:
                conn.close()

            _write_jsonl(root / "data" / "candidates.jsonl", [{"name": "demo", "status": "validated", "tag": "parser"}])
            with (root / "data" / "sink-scan.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"tag": "parser", "kind": "sink", "primitive": "write", "file": "src/parse.c", "line": 10, "method": "parse", "callee": "copy_b"}) + "\n")
            result = db_sync(workspace_root=root)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["counts"]["ambiguous_hypotheses"], 1)
            conn = connect(root)
            try:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM hypothesis_sinks").fetchone()[0], 0)
            finally:
                conn.close()

    def test_basename_only_source_match_never_binds(self) -> None:
        from agentic_fuzz_engine.campaign_db import connect, db_sync, path_suffix_match

        self.assertFalse(path_suffix_match("left/parse.c", "right/parse.c"))
        self.assertFalse(path_suffix_match("parse.c", "parse.c"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_jsonl(root / "data" / "candidates.jsonl", [{"name": "demo", "status": "validated", "tag": "demo"}])
            _write_jsonl(
                root / "data" / "sink-scan.jsonl",
                [{"tag": "demo", "kind": "sink", "primitive": "write", "file": "left/parse.c", "line": 10, "method": "parse", "callee": "copy"}],
            )
            work = root / "work" / "demo"
            work.mkdir(parents=True)
            (work / "hypotheses.json").write_text(
                json.dumps({"hypotheses": [{"id": "H1", "file": "right/parse.c", "line": 10, "function": "parse"}]}),
                encoding="utf-8",
            )
            self.assertTrue(db_sync(workspace_root=root)["ok"])
            conn = connect(root)
            try:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM hypothesis_sinks").fetchone()[0], 0)
            finally:
                conn.close()

    def test_aggregate_source_cap_blocks_and_preserves_previous_index(self) -> None:
        import agentic_fuzz_engine.campaign_db as campaign_db

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_jsonl(root / "data" / "candidates.jsonl", [{"name": "demo", "status": "ready"}])
            self.assertTrue(campaign_db.db_sync(workspace_root=root)["ok"])
            with mock.patch.object(campaign_db, "MAX_TOTAL_SOURCE_BYTES", 8):
                result = campaign_db.db_sync(workspace_root=root)
            self.assertFalse(result["ok"])
            conn = campaign_db.connect(root)
            try:
                self.assertEqual(conn.execute("SELECT name FROM candidates").fetchone()[0], "demo")
            finally:
                conn.close()

    def test_deep_json_huge_integer_and_oversized_line_preserve_previous_index(self) -> None:
        import agentic_fuzz_engine.campaign_db as campaign_db

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "data" / "candidates.jsonl"
            _write_jsonl(source, [{"name": "demo", "status": "ready"}])
            self.assertTrue(campaign_db.db_sync(workspace_root=root)["ok"])

            source.write_text('{"name":"demo","status":' + "[" * 2000 + "0" + "]" * 2000 + "}\n", encoding="utf-8")
            self.assertFalse(campaign_db.db_sync(workspace_root=root)["ok"])
            conn = campaign_db.connect(root)
            try:
                self.assertEqual(conn.execute("SELECT status FROM candidates").fetchone()[0], "ready")
            finally:
                conn.close()

            _write_jsonl(source, [{"name": "demo", "status": "ready"}])
            rounds = root / "work" / "demo" / "rounds.jsonl"
            _write_jsonl(rounds, [{"run_id": "run-1", "round": 1}])
            self.assertTrue(campaign_db.db_sync(workspace_root=root)["ok"])
            _write_jsonl(rounds, [{"run_id": "run-1", "round": 1e300}])
            self.assertFalse(campaign_db.db_sync(workspace_root=root)["ok"])
            conn = campaign_db.connect(root)
            try:
                self.assertEqual(conn.execute("SELECT round FROM rounds").fetchone()[0], 1)
            finally:
                conn.close()

            rounds.unlink()
            source.write_text(json.dumps({"name": "demo", "status": "x" * 100}) + "\n", encoding="utf-8")
            with mock.patch.object(campaign_db, "MAX_RECORD_BYTES", 32):
                result = campaign_db.db_sync(workspace_root=root)
            self.assertFalse(result["ok"])
            conn = campaign_db.connect(root)
            try:
                self.assertEqual(conn.execute("SELECT status FROM candidates").fetchone()[0], "ready")
            finally:
                conn.close()


class DeterministicScoringTests(unittest.TestCase):
    def _policy(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        (root / "campaign-policy.json").write_text(
            json.dumps(
                {
                    "scoring": {
                        "quantile": 0.5,
                        "min_score": 0.5,
                        "lenses": ["reachability", "guarding", "evidence"],
                        "mode": "enforce",
                    }
                }
            ),
            encoding="utf-8",
        )

    def test_exact_lenses_idempotency_exact_quantile_and_advisory_only(self) -> None:
        from agentic_fuzz_engine.candidate_scoring import record_score, scoring_report

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._policy(root)
            votes = [
                {"lens": "evidence", "verdict": "unlikely", "reason": "weak"},
                {"lens": "reachability", "verdict": "likely", "reason": "reachable"},
                {"lens": "guarding", "verdict": "likely", "reason": "no guard"},
            ]
            first = record_score(root, target="demo", hypothesis_id="H1", votes=votes, stream="parser")
            second = record_score(root, target="demo", hypothesis_id="H1", votes=votes, stream="parser")
            self.assertTrue(first["created"])
            self.assertFalse(second["created"])
            self.assertEqual(len(list((root / "data" / "candidate-judgments").glob("*.json"))), 1)
            record_score(
                root,
                target="demo",
                hypothesis_id="H2",
                votes=["likely", "unlikely", "unlikely"],
                stream="parser",
            )
            report = scoring_report(workspace_root=root)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["policy"]["mode"], "advisory")
            self.assertTrue(report["advisory_only"])
            scores = {row["hypothesis_id"]: row for row in report["scores"]}
            self.assertAlmostEqual(scores["H1"]["score"], 2 / 3)
            self.assertAlmostEqual(report["streams"]["parser"]["threshold"], 1 / 3)
            self.assertFalse(scores["H2"]["floor_passed"])

    def test_rejects_missing_duplicate_and_extra_lenses(self) -> None:
        from agentic_fuzz_engine.candidate_scoring import record_score

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._policy(root)
            with self.assertRaisesRegex(ValueError, "exactly 3"):
                record_score(root, target="demo", hypothesis_id="H1", votes=["likely"])
            with self.assertRaisesRegex(ValueError, "each configured lens"):
                record_score(
                    root,
                    target="demo",
                    hypothesis_id="H1",
                    votes=[
                        {"lens": "reachability", "verdict": "likely"},
                        {"lens": "reachability", "verdict": "unlikely"},
                        {"lens": "evidence", "verdict": "likely"},
                    ],
                )

    def test_rejects_conflicting_revision_invalid_policy_and_policy_generation_change(self) -> None:
        from agentic_fuzz_engine.candidate_scoring import record_score, scoring_report

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._policy(root)
            record_score(root, target="demo", hypothesis_id="H1", votes=["likely", "likely", "unlikely"])
            with self.assertRaisesRegex(ValueError, "conflicting judgment"):
                record_score(root, target="demo", hypothesis_id="H1", votes=["unlikely", "likely", "unlikely"])

            policy_path = root / "campaign-policy.json"
            policy_path.write_text(
                json.dumps({"scoring": {"quantile": float("nan"), "lenses": ["a", "b", "b"]}}),
                encoding="utf-8",
            )
            invalid = scoring_report(workspace_root=root)
            self.assertFalse(invalid["ok"])
            self.assertRegex(invalid["blockers"][0], "finite|unique")

            self._policy(root)
            payload = json.loads(policy_path.read_text(encoding="utf-8"))
            payload["scoring"]["min_score"] = 0.75
            policy_path.write_text(json.dumps(payload), encoding="utf-8")
            changed = scoring_report(workspace_root=root)
            self.assertTrue(changed["ok"], changed)
            self.assertEqual(changed["scores"], [])
            self.assertTrue(any("different scoring policy generation" in warning for warning in changed["warnings"]))

    def test_policy_numeric_types_are_exact_and_malformed_json_blocks(self) -> None:
        from agentic_fuzz_engine.candidate_scoring import scoring_report

        invalid_sections = [
            {"quantile": "0.5"},
            {"min_score": True},
            {"votes": 3.0},
            {"votes": "3"},
            {"lenses": ["a", 2]},
            {"lenses": ["a", "b"], "votes": 2},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "campaign-policy.json"
            for section in invalid_sections:
                policy.write_text(json.dumps({"scoring": section}), encoding="utf-8")
                result = scoring_report(workspace_root=root)
                self.assertFalse(result["ok"], section)
            policy.write_text('{"scoring":', encoding="utf-8")
            malformed = scoring_report(workspace_root=root)
            self.assertFalse(malformed["ok"])
            self.assertIn("malformed campaign scoring policy", malformed["blockers"][0])
            policy.write_text(json.dumps({"scoring": ["not", "an", "object"]}), encoding="utf-8")
            section = scoring_report(workspace_root=root)
            self.assertFalse(section["ok"])
            self.assertIn("must be a JSON object", section["blockers"][0])

    def test_tampered_revision_is_a_blocker_and_directory_scan_is_bounded(self) -> None:
        import agentic_fuzz_engine.candidate_scoring as scoring

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._policy(root)
            scoring.record_score(root, target="demo", hypothesis_id="H1", votes=["likely", "likely", "unlikely"])
            original = next((root / "data" / "candidate-judgments").glob("*.json"))
            row = json.loads(original.read_text(encoding="utf-8"))
            original.unlink()
            row["revision"] = "not-an-integer"
            base = {key: value for key, value in row.items() if key != "digest"}
            digest = sha256(json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            row["digest"] = digest
            (original.parent / f"{digest}.json").write_text(json.dumps(row), encoding="utf-8")
            report = scoring.scoring_report(workspace_root=root)
            self.assertFalse(report["ok"])
            self.assertIn("invalid revision", report["blockers"][0])

            for index in range(2):
                (original.parent / f"junk-{index}").write_text("x", encoding="utf-8")
            with mock.patch.object(scoring, "MAX_JUDGMENTS", 2):
                bounded = scoring.scoring_report(workspace_root=root)
            self.assertFalse(bounded["ok"])
            self.assertIn("entry count exceeds cap", bounded["blockers"][0])

    def test_exact_stored_schema_and_hypothesis_api_report_corruption(self) -> None:
        import agentic_fuzz_engine.candidate_scoring as scoring

        mutations = [
            lambda row: row.__setitem__("version", True),
            lambda row: row.__setitem__("votes_likely", False),
            lambda row: row.__setitem__("score", "0.67"),
            lambda row: row.__setitem__("target", 7),
            lambda row: row["judgments"][0].__setitem__("lens", 7),
        ]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self._policy(root)
                scoring.record_score(root, target="demo", hypothesis_id="H1", votes=["likely", "likely", "unlikely"])
                original = next((root / "data" / "candidate-judgments").glob("*.json"))
                row = json.loads(original.read_text(encoding="utf-8"))
                original.unlink()
                mutate(row)
                base = {key: value for key, value in row.items() if key != "digest"}
                digest = sha256(json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
                row["digest"] = digest
                (original.parent / f"{digest}.json").write_text(json.dumps(row), encoding="utf-8")
                report = scoring.scoring_report(workspace_root=root)
                self.assertFalse(report["ok"], row)
                per_target = scoring.hypothesis_scores(root, "demo")
                self.assertFalse(per_target["ok"])
                self.assertEqual(per_target["scores"], {})
                self.assertTrue(per_target["blockers"])

    def test_stored_conflict_blocks_report_and_concurrent_cas_persists_one(self) -> None:
        import agentic_fuzz_engine.candidate_scoring as scoring

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._policy(root)
            scoring.record_score(root, target="demo", hypothesis_id="H1", votes=["likely", "likely", "unlikely"])
            original = next((root / "data" / "candidate-judgments").glob("*.json"))
            conflicting = json.loads(original.read_text(encoding="utf-8"))
            conflicting["judgments"][0]["verdict"] = "unlikely"
            conflicting["votes_likely"] = 1
            conflicting["score"] = 1 / 3
            base = {key: value for key, value in conflicting.items() if key != "digest"}
            digest = sha256(json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            conflicting["digest"] = digest
            (original.parent / f"{digest}.json").write_text(json.dumps(conflicting), encoding="utf-8")
            report = scoring.scoring_report(workspace_root=root)
            self.assertFalse(report["ok"])
            self.assertEqual(len(report["conflicts"]), 1)
            self.assertIn("same candidate revision", report["blockers"][0])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._policy(root)
            barrier = threading.Barrier(2)

            def submit(votes: list[str]):
                barrier.wait()
                try:
                    return scoring.record_score(root, target="demo", hypothesis_id="H1", votes=votes)
                except ValueError as exc:
                    return exc

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(submit, (["likely", "likely", "unlikely"], ["unlikely", "likely", "unlikely"])))
            self.assertEqual(sum(isinstance(result, dict) for result in results), 1)
            self.assertEqual(sum(isinstance(result, ValueError) for result in results), 1)
            self.assertEqual(len(list((root / "data" / "candidate-judgments").glob("*.json"))), 1)
            self.assertTrue(scoring.scoring_report(workspace_root=root)["ok"])

    def test_deep_judgment_json_and_aggregate_cap_are_caught_without_further_reads(self) -> None:
        import agentic_fuzz_engine.candidate_scoring as scoring

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._policy(root)
            directory = root / "data" / "candidate-judgments"
            directory.mkdir(parents=True)
            deep = "[" * 2000 + "0" + "]" * 2000
            (directory / ("0" * 64 + ".json")).write_text(deep, encoding="utf-8")
            report = scoring.scoring_report(workspace_root=root)
            self.assertFalse(report["ok"])
            # CPython releases differ on whether json.loads rejects this depth
            # first; either path must fail closed before accepting a record.
            self.assertRegex(report["blockers"][0], r"^(?:unreadable|malformed) judgment")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._policy(root)
            directory = root / "data" / "candidate-judgments"
            directory.mkdir(parents=True)
            for digit in ("1", "2"):
                (directory / (digit * 64 + ".json")).write_text("{}", encoding="utf-8")
            with (
                mock.patch.object(scoring, "MAX_JUDGMENT_TOTAL_BYTES", 1),
                mock.patch.object(scoring, "safe_read_text", wraps=scoring.safe_read_text) as reader,
            ):
                bounded = scoring.scoring_report(workspace_root=root)
            self.assertFalse(bounded["ok"])
            self.assertIn("aggregate byte cap", bounded["blockers"][0])
            self.assertEqual(reader.call_count, 0)

    def test_judgment_iterable_stops_at_exact_k_plus_one(self) -> None:
        from agentic_fuzz_engine.candidate_scoring import record_score

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._policy(root)
            seen: list[int] = []

            def judgments():
                for index in range(100):
                    seen.append(index)
                    if index > 3:
                        raise AssertionError("iterator consumed beyond K+1")
                    yield "likely"

            with self.assertRaisesRegex(ValueError, "exactly 3"):
                record_score(root, target="demo", hypothesis_id="H1", votes=judgments())
            self.assertEqual(seen, [0, 1, 2, 3])

    def test_calibration_is_bounded_and_requires_strict_booleans(self) -> None:
        from agentic_fuzz_engine.candidate_scoring import MAX_CALIBRATION_LABELS, calibrate

        self.assertFalse(calibrate(labels=[{"score": 0.5, "positive": 1}])["ok"])
        self.assertFalse(calibrate(labels=[{"score": "0.5", "positive": True}])["ok"])
        self.assertFalse(calibrate(labels=[{"score": True, "positive": True}])["ok"])
        too_many = ({"score": 0.5, "positive": True} for _ in range(MAX_CALIBRATION_LABELS + 1))
        result = calibrate(labels=too_many)
        self.assertFalse(result["ok"])
        self.assertIn("count exceeds cap", result["blockers"][0])


if __name__ == "__main__":
    unittest.main()

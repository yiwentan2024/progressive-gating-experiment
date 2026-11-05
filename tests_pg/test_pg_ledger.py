from __future__ import annotations

import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from tests_pg.pg_fixtures import ARTIFACT_SHA, read_csv, write_run
from tools.pg_ledger import _plan_pairs, finalize, verify_internal


class PlanTests(unittest.TestCase):
    def test_default_plan_counts_formal_and_calibration_separately(self):
        cells = _plan_pairs({})
        formal = [cell for cell in cells if not cell["calibration"]]
        calibration = [cell for cell in cells if cell["calibration"]]
        self.assertEqual(len(formal), 18)
        self.assertEqual(len(calibration), 3)
        self.assertEqual({cell["scenario"] for cell in calibration}, {"PG-N01", "PG-ART", "PG-DISP"})


class FinalizeTests(unittest.TestCase):
    def test_finalize_counts_each_run_once_and_selects_one_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "progressive-gating"
            root.mkdir()
            write_run(
                root,
                "PG-DISP",
                "P0",
                1,
                base="2026-10-19T09:00:00Z",
                port=19081,
                decision="OPEN",
                codes=["A1_EFFECTIVE_DISPOSITION_COUNT"],
                evidence="NOT_APPLICABLE",
            )
            write_run(
                root,
                "PG-DISP",
                "P1",
                1,
                base="2026-10-20T18:15:00Z",
                port=29081,
                decision="OPEN",
                codes=["A1_EFFECTIVE_DISPOSITION_COUNT"],
                evidence="NOT_APPLICABLE",
            )
            rc = finalize(Namespace(root=str(root), require_complete=False, batch=None))
            self.assertEqual(rc, 0)
            summary = __import__("json").loads((root / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["denominators"]["formal_runs_planned"], 36)
            self.assertEqual(summary["denominators"]["formal_pairs_planned"], 18)
            self.assertEqual(summary["denominators"]["calibration_pairs_planned"], 3)
            self.assertEqual(summary["formal"]["actual_runs"], 2)
            self.assertEqual(summary["formal"]["selected_pairs"], 1)
            self.assertEqual(summary["formal"]["comparable_pairs"], 1)
            self.assertEqual(summary["formal"]["included_runs"], 2)
            self.assertEqual(summary["formal"]["audit_contrast"]["pairs_with_baseline_pass"], 1)
            self.assertEqual(summary["formal"]["audit_contrast"]["p1_machine_open_total"], 1)
            self.assertEqual(summary["formal"]["audit_contrast"]["p1_open_with_expected_codes"], 1)
            self.assertTrue(summary["inclusion_relation"]["machine_decision_open_is_superset_of_evidence_status_nfi"])

            runs = read_csv(root / "runs.csv")
            self.assertEqual(len(runs), 2)
            for column in ("local_validation", "formal_batch", "selected_attempt", "included_in_formal", "included_in_calibration"):
                self.assertNotIn(column, runs[0])
            included = [row for row in runs if row["inclusion"] == "INCLUDED"]
            self.assertEqual(len(included), 2)
            self.assertEqual({row["status"] for row in included}, {"COMPLETED"})
            self.assertEqual({row["outcome_class"] for row in included}, {"AUDIT_NOT_CONFIGURED", "VALID_MACHINE_DECISION"})
            self.assertEqual({row["dev_deployed_digest"] for row in included}, {ARTIFACT_SHA})
            self.assertEqual({row["staging_deployed_digest"] for row in included}, {ARTIFACT_SHA})

            comparisons = read_csv(root / "comparisons.csv")
            self.assertEqual(len(comparisons), 1)
            for column in (
                "local_validation",
                "selected_attempt",
                "included_in_formal",
                "included_in_calibration",
                "status",
                "comparable",
                "not_comparable_reason",
            ):
                self.assertNotIn(column, comparisons[0])
            self.assertEqual(comparisons[0]["semantic_inputs_match"], "true")
            self.assertEqual(comparisons[0]["baseline_pass_and_p1_open"], "true")
            self.assertEqual(comparisons[0]["expected_codes_hit"], "true")
            self.assertEqual(comparisons[0]["expected_evidence_status_hit"], "true")
            self.assertEqual(comparisons[0]["p0_stage_gates"], "dev:PASS;qa:PASS;staging:PASS")
            self.assertEqual(verify_internal(root), 0)
            self.assertEqual(verify_internal(root, require_complete=True), 2)

    def test_incomplete_evidence_is_explicitly_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "progressive-gating"
            root.mkdir()
            rc = finalize(Namespace(root=str(root), require_complete=False, batch=None))
            self.assertEqual(rc, 0)
            runs = read_csv(root / "runs.csv")
            self.assertEqual(len(runs), 0)
            comparisons = read_csv(root / "comparisons.csv")
            self.assertEqual(len(comparisons), 0)
            summary = __import__("json").loads((root / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(len(summary["missing_evidence"]["planned_cells_without_attempt"]), 21)
            self.assertEqual(summary["missing_evidence"]["scope_batches"], [])
            self.assertEqual(summary["formal_evidence"]["missing_cells"], 18)
            self.assertEqual(summary["calibration_evidence"]["missing_cells"], 3)

    def test_formal_only_root_does_not_report_calibration_cells_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "progressive-gating"
            root.mkdir()
            write_run(
                root,
                "PG-DISP",
                "P0",
                1,
                base="2026-10-19T09:00:00Z",
                port=19081,
                decision="OPEN",
                codes=["A1_EFFECTIVE_DISPOSITION_COUNT"],
                evidence="NOT_APPLICABLE",
            )
            write_run(
                root,
                "PG-DISP",
                "P1",
                1,
                base="2026-10-20T18:15:00Z",
                port=29081,
                decision="OPEN",
                codes=["A1_EFFECTIVE_DISPOSITION_COUNT"],
                evidence="NOT_APPLICABLE",
            )
            self.assertEqual(finalize(Namespace(root=str(root), require_complete=False, batch=None)), 0)
            summary = __import__("json").loads((root / "summary.json").read_text(encoding="utf-8"))
            missing = summary["missing_evidence"]
            self.assertEqual(missing["scope_batches"], ["PG-FORMAL-01"])
            self.assertEqual(len(missing["planned_cells_without_attempt"]), 17)
            self.assertEqual({cell["batch"] for cell in missing["planned_cells_without_attempt"]}, {"PG-FORMAL-01"})

    def test_calibration_only_root_does_not_report_formal_cells_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "progressive-gating"
            root.mkdir()
            for arm, base, port in (("P0", "2026-10-19T09:00:00Z", 19081), ("P1", "2026-10-20T18:15:00Z", 29081)):
                write_run(
                    root,
                    "PG-DISP",
                    arm,
                    1,
                    base=base,
                    port=port,
                    decision="OPEN",
                    codes=["A1_EFFECTIVE_DISPOSITION_COUNT"],
                    evidence="NOT_APPLICABLE",
                )
            for path in root.glob("runs/*/run_meta.json"):
                data = __import__("json").loads(path.read_text(encoding="utf-8"))
                data.update({"batch": "PG-CAL-01", "mode": "calibration", "calibration": True})
                path.write_text(__import__("json").dumps(data), encoding="utf-8")
            self.assertEqual(finalize(Namespace(root=str(root), require_complete=False, batch=None)), 0)
            summary = __import__("json").loads((root / "summary.json").read_text(encoding="utf-8"))
            missing = summary["missing_evidence"]
            self.assertEqual(missing["scope_batches"], ["PG-CAL-01"])
            self.assertEqual(
                {(cell["batch"], cell["scenario"]) for cell in missing["planned_cells_without_attempt"]},
                {("PG-CAL-01", "PG-N01"), ("PG-CAL-01", "PG-ART")},
            )


if __name__ == "__main__":
    unittest.main()

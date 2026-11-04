from __future__ import annotations

import copy
import json
import unittest

from tests_pg.pg_fixtures import ARTIFACT_SHA, audit_for
from tools.pg_case import semantic_sha
from tools.pg_common import ALL_SCENARIOS, load_designs
from verifier.closure_audit import verify


class DesignShapeTests(unittest.TestCase):
    def setUp(self):
        self.designs = load_designs()

    def test_all_six_designs_are_present(self):
        self.assertEqual(set(self.designs), set(ALL_SCENARIOS))
        self.assertEqual(len(self.designs), 6)
        self.assertEqual(
            {scenario: self.designs[scenario]["scenario_family"] for scenario in ALL_SCENARIOS},
            {
                "PG-N01": "N01",
                "PG-ART": "B01",
                "PG-QA": "B02",
                "PG-DISP": "C01",
                "PG-SEQ": "C02",
                "PG-INFO": "I01",
            },
        )

    def test_baseline_controls_do_not_require_audit_cases(self):
        for scenario in ("PG-ART", "PG-QA"):
            design = self.designs[scenario]
            self.assertEqual(design["type"], "BASELINE_BLOCK")
            self.assertFalse(design["requires_audit_case"])
            self.assertEqual(design["audit_expected"]["P0"], "NOT_RUN_UPSTREAM_BLOCKED")
            self.assertEqual(design["audit_expected"]["P1"], "NOT_RUN_UPSTREAM_BLOCKED")
            self.assertEqual(design["baseline_expected"]["first_failure_stage"], "qa")
            self.assertEqual(design["baseline_expected"]["staging"], "NOT_DEPLOYED")

    def test_injection_record_declares_version_and_platform_rule(self):
        from tools.pg_run import _injection_record

        record = _injection_record(
            self.designs["PG-N01"],
            {"stages": {}},
            None,
            {"artifact": {"sha256": "unused"}},
            None,
        )
        self.assertEqual(record["schema"], "pg-injection-1")
        self.assertEqual(record["injector_version"], "pg-inject-1.0.0")
        self.assertEqual(record["change_point"], self.designs["PG-N01"]["injection"])
        self.assertFalse(record["platform_error"])
        self.assertEqual(record["baseline_condition_impact"], "NONE")

    def test_audit_scenarios_declare_expected_diagnostics(self):
        expected = {
            "PG-N01": ("CLOSED", "NOT_APPLICABLE", []),
            "PG-DISP": ("OPEN", "NOT_APPLICABLE", ["A1_EFFECTIVE_DISPOSITION_COUNT"]),
            "PG-SEQ": ("OPEN", "OPEN", ["A2_REQUIREMENT_TEMPORAL_ORDER"]),
            "PG-INFO": ("OPEN", "NFI", ["A1_SCOPE_NOT_ATTESTED"]),
        }
        for scenario, (decision, evidence, codes) in expected.items():
            with self.subTest(scenario=scenario):
                design = self.designs[scenario]
                self.assertTrue(design["requires_audit_case"])
                self.assertEqual(design["audit_expected"]["P0"], "NOT_CONFIGURED")
                self.assertEqual(design["audit_expected"]["P1"], decision)
                self.assertEqual(design["audit_expected"]["evidence_status"], evidence)
                self.assertEqual(design["audit_expected"]["codes"], codes)


class VerifierVerdictTests(unittest.TestCase):
    def _verdict(self, scenario, base, port):
        bundle, _, _ = audit_for(self.designs[scenario], "P0", base, port)
        return bundle, verify(bundle["case"])

    def setUp(self):
        self.designs = load_designs()

    def test_normal_release_is_closed(self):
        bundle, result = self._verdict("PG-N01", "2026-10-19T09:00:00Z", 19081)
        self.assertEqual(result["machine_decision"], "CLOSED")
        self.assertEqual(result["evidence_status"], "NOT_APPLICABLE")
        self.assertEqual(result["failure_codes"], [])
        self.assertEqual(len(bundle["case"]["raw_signals"]), 3)

    def test_missing_effective_disposition_is_open_and_raw_signal_survives(self):
        bundle, result = self._verdict("PG-DISP", "2026-10-19T09:00:00Z", 19081)
        case = bundle["case"]
        self.assertEqual(result["machine_decision"], "OPEN")
        self.assertEqual(result["evidence_status"], "NOT_APPLICABLE")
        self.assertIn("A1_EFFECTIVE_DISPOSITION_COUNT", result["failure_codes"])
        self.assertEqual(result["failure_codes"], ["A1_EFFECTIVE_DISPOSITION_COUNT"])
        self.assertIn("health:qa", [row["signal_id"] for row in case["raw_signals"]])
        self.assertNotIn("health:qa", [row["signal_id"] for row in case["dispositions"]])
        self.assertEqual(bundle["missing_dispositions"], ["health:qa"])
        inventory = bundle["collector"]["bounded_inventory"]
        self.assertEqual(inventory["signal_ids"], ["health:dev", "health:qa", "health:staging"])
        self.assertEqual(inventory["missing_dispositions"], ["health:qa"])
        self.assertFalse(inventory["empty_dispositions"])

    def test_temporal_order_violation_is_open_without_rewriting_history(self):
        bundle, result = self._verdict("PG-SEQ", "2026-10-19T09:00:00Z", 19081)
        case = bundle["case"]
        finding = case["findings"][0]
        self.assertLess(finding["requirement_link"]["accepted_at"], finding["observed_at"])
        self.assertEqual(result["machine_decision"], "OPEN")
        self.assertEqual(result["evidence_status"], "OPEN")
        self.assertEqual(result["failure_codes"], ["A2_REQUIREMENT_TEMPORAL_ORDER"])
        self.assertEqual(case["snapshot"]["current_payload"], case["snapshot"]["frozen_payload"])
        self.assertNotIn("F-PG-01", json.dumps(case["snapshot"]["frozen_payload"], sort_keys=True))
        history = bundle["collector"]["history_successor"]
        self.assertTrue(history["historical_snapshot_unchanged"])
        self.assertEqual(history["finding_ids_visible_after_cutoff"], ["F-PG-01"])

    def test_synthetic_records_are_marked_scripted(self):
        bundle, _, _ = audit_for(self.designs["PG-SEQ"], "P0", "2026-10-19T09:00:00Z", 19081)
        provenance = bundle["collector"]["provenance"]
        self.assertEqual(provenance["candidates_findings"]["type"], "scripted")
        self.assertEqual(provenance["finding_times"]["type"], "scripted")
        self.assertEqual(provenance["audit_time"]["type"], "scripted")

    def test_missing_scope_attestation_is_nfi_and_not_normalized_to_empty(self):
        bundle, result = self._verdict("PG-INFO", "2026-10-19T09:00:00Z", 19081)
        case = bundle["case"]
        attestation = case["scope"]["collector_attestation"]
        self.assertNotIn("query_rule_hash", attestation)
        self.assertTrue(attestation["complete"])
        self.assertEqual(attestation["collector_version"], "1.0.0")
        self.assertIn("inventory_sha256", attestation)
        self.assertEqual(len(case["raw_signals"]), 3)
        self.assertEqual(result["machine_decision"], "OPEN")
        self.assertEqual(result["evidence_status"], "NFI")
        self.assertEqual(result["failure_codes"], ["A1_SCOPE_NOT_ATTESTED"])
        self.assertEqual(bundle["missing_fields"], ["collector_attestation.query_rule_hash"])
        self.assertEqual(
            bundle["collector"]["provenance"]["collector_attestation"]["type"],
            "unavailable",
        )

    def test_artifact_identity_is_carried_by_every_stage(self):
        bundle, _, _ = audit_for(self.designs["PG-N01"], "P0", "2026-10-19T09:00:00Z", 19081)
        case = bundle["case"]
        self.assertEqual(case["artifact"]["expected_sha256"], "sha256:" + ARTIFACT_SHA)
        self.assertEqual(case["artifact"]["deployed_sha256"], "sha256:" + ARTIFACT_SHA)
        self.assertEqual({row["deployed_sha256"] for row in bundle["collector"]["native_run"]["stages"]}, {ARTIFACT_SHA})


class SemanticProjectionTests(unittest.TestCase):
    def setUp(self):
        self.design = load_designs()["PG-N01"]

    def test_projection_is_invariant_to_wall_clock_and_host_port(self):
        p0, _, _ = audit_for(self.design, "P0", "2026-10-19T09:00:00Z", 19081)
        p1, _, _ = audit_for(self.design, "P1", "2026-10-20T15:30:00Z", 29081)
        self.assertNotEqual(p0["case"]["source_cutoff"], p1["case"]["source_cutoff"])
        self.assertNotEqual(p0["case"]["raw_signals"][0]["event_time"], p1["case"]["raw_signals"][0]["event_time"])
        self.assertEqual(semantic_sha(p0["case"]), semantic_sha(p1["case"]))

    def test_projection_changes_when_a_decision_input_changes(self):
        p0, _, _ = audit_for(self.design, "P0", "2026-10-19T09:00:00Z", 19081)
        changed = copy.deepcopy(p0["case"])
        changed["gates"][0]["status"] = "FAIL"
        self.assertNotEqual(semantic_sha(p0["case"]), semantic_sha(changed))

    def test_scripted_finding_offsets_are_equal_across_arms(self):
        design = load_designs()["PG-SEQ"]
        p0, _, _ = audit_for(design, "P0", "2026-10-19T09:00:00Z", 19081)
        p1, _, _ = audit_for(design, "P1", "2026-10-21T21:45:00Z", 29081)
        f0 = p0["case"]["findings"][0]
        f1 = p1["case"]["findings"][0]
        from tools.pg_common import parse_ts
        cutoff0 = parse_ts(p0["case"]["source_cutoff"])
        cutoff1 = parse_ts(p1["case"]["source_cutoff"])
        self.assertNotEqual(p0["case"]["source_cutoff"], p1["case"]["source_cutoff"])
        self.assertEqual(int((parse_ts(f0["observed_at"]) - cutoff0).total_seconds()), 7200)
        self.assertEqual(int((parse_ts(f1["observed_at"]) - cutoff1).total_seconds()), 7200)
        self.assertEqual(semantic_sha(p0["case"]), semantic_sha(p1["case"]))


if __name__ == "__main__":
    unittest.main()

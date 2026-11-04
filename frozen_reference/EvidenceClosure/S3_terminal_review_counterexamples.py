"""Counterexamples independently specified in the pre-publication reviews.

The cases are encoded by the authors for regression.  Their provenance does
not make the resulting run an independent empirical evaluation.
"""
import hashlib
import unittest

from S3_test_analyze_evidence import (
    add_successor_coverage,
    analyze,
    analyzer,
    append,
    closure,
    edit,
    error_codes,
    refresh_coverage,
    refresh_snapshot_digests,
    remove,
    rows,
    write,
    workspace,
)
from S3_v18_semantic_tests import add_later_requirement


def add_excluded_candidate(root, *, reviewed_by="synthetic-reviewer", reviewed_at="2026-01-06T13:45:00Z"):
    append(root / "incident_candidates.csv", {
        "closure_id": "CL-01-complete",
        "candidate_id": "S1-EXCLUDED-1",
        "deployment_id": "S1-DEP",
        "service_id": "service-1",
        "environment": "production",
        "observed_at_utc": "2026-01-06T13:00:00Z",
        "admitted_at_utc": "2026-01-06T13:10:00Z",
        "source_batch_id": "S1-DEP-BATCH-1",
        "signal_digest_sha256": "sha256:" + hashlib.sha256(b"S1-EXCLUDED-1").hexdigest(),
        "status": "excluded",
        "exclusion_reason_code": "monitoring_false_positive",
        "exclusion_rationale": "synthetic exclusion for a temporal and separation-of-duties test",
        "decision_role": "incident_triager",
        "decided_by": "synthetic-triager",
        "decided_at_utc": "2026-01-06T13:30:00Z",
        "reviewed_by": reviewed_by,
        "reviewed_at_utc": reviewed_at,
    })
    refresh_coverage(root, "CL-01-complete")


class TerminalReviewCounterexamples(unittest.TestCase):
    def setUp(self):
        self.temp, self.root, self.policy = workspace()
        self.addCleanup(self.temp.cleanup)

    def result(self):
        refresh_snapshot_digests(self.root, self.policy)
        return analyze(self.root, self.policy)

    def test_historical_closed_snapshot_before_window_end_is_rejected(self):
        append(self.root / "snapshots.csv", {
            "closure_id": "CL-01-complete",
            "snapshot_id": "S1-SNAP-EARLY",
            "release_decision_id": "S1-REL",
            "evaluated_at_utc": "2026-01-05T15:00:00Z",
            "supersedes_snapshot_id": "",
            "declared_status": "closed_as_of",
        })
        edit(
            self.root / "snapshots.csv",
            lambda row: row["snapshot_id"] == "S1-SNAP-1",
            {"supersedes_snapshot_id": "S1-SNAP-EARLY"},
        )
        failures = closure(self.result(), "CL-01-complete")["failure_codes"]
        self.assertIn("historical_snapshot_observation_window_open", failures)
        self.assertIn("historical_snapshot_invalid", failures)

    def test_historical_snapshot_rejects_post_cutoff_selected_path_evidence(self):
        edit(
            self.root / "edges.csv",
            lambda row: row["edge_id"] == "S1-E2",
            {"event_time_utc": "2026-01-06T14:01:00Z"},
        )
        failures = closure(self.result(), "CL-01-complete")["failure_codes"]
        self.assertIn("historical_snapshot_missing_release_path", failures)

    def test_complete_coverage_cannot_precede_window_end(self):
        edit(
            self.root / "candidate_coverage.csv",
            lambda row: row["closure_id"] == "CL-01-complete",
            {"attested_at_utc": "2026-01-05T15:00:00Z"},
        )
        self.assertIn("coverage_attested_before_window_end", error_codes(self.result()))

    def test_raw_to_import_counts_must_reconcile(self):
        fields = {"raw_signal_count": "100", "imported_candidate_count": "0", "noncandidate_count": "0", "rejected_count": "0"}
        edit(self.root / "candidate_coverage.csv", lambda row: row["closure_id"] == "CL-01-complete", fields)
        # Re-signing the inconsistent statement cannot make its arithmetic true.
        header, records = rows(self.root / "candidate_coverage.csv")
        for record in records:
            if record["closure_id"] == "CL-01-complete":
                record["reconciliation_digest_sha256"] = "sha256:" + analyzer.reconciliation_digest(record)
        write(self.root / "candidate_coverage.csv", header, records)
        self.assertIn("candidate_signal_reconciliation_mismatch", error_codes(self.result()))

    def test_raw_inventory_item_deletion_is_rejected(self):
        remove(self.root / "raw_signal_inventory.csv", lambda row: row["raw_signal_id"] == "S5-CAND-1-RAW")
        self.assertIn("raw_signal_inventory_count_mismatch", error_codes(self.result()))

    def test_query_rule_change_cannot_rewrite_an_existing_snapshot(self):
        refresh_snapshot_digests(self.root, self.policy)
        edit(
            self.root / "candidate_coverage.csv",
            lambda row: row["closure_id"] == "CL-05-linked_incident",
            {"query_rule_hash": "sha256:" + hashlib.sha256(b"changed query rule").hexdigest()},
        )
        header, coverages = rows(self.root / "candidate_coverage.csv")
        for coverage in coverages:
            if coverage["closure_id"] == "CL-05-linked_incident":
                coverage["reconciliation_digest_sha256"] = "sha256:" + analyzer.reconciliation_digest(coverage)
        write(self.root / "candidate_coverage.csv", header, coverages)
        failures = closure(analyze(self.root, self.policy), "CL-05-linked_incident")["failure_codes"]
        self.assertIn("snapshot_input_manifest_digest_mismatch", failures)

    def test_reconciliation_digest_binds_collector_and_query_metadata(self):
        edit(
            self.root / "candidate_coverage.csv",
            lambda row: row["closure_id"] == "CL-05-linked_incident",
            {"collector_version": "tampered-version"},
        )
        self.assertIn("candidate_reconciliation_digest_mismatch", error_codes(self.result()))

    def test_raw_inventory_digest_detects_disposition_tampering(self):
        edit(
            self.root / "raw_signal_inventory.csv",
            lambda row: row["raw_signal_id"] == "S5-CAND-1-RAW",
            {"disposition_rationale": "tampered rationale"},
        )
        self.assertIn("raw_inventory_digest_mismatch", error_codes(self.result()))

    def test_raw_inventory_digest_is_row_order_invariant(self):
        for suffix, disposition, reason in (
            ("A", "noncandidate", "non_incident_signal"),
            ("B", "rejected", "malformed_signal"),
        ):
            append(self.root / "raw_signal_inventory.csv", {
                "closure_id": "CL-05-linked_incident",
                "coverage_id": "S5-DEP-COVERAGE-1",
                "raw_signal_id": f"S5-RAW-{suffix}",
                "source_batch_id": "S5-DEP-BATCH-1",
                "signal_digest_sha256": "sha256:" + hashlib.sha256(f"S5-RAW-{suffix}".encode()).hexdigest(),
                "observed_at_utc": "2026-01-09T17:00:00Z",
                "disposition": disposition,
                "disposition_reason_code": reason,
                "disposition_rationale": "synthetic explicit filtering decision",
                "disposition_decided_by": "synthetic-operations-owner",
                "disposition_decided_at_utc": "2026-01-09T17:10:00Z",
            })
        refresh_coverage(self.root, "CL-05-linked_incident")
        refresh_snapshot_digests(self.root, self.policy)
        header, inventory = rows(self.root / "raw_signal_inventory.csv")
        write(self.root / "raw_signal_inventory.csv", header, list(reversed(inventory)))
        self.assertEqual(analyze(self.root, self.policy)["schema_errors"], [])

    def test_candidate_outside_coverage_window_is_rejected(self):
        edit(self.root / "release_manifest.csv", lambda row: row["closure_id"] == "CL-05-linked_incident", {"evaluation_time_utc": "2026-01-10T20:00:00Z"})
        edit(self.root / "incident_candidates.csv", lambda row: row["closure_id"] == "CL-05-linked_incident", {
            "observed_at_utc": "2026-01-10T15:00:00Z",
            "admitted_at_utc": "2026-01-10T15:10:00Z",
            "decided_at_utc": "2026-01-10T15:30:00Z",
            "source_batch_id": "S5-DEP-BATCH-2",
            "reopens_snapshot_id": "S5-SNAP-1",
        })
        append(self.root / "snapshots.csv", {
            "closure_id": "CL-05-linked_incident",
            "snapshot_id": "S5-SNAP-2",
            "release_decision_id": "S5-REL",
            "evaluated_at_utc": "2026-01-10T20:00:00Z",
            "supersedes_snapshot_id": "S5-SNAP-1",
            "declared_status": "closed_as_of",
        })
        add_successor_coverage(self.root, "CL-05-linked_incident", "S5-SNAP-2", "2026-01-10T20:00:00Z")
        refresh_coverage(self.root, "CL-05-linked_incident")
        self.assertIn("candidate_observed_outside_coverage_window", closure(self.result(), "CL-05-linked_incident")["failure_codes"])

    def test_candidate_admission_after_coverage_attestation_is_rejected(self):
        edit(
            self.root / "incident_candidates.csv",
            lambda row: row["closure_id"] == "CL-05-linked_incident",
            {"admitted_at_utc": "2026-01-10T14:01:00Z", "decided_at_utc": "2026-01-10T14:02:00Z"},
        )
        self.assertIn("candidate_admitted_after_coverage_attestation", closure(self.result(), "CL-05-linked_incident")["failure_codes"])

    def test_coverage_version_chain_cannot_skip_the_root(self):
        edit(
            self.root / "candidate_coverage.csv",
            lambda row: row["closure_id"] == "CL-01-complete",
            {"coverage_version": "2"},
        )
        self.assertIn("invalid_candidate_coverage_chain", error_codes(self.result()))
        edit(self.root / "candidate_coverage.csv", lambda row: row["closure_id"] == "CL-01-complete", {"coverage_version": "1", "service_id": "wrong-service"})
        self.assertIn("candidate_coverage_scope_mismatch", closure(self.result(), "CL-01-complete")["failure_codes"])

    def test_candidate_decision_cannot_precede_admission(self):
        edit(
            self.root / "incident_candidates.csv",
            lambda row: row["closure_id"] == "CL-05-linked_incident",
            {"admitted_at_utc": "2026-01-09T17:00:00Z"},
        )
        self.assertIn("candidate_decision_before_admission", error_codes(self.result()))

    def test_candidate_admission_cannot_precede_observation(self):
        edit(
            self.root / "incident_candidates.csv",
            lambda row: row["closure_id"] == "CL-05-linked_incident",
            {"admitted_at_utc": "2026-01-09T15:59:00Z"},
        )
        self.assertIn("candidate_admission_before_observation", error_codes(self.result()))

    def test_exclusion_review_after_cutoff_is_rejected(self):
        add_excluded_candidate(self.root, reviewed_at="2026-01-06T15:00:00Z")
        self.assertIn("incident_candidate_after_cutoff", closure(self.result(), "CL-01-complete")["failure_codes"])

    def test_exclusion_decider_and_reviewer_must_differ(self):
        append(self.policy.parent / "S4_principal_registry.csv", {"registry_version": "V21.0", "alias": "synthetic-triager-alias", "principal_id": "principal.synthetic.triager", "effective_at_utc": "2025-01-01T00:00:00Z"})
        add_excluded_candidate(self.root, reviewed_by="synthetic-triager-alias")
        self.assertIn("candidate_review_separation_failure", error_codes(self.result()))
        append(self.policy.parent / "S4_principal_registry.csv", {"registry_version": "V21.0", "alias": "synthetic-triager-alias", "principal_id": "principal.synthetic.other", "effective_at_utc": "2025-01-01T00:00:00Z"})
        self.assertIn("principal_alias_conflict", error_codes(self.result()))

    def test_exclusion_review_cannot_precede_decision(self):
        add_excluded_candidate(self.root, reviewed_at="2026-01-06T13:20:00Z")
        self.assertIn("missing_candidate_exclusion_review", error_codes(self.result()))

    def test_candidate_decider_requires_service_scoped_authority(self):
        edit(
            self.policy.parent / "S4_candidate_review_authorizations.csv",
            lambda row: row["subject"] == "synthetic-triager",
            {"service_scope": "service-2"},
        )
        self.assertIn("unauthorized_candidate_decider", error_codes(self.result()))
        edit(self.policy.parent / "S4_candidate_review_authorizations.csv", lambda row: row["subject"] == "synthetic-triager", {"service_scope": "*"})
        edit(self.root / "incident_candidates.csv", lambda row: row["closure_id"] == "CL-05-linked_incident", {"decided_by": "unknown-decider"})
        self.assertIn("unknown_principal_alias", error_codes(self.result()))

    def test_exclusion_reviewer_authority_must_be_effective(self):
        edit(
            self.policy.parent / "S4_candidate_review_authorizations.csv",
            lambda row: row["subject"] == "synthetic-reviewer",
            {"retired_at_utc": "2026-01-06T13:40:00Z"},
        )
        add_excluded_candidate(self.root)
        self.assertIn("unauthorized_candidate_reviewer", error_codes(self.result()))

    def test_exclusion_reviewer_authority_is_service_scoped(self):
        edit(
            self.policy.parent / "S4_candidate_review_authorizations.csv",
            lambda row: row["subject"] == "synthetic-reviewer",
            {"service_scope": "service-2"},
        )
        add_excluded_candidate(self.root)
        self.assertIn("unauthorized_candidate_reviewer", error_codes(self.result()))

    def test_logical_requirement_identity_reaches_earlier_version_check(self):
        add_later_requirement(self.root)
        append(self.root / "nodes.csv", {
            "closure_id": "CL-00-history",
            "node_id": "S7-REQ-OLD",
            "logical_work_item_id": "S7-REQ-NEW",
            "node_type": "WorkItem",
            "work_item_kind": "Requirement",
            "service_id": "service-5",
            "version": "0",
            "event_time_utc": "2026-01-08T12:00:00Z",
            "created_at_utc": "2026-01-08T10:00:00Z",
            "accepted_at_utc": "2026-01-08T12:00:00Z",
            "owner": "requirement-owner",
            "status": "accepted",
            "accepted_revision": "r0",
            "metadata_json": "{}",
        })
        self.assertIn("retrospective_requirement_backfill", closure(self.result(), "CL-05-linked_incident")["failure_codes"])

    def test_snapshot_input_digest_detects_silent_history_rewrite(self):
        refresh_snapshot_digests(self.root, self.policy)
        edit(
            self.root / "snapshots.csv",
            lambda row: row["snapshot_id"] == "S1-SNAP-1",
            {"input_manifest_digest": "sha256:" + "0" * 64},
        )
        self.assertIn("snapshot_input_manifest_digest_mismatch", closure(analyze(self.root, self.policy), "CL-01-complete")["failure_codes"])
        edit(self.policy.parent / "S4_principal_registry.csv", lambda row: row["alias"] == "synthetic-triager", {"principal_id": "principal.rebound.without.successor"})
        self.assertIn("snapshot_input_manifest_digest_mismatch", closure(analyze(self.root, self.policy), "CL-01-complete")["failure_codes"])

    def test_invalid_input_still_reports_data_quality(self):
        edit(self.root / "nodes.csv", lambda row: row["node_id"] == "S1-REQ", {"accepted_at_utc": ""})
        result = self.result()
        self.assertFalse(result["valid_input"])
        self.assertIsNone(result["metrics"])
        self.assertTrue(result["data_quality"]["outcome_metrics_suppressed"])
        self.assertGreater(result["data_quality"]["required_values"]["missing"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

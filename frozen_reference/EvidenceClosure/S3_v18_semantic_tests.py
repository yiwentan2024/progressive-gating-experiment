"""Semantic counterexamples for collection, lifecycle, reopening, and output."""
import csv
import unittest

from S3_test_analyze_evidence import (
    analyze,
    append,
    closure,
    edit,
    error_codes,
    add_successor_coverage,
    refresh_coverage,
    refresh_snapshot_digests,
    remove,
    workspace,
)


def add_later_requirement(root, *, created="2026-01-12T09:00:00Z", accepted="2026-01-12T10:00:00Z", approved="2026-01-12T12:00:00Z"):
    append(root / "nodes.csv", {
        "closure_id": "CL-07-followup", "node_id": "S7-REQ-NEW", "node_type": "WorkItem",
        "logical_work_item_id": "S7-REQ-NEW",
        "work_item_kind": "Requirement", "service_id": "service-5", "version": "1",
        "event_time_utc": accepted, "created_at_utc": created, "accepted_at_utc": accepted,
        "owner": "requirement-owner", "status": "accepted", "accepted_revision": "r1", "metadata_json": "{}",
    })
    append(root / "nodes.csv", {
        "closure_id": "CL-07-followup", "node_id": "S7-REL", "node_type": "ReleaseDecision",
        "service_id": "service-5", "version": "1", "policy_version": "p18.0",
        "event_time_utc": approved, "owner": "release-owner", "status": "approved",
        "release_approved": "true", "metadata_json": "{}",
    })
    append(root / "edges.csv", {
        "closure_id": "CL-05-linked_incident", "edge_id": "S5-FND-CREATES-S7-REQ",
        "edge_type": "creates_requirement", "source_node_id": "S5-FND", "target_node_id": "S7-REQ-NEW",
        "event_time_utc": created, "source_version": "1", "target_version": "1",
    })


class SemanticCounterexamples(unittest.TestCase):
    def setUp(self):
        self.temp, self.root, self.policy = workspace()
        self.addCleanup(self.temp.cleanup)

    def result(self):
        refresh_snapshot_digests(self.root, self.policy)
        return analyze(self.root, self.policy)

    def test_zero_candidate_attestation_is_valid(self):
        result = self.result()
        self.assertTrue(closure(result, "CL-01-complete")["closed_as_of"])
        with (self.root / "incident_candidates.csv").open(encoding="utf-8", newline="") as source:
            self.assertFalse(any(row["closure_id"] == "CL-01-complete" for row in csv.DictReader(source)))

    def test_collection_count_mismatch_blocks_closure(self):
        edit(self.root / "candidate_coverage.csv", lambda row: row["closure_id"] == "CL-01-complete", {"raw_signal_count": "1", "imported_candidate_count": "1"})
        self.assertIn("invalid_candidate_collection_attestation", closure(self.result(), "CL-01-complete")["failure_codes"])

    def test_collection_digest_mismatch_blocks_closure(self):
        edit(self.root / "candidate_coverage.csv", lambda row: row["closure_id"] == "CL-05-linked_incident", {"candidate_digest_sha256": "sha256:" + "0" * 64})
        self.assertIn("invalid_candidate_collection_attestation", closure(self.result(), "CL-05-linked_incident")["failure_codes"])

    def test_candidate_batch_without_attestation_blocks_closure(self):
        edit(self.root / "incident_candidates.csv", lambda row: row["closure_id"] == "CL-05-linked_incident", {"source_batch_id": "UNATTESTED-BATCH"})
        failures = closure(self.result(), "CL-05-linked_incident")["failure_codes"]
        self.assertIn("candidate_without_collection_attestation", failures)

    def test_silent_candidate_deletion_does_not_hide_incident(self):
        remove(self.root / "incident_candidates.csv", lambda row: row["closure_id"] == "CL-05-linked_incident")
        refresh_coverage(self.root, "CL-05-linked_incident")
        self.assertIn("incident_without_unique_attributed_candidate", closure(self.result(), "CL-05-linked_incident")["failure_codes"])

    def test_requirement_lifecycle_times_are_required(self):
        edit(self.root / "nodes.csv", lambda row: row["node_id"] == "S1-REQ", {"created_at_utc": "", "accepted_at_utc": ""})
        codes = error_codes(self.result())
        self.assertIn("missing_requirement_lifecycle_time", codes)
        self.assertFalse(self.result()["valid_input"])

    def test_requirement_acceptance_cannot_precede_creation(self):
        edit(self.root / "nodes.csv", lambda row: row["node_id"] == "S1-REQ", {"created_at_utc": "2026-01-05T09:00:00Z", "accepted_at_utc": "2026-01-05T08:00:00Z"})
        self.assertIn("requirement_acceptance_before_creation", error_codes(self.result()))

    def test_later_requirement_must_be_accepted_before_target_release_approval(self):
        remove(self.root / "edges.csv", lambda row: row["edge_id"] == "S5-FND-REQ")
        add_later_requirement(self.root, accepted="2026-01-12T13:00:00Z", approved="2026-01-12T12:00:00Z")
        self.assertIn("retrospective_requirement_backfill", closure(self.result(), "CL-05-linked_incident")["failure_codes"])

    def test_existing_and_later_requirement_paths_may_coexist(self):
        add_later_requirement(self.root)
        source = closure(self.result(), "CL-05-linked_incident")
        self.assertFalse(source["closed_as_of"])
        self.assertIn("later_requirement_target_episode_incomplete", source["failure_codes"])

    def test_deprecated_finding_derived_from_relation_is_rejected(self):
        edit(self.root / "edges.csv", lambda row: row["edge_id"] == "S5-FND-REQ", {"edge_type": "derived_from"})
        self.assertIn("deprecated_finding_requirement_edge", error_codes(self.result()))

    def test_late_candidate_admission_requires_direct_successor(self):
        edit(self.root / "incident_candidates.csv", lambda row: row["closure_id"] == "CL-05-linked_incident", {"admitted_at_utc": "2026-01-10T15:00:00Z"})
        failures = closure(self.result(), "CL-05-linked_incident")["failure_codes"]
        self.assertIn("late_candidate_admission_without_reopen", failures)

    def test_late_candidate_admission_with_one_direct_successor_is_valid(self):
        edit(self.root / "release_manifest.csv", lambda row: row["closure_id"] == "CL-05-linked_incident", {"evaluation_time_utc": "2026-01-10T20:00:00Z"})
        edit(self.root / "incident_candidates.csv", lambda row: row["closure_id"] == "CL-05-linked_incident", {
            "admitted_at_utc": "2026-01-10T15:00:00Z", "source_batch_id": "S5-DEP-BATCH-2",
            "decided_at_utc": "2026-01-10T15:30:00Z", "reopens_snapshot_id": "S5-SNAP-1",
        })
        append(self.root / "snapshots.csv", {
            "closure_id": "CL-05-linked_incident", "snapshot_id": "S5-SNAP-2",
            "release_decision_id": "S5-REL", "evaluated_at_utc": "2026-01-10T20:00:00Z",
            "supersedes_snapshot_id": "S5-SNAP-1", "declared_status": "closed_as_of",
        })
        add_successor_coverage(self.root, "CL-05-linked_incident", "S5-SNAP-2", "2026-01-10T20:00:00Z")
        refresh_coverage(self.root, "CL-05-linked_incident")
        self.assertTrue(closure(self.result(), "CL-05-linked_incident")["closed_as_of"])

    def test_external_output_uses_closed_as_of_and_reports_completeness(self):
        result = self.result()
        self.assertNotIn("closed", result["closure_results"][0])
        self.assertIn("closed_as_of", result["closure_results"][0])
        self.assertIn("data_quality", result)
        self.assertEqual(result["data_quality"]["required_values"]["estimate"], 1.0)
        self.assertEqual(result["data_quality"]["candidate_coverage"]["estimate"], 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

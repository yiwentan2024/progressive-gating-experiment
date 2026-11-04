"""Review-derived adversarial cases. Independent human authorship is not claimed."""
import subprocess
import sys
import unittest
from S3_test_analyze_evidence import HERE, SCHEMA, add_late_incident, add_retry, add_successor_coverage, analyze, append, closure, edit, error_codes, refresh_snapshot_digests, remove, rows, workspace


def make_exception_temporally_valid(root):
    edit(root / "exceptions.csv", lambda r: r["exception_id"] == "S4-EX", {"expiry_time_utc": "2026-01-08T14:00:00Z", "revoked_at_utc": ""})
    edit(root / "snapshots.csv", lambda r: r["closure_id"] == "CL-04-expired_exception", {"declared_status": "closed_as_of"})


class ReviewDerivedAdversarialTests(unittest.TestCase):
    def setUp(self): self.temp,self.root,self.policy=workspace(); self.addCleanup(self.temp.cleanup)
    def result(self):
        refresh_snapshot_digests(self.root, self.policy)
        return analyze(self.root,self.policy)

    def test_finding_cannot_derive_from_unrelated_requirement(self):
        edit(self.root/"edges.csv",lambda r:r["edge_id"]=="S5-FND-REQ",{"target_node_id":"S1-REQ"})
        self.assertIn("finding_requirement_outside_release",closure(self.result(),"CL-05-linked_incident")["failure_codes"])

    def test_late_attribution_not_late_opening_triggers_reopen(self):
        add_late_incident(self.root,reopen=False); self.assertIn("late_attribution_without_reopen_snapshot",closure(self.result(),"CL-01-complete")["failure_codes"])

    def test_forged_second_snapshot_does_not_satisfy_reopen(self):
        add_late_incident(self.root,reopen=True); edit(self.root/"snapshots.csv",lambda r:r["snapshot_id"]=="S1-SNAP-2",{"supersedes_snapshot_id":"S5-SNAP-1"})
        self.assertIn("invalid_snapshot_supersession",error_codes(self.result()))

    def test_snapshot_cycle_or_self_supersession_is_rejected(self):
        edit(self.root/"snapshots.csv",lambda r:r["snapshot_id"]=="S1-SNAP-1",{"supersedes_snapshot_id":"S1-SNAP-1"})
        self.assertIn("snapshot_chain_missing_root",error_codes(self.result()))

    def test_gate_row_cannot_disagree_with_graph_edge(self):
        edit(self.root/"gate_evaluations.csv",lambda r:r["closure_id"]=="CL-01-complete" and r["gate_id"]=="G4",{"target_node_id":"S1-CHG"})
        self.assertIn("gate_edge_mismatch",error_codes(self.result()))

    def test_incident_and_exception_rows_cannot_disagree_with_edges(self):
        edit(self.root/"incidents.csv",lambda r:r["closure_id"]=="CL-05-linked_incident",{"deployment_id":"S5-REL"}); self.assertIn("incident_edge_mismatch",error_codes(self.result()))
        edit(self.root/"exceptions.csv",lambda r:True,{"gate_evaluation_id":"S4-GE-G5"}); self.assertIn("exception_edge_mismatch",error_codes(self.result()))

    def test_retry_same_time_is_rejected(self):
        add_retry(self.root,evaluated="2026-01-05T09:15:00Z"); self.assertIn("nonmonotonic_gate_retry_time",error_codes(self.result()))

    def test_retry_cannot_change_policy_or_phase(self):
        add_retry(self.root,policy="wrong",phase="post_deployment"); self.assertIn("unauthorized_gate_retry_change",error_codes(self.result()))

    def test_snapshot_declared_closed_cannot_override_computed_open(self):
        edit(self.root/"snapshots.csv",lambda r:r["closure_id"]=="CL-03-failed_gate",{"declared_status":"closed_as_of"})
        self.assertIn("snapshot_status_mismatch",closure(self.result(),"CL-03-failed_gate")["failure_codes"])
        temp, root, policy = workspace(); self.addCleanup(temp.cleanup)
        edit(root / "snapshots.csv", lambda r: r["snapshot_id"] == "S1-SNAP-1", {"declared_status": "open"})
        refresh_snapshot_digests(root, policy)
        historical = closure(analyze(root, policy), "CL-01-complete")
        self.assertIn("historical_snapshot_status_mismatch", historical["failure_codes"])

    def test_posthoc_gate_reclassification_is_schema_error(self):
        edit(self.root/"gate_evaluations.csv",lambda r:r["closure_id"]=="CL-01-complete" and r["gate_id"]=="G9",{"gate_mode":"optional_decision"})
        self.assertIn("posthoc_gate_reclassification",error_codes(self.result()))

    def test_invalid_registry_interval_is_machine_readable(self):
        edit(self.policy,lambda r:r["gate_id"]=="G1",{"retired_at_utc":"2025-12-31T00:00:00Z"})
        self.assertIn("invalid_policy_interval",error_codes(self.result()))

    def test_missing_input_file_returns_json_error_not_exception(self):
        (self.root/"snapshots.csv").unlink(); result=analyze(self.root,self.policy); self.assertIn("missing_input_file",error_codes(result)); self.assertEqual(result["error_schema_version"],"1.0.0"); self.assertIsNone(result["metrics"]); self.assertIn("data_quality", result)

    def test_each_required_gate_evidence_field_rejects_trimmed_blank(self):
        for field in ("gate_owner", "threshold_operator", "threshold_value", "observed_value", "unit"):
            with self.subTest(field=field):
                temp, root, policy = workspace()
                self.addCleanup(temp.cleanup)
                edit(root / "gate_evaluations.csv", lambda r: r["closure_id"] == "CL-01-complete" and r["gate_id"] == "G1", {field: "   "})
                result = analyze(root, policy)
                self.assertIn("missing_required_gate_evidence", error_codes(result))
                self.assertFalse(result["valid_input"])
                self.assertIsNone(result["metrics"])
                self.assertIn("schema_validation_error", closure(result, "CL-01-complete")["failure_codes"])

    def test_required_value_matrix_exactly_covers_schema_and_registries(self):
        fields, records = rows(self.policy.parent / "S1_data_dictionary.csv")
        self.assertIn("value_required", fields)
        actual = {(row["file"], row["field"]) for row in records}
        expected = {(name, field) for name, schema_fields in SCHEMA.items() for field in schema_fields}
        expected.update(("S4_policy_registry.csv", field) for field in __import__("S3_analyze_evidence").POLICY_FIELDS)
        expected.update(("S4_gate_owner_authorizations.csv", field) for field in __import__("S3_analyze_evidence").GATE_OWNER_AUTHORIZATION_FIELDS)
        expected.update(("S4_exception_authority_registry.csv", field) for field in __import__("S3_analyze_evidence").EXCEPTION_AUTHORITY_FIELDS)
        expected.update(("S4_candidate_review_authorizations.csv", field) for field in __import__("S3_analyze_evidence").CANDIDATE_REVIEW_AUTHORITY_FIELDS)
        expected.update(("S4_principal_registry.csv", field) for field in __import__("S3_analyze_evidence").PRINCIPAL_REGISTRY_FIELDS)
        self.assertEqual(actual, expected)
        self.assertEqual(self.result()["validation_audit"]["required_value_matrix_fields"], len(expected))

    def test_blank_required_gate_value_cli_returns_exit_2(self):
        edit(self.root / "gate_evaluations.csv", lambda r: r["closure_id"] == "CL-01-complete" and r["gate_id"] == "G1", {"observed_value": ""})
        output = self.policy.parent / "cli-result.json"
        process = subprocess.run([sys.executable, str(HERE / "S3_analyze_evidence.py"), "--input-dir", str(self.root), "--policy-registry", str(self.policy), "--output", str(output)], capture_output=True, text=True)
        self.assertEqual(process.returncode, 2)
        self.assertTrue(output.exists())

    def test_policy_owner_mismatch_and_unauthorized_delegate_stay_open(self):
        edit(self.root / "gate_evaluations.csv", lambda r: r["closure_id"] == "CL-01-complete" and r["gate_id"] == "G1", {"gate_owner": "unauthorized-actor"})
        failures = closure(self.result(), "CL-01-complete")["failure_codes"]
        self.assertIn("gate_owner_policy_mismatch", failures)
        self.assertIn("unauthorized_gate_owner", failures)

    def test_effective_scoped_gate_owner_delegation_is_accepted(self):
        append(self.policy.parent / "S4_gate_owner_authorizations.csv", {"authorization_id": "GOA-1", "delegator": "G1-owner", "delegate": "authorized-delegate", "policy_version": "p18.0", "gate_scope": "G1", "service_scope": "service-1", "effective_at_utc": "2026-01-01T00:00:00Z"})
        edit(self.root / "gate_evaluations.csv", lambda r: r["closure_id"] == "CL-01-complete" and r["gate_id"] == "G1", {"gate_owner": "authorized-delegate"})
        self.assertTrue(closure(self.result(), "CL-01-complete")["closed_as_of"])

    def test_retry_cannot_silently_change_owner(self):
        add_retry(self.root, owner="different-owner")
        self.assertIn("unauthorized_gate_retry_change", error_codes(self.result()))

    def test_eq_contradiction_cannot_be_declared_pass(self):
        edit(self.root / "gate_evaluations.csv", lambda r: r["closure_id"] == "CL-01-complete" and r["gate_id"] == "G1", {"observed_value": "contradictory", "decision": "pass"})
        self.assertIn("gate_decision_evidence_mismatch", closure(self.result(), "CL-01-complete")["failure_codes"])

    def test_numeric_gate_is_recomputed_under_policy_type_and_unit(self):
        edit(self.policy, lambda r: r["gate_id"] == "G1", {"value_type": "number", "unit": "score"})
        edit(self.root / "gate_evaluations.csv", lambda r: r["closure_id"] == "CL-01-complete" and r["gate_id"] == "G1", {"threshold_operator": "ge", "threshold_value": "0.90", "observed_value": "0.95", "unit": "score", "decision": "pass"})
        self.assertTrue(closure(self.result(), "CL-01-complete")["closed_as_of"])

    def test_unit_mismatch_and_unparseable_value_are_schema_errors(self):
        edit(self.root / "gate_evaluations.csv", lambda r: r["closure_id"] == "CL-01-complete" and r["gate_id"] == "G1", {"unit": "wrong-unit"})
        self.assertIn("gate_unit_policy_mismatch", error_codes(self.result()))
        self.temp.cleanup(); self.temp, self.root, self.policy = workspace(); self.addCleanup(self.temp.cleanup)
        edit(self.policy, lambda r: r["gate_id"] == "G1", {"value_type": "number", "unit": "score"})
        edit(self.root / "gate_evaluations.csv", lambda r: r["closure_id"] == "CL-01-complete" and r["gate_id"] == "G1", {"threshold_operator": "gt", "threshold_value": "not-a-number", "observed_value": "0.95", "unit": "score"})
        self.assertIn("unparseable_gate_value", error_codes(self.result()))

    def test_blank_exception_approver_and_rationale_are_invalid_and_counted(self):
        for field in ("approver", "rationale"):
            with self.subTest(field=field):
                temp, root, policy = workspace(); self.addCleanup(temp.cleanup)
                make_exception_temporally_valid(root)
                edit(root / "exceptions.csv", lambda r: r["exception_id"] == "S4-EX", {field: " "})
                result = analyze(root, policy)
                self.assertIn("missing_required_exception_authorization", error_codes(result))
                self.assertEqual(result["validation_audit"]["invalid_exception_decisions"], 1)
                self.assertIsNone(result["metrics"])

    def test_unauthorized_exception_approver_is_rejected_and_enters_eir(self):
        make_exception_temporally_valid(self.root)
        edit(self.root / "exceptions.csv", lambda r: r["exception_id"] == "S4-EX", {"approver": "unauthorized-approver"})
        result = self.result()
        failures = closure(result, "CL-04-expired_exception")["failure_codes"]
        self.assertIn("unauthorized_exception_approver", failures)
        self.assertEqual(result["metrics"]["exception_invalidity_rate"]["numerator"], 1)

    def test_effective_scoped_exception_authority_can_close(self):
        make_exception_temporally_valid(self.root)
        result = self.result()
        self.assertTrue(closure(result, "CL-04-expired_exception")["closed_as_of"])
        self.assertEqual(result["metrics"]["exception_invalidity_rate"]["numerator"], 0)

    def test_revoked_exception_is_invalid(self):
        make_exception_temporally_valid(self.root)
        edit(self.root / "exceptions.csv", lambda r: r["exception_id"] == "S4-EX", {"revoked_at_utc": "2026-01-08T12:30:00Z"})
        self.assertIn("invalid_exception_authorization", closure(self.result(), "CL-04-expired_exception")["failure_codes"])

    def test_nonfinite_gate_operands_are_rejected(self):
        for field, token in (("observed_value", "NaN"), ("threshold_value", "Infinity"), ("observed_value", "-Infinity")):
            with self.subTest(field=field, token=token):
                temp, root, policy = workspace(); self.addCleanup(temp.cleanup)
                edit(policy, lambda r: r["gate_id"] == "G1", {"value_type": "number", "unit": "score"})
                edit(root / "gate_evaluations.csv", lambda r: r["closure_id"] == "CL-01-complete" and r["gate_id"] == "G1", {"threshold_operator": "ge", "threshold_value": "0.9", "observed_value": "0.95", "unit": "score", field: token})
                result = analyze(root, policy)
                self.assertIn("unparseable_gate_value", error_codes(result))
                self.assertFalse(result["valid_input"]); self.assertIsNone(result["metrics"])

    def test_nonfinite_ttl_window_and_policy_bounds_are_rejected(self):
        mutations = (
            ("incident TTL", lambda root, policy: edit(root / "incidents.csv", lambda r: r["closure_id"] == "CL-05-linked_incident", {"feedback_ttl_hours": "NaN"})),
            ("observation window", lambda root, policy: edit(root / "release_manifest.csv", lambda r: r["closure_id"] == "CL-01-complete", {"observation_window_hours": "Infinity"})),
            ("policy lower bound", lambda root, policy: edit(policy, lambda r: r["gate_id"] == "G1", {"min_observation_window_hours": "-Infinity"})),
            ("policy upper bound", lambda root, policy: edit(policy, lambda r: r["gate_id"] == "G1", {"max_observation_window_hours": "NaN"})),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                temp, root, policy = workspace(); self.addCleanup(temp.cleanup); mutate(root, policy)
                result = analyze(root, policy)
                self.assertIn("invalid_nonfinite_number", error_codes(result)); self.assertFalse(result["valid_input"]); self.assertIsNone(result["metrics"])

    def test_nonfinite_json_constant_is_rejected(self):
        edit(self.root / "nodes.csv", lambda r: r["closure_id"] == "CL-01-complete" and r["node_id"] == "S1-REQ", {"metadata_json": '{"score": NaN}'})
        result = self.result(); self.assertFalse(result["valid_input"]); self.assertIsNone(result["metrics"])

    def test_nan_exception_counterexample_cli_exits_2(self):
        edit(self.root / "incidents.csv", lambda r: r["closure_id"] == "CL-05-linked_incident", {"feedback_ttl_hours": "NaN"})
        output = self.policy.parent / "nonfinite-cli-result.json"
        process = subprocess.run([sys.executable, str(HERE / "S3_analyze_evidence.py"), "--input-dir", str(self.root), "--policy-registry", str(self.policy), "--output", str(output)], capture_output=True, text=True)
        payload = __import__("json").loads(output.read_text(encoding="utf-8"))
        self.assertEqual(process.returncode, 2); self.assertFalse(payload["valid_input"]); self.assertIsNone(payload["metrics"])
        self.assertFalse(closure(payload, "CL-05-linked_incident")["closed_as_of"])

    def test_authorization_ids_must_be_unique(self):
        source = self.policy.parent / "S4_gate_owner_authorizations.csv"
        append(source, {"authorization_id": "GOA-1", "delegator": "G1-owner", "delegate": "delegate-a", "policy_version": "p18.0", "gate_scope": "G1", "service_scope": "service-1", "effective_at_utc": "2026-01-01T00:00:00Z"})
        append(source, {"authorization_id": "GOA-1", "delegator": "G1-owner", "delegate": "delegate-b", "policy_version": "p18.0", "gate_scope": "G1", "service_scope": "service-1", "effective_at_utc": "2026-01-01T00:00:00Z"})
        self.assertIn("duplicate_authorization_id", error_codes(self.result()))

    def test_authorization_interval_policy_gate_and_delegator_are_validated(self):
        source = self.policy.parent / "S4_gate_owner_authorizations.csv"
        append(source, {"authorization_id": "GOA-BAD", "delegator": "wrong-owner", "delegate": "delegate-a", "policy_version": "unknown", "gate_scope": "UNKNOWN-GATE", "service_scope": "service-1", "effective_at_utc": "2026-02-01T00:00:00Z", "retired_at_utc": "2026-01-01T00:00:00Z"})
        codes = error_codes(self.result())
        for code in ("unknown_authorization_policy", "unknown_authorization_policy_gate", "invalid_authorization_interval"):
            self.assertIn(code, codes)

    def test_exception_authority_role_is_controlled(self):
        edit(self.policy.parent / "S4_exception_authority_registry.csv", lambda r: True, {"role": "invented-role"})
        result = self.result(); self.assertIn("invalid_authorization_role", error_codes(result)); self.assertIsNone(result["metrics"])

    def test_json_exponent_overflow_is_rejected_recursively(self):
        values = ("1e999", "-1e999", '{"outer":{"x":1e999}}', '{"items":[0,-1e999]}')
        for value in values:
            with self.subTest(value=value):
                temp, root, policy = workspace(); self.addCleanup(temp.cleanup)
                edit(root / "nodes.csv", lambda r: r["closure_id"] == "CL-01-complete" and r["node_id"] == "S1-REQ", {"metadata_json": value})
                result = analyze(root, policy)
                self.assertIn("invalid_nonfinite_json_number", error_codes(result))
                self.assertFalse(result["valid_input"]); self.assertIsNone(result["metrics"])
                self.assertFalse(closure(result, "CL-01-complete")["closed_as_of"])

    def test_json_exponent_overflow_cli_returns_2(self):
        edit(self.root / "nodes.csv", lambda r: r["closure_id"] == "CL-01-complete" and r["node_id"] == "S1-REQ", {"metadata_json": '{"items":[{"x":1e999}]}'})
        output = self.policy.parent / "json-overflow-cli.json"
        process = subprocess.run([sys.executable, str(HERE / "S3_analyze_evidence.py"), "--input-dir", str(self.root), "--policy-registry", str(self.policy), "--output", str(output)], capture_output=True, text=True)
        payload = __import__("json").loads(output.read_text(encoding="utf-8"))
        self.assertEqual(process.returncode, 2); self.assertFalse(payload["valid_input"]); self.assertIsNone(payload["metrics"])

    def test_authorization_scope_requires_policy_gate_joint_key(self):
        append(self.policy, {"policy_version": "p18.partial", "gate_id": "G1", "gate_mode": "required", "phase": "pre_approval", "effective_at_utc": "2026-01-01T00:00:00Z", "owner": "partial-owner", "value_type": "string", "unit": "illustrative configuration", "min_observation_window_hours": "1", "max_observation_window_hours": "168"})
        append(self.policy.parent / "S4_gate_owner_authorizations.csv", {"authorization_id": "GOA-PARTIAL", "delegator": "partial-owner", "delegate": "delegate", "policy_version": "p18.partial", "gate_scope": "G3", "service_scope": "*", "effective_at_utc": "2026-01-01T00:00:00Z"})
        result = self.result(); self.assertIn("unknown_authorization_policy_gate", error_codes(result)); self.assertIsNone(result["metrics"])

    def test_gate_scoped_delegator_matches_that_gate_owner(self):
        append(self.policy.parent / "S4_gate_owner_authorizations.csv", {"authorization_id": "GOA-WRONG-OWNER", "delegator": "G1-owner", "delegate": "delegate", "policy_version": "p18.0", "gate_scope": "G3", "service_scope": "*", "effective_at_utc": "2026-01-01T00:00:00Z"})
        result = self.result(); self.assertIn("authorization_gate_owner_mismatch", error_codes(result)); self.assertFalse(result["valid_input"]); self.assertIsNone(result["metrics"])

    def test_wildcard_delegation_rejects_multi_owner_policy(self):
        append(self.policy.parent / "S4_gate_owner_authorizations.csv", {"authorization_id": "GOA-WILDCARD", "delegator": "G1-owner", "delegate": "delegate", "policy_version": "p18.0", "gate_scope": "*", "service_scope": "*", "effective_at_utc": "2026-01-01T00:00:00Z"})
        result = self.result(); self.assertIn("ambiguous_wildcard_authorization_owner", error_codes(result)); self.assertIsNone(result["metrics"])

    def test_unresolved_incident_candidate_blocks_provisional_closure(self):
        edit(self.root / "incident_candidates.csv", lambda r: r["closure_id"] == "CL-05-linked_incident", {"status": "unresolved", "incident_id": "", "decision_role": "", "decided_by": "", "decided_at_utc": ""})
        self.assertIn("unresolved_incident_candidate", closure(self.result(), "CL-05-linked_incident")["failure_codes"])

    def test_each_deployment_requires_candidate_coverage(self):
        remove(self.root / "candidate_coverage.csv", lambda r: r["closure_id"] == "CL-01-complete")
        self.assertIn("missing_or_duplicate_candidate_coverage", closure(self.result(), "CL-01-complete")["failure_codes"])

    def test_finding_may_create_only_a_later_requirement(self):
        # A closed target episode that implements a sibling Requirement must
        # not satisfy the exact creates_requirement edge.
        append(self.root / "nodes.csv", {"closure_id": "CL-01-complete", "node_id": "S1-REQ-SIBLING", "logical_work_item_id": "S1-REQ-SIBLING", "node_type": "WorkItem", "work_item_kind": "Requirement", "service_id": "service-1", "version": "1", "event_time_utc": "2026-01-05T08:00:00Z", "created_at_utc": "2026-01-05T07:00:00Z", "accepted_at_utc": "2026-01-05T08:00:00Z", "owner": "requirement-owner", "status": "accepted", "accepted_revision": "r2", "metadata_json": "{}"})
        append(self.root / "edges.csv", {"closure_id": "CL-05-linked_incident", "edge_id": "S5-FND-CREATES-S1-SIBLING", "edge_type": "creates_requirement", "source_node_id": "S5-FND", "target_node_id": "S1-REQ-SIBLING", "event_time_utc": "2026-01-09T18:00:00Z", "source_version": "1", "target_version": "1"})
        sibling = closure(self.result(), "CL-05-linked_incident")
        self.assertFalse(sibling["closed_as_of"])
        self.assertIn("later_requirement_target_requirement_not_implemented", sibling["failure_codes"])
        remove(self.root / "edges.csv", lambda r: r["edge_id"] == "S5-FND-CREATES-S1-SIBLING")
        remove(self.root / "edges.csv", lambda r: r["edge_id"] == "S5-FND-REQ")
        append(self.root / "nodes.csv", {"closure_id": "CL-07-followup", "node_id": "S7-REQ-NEW", "logical_work_item_id": "S7-REQ-NEW", "node_type": "WorkItem", "work_item_kind": "Requirement", "service_id": "service-5", "version": "1", "event_time_utc": "2026-01-12T10:00:00Z", "created_at_utc": "2026-01-12T09:00:00Z", "accepted_at_utc": "2026-01-12T10:00:00Z", "owner": "requirement-owner", "status": "accepted", "accepted_revision": "r1", "metadata_json": "{}"})
        append(self.root / "nodes.csv", {"closure_id": "CL-07-followup", "node_id": "S7-REL", "node_type": "ReleaseDecision", "service_id": "service-5", "version": "1", "policy_version": "p18.0", "event_time_utc": "2026-01-12T12:00:00Z", "owner": "release-owner", "status": "approved", "release_approved": "true", "metadata_json": "{}"})
        append(self.root / "edges.csv", {"closure_id": "CL-05-linked_incident", "edge_id": "S5-FND-CREATES-S7-REQ", "edge_type": "creates_requirement", "source_node_id": "S5-FND", "target_node_id": "S7-REQ-NEW", "event_time_utc": "2026-01-12T10:00:00Z", "source_version": "1", "target_version": "1"})
        # The original source snapshot must remain open because the target
        # Requirement is not visible at its 2026-01-10 cutoff.  A legal source
        # successor after the target episode is the only route to closure.
        edit(self.root / "release_manifest.csv", lambda r: r["closure_id"] == "CL-05-linked_incident", {"evaluation_time_utc": "2026-01-12T14:00:00Z"})
        edit(self.root / "snapshots.csv", lambda r: r["snapshot_id"] == "S5-SNAP-1", {"declared_status": "open"})
        append(self.root / "snapshots.csv", {"closure_id": "CL-05-linked_incident", "snapshot_id": "S5-SNAP-2", "release_decision_id": "S5-REL", "evaluated_at_utc": "2026-01-12T14:00:00Z", "supersedes_snapshot_id": "S5-SNAP-1", "declared_status": "closed_as_of"})
        add_successor_coverage(self.root, "CL-05-linked_incident", "S5-SNAP-2", "2026-01-12T14:00:00Z")
        source = closure(self.result(), "CL-05-linked_incident")
        self.assertFalse(source["closed_as_of"])
        self.assertIn("later_requirement_target_episode_incomplete", source["failure_codes"])
        edit(self.root / "nodes.csv", lambda r: r["node_id"] == "S7-REQ-NEW", {"created_at_utc": "2026-01-09T19:00:00Z"})
        self.assertIn("retrospective_requirement_backfill", closure(self.result(), "CL-05-linked_incident")["failure_codes"])

    def test_nonwaivable_gate_cannot_close_by_exception(self):
        make_exception_temporally_valid(self.root)
        edit(self.policy, lambda r: r["gate_id"] == "G3", {"waiver_allowed": "no"})
        self.assertIn("nonwaivable_gate_exception", closure(self.result(), "CL-04-expired_exception")["failure_codes"])


if __name__ == "__main__": unittest.main(verbosity=2)

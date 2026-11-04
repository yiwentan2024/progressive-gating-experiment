import csv
import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).parent
module_path = Path(os.environ.get("ANALYZER_UNDER_TEST", HERE / "S3_analyze_evidence.py"))
spec = importlib.util.spec_from_file_location("analyzer_under_test", module_path)
analyzer = importlib.util.module_from_spec(spec); spec.loader.exec_module(analyzer)
analyze, SCHEMA = analyzer.analyze, analyzer.SCHEMA
SYN, POLICY = HERE / "S6_synthetic", HERE / "S4_policy_registry.csv"
DICTIONARY = HERE / "S1_data_dictionary.csv"
OWNER_AUTHORIZATIONS = HERE / "S4_gate_owner_authorizations.csv"
EXCEPTION_AUTHORITIES = HERE / "S4_exception_authority_registry.csv"
CANDIDATE_AUTHORITIES = HERE / "S4_candidate_review_authorizations.csv"
PRINCIPAL_REGISTRY = HERE / "S4_principal_registry.csv"


def workspace():
    temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name) / "data"; root.mkdir()
    for name in SCHEMA: shutil.copy2(SYN / name, root / name)
    policy = Path(temporary.name) / "S4_policy_registry.csv"; shutil.copy2(POLICY, policy)
    shutil.copy2(DICTIONARY, Path(temporary.name) / DICTIONARY.name)
    shutil.copy2(OWNER_AUTHORIZATIONS, Path(temporary.name) / OWNER_AUTHORIZATIONS.name)
    shutil.copy2(EXCEPTION_AUTHORITIES, Path(temporary.name) / EXCEPTION_AUTHORITIES.name)
    shutil.copy2(CANDIDATE_AUTHORITIES, Path(temporary.name) / CANDIDATE_AUTHORITIES.name)
    shutil.copy2(PRINCIPAL_REGISTRY, Path(temporary.name) / PRINCIPAL_REGISTRY.name)
    return temporary, root, policy


def rows(path):
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source); return reader.fieldnames, list(reader)


def write(path, fields, records):
    with path.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fields); writer.writeheader(); writer.writerows(records)


def edit(path, predicate, updates):
    fields, records = rows(path)
    for record in records:
        if predicate(record): record.update(updates); break
    write(path, fields, records)


def append(path, record):
    fields, records = rows(path); records.append({field: record.get(field, "") for field in fields}); write(path, fields, records)


def remove(path, predicate):
    fields, records = rows(path); write(path, fields, [record for record in records if not predicate(record)])


def refresh_coverage(root, closure_id):
    _, candidates = rows(root / "incident_candidates.csv")
    fields, coverages = rows(root / "candidate_coverage.csv")
    raw_fields, raw_records = rows(root / "raw_signal_inventory.csv")
    for coverage in coverages:
        if coverage["closure_id"] != closure_id:
            continue
        batch = sorted(
            (
                row for row in candidates
                if row["deployment_id"] == coverage["deployment_id"]
                and row["source_batch_id"] == coverage["source_batch_id"]
            ),
            key=lambda row: row["candidate_id"],
        )
        payload = "\n".join(f"{row['candidate_id']}|{row['signal_digest_sha256']}" for row in batch).encode()
        retained = [
            row for row in raw_records
            if row["coverage_id"] != coverage["coverage_id"] or row["disposition"] != "imported_candidate"
        ]
        imported = [{
            "closure_id": coverage["closure_id"],
            "coverage_id": coverage["coverage_id"],
            "raw_signal_id": f"{candidate['candidate_id']}-RAW",
            "source_batch_id": coverage["source_batch_id"],
            "signal_digest_sha256": candidate["signal_digest_sha256"],
            "observed_at_utc": candidate["observed_at_utc"],
            "disposition": "imported_candidate",
            "candidate_id": candidate["candidate_id"],
            "disposition_reason_code": "admitted_to_candidate_registry",
            "disposition_rationale": "test fixture signal admitted to the candidate registry",
            "disposition_decided_by": coverage["responsible_actor"],
            "disposition_decided_at_utc": candidate["admitted_at_utc"],
        } for candidate in batch]
        raw_records = retained + imported
        inventory = [row for row in raw_records if row["coverage_id"] == coverage["coverage_id"]]
        noncandidate = [row for row in inventory if row["disposition"] == "noncandidate"]
        rejected = [row for row in inventory if row["disposition"] == "rejected"]
        reason_counts = {}
        for row in noncandidate + rejected:
            reason_counts[row["disposition_reason_code"]] = reason_counts.get(row["disposition_reason_code"], 0) + 1
        coverage["raw_signal_count"] = str(len(inventory))
        coverage["imported_candidate_count"] = str(len(batch))
        coverage["noncandidate_count"] = str(len(noncandidate))
        coverage["rejected_count"] = str(len(rejected))
        coverage["filter_reason_summary_json"] = json.dumps(dict(sorted(reason_counts.items())), separators=(",", ":"))
        coverage["candidate_digest_sha256"] = "sha256:" + hashlib.sha256(payload).hexdigest()
        coverage["raw_inventory_digest_sha256"] = "sha256:" + analyzer.raw_inventory_digest(inventory)
        coverage["reconciliation_digest_sha256"] = "sha256:" + analyzer.reconciliation_digest(coverage)
    write(root / "candidate_coverage.csv", fields, coverages)
    write(root / "raw_signal_inventory.csv", raw_fields, raw_records)


def refresh_snapshot_digests(root, policy):
    tables = {name: rows(root / name)[1] for name in SCHEMA}
    policy_rows = rows(policy)[1]
    owner_rows = rows(policy.parent / OWNER_AUTHORIZATIONS.name)[1]
    exception_rows = rows(policy.parent / EXCEPTION_AUTHORITIES.name)[1]
    candidate_authority_rows = rows(policy.parent / CANDIDATE_AUTHORITIES.name)[1]
    principal_rows = rows(policy.parent / PRINCIPAL_REGISTRY.name)[1]

    def parsed(value):
        if not value:
            return None
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (TypeError, ValueError, OverflowError):
            return datetime.max.replace(tzinfo=timezone.utc)
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        return result.astimezone(timezone.utc)

    def visible(record, cutoff, fields):
        return all(not record.get(field) or parsed(record[field]) <= cutoff for field in fields)

    snapshot_fields, snapshots = rows(root / "snapshots.csv")
    for snapshot in snapshots:
        cutoff = parsed(snapshot["evaluated_at_utc"])
        closure_id = snapshot["closure_id"]
        release_id = snapshot["release_decision_id"]
        manifest_rows = [row for row in tables["release_manifest.csv"] if row["release_decision_id"] == release_id]
        policy_version = manifest_rows[0]["policy_version"] if manifest_rows else ""
        external_target_ids = {
            edge["target_node_id"] for edge in tables["edges.csv"]
            if edge["closure_id"] == closure_id
            and edge["edge_type"] == "creates_requirement"
            and any(node["node_id"] == edge["target_node_id"] and node["closure_id"] != closure_id for node in tables["nodes.csv"])
        }
        selected = {
            "manifest": manifest_rows,
            "policy": [row for row in policy_rows if row["policy_version"] == policy_version and parsed(row["effective_at_utc"]) <= cutoff],
            "owner_authority": [row for row in owner_rows if row["policy_version"] == policy_version and parsed(row["effective_at_utc"]) <= cutoff],
            "exception_authority": [row for row in exception_rows if row["policy_version"] == policy_version and parsed(row["effective_at_utc"]) <= cutoff],
            "candidate_authority": [row for row in candidate_authority_rows if parsed(row["effective_at_utc"]) <= cutoff],
            "principal_registry": [row for row in principal_rows if parsed(row["effective_at_utc"]) <= cutoff],
            "gates": [row for row in tables["gate_evaluations.csv"] if row["closure_id"] == closure_id and visible(row, cutoff, ["evaluated_at_utc"])],
            "coverage": [row for row in tables["candidate_coverage.csv"] if row["effective_from_snapshot_id"] == snapshot["snapshot_id"] and visible(row, cutoff, ["attested_at_utc"])],
            "raw_signals": [row for row in tables["raw_signal_inventory.csv"] if row["closure_id"] == closure_id and visible(row, cutoff, ["observed_at_utc", "disposition_decided_at_utc"])],
            "candidates": [row for row in tables["incident_candidates.csv"] if row["closure_id"] == closure_id and visible(row, cutoff, ["observed_at_utc", "admitted_at_utc", "decided_at_utc", "reviewed_at_utc"])],
            "incidents": [row for row in tables["incidents.csv"] if row["closure_id"] == closure_id and visible(row, cutoff, ["opened_at_utc", "reported_at_utc", "attribution_time_utc", "feedback_link_time_utc", "resolved_at_utc"])],
            "nodes": [row for row in tables["nodes.csv"] if (row["closure_id"] == closure_id or row["node_id"] in external_target_ids) and visible(row, cutoff, ["event_time_utc", "created_at_utc", "accepted_at_utc"])],
            "edges": [row for row in tables["edges.csv"] if row["closure_id"] == closure_id and visible(row, cutoff, ["event_time_utc"])],
        }
        normalized = {}
        for name, records in selected.items():
            normalized[name] = [{key: value for key, value in sorted(record.items())} for record in records]
            normalized[name].sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
        payload = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
        snapshot["input_manifest_digest"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    write(root / "snapshots.csv", snapshot_fields, snapshots)


def add_successor_coverage(root, closure_id, snapshot_id, attested_at, *, batch_suffix="2"):
    fields, coverages = rows(root / "candidate_coverage.csv")
    prior = max(
        (row for row in coverages if row["closure_id"] == closure_id),
        key=lambda row: int(row["coverage_version"]),
    )
    successor = {field: prior.get(field, "") for field in fields}
    successor.update(
        coverage_id=f"{prior['deployment_id']}-COVERAGE-{int(prior['coverage_version']) + 1}",
        coverage_version=str(int(prior["coverage_version"]) + 1),
        supersedes_coverage_id=prior["coverage_id"],
        effective_from_snapshot_id=snapshot_id,
        source_batch_id=f"{prior['deployment_id']}-BATCH-{batch_suffix}",
        raw_signal_count="0",
        imported_candidate_count="0",
        noncandidate_count="0",
        rejected_count="0",
        filter_reason_summary_json="{}",
        candidate_digest_sha256="sha256:" + hashlib.sha256(b"").hexdigest(),
        raw_inventory_digest_sha256="sha256:" + analyzer.raw_inventory_digest([]),
        attested_at_utc=attested_at,
    )
    successor["reconciliation_digest_sha256"] = "sha256:" + analyzer.reconciliation_digest(successor)
    coverages.append(successor)
    write(root / "candidate_coverage.csv", fields, coverages)
    return successor


def closure(result, closure_id):
    return {row["closure_id"]: row for row in result["closure_results"]}[closure_id]


def error_codes(result):
    return {row["code"] for row in result["schema_errors"]}


def add_retry(root, evaluated="2026-01-05T12:45:00Z", target="S1-CHG", policy="p18.0", mode="required", phase="pre_approval", owner="G1-owner"):
    append(root / "nodes.csv", {"closure_id":"CL-01-complete","node_id":"S1-GE-G1-R2","node_type":"GateEvaluation","service_id":"service-1","version":"1","policy_version":policy,"event_time_utc":evaluated,"owner":"G1-owner","status":"pass","metadata_json":"{}"})
    append(root / "edges.csv", {"closure_id":"CL-01-complete","edge_id":"S1-GE-G1-R2-E","edge_type":"evaluates","source_node_id":"S1-GE-G1-R2","target_node_id":target,"event_time_utc":evaluated,"source_version":"1","target_version":"1"})
    append(root / "gate_evaluations.csv", {"closure_id":"CL-01-complete","gate_evaluation_id":"S1-GE-G1-R2","target_node_id":target,"gate_id":"G1","gate_mode":mode,"phase":phase,"attempt":"2","supersedes_gate_evaluation_id":"S1-GE-G1","policy_version":policy,"gate_owner":owner,"evaluated_at_utc":evaluated,"threshold_operator":"eq","threshold_value":"synthetic","observed_value":"synthetic","unit":"illustrative configuration","decision":"pass"})


def add_late_incident(root, *, reported="2026-01-06T15:15:00Z", attributed="2026-01-06T15:30:00Z", reopen=True):
    if reopen:
        edit(root / "release_manifest.csv", lambda r:r["closure_id"]=="CL-01-complete", {"evaluation_time_utc":"2026-01-06T20:00:00Z"})
        append(root / "snapshots.csv", {"closure_id":"CL-01-complete","snapshot_id":"S1-SNAP-2","release_decision_id":"S1-REL","evaluated_at_utc":"2026-01-06T20:00:00Z","supersedes_snapshot_id":"S1-SNAP-1","declared_status":"closed_as_of"})
        add_successor_coverage(root, "CL-01-complete", "S1-SNAP-2", "2026-01-06T20:00:00Z")
    append(root / "nodes.csv", {"closure_id":"CL-01-complete","node_id":"S1-LATE","node_type":"Incident","service_id":"service-1","version":"1","event_time_utc":"2026-01-06T10:00:00Z","owner":"incident-owner","status":"resolved","metadata_json":"{}"})
    append(root / "nodes.csv", {"closure_id":"CL-01-complete","node_id":"S1-LATE-F","logical_work_item_id":"S1-LATE-F","node_type":"WorkItem","work_item_kind":"Finding","service_id":"service-1","version":"1","event_time_utc":"2026-01-06T16:00:00Z","owner":"finding-owner","status":"closed","metadata_json":"{}"})
    append(root / "edges.csv", {"closure_id":"CL-01-complete","edge_id":"S1-LATE-D","edge_type":"attributed_to","source_node_id":"S1-LATE","target_node_id":"S1-DEP","event_time_utc":attributed,"source_version":"1","target_version":"1"})
    append(root / "edges.csv", {"closure_id":"CL-01-complete","edge_id":"S1-LATE-FE","edge_type":"creates_finding","source_node_id":"S1-LATE","target_node_id":"S1-LATE-F","event_time_utc":"2026-01-06T16:00:00Z","source_version":"1","target_version":"1"})
    append(root / "edges.csv", {"closure_id":"CL-01-complete","edge_id":"S1-LATE-DR","edge_type":"violates_or_relates_to","source_node_id":"S1-LATE-F","target_node_id":"S1-REQ","event_time_utc":"2026-01-06T16:00:00Z","source_version":"1","target_version":"1"})
    append(root / "incidents.csv", {"closure_id":"CL-01-complete","incident_id":"S1-LATE","deployment_id":"S1-DEP","classification":"deployment_induced","severity":"low","opened_at_utc":"2026-01-06T10:00:00Z","reported_at_utc":reported,"attribution_time_utc":attributed,"classifier":"service-owner","classification_evidence":"review-derived late attribution fixture","finding_id":"S1-LATE-F","feedback_link_time_utc":"2026-01-06T16:00:00Z","feedback_ttl_hours":"8","resolved_at_utc":"2026-01-06T18:00:00Z","resolution_validator":"incident-owner","resolution_evidence":"late fix verified","reopens_snapshot_id":"S1-SNAP-1" if reopen else "","late_discovery_action":"reopen" if reopen else ""})
    append(root / "incident_candidates.csv", {"closure_id":"CL-01-complete","candidate_id":"S1-LATE-CAND","deployment_id":"S1-DEP","service_id":"service-1","environment":"production","observed_at_utc":"2026-01-06T10:00:00Z","admitted_at_utc":"2026-01-06T15:00:00Z","source_batch_id":"S1-DEP-BATCH-2","signal_digest_sha256":"sha256:" + hashlib.sha256(b"S1-LATE-CAND").hexdigest(),"status":"attributed","incident_id":"S1-LATE","decision_role":"incident_triager","decided_by":"synthetic-triager","decided_at_utc":attributed,"reopens_snapshot_id":"S1-SNAP-1" if reopen else ""})
    refresh_coverage(root, "CL-01-complete")


class ContractUnitTests(unittest.TestCase):
    def setUp(self):
        self.temp, self.root, self.policy = workspace(); self.addCleanup(self.temp.cleanup)
    def result(self):
        refresh_snapshot_digests(self.root, self.policy)
        return analyze(self.root, self.policy)

    def test_baseline_scenarios_and_metric_units(self):
        result=self.result(); self.assertEqual(result["schema_errors"],[])
        self.assertTrue(closure(result,"CL-01-complete")["closed_as_of"]); self.assertTrue(closure(result,"CL-05-linked_incident")["closed_as_of"])
        self.assertIn("orphan_release",closure(result,"CL-02-orphan")["failure_codes"]); self.assertIn("failed_decision_gate",closure(result,"CL-03-failed_gate")["failure_codes"])
        self.assertIn("invalid_exception_authorization",closure(result,"CL-04-expired_exception")["failure_codes"]); self.assertIn("unresolved_deployment_incident",closure(result,"CL-06-unlinked_incident")["failure_codes"])
        self.assertTrue(result["valid_input"]); self.assertEqual(result["schema_version"],"1.0.0"); self.assertIn("incident_attribution",result["metrics"]["latency_families"]); self.assertNotIn("confidence",json.dumps(result).lower())
        self.assertEqual(result["metrics"]["latency_families"]["incident_feedback_link"]["right_censored"],1)
        self.assertEqual(result["metrics"]["latency_families"]["incident_attribution"]["n"],2)
        self.assertEqual(result["metrics"]["latency_families"]["incident_attribution"]["right_censored"],0)

    def test_manifest_selects_one_build_path(self):
        append(self.root/"nodes.csv",{"closure_id":"CL-01-complete","node_id":"S1-BLD-OLD","node_type":"Build","service_id":"service-1","version":"1","event_time_utc":"2026-01-05T09:30:00Z","owner":"build-owner","status":"success","metadata_json":"{}"})
        append(self.root/"nodes.csv",{"closure_id":"CL-01-complete","node_id":"S1-ART-OLD","node_type":"Artifact","service_id":"service-1","version":"1","event_time_utc":"2026-01-05T10:00:00Z","owner":"artifact-owner","status":"superseded","artifact_digest":"sha256:old","immutable":"true","metadata_json":"{}"})
        append(self.root/"edges.csv",{"closure_id":"CL-01-complete","edge_id":"S1-OLD-TR","edge_type":"triggers","source_node_id":"S1-CHG","target_node_id":"S1-BLD-OLD","event_time_utc":"2026-01-05T10:00:00Z","source_version":"1","target_version":"1"})
        append(self.root/"edges.csv",{"closure_id":"CL-01-complete","edge_id":"S1-OLD-PR","edge_type":"produces","source_node_id":"S1-BLD-OLD","target_node_id":"S1-ART-OLD","event_time_utc":"2026-01-05T10:00:00Z","source_version":"1","target_version":"1"})
        self.assertTrue(closure(self.result(),"CL-01-complete")["closed_as_of"])

    def test_selected_build_must_be_triggered_by_change(self):
        append(self.root/"nodes.csv",{"closure_id":"CL-01-complete","node_id":"S1-BLD-DETACHED","node_type":"Build","service_id":"service-1","version":"1","event_time_utc":"2026-01-05T09:30:00Z","owner":"build-owner","status":"success","metadata_json":"{}"})
        append(self.root/"nodes.csv",{"closure_id":"CL-01-complete","node_id":"S1-TST-DETACHED","node_type":"TestRun","service_id":"service-1","version":"1","event_time_utc":"2026-01-05T10:00:00Z","owner":"test-owner","status":"pass","mandatory":"true","metadata_json":"{}"})
        append(self.root/"nodes.csv",{"closure_id":"CL-01-complete","node_id":"S1-ART-DETACHED","node_type":"Artifact","service_id":"service-1","version":"1","event_time_utc":"2026-01-05T10:30:00Z","owner":"artifact-owner","status":"ready","artifact_digest":"sha256:detached","immutable":"true","metadata_json":"{}"})
        append(self.root/"edges.csv",{"closure_id":"CL-01-complete","edge_id":"S1-DT-TEST","edge_type":"evaluated_by","source_node_id":"S1-BLD-DETACHED","target_node_id":"S1-TST-DETACHED","event_time_utc":"2026-01-05T10:00:00Z","source_version":"1","target_version":"1"})
        append(self.root/"edges.csv",{"closure_id":"CL-01-complete","edge_id":"S1-DT-ART","edge_type":"produces","source_node_id":"S1-BLD-DETACHED","target_node_id":"S1-ART-DETACHED","event_time_utc":"2026-01-05T10:30:00Z","source_version":"1","target_version":"1"})
        append(self.root/"edges.csv",{"closure_id":"CL-01-complete","edge_id":"S1-DT-APP","edge_type":"approves","source_node_id":"S1-REL","target_node_id":"S1-ART-DETACHED","event_time_utc":"2026-01-05T13:00:00Z","source_version":"1","target_version":"1"})
        edit(self.root/"release_manifest.csv",lambda r:r["closure_id"]=="CL-01-complete",{"selected_build_id":"S1-BLD-DETACHED","selected_test_run_ids":"S1-TST-DETACHED","selected_artifact_id":"S1-ART-DETACHED","artifact_digest":"sha256:detached"})
        self.assertIn("selected_build_not_linked",closure(self.result(),"CL-01-complete")["failure_codes"])

    def test_duplicate_selected_test_is_rejected(self):
        edit(self.root/"release_manifest.csv",lambda r:r["closure_id"]=="CL-01-complete",{"selected_test_run_ids":"S1-TST|S1-TST"})
        self.assertIn("duplicate_selected_test",closure(self.result(),"CL-01-complete")["failure_codes"])

    def test_informational_and_optional_gate_semantics(self):
        before=self.result()["metrics"]["decision_gate_rejection_rate"]["denominator"]
        edit(self.root/"gate_evaluations.csv",lambda r:r["closure_id"]=="CL-01-complete" and r["gate_id"]=="G9",{"observed_value":"contradictory","decision":"fail"})
        result=self.result(); self.assertTrue(closure(result,"CL-01-complete")["closed_as_of"]); self.assertEqual(before,result["metrics"]["decision_gate_rejection_rate"]["denominator"])
        edit(self.root/"gate_evaluations.csv",lambda r:r["closure_id"]=="CL-01-complete" and r["gate_id"]=="G8",{"observed_value":"contradictory","decision":"fail"})
        self.assertIn("failed_decision_gate",closure(self.result(),"CL-01-complete")["failure_codes"])

    def test_policy_identity_effectivity_uniqueness_and_range(self):
        edit(self.root/"gate_evaluations.csv",lambda r:r["closure_id"]=="CL-01-complete" and r["gate_id"]=="G3",{"policy_version":"wrong"})
        self.assertIn("gate_policy_mismatch",closure(self.result(),"CL-01-complete")["failure_codes"])
        edit(self.root/"gate_evaluations.csv",lambda r:r["closure_id"]=="CL-01-complete" and r["gate_id"]=="G3",{"policy_version":"p18.0"})
        fields,records=rows(self.policy)
        for record in records: record["effective_at_utc"]="2026-02-01T00:00:00Z"
        write(self.policy,fields,records); self.assertIn("policy_not_effective_at_approval",closure(self.result(),"CL-01-complete")["failure_codes"])
        append(self.policy,records[0]); self.assertIn("duplicate_policy_gate",error_codes(self.result()))

    def test_observation_window_positive_and_policy_bounded(self):
        for value in ("0","-1","169"):
            temp,root,policy=workspace(); self.addCleanup(temp.cleanup)
            edit(root/"release_manifest.csv",lambda r:r["closure_id"]=="CL-01-complete",{"observation_window_hours":value})
            result=analyze(root,policy); self.assertFalse(closure(result,"CL-01-complete")["closed_as_of"])
            if value in {"0","-1"}: self.assertIn("invalid_number",error_codes(result))

    def test_gate_target_and_approval_temporal_cutoffs(self):
        edit(self.root/"gate_evaluations.csv",lambda r:r["closure_id"]=="CL-01-complete" and r["gate_id"]=="G4",{"evaluated_at_utc":"2026-01-05T10:00:00Z"})
        self.assertIn("gate_before_target",closure(self.result(),"CL-01-complete")["failure_codes"])
        edit(self.root/"gate_evaluations.csv",lambda r:r["closure_id"]=="CL-01-complete" and r["gate_id"]=="G4",{"evaluated_at_utc":"2026-01-05T11:45:00Z"})
        edit(self.root/"gate_evaluations.csv",lambda r:r["closure_id"]=="CL-01-complete" and r["gate_id"]=="G3",{"evaluated_at_utc":"2026-01-05T13:00:01Z"})
        self.assertIn("preapproval_gate_after_approval",closure(self.result(),"CL-01-complete")["failure_codes"])

    def test_observation_window_and_multiple_deployments(self):
        edit(self.root/"release_manifest.csv",lambda r:r["closure_id"]=="CL-01-complete",{"evaluation_time_utc":"2026-01-05T20:00:00Z"}); edit(self.root/"snapshots.csv",lambda r:r["closure_id"]=="CL-01-complete",{"evaluated_at_utc":"2026-01-05T20:00:00Z"})
        self.assertIn("observation_window_open",closure(self.result(),"CL-01-complete")["failure_codes"])
        self.temp.cleanup(); self.temp,self.root,self.policy=workspace(); self.addCleanup(self.temp.cleanup)
        append(self.root/"nodes.csv",{"closure_id":"CL-01-complete","node_id":"S1-DEP-2","node_type":"Deployment","service_id":"service-1","version":"1","event_time_utc":"2026-01-05T15:00:00Z","owner":"operations","status":"success","environment":"production-b","metadata_json":"{}"})
        append(self.root/"edges.csv",{"closure_id":"CL-01-complete","edge_id":"S1-DEP2-E","edge_type":"executes","source_node_id":"S1-DEP-2","target_node_id":"S1-REL","event_time_utc":"2026-01-05T15:00:00Z","source_version":"1","target_version":"1"})
        self.assertIn("observation_window_open",closure(self.result(),"CL-01-complete")["failure_codes"])

    def test_no_deployment_is_open(self):
        remove(self.root/"edges.csv",lambda r:r["closure_id"]=="CL-01-complete" and r["edge_type"]=="executes")
        self.assertIn("missing_deployment",closure(self.result(),"CL-01-complete")["failure_codes"])

    def test_finding_requires_release_requirement_lineage(self):
        remove(self.root/"edges.csv",lambda r:r["edge_id"]=="S5-FND-REQ")
        self.assertIn("missing_finding_requirement_lineage",closure(self.result(),"CL-05-linked_incident")["failure_codes"])

    def test_derived_edge_wrong_kind_cross_service_and_stale_version(self):
        edit(self.root/"edges.csv",lambda r:r["edge_id"]=="S5-FND-REQ",{"target_node_id":"S5-FND"})
        self.assertIn("domain_range_violation",error_codes(self.result()))
        edit(self.root/"edges.csv",lambda r:r["edge_id"]=="S5-FND-REQ",{"target_node_id":"S1-REQ","target_version":"1"})
        codes=error_codes(self.result()); self.assertIn("cross_service_contamination",codes); self.assertIn("cross_closure_edge",codes)
        edit(self.root/"edges.csv",lambda r:r["edge_id"]=="S5-FND-REQ",{"target_node_id":"S5-REQ","target_version":"stale"})
        self.assertIn("stale_version",error_codes(self.result()))

    def test_gate_incident_exception_rows_match_canonical_edges(self):
        edit(self.root/"gate_evaluations.csv",lambda r:r["closure_id"]=="CL-01-complete" and r["gate_id"]=="G1",{"target_node_id":"S1-ART"})
        self.assertIn("gate_edge_mismatch",error_codes(self.result()))
        edit(self.root/"incidents.csv",lambda r:r["closure_id"]=="CL-05-linked_incident",{"deployment_id":"S1-DEP"})
        self.assertIn("incident_edge_mismatch",error_codes(self.result()))
        edit(self.root/"exceptions.csv",lambda r:True,{"gate_evaluation_id":"S1-GE-G1"})
        self.assertIn("exception_edge_mismatch",error_codes(self.result()))

    def test_gate_retry_time_and_identity_are_immutable(self):
        add_retry(self.root,evaluated="2026-01-05T09:10:00Z")
        self.assertIn("nonmonotonic_gate_retry_time",error_codes(self.result()))
        self.temp.cleanup(); self.temp,self.root,self.policy=workspace(); self.addCleanup(self.temp.cleanup)
        add_retry(self.root,target="S1-ART")
        self.assertIn("unauthorized_gate_retry_change",error_codes(self.result()))

    def test_snapshot_chain_and_status_are_validated(self):
        edit(self.root/"release_manifest.csv",lambda r:r["closure_id"]=="CL-01-complete",{"evaluation_time_utc":"2026-01-06T20:00:00Z"})
        append(self.root/"snapshots.csv",{"closure_id":"CL-01-complete","snapshot_id":"S1-SNAP-2","release_decision_id":"S1-REL","evaluated_at_utc":"2026-01-06T20:00:00Z","supersedes_snapshot_id":"wrong","declared_status":"closed_as_of"})
        add_successor_coverage(self.root, "CL-01-complete", "S1-SNAP-2", "2026-01-06T20:00:00Z")
        self.assertIn("invalid_snapshot_supersession",error_codes(self.result()))
        edit(self.root/"snapshots.csv",lambda r:r["snapshot_id"]=="S1-SNAP-2",{"supersedes_snapshot_id":"S1-SNAP-1"})
        self.assertTrue(closure(self.result(),"CL-01-complete")["closed_as_of"])
        edit(self.root/"snapshots.csv",lambda r:r["snapshot_id"]=="S1-SNAP-2",{"declared_status":"open"})
        self.assertIn("snapshot_status_mismatch",closure(self.result(),"CL-01-complete")["failure_codes"])

    def test_duplicate_and_cross_release_snapshot_rejected(self):
        append(self.root/"snapshots.csv",{"closure_id":"CL-01-complete","snapshot_id":"S1-SNAP-1","release_decision_id":"S1-REL","evaluated_at_utc":"2026-01-06T15:00:00Z","supersedes_snapshot_id":"S1-SNAP-1","declared_status":"open"})
        self.assertIn("duplicate_snapshot_id",error_codes(self.result()))
        edit(self.root/"snapshots.csv",lambda r:r["closure_id"]=="CL-05-linked_incident",{"release_decision_id":"S1-REL"})
        self.assertIn("snapshot_release_mismatch",error_codes(self.result()))

    def test_window_internal_opening_but_late_attribution_requires_reopen(self):
        add_late_incident(self.root,reopen=False)
        self.assertIn("late_attribution_without_reopen_snapshot",closure(self.result(),"CL-01-complete")["failure_codes"])

    def test_late_attribution_reopens_and_recloses(self):
        add_late_incident(self.root,reopen=True)
        self.assertTrue(closure(self.result(),"CL-01-complete")["closed_as_of"])

    def test_late_reporting_is_distinct_from_opening_and_attribution(self):
        add_late_incident(self.root,reported="2026-01-06T15:30:00Z",attributed="2026-01-06T12:00:00Z",reopen=False)
        self.assertIn("late_attribution_without_reopen_snapshot",closure(self.result(),"CL-01-complete")["failure_codes"])

    def test_feedback_ttl_begins_at_attribution(self):
        edit(self.root/"incidents.csv",lambda r:r["closure_id"]=="CL-05-linked_incident",{"feedback_link_time_utc":"2026-01-10T00:30:00Z"})
        self.assertTrue(closure(self.result(),"CL-05-linked_incident")["closed_as_of"])
        edit(self.root/"incidents.csv",lambda r:r["closure_id"]=="CL-05-linked_incident",{"feedback_link_time_utc":"2026-01-10T00:30:01Z"})
        self.assertIn("missing_or_late_feedback_link",closure(self.result(),"CL-05-linked_incident")["failure_codes"])

    def test_feedback_after_cutoff_must_not_close(self):
        edit(self.root/"incidents.csv",lambda r:r["closure_id"]=="CL-05-linked_incident",{"feedback_link_time_utc":"2026-01-10T14:30:00Z","feedback_ttl_hours":"48","resolved_at_utc":"2026-01-10T15:00:00Z"})
        result=self.result(); failures=closure(result,"CL-05-linked_incident")["failure_codes"]
        self.assertIn("feedback_after_cutoff",failures); self.assertFalse(closure(result,"CL-05-linked_incident")["closed_as_of"])
        self.assertEqual(result["metrics"]["feedback_link_success"]["numerator"],0)
        self.assertEqual(result["metrics"]["feedback_link_success"]["right_censored"],2)
        self.assertEqual(result["metrics"]["latency_families"]["incident_feedback_link"]["n"],0)
        self.assertEqual(result["metrics"]["latency_families"]["incident_feedback_link"]["right_censored"],2)

    def test_attribution_after_cutoff_not_in_latency(self):
        edit(self.root/"incidents.csv",lambda r:r["closure_id"]=="CL-05-linked_incident",{"attribution_time_utc":"2026-01-10T15:00:00Z"})
        result=self.result(); family=result["metrics"]["latency_families"]["incident_attribution"]
        self.assertIn("incident_time_inversion",closure(result,"CL-05-linked_incident")["failure_codes"])
        self.assertEqual(family["n"],1); self.assertEqual(family["right_censored"],1)
        self.assertEqual(family["maximum"],0.5)

    def test_feedback_before_report_must_not_close(self):
        edit(self.root/"incidents.csv",lambda r:r["closure_id"]=="CL-05-linked_incident",{"reported_at_utc":"2026-01-09T21:00:00Z"})
        result=self.result(); self.assertIn("feedback_before_report",closure(result,"CL-05-linked_incident")["failure_codes"])
        self.assertEqual(result["metrics"]["feedback_link_success"]["numerator"],0)

    def test_resolution_before_feedback_must_not_close(self):
        edit(self.root/"incidents.csv",lambda r:r["closure_id"]=="CL-05-linked_incident",{"resolved_at_utc":"2026-01-09T19:59:59Z"})
        result=self.result(); self.assertIn("resolution_before_feedback",closure(result,"CL-05-linked_incident")["failure_codes"])
        self.assertEqual(result["metrics"]["latency_families"]["incident_resolution"]["n"],0)

    def test_gate_resolution_cutoff_pair_is_right_censored(self):
        edit(self.root/"gate_evaluations.csv",lambda r:r["closure_id"]=="CL-03-failed_gate" and r["decision"]=="fail",{"resolution_time_utc":"2026-01-08T15:00:00Z"})
        after=self.result()["metrics"]["latency_families"]["gate_resolution"]
        self.assertEqual(after["n"],0); self.assertEqual(after["right_censored"],1)
        edit(self.root/"gate_evaluations.csv",lambda r:r["closure_id"]=="CL-03-failed_gate" and r["decision"]=="fail",{"resolution_time_utc":"2026-01-07T11:15:00Z"})
        before=self.result()["metrics"]["latency_families"]["gate_resolution"]
        self.assertEqual(before["n"],1); self.assertEqual(before["right_censored"],0)

    def test_partial_order_is_independent_of_sibling_row_order(self):
        append(self.root/"nodes.csv",{"closure_id":"CL-01-complete","node_id":"S1-REQ-2","logical_work_item_id":"S1-REQ-2","node_type":"WorkItem","work_item_kind":"Requirement","service_id":"service-1","version":"1","event_time_utc":"2026-01-04T11:00:00Z","created_at_utc":"2026-01-04T10:00:00Z","accepted_at_utc":"2026-01-04T11:00:00Z","owner":"product-owner","status":"accepted","accepted_revision":"1","metadata_json":"{}"})
        append(self.root/"nodes.csv",{"closure_id":"CL-01-complete","node_id":"S1-TST-2","node_type":"TestRun","service_id":"service-1","version":"1","event_time_utc":"2026-01-05T10:45:00Z","owner":"test-owner","status":"pass","mandatory":"true","metadata_json":"{}"})
        append(self.root/"edges.csv",{"closure_id":"CL-01-complete","edge_id":"S1-IMP-2","edge_type":"implements","source_node_id":"S1-CHG","target_node_id":"S1-REQ-2","event_time_utc":"2026-01-05T09:00:00Z","source_version":"1","target_version":"1"})
        append(self.root/"edges.csv",{"closure_id":"CL-01-complete","edge_id":"S1-EVAL-2","edge_type":"evaluated_by","source_node_id":"S1-BLD","target_node_id":"S1-TST-2","event_time_utc":"2026-01-05T10:45:00Z","source_version":"1","target_version":"1"})
        edit(self.root/"release_manifest.csv",lambda r:r["closure_id"]=="CL-01-complete",{"selected_test_run_ids":"S1-TST|S1-TST-2"})
        first=self.result(); self.assertTrue(closure(first,"CL-01-complete")["closed_as_of"])
        for name in ("nodes.csv","edges.csv"):
            fields,records=rows(self.root/name); write(self.root/name,fields,list(reversed(records)))
        second=self.result(); self.assertEqual(closure(first,"CL-01-complete"),closure(second,"CL-01-complete"))

    def test_duplicate_exception_for_one_gate_rejected(self):
        append(self.root/"nodes.csv",{"closure_id":"CL-04-expired_exception","node_id":"S4-EXC-2","node_type":"Exception","service_id":"service-4","version":"1","policy_version":"p18.0","event_time_utc":"2026-01-08T11:00:00Z","owner":"release-authority","status":"approved","metadata_json":"{}"})
        append(self.root/"edges.csv",{"closure_id":"CL-04-expired_exception","edge_id":"S4-EXC-2-E","edge_type":"authorizes","source_node_id":"S4-EXC-2","target_node_id":"S4-GE-G3","event_time_utc":"2026-01-08T11:00:00Z","source_version":"1","target_version":"1"})
        append(self.root/"exceptions.csv",{"closure_id":"CL-04-expired_exception","exception_id":"S4-EXC-2","gate_evaluation_id":"S4-GE-G3","policy_version":"p18.0","approver":"release-authority","scope_gate_id":"G3","scope_service_id":"service-4","risk_class":"medium","issue_time_utc":"2026-01-08T11:00:00Z","expiry_time_utc":"2026-01-08T13:00:00Z","rationale":"duplicate","status":"approved"})
        self.assertIn("duplicate_exception_for_gate",error_codes(self.result()))

    def test_malformed_values_return_stable_schema_errors(self):
        edit(self.root/"nodes.csv",lambda r:r["node_id"]=="S1-CHG",{"event_time_utc":"not-a-time"})
        edit(self.root/"gate_evaluations.csv",lambda r:r["closure_id"]=="CL-01-complete" and r["gate_id"]=="G1",{"attempt":"NaN"})
        edit(self.root/"release_manifest.csv",lambda r:r["closure_id"]=="CL-01-complete",{"observation_window_hours":"not-a-number"})
        result=self.result(); codes=error_codes(result); self.assertIn("invalid_timestamp",codes); self.assertIn("invalid_integer",codes); self.assertIn("invalid_number",codes); self.assertEqual(result["error_schema_version"],"1.0.0"); self.assertFalse(result["valid_input"]); self.assertIsNone(result["metrics"]); self.assertIn("data_quality", result)

    def test_service_version_and_digest_isolation(self):
        edit(self.root/"nodes.csv",lambda r:r["node_id"]=="S1-ART",{"service_id":"wrong"}); edit(self.root/"edges.csv",lambda r:r["edge_type"]=="implements",{"source_version":"stale"}); edit(self.root/"release_manifest.csv",lambda r:r["closure_id"]=="CL-01-complete",{"artifact_digest":"sha256:tampered"})
        codes=error_codes(self.result()); self.assertIn("cross_service_contamination",codes); self.assertIn("stale_version",codes); self.assertIn("artifact_digest_mismatch",closure(self.result(),"CL-01-complete")["failure_codes"])

    def test_deterministic_and_read_only(self):
        before={name:(self.root/name).read_bytes() for name in SCHEMA}; self.assertEqual(self.result(),self.result()); self.assertEqual(before,{name:(self.root/name).read_bytes() for name in SCHEMA})


if __name__ == "__main__": unittest.main(verbosity=2)

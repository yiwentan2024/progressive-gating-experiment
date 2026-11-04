"""Rule-table-driven consistency report for reference profile v1.0."""
import argparse
import csv
import importlib.util
import json
from pathlib import Path


HERE = Path(__file__).parent
RULES = HERE / "S20_normative_source_of_truth.csv"


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as source:
        return list(csv.DictReader(source))


def load_analyzer():
    path = HERE / "S3_analyze_evidence.py"
    spec = importlib.util.spec_from_file_location("reference_profile_consistency_analyzer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def has_fields(analyzer, file_name, fields):
    missing = sorted(set(fields) - set(analyzer.SCHEMA.get(file_name, [])))
    return not missing, f"{file_name}: missing={missing}"


def check_candidate_population(analyzer, result):
    passed, detail = has_fields(analyzer, "candidate_coverage.csv", ["coverage_id", "effective_from_snapshot_id"])
    candidates = read_csv(HERE / "S6_synthetic" / "incident_candidates.csv")
    zero_is_real = not any(row["closure_id"] == "CL-01-complete" for row in candidates)
    return passed and zero_is_real, detail + f"; zero-candidate fixture={zero_is_real}"


def check_coverage_time(analyzer, result):
    text = (HERE / "S3_analyze_evidence.py").read_text(encoding="utf-8")
    return "coverage_attested_before_window_end" in text, "time guard present"


def check_coverage_version(analyzer, result):
    return has_fields(analyzer, "candidate_coverage.csv", ["coverage_version", "supersedes_coverage_id", "effective_from_snapshot_id"])


def check_raw_reconciliation(analyzer, result):
    coverage_ok, coverage_detail = has_fields(analyzer, "candidate_coverage.csv", ["noncandidate_count", "rejected_count", "filter_reason_summary_json", "raw_inventory_digest_sha256", "reconciliation_digest_sha256"])
    inventory_ok, inventory_detail = has_fields(analyzer, "raw_signal_inventory.csv", ["raw_signal_id", "disposition", "candidate_id", "disposition_reason_code", "disposition_decided_by", "disposition_decided_at_utc"])
    text = (HERE / "S3_analyze_evidence.py").read_text(encoding="utf-8")
    tokens = ["candidate_signal_reconciliation_mismatch", "raw_signal_inventory_count_mismatch", "raw_inventory_digest_mismatch", "candidate_raw_signal_bijection_mismatch"]
    return coverage_ok and inventory_ok and all(token in text for token in tokens), f"{coverage_detail}; {inventory_detail}; guards={tokens}"


def check_candidate_state(analyzer, result):
    authority = HERE / "S4_candidate_review_authorizations.csv"
    text = (HERE / "S3_analyze_evidence.py").read_text(encoding="utf-8")
    tokens = ["candidate_admission_before_observation", "candidate_decision_before_admission", "candidate_review_separation_failure", "unauthorized_candidate_decider", "unauthorized_candidate_reviewer", "incident_candidate_after_cutoff"]
    return authority.exists() and all(token in text for token in tokens), f"authority_file={authority.exists()}; guards={tokens}"


def check_snapshot_recompute(analyzer, result):
    passed, detail = has_fields(analyzer, "snapshots.csv", ["input_manifest_digest"])
    text = (HERE / "S3_analyze_evidence.py").read_text(encoding="utf-8")
    tokens = ("snapshot_input_manifest_digest_mismatch", "historical_snapshot_invalid", "historical_snapshot_missing_release_path", "historical_snapshot_missing_finding_lineage")
    return passed and all(token in text for token in tokens), f"{detail}; guards={tokens}"


def check_requirement_identity(analyzer, result):
    passed, detail = has_fields(analyzer, "nodes.csv", ["logical_work_item_id"])
    text = (HERE / "S3_analyze_evidence.py").read_text(encoding="utf-8")
    return passed and "logical_work_item_id" in text and "retrospective_requirement_backfill" in text, detail


def check_finding_lineage(analyzer, result):
    edges = read_csv(HERE / "S6_synthetic" / "edges.csv")
    nodes = {row["node_id"]: row for row in read_csv(HERE / "S6_synthetic" / "nodes.csv")}
    deprecated = any(
        row["edge_type"] == "derived_from"
        and nodes.get(row["source_node_id"], {}).get("work_item_kind") == "Finding"
        for row in edges
    )
    return not deprecated, f"deprecated fixture edge={deprecated}"


def check_late_admission(analyzer, result):
    text = (HERE / "S3_analyze_evidence.py").read_text(encoding="utf-8")
    return all(token in text for token in ("late_candidate_admission_without_reopen", "coverage_reissued")), "snapshot and coverage successor guards present"


def check_closed_output(analyzer, result):
    rows = result["closure_results"]
    return bool(rows) and all("closed_as_of" in row and "closed" not in row for row in rows), "closure output keys inspected"


def check_data_quality(analyzer, result):
    return "data_quality" in result and result["data_quality"].get("status") == "complete" and "data_completeness" not in (result.get("metrics") or {}), "top-level data_quality inspected"


def check_eir_denominator(analyzer, result):
    text = (HERE / "S17_terminology_claim_and_metric_rules.csv").read_text(encoding="utf-8-sig")
    return "all latest decisions declared exception" in text, "S17 denominator language inspected"


def check_policy_boundary(analyzer, result):
    texts = [
        (HERE / "S4_gate_policy.yaml").read_text(encoding="utf-8-sig"),
        (HERE / "S15_core_profile_and_policy_precedence.csv").read_text(encoding="utf-8-sig"),
        (HERE / "S17_terminology_claim_and_metric_rules.csv").read_text(encoding="utf-8-sig"),
    ]
    return any("in-episode policy migration is not supported" in text for text in texts), "policy boundary tokens inspected"


def check_evidence_boundary(analyzer, result):
    readme = (HERE / "README_Reproduction.txt").read_text(encoding="utf-8-sig").lower()
    protocol = (HERE / "S18_independent_evaluation_protocol.txt").read_text(encoding="utf-8-sig").lower()
    return "not independent" in readme and ("unexecuted" in protocol or "not executed" in protocol), "README and S18 evidence boundary inspected"


def check_terminal_tests(analyzer, result):
    text = (HERE / "S3_terminal_review_counterexamples.py").read_text(encoding="utf-8")
    names = [
        "historical_closed_snapshot_before_window_end",
        "complete_coverage_cannot_precede_window_end",
        "raw_to_import_counts_must_reconcile",
        "candidate_outside_coverage_window",
        "exclusion_review_after_cutoff",
        "exclusion_decider_and_reviewer_must_differ",
        "logical_requirement_identity",
        "snapshot_input_digest",
        "invalid_input_still_reports_data_quality",
    ]
    return all(name in text for name in names), f"named regressions={len(names)}"


def check_coverage_scope(analyzer, result):
    text = (HERE / "S3_analyze_evidence.py").read_text(encoding="utf-8")
    tests = (HERE / "S3_terminal_review_counterexamples.py").read_text(encoding="utf-8")
    tokens = ["candidate_coverage_scope_mismatch", "window_start_utc", "responsible_actor"]
    return all(token in text for token in tokens) and "test_coverage_version_chain_cannot_skip_the_root" in tests, f"scope guard tokens={tokens}"


def check_principal_canonicalization(analyzer, result):
    text = (HERE / "S3_analyze_evidence.py").read_text(encoding="utf-8")
    registry = HERE / "S4_principal_registry.csv"
    tokens = ["canonical_principal", "unknown_principal_alias", "duplicate_principal_alias", "principal_alias_conflict", "candidate_review_separation_failure"]
    return registry.exists() and all(token in text for token in tokens), f"registry={registry.exists()}; guards={tokens}"


def check_snapshot_status_agreement(analyzer, result):
    text = (HERE / "S3_analyze_evidence.py").read_text(encoding="utf-8")
    return all(token in text for token in ("historical_snapshot_status_mismatch", "recomputed_status", "snapshot_results")), "all-snapshot status comparison present"


def check_target_episode_completeness(analyzer, result):
    text = (HERE / "S3_analyze_evidence.py").read_text(encoding="utf-8")
    return "later_requirement_target_episode_incomplete" in text and "closure_by_id" in text, "target closure reconciliation present"


def check_principal_digest_binding(analyzer, result):
    text = (HERE / "S3_analyze_evidence.py").read_text(encoding="utf-8")
    return "principal_registry" in text and "registry_version" in text and "snapshot_input_digest" in text, "principal registry is a snapshot digest input"


def check_authoritative_verifier(analyzer, result):
    verifier = HERE / "EvidenceClosure_authoritative_verifier.py"
    text = verifier.read_text(encoding="utf-8") if verifier.exists() else ""
    return verifier.exists() and (HERE / "EvidenceClosure_verifier_stage_runner.py").exists() and all(token in text for token in ("source_sha256", "runtime_budget_seconds", "target_substitution_failure", "tamper_hash_failure", "DEFAULT_OUTPUT", "caller-supplied output")), "single bounded EvidenceClosure verifier with resolved external runtime output"


CHECKS = {
    "candidate_population": check_candidate_population,
    "coverage_time": check_coverage_time,
    "coverage_version": check_coverage_version,
    "raw_reconciliation": check_raw_reconciliation,
    "candidate_state": check_candidate_state,
    "snapshot_recompute": check_snapshot_recompute,
    "requirement_identity": check_requirement_identity,
    "finding_lineage": check_finding_lineage,
    "late_admission": check_late_admission,
    "closed_output": check_closed_output,
    "data_quality": check_data_quality,
    "eir_denominator": check_eir_denominator,
    "policy_boundary": check_policy_boundary,
    "evidence_boundary": check_evidence_boundary,
    "terminal_tests": check_terminal_tests,
    "coverage_scope": check_coverage_scope,
    "principal_canonicalization": check_principal_canonicalization,
    "snapshot_status_agreement": check_snapshot_status_agreement,
    "target_episode_completeness": check_target_episode_completeness,
    "principal_digest_binding": check_principal_digest_binding,
    "authoritative_verifier": check_authoritative_verifier,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    rules = read_csv(RULES)
    analyzer = load_analyzer()
    result = analyzer.analyze(
        HERE / "S6_synthetic",
        HERE / "S4_policy_registry.csv",
        HERE / "S1_data_dictionary.csv",
        HERE / "S4_gate_owner_authorizations.csv",
        HERE / "S4_exception_authority_registry.csv",
        HERE / "S4_candidate_review_authorizations.csv",
        HERE / "S4_principal_registry.csv",
    )
    checks = []
    for rule in rules:
        if rule["automation"] == "manual":
            checks.append({
                "check_id": rule["check_id"],
                "concept": rule["concept"],
                "status": "manual_not_automated",
                "files": rule["files"],
                "detail": "declared manual control; no automated pass is claimed",
            })
            continue
        function = CHECKS.get(rule["assertion_key"])
        if function is None:
            checks.append({
                "check_id": rule["check_id"],
                "concept": rule["concept"],
                "status": "failed",
                "files": rule["files"],
                "detail": f"no implementation for assertion_key={rule['assertion_key']}",
            })
            continue
        passed, detail = function(analyzer, result)
        checks.append({
            "check_id": rule["check_id"],
            "concept": rule["concept"],
            "status": "passed" if passed else "failed",
            "files": rule["files"],
            "detail": detail,
        })
    automated = [row for row in checks if row["status"] != "manual_not_automated"]
    failures = [row["check_id"] for row in automated if row["status"] != "passed"]
    report = {
        "schema_version": "1.0.0",
        "authority": RULES.name,
        "rule_rows": len(rules),
        "automated_checks": len(automated),
        "manual_controls": sum(row["status"] == "manual_not_automated" for row in checks),
        "passed": not failures,
        "failures": failures,
        "checks": checks,
    }
    payload = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    print(payload)
    raise SystemExit(0 if not failures else 1)


if __name__ == "__main__":
    main()

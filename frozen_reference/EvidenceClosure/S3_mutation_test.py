"""Run review-targeted mutants without modifying the frozen evidence package."""
import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).parent
SOURCE_PATH = HERE / "S3_analyze_evidence.py"
SOURCE_BYTES = SOURCE_PATH.read_bytes()
SOURCE = SOURCE_BYTES.decode("utf-8")
LINE_ENDING = "\r\n" if "\r\n" in SOURCE else "\n"
SOURCE_SHA256 = hashlib.sha256(SOURCE_BYTES).hexdigest()
MUTANTS = {
    "M01_cross_service": ('if source["service_id"] != target["service_id"]:', 'if False and source["service_id"] != target["service_id"]:', "cross-service edge isolation"),
    "M02_artifact_digest": ('elif artifact["artifact_digest"] != row["artifact_digest"]:', 'elif False and artifact["artifact_digest"] != row["artifact_digest"]:', "manifest/artifact digest identity"),
    "M03_gate_target_time": ('if target_time and evaluated and evaluated < target_time:', 'if False and target_time and evaluated and evaluated < target_time:', "gate cannot predate target"),
    "M04_approval_cutoff": ('if approved and evaluated and gate["phase"] == "pre_approval" and evaluated > approved:', 'if False and approved and evaluated and gate["phase"] == "pre_approval" and evaluated > approved:', "preapproval gate cutoff"),
    "M05_policy_match": ('if gate["policy_version"] != policy_version:', 'if False and gate["policy_version"] != policy_version:', "gate/release policy agreement"),
    "M06_informational_nonblocking": ('if gate["gate_mode"] != "informational" and gate["decision"] == "fail":', 'if gate["decision"] == "fail":', "informational gates are nonblocking"),
    "M07_window_close": ('if t_eval and t_eval < window_end[deployment["node_id"]]:', 'if False and t_eval and t_eval < window_end[deployment["node_id"]]:', "per-deployment window closure"),
    "M08_selected_build_link": ('if not build or build["node_type"] != "Build" or build["node_id"] not in outgoing.get((change["node_id"], "triggers"), []):', 'if not build or build["node_type"] != "Build":', "manifest-selected build linkage"),
    "M09_requirement_union": ('if not existing_targets and not created_targets:', 'if False and not existing_targets and not created_targets:', "Finding has existing-requirement or later-requirement lineage"),
    "M10_late_attribution": ('requires_reopen = late_attribution or late_reporting', 'requires_reopen = False', "late attribution/reporting reopens snapshot"),
    "M11_snapshot_chain": ('if row["supersedes_snapshot_id"] != ordered[index - 1]["snapshot_id"]:', 'if False and row["supersedes_snapshot_id"] != ordered[index - 1]["snapshot_id"]:', "linear snapshot supersession"),
    "M12_row_edge_consistency": ('if targets != [target_id]:', 'if False and targets != [target_id]:', "row/canonical-edge consistency"),
    "M13_retry_time": ('if index and row["_evaluated"] <= ordered[index - 1]["_evaluated"]:', 'if False and index and row["_evaluated"] <= ordered[index - 1]["_evaluated"]:', "strict retry-time monotonicity"),
    "M14_positive_window": ('observation_hours = float_value(context["observation_window_hours"], closure_id, release_id, "observation_window_hours", minimum=0.000001)', 'observation_hours = float_value(context["observation_window_hours"], closure_id, release_id, "observation_window_hours", minimum=None)', "positive observation window"),
    "M15_duplicate_exception": ('if count > 1:', 'if False and count > 1:', "one Exception per GateEvaluation"),
    "M16_snapshot_status": ('if snapshots and snapshots[-1]["declared_status"] != expected_status:', 'if False and snapshots and snapshots[-1]["declared_status"] != expected_status:', "declared/computed snapshot status"),
    "M17_feedback_after_report": ('and linked >= max(reported, attributed)', 'and linked >= attributed', "feedback cannot precede incident reporting"),
    "M18_feedback_cutoff": ('feedback_within_cutoff = bool(linked and t_eval and linked <= t_eval)', 'feedback_within_cutoff = bool(linked and t_eval)', "feedback is observed no later than t_eval"),
    "M19_resolution_after_feedback": ('and resolved >= linked >= max(reported, attributed)', 'and resolved >= attributed and linked >= max(reported, attributed)', "resolution cannot precede effective feedback"),
    "M20_gate_resolution_cutoff": ('elif resolved and evaluated and t_eval and resolved <= t_eval:', 'elif resolved and evaluated and t_eval:', "gate-resolution latency is right-censored at t_eval"),
    "M21_feedback_latency_censor": ('censored["incident_feedback_link"] += 1', 'censored["incident_feedback_link"] += 0', "missing or post-cutoff feedback is counted as latency censoring"),
    "M22_attribution_cutoff": ('if t_eval and attributed <= t_eval:', 'if t_eval:', "post-cutoff attribution is excluded from latency samples"),
    "M23_required_value": ('if required and not value:', 'if False and required and not value:', "S1 value-required fields reject trimmed blanks"),
    "M24_gate_owner_authority": ('if not gate.get("_owner_authorized"):', 'if False and not gate.get("_owner_authorized"):', "gate owner must match policy or effective scoped delegation"),
    "M25_gate_decision_evidence": ('if evidence_pass is not None and not decision_matches:', 'if False and evidence_pass is not None and not decision_matches:', "declared gate decision agrees with computed evidence"),
    "M26_exception_authority": ('and target\n                and authority["service_scope"].strip() in {"*", target["service_id"].strip()}', 'and False\n                and target\n                and authority["service_scope"].strip() in {"*", target["service_id"].strip()}', "exception approver requires effective scoped authority"),
    "M27_retry_owner": ('stable = {(row["target_node_id"], row["policy_version"], row["gate_mode"], row["phase"], row["gate_owner"]) for row in ordered}', 'stable = {(row["target_node_id"], row["policy_version"], row["gate_mode"], row["phase"]) for row in ordered}', "gate retry preserves owner identity"),
    "M28_gate_unit": ('if row["unit"].strip() != policy["unit"].strip():', 'if False and row["unit"].strip() != policy["unit"].strip():', "gate unit agrees with effective policy"),
    "M29_nonfinite_number": ('if not math.isfinite(result):\n                raise ValueError("number must be finite")', 'if False and not math.isfinite(result):\n                raise ValueError("number must be finite")', "typed gate numbers must be finite"),
    "M30_authorization_id": ('if not authorization_id or authorization_id in seen_authorization_ids:', 'if False and (not authorization_id or authorization_id in seen_authorization_ids):', "owner authorization IDs are nonempty and unique"),
    "M31_authorization_interval": ('if effective and retired and retired <= effective:\n            error("invalid_authorization_interval"', 'if False and effective and retired and retired <= effective:\n            error("invalid_authorization_interval"', "authorization retirement follows effectiveness"),
    "M32_authorization_role": ('if row["role"].strip() not in AUTHORITY_ROLES:', 'if False and row["role"].strip() not in AUTHORITY_ROLES:', "exception authority role is controlled"),
    "M33_json_recursive_finite": ('if isinstance(value, float):\n            return math.isfinite(value)', 'if isinstance(value, float):\n            return True', "parsed JSON numbers remain finite at every nesting level"),
    "M34_policy_gate_joint_key": ('if gate_scope != "*" and (policy_version, gate_scope) not in known_policy_gate_pairs:', 'if False and gate_scope != "*" and (policy_version, gate_scope) not in known_policy_gate_pairs:', "authorization scope resolves by policy-version/gate joint key"),
    "M35_gate_specific_delegator": ('elif (policy_version, gate_scope) in policies and row["delegator"].strip() != policies[(policy_version, gate_scope)]["owner"].strip():', 'elif False and (policy_version, gate_scope) in policies and row["delegator"].strip() != policies[(policy_version, gate_scope)]["owner"].strip():', "gate-scoped delegator equals that gate owner"),
    "M36_unresolved_candidate": ('if candidate["status"] == "unresolved":\n                failures.append("unresolved_incident_candidate")', 'if False and candidate["status"] == "unresolved":\n                failures.append("unresolved_incident_candidate")', "unresolved incident candidates block closed_as_of"),
    "M37_no_requirement_backfill": ('or not (finding["_time"] < target["_created"] <= target["_accepted"] <= target_approved)', 'or False', "later requirement creation and acceptance follow the Finding and precede target approval"),
    "M38_nonwaivable_exception": ('if gate_policy and not as_bool(gate_policy["waiver_allowed"]):', 'if False and gate_policy and not as_bool(gate_policy["waiver_allowed"]):', "nonwaivable gates cannot be closed by exception"),
    "M39_collection_count": ('count_valid = coverage["_imported_count"] == len(batch_candidates)', 'count_valid = True', "collection imported count agrees with the candidate table"),
    "M40_collection_digest": ('digest_valid = coverage["candidate_digest_sha256"] == "sha256:" + candidate_digest(batch_candidates)', 'digest_valid = True', "collection digest agrees with the admitted candidate identity set"),
    "M41_deprecated_finding_edge": ('if row["edge_type"] == "derived_from" and source["work_item_kind"] == "Finding" and target["work_item_kind"] == "Requirement":', 'if False and row["edge_type"] == "derived_from" and source["work_item_kind"] == "Finding" and target["work_item_kind"] == "Requirement":', "Finding-to-Requirement derived_from is rejected in V18"),
    "M42_requirement_lifecycle": ('error("missing_requirement_lifecycle_time", "Requirement requires created_at_utc and accepted_at_utc", closure_id, node_id)', 'error("mutated_missing_requirement_lifecycle_time", "Requirement requires created_at_utc and accepted_at_utc", closure_id, node_id)', "Requirement creation and acceptance times have a stable failure code"),
    "M43_late_candidate_admission": ('if prior_admission_snapshots:', 'if False and prior_admission_snapshots:', "late candidate admission reopens one prior snapshot"),
    "M44_completeness_output": ('"data_completeness": {', '"data_completeness_removed": {', "data completeness is an explicit output family"),
    "M45_incident_candidate_bijection": ('if len(admitted_candidates) != 1:', 'if False and len(admitted_candidates) != 1:', "every deployment-induced incident has one attributed candidate"),
    "M46_candidate_batch_attestation": ('if (candidate["deployment_id"], candidate["source_batch_id"]) not in coverage_batch_keys:', 'if False and (candidate["deployment_id"], candidate["source_batch_id"]) not in coverage_batch_keys:', "each candidate batch has a collection attestation"),
    "M47_coverage_attestation_time": ('if row["_window_end"] and row["_attested"] and row["_attested"] < row["_window_end"]:', 'if False and row["_window_end"] and row["_attested"] and row["_attested"] < row["_window_end"]:', "coverage attestation follows the observation-window end"),
    "M48_coverage_version_root": ('if ordered[0]["_coverage_version"] != 1 or ordered[0]["supersedes_coverage_id"]:', 'if False and (ordered[0]["_coverage_version"] != 1 or ordered[0]["supersedes_coverage_id"]):', "coverage version chain starts at an unsuperseded root"),
    "M49_raw_inventory_count": ('if coverage["_raw_count"] is not None and coverage["_raw_count"] != len(inventory):', 'if False and coverage["_raw_count"] is not None and coverage["_raw_count"] != len(inventory):', "raw count equals immutable inventory rows"),
    "M50_raw_inventory_digest": ('if coverage["raw_inventory_digest_sha256"] != expected_inventory_digest:', 'if False and coverage["raw_inventory_digest_sha256"] != expected_inventory_digest:', "raw inventory digest detects item or disposition tampering"),
    "M51_reconciliation_metadata_digest": ('elif row["reconciliation_digest_sha256"] != "sha256:" + reconciliation_digest(row):', 'elif False and row["reconciliation_digest_sha256"] != "sha256:" + reconciliation_digest(row):', "reconciliation digest binds query and collector metadata"),
    "M52_candidate_observed_window": ('and not (candidate_coverage["_window_start"] <= observed <= candidate_coverage["_window_end"])', 'and False', "candidate observation lies within the coverage window"),
    "M53_candidate_admitted_attestation": ('if admitted and candidate_coverage["_attested"] and admitted > candidate_coverage["_attested"]:', 'if False and admitted and candidate_coverage["_attested"] and admitted > candidate_coverage["_attested"]:', "candidate admission is covered by the attestation"),
    "M54_candidate_observation_admission_order": ('if row["_observed"] and row["_admitted"] and row["_admitted"] < row["_observed"]:', 'if False and row["_observed"] and row["_admitted"] and row["_admitted"] < row["_observed"]:', "candidate observation precedes admission"),
    "M55_candidate_admission_decision_order": ('if row["_admitted"] and row["_decided"] and row["_decided"] < row["_admitted"]:', 'if False and row["_admitted"] and row["_decided"] and row["_decided"] < row["_admitted"]:', "candidate admission precedes decision"),
    "M56_candidate_review_order": ('or (row["_decided"] and row["_reviewed"] < row["_decided"])', 'or False', "exclusion decision precedes review"),
    "M57_candidate_actor_separation": ('elif canonical_principal(row["reviewed_by"], row["_reviewed"], object_id=candidate_id) == canonical_principal(row["decided_by"], row["_decided"], object_id=candidate_id):', 'elif False and canonical_principal(row["reviewed_by"], row["_reviewed"], object_id=candidate_id) == canonical_principal(row["decided_by"], row["_decided"], object_id=candidate_id):', "exclusion decider and reviewer are distinct canonical principals"),
    "M58_candidate_reviewer_authority": ('elif not candidate_actor_authorized(row["reviewed_by"], "governance_reviewer", row["service_id"], row["_reviewed"]):', 'elif False and not candidate_actor_authorized(row["reviewed_by"], "governance_reviewer", row["service_id"], row["_reviewed"]):', "exclusion reviewer has effective service-scoped authority"),
    "M59_candidate_decider_authority": ('elif not candidate_actor_authorized(row["decided_by"], row["decision_role"], row["service_id"], row["_decided"]):', 'elif False and not candidate_actor_authorized(row["decided_by"], row["decision_role"], row["service_id"], row["_decided"]):', "candidate decider has effective service-scoped authority"),
    "M60_snapshot_input_digest": ('if snapshot["input_manifest_digest"] != expected_digest:', 'if False and snapshot["input_manifest_digest"] != expected_digest:', "each snapshot binds its own immutable visible-input digest"),
    "M61_historical_window": ('if not snapshot_cutoff or any(', 'if False and (not snapshot_cutoff) and any(', "historical closed snapshot is rejected before its observation window closes"),
    "M62_historical_release_path": ('if not release_path_valid:', 'if False and not release_path_valid:', "historical snapshot recomputes its selected release path from cutoff-visible evidence"),
}


def main():
    parser=argparse.ArgumentParser(description="Run reference-profile review-targeted mutation checks.")
    parser.add_argument("--output",default=str(HERE/"reproduced"/"S3_mutation_report.json"),help="write regenerated report outside the frozen evidence files")
    parser.add_argument("--cluster-a",action="store_true",help="run only the P0 snapshot/coverage/candidate-exclusion mutants")
    parser.add_argument("--mutant",help="run one exact mutant ID")
    parser.add_argument("--skip-baseline",action="store_true",help="use only after an external green 107-test baseline gate")
    args=parser.parse_args()
    results=[]
    with tempfile.TemporaryDirectory() as directory:
        if args.skip_baseline:
            baseline={"returncode":0,"tests_run":107,"status":"green","gate":"external_stage_baseline"}
        else:
            baseline_env=dict(os.environ, ANALYZER_UNDER_TEST=str(HERE / "S3_analyze_evidence.py"), PYTHONPATH=str(HERE))
            baseline_process=subprocess.run([sys.executable,"-m","unittest","-v","S3_test_analyze_evidence.py","S3_adversarial_review_tests.py","S3_v18_semantic_tests.py","S3_terminal_review_counterexamples.py"],cwd=HERE,env=baseline_env,capture_output=True,text=True)
            baseline_output=(baseline_process.stdout+"\n"+baseline_process.stderr).strip()
            baseline_match=re.search(r"Ran (\d+) tests? in", baseline_output)
            baseline={"returncode":baseline_process.returncode,"tests_run":int(baseline_match.group(1)) if baseline_match else None,"status":"green" if baseline_process.returncode == 0 else "red"}
        if baseline["returncode"] != 0 or baseline["tests_run"] != 107:
            report={"scope":"P0 cluster A targeted mutants","baseline":baseline,"baseline_gate":"aborted_red_baseline","source_sha256":__import__('hashlib').sha256(SOURCE.encode('utf-8')).hexdigest(),"generated":0,"killed_by_assertion":0,"killed_by_crash":0,"survived":[],"targeted_mutation_score":None}
            output=Path(args.output); output.parent.mkdir(parents=True,exist_ok=True); output.write_text(json.dumps(report,indent=2),encoding="utf-8")
            print(json.dumps(report,indent=2)); raise SystemExit(2)
        selected = {
            mutant_id: definition for mutant_id, definition in MUTANTS.items()
            if (not args.cluster_a or int(mutant_id[1:3]) >= 47)
            and (not args.mutant or mutant_id == args.mutant)
        }
        for mutant_id,(old,new,guard) in selected.items():
            old_exact, new_exact = old.replace("\n", LINE_ENDING), new.replace("\n", LINE_ENDING)
            if old_exact not in SOURCE:
                results.append({"mutant_id":mutant_id,"guard":guard,"status":"not_generated","reason":"source pattern absent"}); continue
            mutant=Path(directory)/f"{mutant_id}.py"; mutant.write_bytes(SOURCE.replace(old_exact,new_exact,1).encode("utf-8")); mutant_sha256=hashlib.sha256(mutant.read_bytes()).hexdigest()
            env=dict(os.environ,ANALYZER_UNDER_TEST=str(mutant),PYTHONPATH=str(HERE))
            process=subprocess.run([sys.executable,"-m","unittest","-v","S3_test_analyze_evidence.py","S3_adversarial_review_tests.py","S3_v18_semantic_tests.py","S3_terminal_review_counterexamples.py"],cwd=HERE,env=env,capture_output=True,text=True)
            output=(process.stdout+"\n"+process.stderr).strip()
            failing=[]
            for line in output.splitlines():
                match=re.match(r"(test_[^ ]+ \([^)]*\)) \.\.\. (FAIL|ERROR)$",line.strip())
                if match: failing.append({"test":match.group(1),"outcome":match.group(2)})
                detail=re.match(r"(FAIL|ERROR): (test_[^ ]+ \([^)]*\))(?: \([^)]*\))?$",line.strip())
                if detail: failing.append({"test":detail.group(2),"outcome":detail.group(1)})
            if process.returncode==0: status="survived"
            elif failing and any(item["outcome"]=="FAIL" for item in failing): status="killed_assertion"
            else: status="killed_crash"
            results.append({"mutant_id":mutant_id,"guard":guard,"status":status,"returncode":process.returncode,"mutant_source_sha256":mutant_sha256,"failing_tests":failing,"output_tail":"\n".join(output.splitlines()[-18:])})
    generated=[row for row in results if row["status"]!="not_generated"]
    assertion_killed=[row for row in generated if row["status"]=="killed_assertion"]
    crash_killed=[row for row in generated if row["status"]=="killed_crash"]
    survived=[row for row in generated if row["status"]=="survived"]
    report={"scope":"P0 cluster A targeted mutants" if args.cluster_a else "review-targeted mutants; not a whole-program mutation adequacy claim","command":"python S3_mutation_test.py --cluster-a --output <path>" if args.cluster_a else "python S3_mutation_test.py --output <path>","python":platform.python_version(),"platform":platform.platform(),"source_path":SOURCE_PATH.name,"source_bytes":len(SOURCE_BYTES),"source_sha256":SOURCE_SHA256,"baseline":baseline,"baseline_gate":"green_107_of_107","generated":len(generated),"killed_by_assertion":len(assertion_killed),"killed_by_crash":len(crash_killed),"survived":[row["mutant_id"] for row in survived],"targeted_mutation_score":round((len(assertion_killed)+len(crash_killed))/len(generated),6) if generated else None,"results":results}
    output=Path(args.output); output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if generated and not survived and not crash_killed else 1)


if __name__=="__main__": main()


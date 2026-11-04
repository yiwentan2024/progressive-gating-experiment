"""Build and verify the progressive-gating ledgers.

runs.csv         one row per actual run attempt
comparisons.csv  one row per actual pair attempt
summary.json     planned matrix, scenario and run denominators, missing cells,
                 with NFI as an explicit subclass of machine OPEN rather than
                 a second count
MANIFEST.sha256  exact bytes of every other deliverable member
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import shutil
from pathlib import Path

from tools.pg_common import (
    ALL_SCENARIOS,
    CALIBRATION_SCENARIOS,
    PG_ROOT,
    ROOT,
    load_designs,
    read_json,
    sanitize_name,
    sha,
    sha256_file,
    utc_now,
    write_json,
)

RUNS_COLUMNS = [
    "batch",
    "calibration",
    "local_validation",
    "formal_batch",
    "scenario_id",
    "scenario_family",
    "arm",
    "baseline_variant",
    "repeat_index",
    "attempt",
    "pair_key",
    "run_key",
    "selected_attempt",
    "included_in_formal",
    "included_in_calibration",
    "status",
    "github_run_id",
    "github_run_url",
    "github_job_id",
    "source_commit",
    "workflow_sha256",
    "verifier_sha256",
    "collector_rule_sha256",
    "build_id",
    "expected_artifact_sha256",
    "dev_requested_image",
    "dev_deployed_digest",
    "dev_image_id",
    "qa_requested_image",
    "qa_deployed_digest",
    "qa_image_id",
    "staging_requested_image",
    "staging_deployed_digest",
    "staging_image_id",
    "dev_gate",
    "qa_gate",
    "staging_gate",
    "dev_image_identity",
    "qa_image_identity",
    "staging_image_identity",
    "dev_attestation_binding",
    "qa_attestation_binding",
    "staging_attestation_binding",
    "first_failure_stage",
    "first_failure_reason",
    "downstream_deployed",
    "attestation_status",
    "attestation_verify_exit",
    "audit_status",
    "audit_machine_decision",
    "audit_evidence_status",
    "audit_codes",
    "outcome_class",
    "expected_match",
    "inclusion",
    "exclusion_reason",
    "input_sha256",
    "canonical_input_sha256",
    "semantic_sha256",
    "audit_record_path",
    "evidence_path",
    "started_at_utc",
    "finished_at_utc",
]

COMPARISON_COLUMNS = [
    "batch",
    "calibration",
    "local_validation",
    "scenario_id",
    "scenario_family",
    "repeat_index",
    "attempt",
    "pair_key",
    "p0_run_key",
    "p1_run_key",
    "selected_attempt",
    "included_in_formal",
    "included_in_calibration",
    "status",
    "same_build",
    "same_artifact_digest",
    "same_scenario_design",
    "semantic_inputs_match",
    "baseline_outcomes_match",
    "p0_baseline",
    "p1_baseline",
    "p0_first_failure_stage",
    "p0_first_failure_code",
    "p1_first_failure_stage",
    "p1_first_failure_code",
    "p0_stage_gates",
    "p1_stage_gates",
    "p0_audit_status",
    "p1_audit_status",
    "p1_machine_decision",
    "p1_evidence_status",
    "p1_codes",
    "expected_codes_hit",
    "expected_evidence_status_hit",
    "baseline_pass_and_p1_open",
    "baseline_failure_control",
    "comparable",
    "not_comparable_reason",
]


def _blank(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _bool(value) -> str:
    return "true" if value else "false"


def load_metas(root: Path) -> list:
    metas = []
    runs_dir = root / "runs"
    if not runs_dir.is_dir():
        return metas
    for path in sorted(runs_dir.glob("*/run_meta.json")):
        try:
            meta = read_json(path)
        except (OSError, ValueError):
            continue
        meta["_dir"] = str(path.parent)
        meta["_rel"] = str(path.parent.relative_to(root))
        metas.append(meta)
    return metas


def _artifact(meta, name):
    try:
        return read_json(Path(meta["_dir"]) / name)
    except (OSError, ValueError):
        return {}


def _evidence(meta) -> dict:
    return {
        "chain": _artifact(meta, "raw/chain_result.json"),
        "case": _artifact(meta, "normalized/case.json"),
        "injection": _artifact(meta, "injection.json"),
        "verifier": _artifact(meta, "verifier/result.json"),
    }


def _stage(meta, evidence, stage) -> dict:
    return (evidence["chain"].get("stages") or {}).get(stage, {})


def _baseline_signature(meta, evidence) -> dict:
    chain = evidence["chain"]
    return {
        "baseline": meta.get("baseline_result"),
        "first_failure_stage": meta.get("first_failure_stage"),
        "first_failure_code": meta.get("first_failure_code"),
        "stages": {
            stage: ((chain.get("stages") or {}).get(stage) or {}).get("gate_status", "NOT_DEPLOYED")
            for stage in ("dev", "qa", "staging")
        },
        "downstream": chain.get("downstream"),
    }


def _semantic_match(p0, p1, e0, e1) -> bool:
    s0, s1 = p0.get("semantic_sha256"), p1.get("semantic_sha256")
    if s0 is not None and s1 is not None:
        return s0 == s1
    if s0 is None and s1 is None:
        # Baseline-block pairs have no audit case; compare the live stage outcome.
        return _baseline_signature(p0, e0) == _baseline_signature(p1, e1)
    return False


def _attempt_record(p0, p1, e0, e1, design, calibration, local) -> dict:
    reasons = []
    same_build = bool(p0 and p1 and p0.get("build", {}).get("build_id") == p1.get("build", {}).get("build_id"))
    same_artifact = bool(
        p0
        and p1
        and p0.get("build", {}).get("artifact", {}).get("sha256")
        == p1.get("build", {}).get("artifact", {}).get("sha256")
    )
    same_design = bool(p0 and p1 and p0.get("design_sha256") == p1.get("design_sha256"))
    semantic_match = bool(p0 and p1 and _semantic_match(p0, p1, e0, e1))
    baseline_match = bool(
        p0
        and p1
        and p0.get("baseline_result") == p1.get("baseline_result")
        and p0.get("first_failure_stage") == p1.get("first_failure_stage")
        and p0.get("first_failure_code") == p1.get("first_failure_code")
    )
    valid = bool(
        p0
        and p1
        and p0.get("valid_execution")
        and p1.get("valid_execution")
        and p0.get("baseline_result") != "TOOL_FAILURE"
        and p1.get("baseline_result") != "TOOL_FAILURE"
    )
    if not (p0 and p1):
        reasons.append("missing arm")
    if not same_build:
        reasons.append("different build_id")
    if not same_artifact:
        reasons.append("different pinned artifact digest")
    if not same_design:
        reasons.append("different scenario design hash")
    if not semantic_match:
        reasons.append("semantic input mismatch")
    if not baseline_match:
        reasons.append("baseline outcomes differ")
    if not valid:
        reasons.append("tool failure or incomplete execution")
    comparable = all([p0, p1, same_build, same_artifact, same_design, semantic_match, baseline_match, valid])
    p1_decision = (p1 or {}).get("audit_machine_decision")
    p1_codes = (p1 or {}).get("audit_failure_codes") or []
    expected_codes = design.get("audit_expected", {}).get("codes", [])
    expected_evidence = design.get("audit_expected", {}).get("evidence_status")
    if design.get("type") == "BASELINE_BLOCK":
        expected_codes_hit = bool(
            (p0 or {}).get("first_failure_code") == design["baseline_expected"]["first_failure_code"]
            and (p1 or {}).get("first_failure_code") == design["baseline_expected"]["first_failure_code"]
        )
        expected_evidence_hit = True
    else:
        expected_codes_hit = set(expected_codes).issubset(set(p1_codes)) if expected_codes else True
        expected_evidence_hit = (
            (p1 or {}).get("audit_evidence_status") == expected_evidence if expected_evidence else True
        )
    baseline_pass = bool((p0 or {}).get("baseline_result") == "PASS" and (p1 or {}).get("baseline_result") == "PASS")
    baseline_failure_control = bool(
        design.get("type") == "BASELINE_BLOCK"
        and (p0 or {}).get("baseline_result") == "FAIL"
        and (p1 or {}).get("baseline_result") == "FAIL"
        and expected_codes_hit
        and all(
            item.get("deployed") is False
            for item in (((p0 or {}).get("downstream") or {}).values())
        )
        and all(
            item.get("deployed") is False
            for item in (((p1 or {}).get("downstream") or {}).values())
        )
    )
    return {
        "same_build": same_build,
        "same_artifact_digest": same_artifact,
        "same_scenario_design": same_design,
        "semantic_inputs_match": semantic_match,
        "baseline_outcomes_match": baseline_match,
        "comparable": comparable,
        "not_comparable_reason": "; ".join(reasons),
        "expected_codes_hit": expected_codes_hit,
        "expected_evidence_status_hit": expected_evidence_hit,
        "baseline_pass_and_p1_open": bool(baseline_pass and p1_decision == "OPEN"),
        "baseline_failure_control": baseline_failure_control,
    }


def _select_attempt(records: list) -> dict | None:
    if not records:
        return None
    comparable = [r for r in records if r["comparable"]]
    if comparable:
        return comparable[0]
    return records[0]


def _pair_attempts(metas: list, batch: str, scenario: str, repeat: int) -> list:
    attempts = sorted(
        {
            m.get("attempt")
            for m in metas
            if m.get("batch") == batch and m.get("scenario") == scenario and m.get("repeat_index") == repeat
        }
    )
    rows = []
    designs = load_designs()
    for attempt in attempts:
        group = [
            m
            for m in metas
            if m.get("batch") == batch
            and m.get("scenario") == scenario
            and m.get("repeat_index") == repeat
            and m.get("attempt") == attempt
        ]
        p0 = next((m for m in group if m.get("arm") == "P0"), None)
        p1 = next((m for m in group if m.get("arm") == "P1"), None)
        e0 = _evidence(p0) if p0 else {}
        e1 = _evidence(p1) if p1 else {}
        record = _attempt_record(p0, p1, e0, e1, designs[scenario], False, False)
        rows.append({"attempt": attempt, "p0": p0, "p1": p1, "e0": e0, "e1": e1, **record})
    return rows


def _plan_pairs(protocol: dict | None) -> list:
    protocol = protocol or {}
    batches = []
    formal = (protocol.get("batch_plan") or {}).get("formal") or {}
    calibration = (protocol.get("batch_plan") or {}).get("calibration") or {}
    batches.append(
        (
            formal.get("batch_id", "PG-FORMAL-01"),
            formal.get("scenarios", list(ALL_SCENARIOS)),
            int(formal.get("repeats", 3)),
            False,
        )
    )
    batches.append(
        (
            calibration.get("batch_id", "PG-CAL-01"),
            calibration.get("scenarios", list(CALIBRATION_SCENARIOS)),
            int(calibration.get("repeats", 1)),
            True,
        )
    )
    cells = []
    for batch, scenarios, repeats, calibration_flag in batches:
        for scenario in scenarios:
            for repeat in range(1, repeats + 1):
                cells.append(
                    {
                        "batch": batch,
                        "scenario": scenario,
                        "repeat": repeat,
                        "calibration": calibration_flag,
                    }
                )
    return cells


def _outcome_class(meta) -> str:
    if not meta.get("valid_execution"):
        return "TOOL_FAILURE"
    status = meta.get("audit_status")
    if status == "NOT_CONFIGURED":
        return "AUDIT_NOT_CONFIGURED"
    if status == "NOT_RUN_UPSTREAM_BLOCKED":
        return "AUDIT_NOT_RUN_UPSTREAM_BLOCKED"
    if status == "TOOL_FAILURE":
        return "AUDIT_TOOL_FAILURE"
    if status == "RUN" and meta.get("audit_machine_decision") in ("CLOSED", "OPEN"):
        return "VALID_MACHINE_DECISION"
    return "UNKNOWN"


def _stage_gates(chain: dict) -> str:
    return ";".join(
        f"{stage}:{((chain.get('stages') or {}).get(stage) or {}).get('gate_status') or 'NOT_DEPLOYED'}"
        for stage in ("dev", "qa", "staging")
    )


def _run_row(meta, evidence, selected_attempt, included_formal, included_calibration, local_validation, inclusion, exclusion):
    design = load_designs()[meta["scenario"]]
    chain = evidence["chain"]
    stage_rows = {}
    for stage in ("dev", "qa", "staging"):
        row = (chain.get("stages") or {}).get(stage, {})
        stage_rows[stage] = {
            "requested": row.get("image_tag") or "",
            "deployed": row.get("deployed_sha256") or "",
            "image_id": row.get("image_id") or "",
            "gate": row.get("gate_status") or "NOT_DEPLOYED",
            "image_identity": row.get("image_identity_check") or "NOT_EXECUTED",
            "attestation_binding": row.get("attestation_binding") or "NOT_EXECUTED",
        }
    downstream = chain.get("downstream") or {}
    if downstream:
        if any(v.get("deployed") is True for v in downstream.values()):
            downstream_value = "YES"
        elif all(v.get("deployed") is False for v in downstream.values()):
            downstream_value = "NO"
        else:
            downstream_value = "UNKNOWN"
    else:
        downstream_value = "UNKNOWN"
    return {
        "batch": meta.get("batch"),
        "calibration": _bool(meta.get("calibration")),
        "local_validation": _bool(local_validation),
        "formal_batch": _bool(str(meta.get("batch", "")).startswith("PG-FORMAL")),
        "scenario_id": meta.get("scenario"),
        "scenario_family": design.get("scenario_family"),
        "arm": meta.get("arm"),
        "baseline_variant": "B1" if meta.get("arm") == "P0" else "B2",
        "repeat_index": meta.get("repeat_index"),
        "attempt": meta.get("attempt"),
        "pair_key": meta.get("pair_key"),
        "run_key": meta.get("run_key"),
        "selected_attempt": _bool(selected_attempt),
        "included_in_formal": _bool(included_formal),
        "included_in_calibration": _bool(included_calibration),
        "status": "COMPLETED" if meta.get("valid_execution") else "TOOL_FAILURE",
        "github_run_id": meta.get("github_run_id"),
        "github_run_url": meta.get("github_run_url"),
        "github_job_id": meta.get("github_job_id"),
        "source_commit": meta.get("source_commit"),
        "workflow_sha256": meta.get("workflow_sha256"),
        "verifier_sha256": meta.get("verifier_sha256"),
        "collector_rule_sha256": meta.get("collector_rule_sha256"),
        "build_id": meta.get("build", {}).get("build_id"),
        "expected_artifact_sha256": meta.get("build", {}).get("artifact", {}).get("sha256"),
        "dev_requested_image": stage_rows["dev"]["requested"],
        "dev_deployed_digest": stage_rows["dev"]["deployed"],
        "dev_image_id": stage_rows["dev"]["image_id"],
        "qa_requested_image": stage_rows["qa"]["requested"],
        "qa_deployed_digest": stage_rows["qa"]["deployed"],
        "qa_image_id": stage_rows["qa"]["image_id"],
        "staging_requested_image": stage_rows["staging"]["requested"],
        "staging_deployed_digest": stage_rows["staging"]["deployed"],
        "staging_image_id": stage_rows["staging"]["image_id"],
        "dev_gate": stage_rows["dev"]["gate"],
        "qa_gate": stage_rows["qa"]["gate"],
        "staging_gate": stage_rows["staging"]["gate"],
        "dev_image_identity": stage_rows["dev"]["image_identity"],
        "qa_image_identity": stage_rows["qa"]["image_identity"],
        "staging_image_identity": stage_rows["staging"]["image_identity"],
        "dev_attestation_binding": stage_rows["dev"]["attestation_binding"],
        "qa_attestation_binding": stage_rows["qa"]["attestation_binding"],
        "staging_attestation_binding": stage_rows["staging"]["attestation_binding"],
        "first_failure_stage": meta.get("first_failure_stage"),
        "first_failure_reason": meta.get("first_failure_code"),
        "downstream_deployed": downstream_value,
        "attestation_status": meta.get("build", {}).get("attestation", {}).get("status"),
        "attestation_verify_exit": meta.get("build", {}).get("attestation", {}).get("verify_exit"),
        "audit_status": meta.get("audit_status"),
        "audit_machine_decision": meta.get("audit_machine_decision"),
        "audit_evidence_status": meta.get("audit_evidence_status"),
        "audit_codes": ";".join(meta.get("audit_failure_codes") or []),
        "outcome_class": _outcome_class(meta),
        "expected_match": _bool(meta.get("expected_match")),
        "inclusion": inclusion,
        "exclusion_reason": exclusion,
        "input_sha256": meta.get("input_sha256"),
        "canonical_input_sha256": meta.get("canonical_input_sha256"),
        "semantic_sha256": meta.get("semantic_sha256"),
        "audit_record_path": (meta.get("evidence_paths") or {}).get("audit_record"),
        "evidence_path": meta.get("_rel"),
        "started_at_utc": meta.get("started_at_utc"),
        "finished_at_utc": meta.get("finished_at_utc"),
    }


def _comparison_row(cell, attempt_record, selected, included_formal, included_calibration, local_validation):
    scenario = cell["scenario"]
    design = load_designs()[scenario]
    p0 = attempt_record.get("p0") or {}
    p1 = attempt_record.get("p1") or {}
    e0 = attempt_record.get("e0") or {}
    e1 = attempt_record.get("e1") or {}
    return {
        "batch": cell["batch"],
        "calibration": _bool(cell["calibration"]),
        "local_validation": _bool(local_validation),
        "scenario_id": scenario,
        "scenario_family": design.get("scenario_family"),
        "repeat_index": cell["repeat"],
        "attempt": attempt_record["attempt"],
        "pair_key": (p0.get("pair_key") or p1.get("pair_key")),
        "p0_run_key": p0.get("run_key"),
        "p1_run_key": p1.get("run_key"),
        "selected_attempt": _bool(selected),
        "included_in_formal": _bool(included_formal),
        "included_in_calibration": _bool(included_calibration),
        "status": "COMPLETED" if (p0.get("valid_execution") and p1.get("valid_execution")) else "TOOL_FAILURE",
        "same_build": _bool(attempt_record["same_build"]),
        "same_artifact_digest": _bool(attempt_record["same_artifact_digest"]),
        "same_scenario_design": _bool(attempt_record["same_scenario_design"]),
        "semantic_inputs_match": _bool(attempt_record["semantic_inputs_match"]),
        "baseline_outcomes_match": _bool(attempt_record["baseline_outcomes_match"]),
        "p0_baseline": p0.get("baseline_result"),
        "p1_baseline": p1.get("baseline_result"),
        "p0_first_failure_stage": p0.get("first_failure_stage"),
        "p0_first_failure_code": p0.get("first_failure_code"),
        "p1_first_failure_stage": p1.get("first_failure_stage"),
        "p1_first_failure_code": p1.get("first_failure_code"),
        "p0_stage_gates": _stage_gates(e0.get("chain") or {}),
        "p1_stage_gates": _stage_gates(e1.get("chain") or {}),
        "p0_audit_status": p0.get("audit_status"),
        "p1_audit_status": p1.get("audit_status"),
        "p1_machine_decision": p1.get("audit_machine_decision"),
        "p1_evidence_status": p1.get("audit_evidence_status"),
        "p1_codes": ";".join(p1.get("audit_failure_codes") or []),
        "expected_codes_hit": _bool(attempt_record["expected_codes_hit"]),
        "expected_evidence_status_hit": _bool(attempt_record["expected_evidence_status_hit"]),
        "baseline_pass_and_p1_open": _bool(attempt_record["baseline_pass_and_p1_open"]),
        "baseline_failure_control": _bool(attempt_record["baseline_failure_control"]),
        "comparable": _bool(attempt_record["comparable"]),
        "not_comparable_reason": attempt_record["not_comparable_reason"],
    }


def _write_csv(path: Path, columns: list, rows: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _blank(row.get(key)) for key in columns})


def _stage_counts(metas: list) -> dict:
    counts = {
        stage: {
            "PASS": 0,
            "FAIL": 0,
            "TOOL_FAILURE": 0,
            "UPSTREAM_NOT_RUN": 0,
            "NOT_DEPLOYED": 0,
            "UNKNOWN": 0,
        }
        for stage in ("dev", "qa", "staging")
    }
    for meta in metas:
        chain = _evidence(meta)["chain"]
        failure_stage = chain.get("first_failure_stage")
        failure_index = ("dev", "qa", "staging").index(failure_stage) if failure_stage in ("dev", "qa", "staging") else None
        for index, stage in enumerate(("dev", "qa", "staging")):
            status = ((chain.get("stages") or {}).get(stage) or {}).get("gate_status")
            if status in counts[stage]:
                counts[stage][status] += 1
            elif failure_index is not None and index > failure_index:
                counts[stage]["UPSTREAM_NOT_RUN"] += 1
            elif not status:
                counts[stage]["NOT_DEPLOYED"] += 1
            else:
                counts[stage]["UNKNOWN"] += 1
    return counts


def _aggregate_batch(metas: list, pairs: list, batch: str, include_all: bool = False) -> dict:
    batch_metas = [m for m in metas if m.get("batch") == batch]
    selected_pairs = [p for p in pairs if p.get("batch") == batch and p.get("selected")]
    selected_runs = [
        pair[key] for pair in selected_pairs for key in ("p0", "p1") if pair.get(key)
    ]
    included_runs = selected_runs if include_all else [m for m in selected_runs if m.get("formal_eligible")]
    baseline_pass_pairs = [p for p in selected_pairs if p.get("comparable") and (p.get("p0") or {}).get("baseline_result") == "PASS" and (p.get("p1") or {}).get("baseline_result") == "PASS"]
    p1_open = [p for p in baseline_pass_pairs if (p.get("p1") or {}).get("audit_machine_decision") == "OPEN"]
    open_evidence = [p for p in p1_open if (p.get("p1") or {}).get("audit_evidence_status") == "OPEN"]
    open_nfi = [p for p in p1_open if (p.get("p1") or {}).get("audit_evidence_status") == "NFI"]
    open_other = [p for p in p1_open if p not in open_evidence and p not in open_nfi]
    closed = [p for p in baseline_pass_pairs if (p.get("p1") or {}).get("audit_machine_decision") == "CLOSED"]
    audit_tool_failure = [p for p in selected_pairs if (p.get("p1") or {}).get("audit_status") == "TOOL_FAILURE"]
    baseline_controls = [
        p
        for p in selected_pairs
        if p.get("comparable") and (p.get("p0") or {}).get("scenario") in ("PG-ART", "PG-QA")
    ]
    return {
        "batch": batch,
        "actual_runs": len(batch_metas),
        "selected_pairs": len(selected_pairs),
        "comparable_pairs": len([p for p in selected_pairs if p.get("comparable")]),
        "included_runs": len(included_runs),
        "stage_counts": _stage_counts(included_runs),
        "baseline_controls": {
            "pairs": len(baseline_controls),
            "actual_baseline_failure_and_downstream_absent": len(
                [p for p in baseline_controls if p.get("baseline_failure_control")]
            ),
        },
        "audit_contrast": {
            "pairs_with_baseline_pass": len(baseline_pass_pairs),
            "p0_not_configured": len(
                [p for p in baseline_pass_pairs if (p.get("p0") or {}).get("audit_status") == "NOT_CONFIGURED"]
            ),
            "p1_closed": len(closed),
            "p1_machine_open_total": len(p1_open),
            "p1_machine_open_evidence_open": len(open_evidence),
            "p1_machine_open_evidence_nfi": len(open_nfi),
            "p1_machine_open_evidence_other": len(open_other),
            "nfi_is_subclass_of_machine_open": True,
            "p1_audit_tool_failure": len(audit_tool_failure),
            "p1_open_with_expected_codes": len(
                [p for p in p1_open if p.get("expected_codes_hit")]
            ),
        },
        "anomalies": [
            {
                "run_key": m.get("run_key"),
                "scenario": m.get("scenario"),
                "arm": m.get("arm"),
                "attempt": m.get("attempt"),
                "reason": m.get("chain_error") or "tool failure or expected mismatch",
                "valid_execution": m.get("valid_execution"),
                "expected_match": m.get("expected_match"),
            }
            for m in batch_metas
            if not m.get("valid_execution") or m.get("audit_status") == "TOOL_FAILURE" or not m.get("expected_match")
        ],
    }


def _scenario_summary(pairs: list) -> list:
    designs = load_designs()
    rows = []
    for scenario in ALL_SCENARIOS:
        selected = [p for p in pairs if p.get("scenario") == scenario and p.get("selected") and p.get("comparable")]
        decisions = [(p.get("p1") or {}).get("audit_machine_decision") for p in selected]
        baselines = [(p.get("p0") or {}).get("baseline_result") for p in selected]
        rows.append(
            {
                "scenario_id": scenario,
                "scenario_family": designs[scenario].get("scenario_family"),
                "expected": designs[scenario].get("audit_expected"),
                "selected_comparable_pairs": len(selected),
                "baseline_results": baselines,
                "p1_decisions": decisions,
                "all_repeats_agree": len(set(decisions)) <= 1 and len(set(baselines)) <= 1,
            }
        )
    return rows


def _hashes(protocol: dict | None = None) -> dict:
    protocol = protocol or {}
    raw = protocol.get("hashes") or {}
    hashes = dict(raw) if isinstance(raw, dict) else {row["path"]: row for row in raw}
    hashes["protocol"] = {
        "path": "progressive-gating/protocol.json",
        "sha256": sha256_file(PG_ROOT / "protocol.json") if (PG_ROOT / "protocol.json").is_file() else None,
    }
    return hashes


def finalize(args) -> int:
    root = Path(args.root)
    if not root.is_absolute():
        root = ROOT / root
    root.mkdir(parents=True, exist_ok=True)
    protocol_path = root / "protocol.json"
    protocol = read_json(protocol_path) if protocol_path.is_file() else {}
    designs = load_designs()
    metas = load_metas(root)
    present_batches = {str(m.get("batch")) for m in metas if m.get("batch")}
    cells = _plan_pairs(protocol)
    all_pairs = []
    for cell in cells:
        attempts = _pair_attempts(metas, cell["batch"], cell["scenario"], cell["repeat"])
        for record in attempts:
            record["batch"] = cell["batch"]
            record["scenario"] = cell["scenario"]
            record["repeat"] = cell["repeat"]
            record["calibration"] = cell["calibration"]
            all_pairs.append(record)
        selected = _select_attempt(attempts)
        if selected is not None:
            selected["selected"] = True
    # Local batches: no plan, but the same attempt/comparison rules apply.
    local_batches = sorted(
        {
            m.get("batch")
            for m in metas
            if m.get("batch")
            and not str(m.get("batch")).startswith("PG-FORMAL")
            and not str(m.get("batch")).startswith("PG-CAL")
        }
    )
    local_cells = []
    for batch in local_batches:
        scenarios = sorted({m.get("scenario") for m in metas if m.get("batch") == batch})
        for scenario in scenarios:
            repeats = sorted({m.get("repeat_index") for m in metas if m.get("batch") == batch and m.get("scenario") == scenario})
            for repeat in repeats:
                local_cells.append({"batch": batch, "scenario": scenario, "repeat": repeat, "calibration": False})
    for cell in local_cells:
        attempts = _pair_attempts(metas, cell["batch"], cell["scenario"], cell["repeat"])
        for record in attempts:
            record["batch"] = cell["batch"]
            record["scenario"] = cell["scenario"]
            record["repeat"] = cell["repeat"]
            record["calibration"] = False
            all_pairs.append(record)
        selected = _select_attempt(attempts)
        if selected is not None:
            selected["selected"] = True

    # Selected attempt per (batch, scenario, repeat).
    selected_by_cell = {}
    for pair in all_pairs:
        if pair.get("selected"):
            selected_by_cell[(pair["batch"], pair["scenario"], pair["repeat"])] = pair["attempt"]

    runs_rows = []
    comparisons_rows = []
    missing_cells = []
    missing_runs = []
    for cell in cells + local_cells:
        cell_pair_rows = [
            p for p in all_pairs if p["batch"] == cell["batch"] and p["scenario"] == cell["scenario"] and p["repeat"] == cell["repeat"]
        ]
        selected_attempt = selected_by_cell.get((cell["batch"], cell["scenario"], cell["repeat"]))
        local = cell["batch"] not in {x["batch"] for x in cells}
        if not cell_pair_rows:
            missing_cells.append(
                {
                    "batch": cell["batch"],
                    "scenario": cell["scenario"],
                    "repeat_index": cell["repeat"],
                    "calibration": cell["calibration"],
                    "reason": "no attempt evidence",
                }
            )
            continue
        for pair in cell_pair_rows:
            pair_selected = pair["attempt"] == selected_attempt
            p0 = pair.get("p0")
            p1 = pair.get("p1")
            for meta, evidence, arm in ((p0, pair.get("e0"), "P0"), (p1, pair.get("e1"), "P1")):
                if not meta:
                    missing_runs.append(
                        {
                            "batch": cell["batch"],
                            "scenario": cell["scenario"],
                            "repeat_index": cell["repeat"],
                            "attempt": pair["attempt"],
                            "arm": arm,
                            "reason": "arm evidence missing for an attempted pair",
                        }
                    )
                    continue
                included_formal = bool(
                    pair_selected
                    and pair["comparable"]
                    and str(cell["batch"]).startswith("PG-FORMAL")
                    and meta.get("formal_eligible")
                )
                included_calibration = bool(
                    pair_selected
                    and pair["comparable"]
                    and str(cell["batch"]).startswith("PG-CAL")
                    and not meta.get("local")
                )
                inclusion = "INCLUDED" if (included_formal or included_calibration) else "EXCLUDED"
                exclusion = ""
                if not pair_selected:
                    exclusion = f"attempt {pair['attempt']} not selected (selected {selected_attempt})"
                elif not pair["comparable"]:
                    exclusion = pair["not_comparable_reason"]
                elif str(cell["batch"]).startswith("PG-FORMAL") and not meta.get("formal_eligible"):
                    exclusion = "run is not formal-eligible (attestation/local/dirty)"
                elif not (included_formal or included_calibration):
                    exclusion = "batch type does not count this run"
                runs_rows.append(
                    _run_row(
                        meta,
                        evidence,
                        pair_selected,
                        included_formal,
                        included_calibration,
                        local,
                        inclusion,
                        exclusion,
                    )
                )
            comparisons_rows.append(
                _comparison_row(
                    cell,
                    pair,
                    pair_selected,
                    bool(
                        pair_selected
                        and pair["comparable"]
                        and str(cell["batch"]).startswith("PG-FORMAL")
                        and p0
                        and p1
                        and p0.get("formal_eligible")
                        and p1.get("formal_eligible")
                    ),
                    bool(
                        pair_selected
                        and pair["comparable"]
                        and str(cell["batch"]).startswith("PG-CAL")
                        and not ((p0 or {}).get("local") or (p1 or {}).get("local"))
                    ),
                    local,
                )
            )

    _write_csv(root / "runs.csv", RUNS_COLUMNS, runs_rows)
    _write_csv(root / "comparisons.csv", COMPARISON_COLUMNS, comparisons_rows)

    formal_batch = ((protocol.get("batch_plan") or {}).get("formal") or {}).get("batch_id", "PG-FORMAL-01")
    calibration_batch = ((protocol.get("batch_plan") or {}).get("calibration") or {}).get("batch_id", "PG-CAL-01")
    formal_spec = (protocol.get("batch_plan") or {}).get("formal") or {}
    calibration_spec = (protocol.get("batch_plan") or {}).get("calibration") or {}
    formal_scenarios = formal_spec.get("scenarios", list(ALL_SCENARIOS))
    formal_repeats = int(formal_spec.get("repeats", 3))
    calibration_scenarios = calibration_spec.get("scenarios", list(CALIBRATION_SCENARIOS))
    calibration_repeats = int(calibration_spec.get("repeats", 1))
    formal_pairs = [p for p in all_pairs if p["batch"] == formal_batch]
    calibration_pairs = [p for p in all_pairs if p["batch"] == calibration_batch]
    local_pairs = [p for p in all_pairs if p["batch"] in local_batches]
    formal_metas = [m for m in metas if m.get("batch") == formal_batch]
    calibration_metas = [m for m in metas if m.get("batch") == calibration_batch]
    local_metas = [m for m in metas if m.get("batch") in local_batches]
    formal_summary = _aggregate_batch(formal_metas, formal_pairs, formal_batch)
    summary = {
        "schema": "pg-summary-1",
        "generated_at_utc": utc_now(),
        "protocol": {
            "path": "protocol.json",
            "sha256": sha256_file(protocol_path) if protocol_path.is_file() else None,
        },
        "verifier": {
            "path": "verifier/closure_audit.py",
            "sha256": sha256_file(ROOT / "verifier" / "closure_audit.py"),
        },
        "denominators": {
            "formal_scenarios": len(formal_scenarios),
            "formal_runs_planned": 2 * len(formal_scenarios) * formal_repeats,
            "formal_pairs_planned": len(formal_scenarios) * formal_repeats,
            "formal_repeats_per_scenario": formal_repeats,
            "repeat_note": "three repeats are consistency checks, not three independent scenarios",
            "calibration_scenarios": len(calibration_scenarios),
            "calibration_runs_planned": 2 * len(calibration_scenarios) * calibration_repeats,
            "calibration_pairs_planned": len(calibration_scenarios) * calibration_repeats,
        },
        "formal": formal_summary,
        "formal_evidence": {
            "planned_runs": 2 * len(formal_scenarios) * formal_repeats,
            "actual_runs": len(formal_metas),
            "valid_execution_runs": len([m for m in formal_metas if m.get("valid_execution")]),
            "formal_eligible_runs": len([m for m in formal_metas if m.get("formal_eligible")]),
            "missing_cells": len([c for c in missing_cells if c["batch"] == formal_batch]),
            "reruns": len([m for m in formal_metas if m.get("attempt", 1) > 1]),
        },
        "calibration": _aggregate_batch(calibration_metas, calibration_pairs, calibration_batch, include_all=True),
        "calibration_evidence": {
            "planned_runs": 2 * len(calibration_scenarios) * calibration_repeats,
            "actual_runs": len(calibration_metas),
            "valid_execution_runs": len([m for m in calibration_metas if m.get("valid_execution")]),
            "missing_cells": len([c for c in missing_cells if c["batch"] == calibration_batch]),
            "reruns": len([m for m in calibration_metas if m.get("attempt", 1) > 1]),
        },
        "missing_evidence": {
            "scope_batches": sorted(present_batches),
            "scope_rule": "planned cells are scoped to the batches present in this evidence root; an evidence root with no run_meta.json reports the full plan",
            "planned_cells_without_attempt": [
                c for c in missing_cells if not present_batches or str(c["batch"]) in present_batches
            ],
            "attempted_pairs_with_missing_arm": missing_runs,
        },
        "attempt_selection": {
            "rule": "first comparable attempt per (batch, scenario, repeat)",
            "all_attempts_retained_in_runs_csv": True,
            "no_cherry_picking": True,
        },
        "local_validation": {
            "batches": local_batches,
            "runs": len(local_metas),
            "pairs": len(local_pairs),
            "aggregate_by_batch": {
                batch: _aggregate_batch(local_metas, local_pairs, batch, include_all=True) for batch in local_batches
            },
            "note": "local validation uses no GitHub attestation and is excluded from formal and calibration denominators",
        },
        "scenario_level": _scenario_summary(formal_pairs),
        "scenario_level_local": _scenario_summary(local_pairs),
        "anomalies": formal_summary.get("anomalies", []),
        "hashes": _hashes(protocol),
        "manifest_rule": "MANIFEST.sha256 hashes every regular file under progressive-gating/ except MANIFEST.sha256 itself, __pycache__ and .DS_Store; paths are relative to progressive-gating/.",
        "inclusion_relation": {
            "machine_decision_open_is_superset_of_evidence_status_nfi": True,
            "note": "NFI is counted as a subcategory of OPEN, never added to the OPEN total a second time.",
        },
    }
    write_json(root / "summary.json", summary)

    # Keep the workflow bytes beside the evidence.
    workflow_src = ROOT / ".github/workflows/progressive-gating.yml"
    if workflow_src.is_file():
        workflow_dir = root / "workflow"
        workflow_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(workflow_src, workflow_dir / "progressive-gating.yml")
        (workflow_dir / "sha256.txt").write_text(
            f"{sha256_file(workflow_src)}  .github/workflows/progressive-gating.yml\n",
            encoding="utf-8",
        )

    write_manifest(root)
    print(
        json.dumps(
            {
                "formal_runs": len(formal_metas),
                "formal_pairs": len(formal_pairs),
                "selected_comparable_pairs": len([p for p in formal_pairs if p.get("selected") and p.get("comparable")]),
                "audit_contrast": summary["formal"]["audit_contrast"],
                "local_runs": len(local_metas),
                "manifest": "MANIFEST.sha256",
            },
            indent=2,
        )
    )
    if args.require_complete:
        return verify_internal(root, require_complete=True)
    return 0


def write_manifest(root: Path) -> None:
    lines = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name == "MANIFEST.sha256" or "__pycache__" in path.parts or path.name == ".DS_Store":
            continue
        lines.append(f"{sha256_file(path)}  {path.relative_to(root)}")
    (root / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_internal(root: Path, require_complete: bool = False) -> int:
    manifest = root / "MANIFEST.sha256"
    problems = []
    if not manifest.is_file():
        problems.append("MANIFEST.sha256 missing")
    else:
        expected = {}
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            digest, rel = line.split("  ", 1)
            expected[rel] = digest
        actual = {}
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if path.name == "MANIFEST.sha256" or "__pycache__" in path.parts or path.name == ".DS_Store":
                continue
            actual[str(path.relative_to(root))] = sha256_file(path)
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        changed = sorted(rel for rel in set(expected) & set(actual) if expected[rel] != actual[rel])
        if missing:
            problems.append(f"missing from tree: {missing}")
        if extra:
            problems.append(f"unlisted files: {extra}")
        if changed:
            problems.append(f"hash changes: {changed}")
    protocol_path = root / "protocol.json"
    protocol = read_json(protocol_path) if protocol_path.is_file() else {}
    hashes = protocol.get("hashes") or {}
    items = hashes.items() if isinstance(hashes, dict) else [(row.get("path"), row) for row in hashes]
    for name, item in items:
        path = ROOT / item["path"]
        if not path.is_file() or sha256_file(path) != item["sha256"]:
            problems.append(f"protocol hash mismatch: {name}")
    if require_complete:
        formal = ((protocol.get("batch_plan") or {}).get("formal") or {})
        batch = formal.get("batch_id", "PG-FORMAL-01")
        scenarios = formal.get("scenarios", ALL_SCENARIOS)
        repeats = int(formal.get("repeats", 3))
        metas = [m for m in load_metas(root) if m.get("batch") == batch]
        problems_cells = []
        selected_pairs = 0
        selected_formal_runs = 0
        for scenario in scenarios:
            for repeat in range(1, repeats + 1):
                attempts = _pair_attempts(metas, batch, scenario, repeat)
                selected = _select_attempt(attempts)
                if selected is None:
                    problems_cells.append(f"{scenario}/r{repeat}: no attempt")
                    continue
                if not selected["comparable"]:
                    problems_cells.append(f"{scenario}/r{repeat}: {selected['not_comparable_reason']}")
                    continue
                selected_pairs += 1
                for key in ("p0", "p1"):
                    meta = selected.get(key)
                    if not (meta and meta.get("valid_execution") and meta.get("formal_eligible")):
                        problems_cells.append(f"{scenario}/r{repeat}: {key} not formal-eligible")
                    else:
                        selected_formal_runs += 1
        expected_cells = len(scenarios) * repeats
        if selected_pairs < expected_cells:
            problems.append(f"require-complete: {selected_pairs}/{expected_cells} selected comparable pairs")
        if selected_formal_runs < expected_cells * 2:
            problems.append(f"require-complete: {selected_formal_runs}/{expected_cells * 2} selected formal-eligible runs")
        problems.extend(f"require-complete: {item}" for item in problems_cells)
    if problems:
        print("\n".join(problems))
        return 2
    print("MANIFEST_AND_PROTOCOL_OK")
    return 0


def verify(args) -> int:
    root = Path(args.root)
    if not root.is_absolute():
        root = ROOT / root
    return verify_internal(root, require_complete=args.require_complete)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("finalize")
    p.add_argument("--root", default="progressive-gating")
    p.add_argument("--batch", default=None)
    p.add_argument("--require-complete", action="store_true")
    p.set_defaults(func=finalize)
    p = sub.add_parser("verify")
    p.add_argument("--root", default="progressive-gating")
    p.add_argument("--require-complete", action="store_true")
    p.set_defaults(func=verify)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

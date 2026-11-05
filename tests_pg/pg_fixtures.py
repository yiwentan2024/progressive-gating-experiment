"""Shared fixtures for progressive-gating tests. No Docker is required."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from tools.pg_case import build_audit_case, semantic_sha
from tools.pg_common import read_json, write_json

ARTIFACT_SHA = "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
STAGES = ("dev", "qa", "staging")


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def make_chain(base: str, port: int, gap_minutes: int = 10) -> dict:
    start = dt.datetime.fromisoformat(base.replace("Z", "+00:00"))
    stages = {}
    for index, stage in enumerate(STAGES):
        gate = start + dt.timedelta(minutes=gap_minutes * index)
        stages[stage] = {
            "stage": stage,
            "gate_status": "PASS",
            "first_failure_code": None,
            "gate_event_id": f"evt-test-{stage}",
            "event_time": _iso(gate),
            "ingest_time": _iso(gate),
            "gate_time": _iso(gate),
            "http_status": 200,
            "source_url": f"http://127.0.0.1:{port}/health",
            "signal_id": f"health:{stage}",
            "expected_sha256": ARTIFACT_SHA,
            "deployed_sha256": ARTIFACT_SHA,
            "container_id": f"cid-{stage}-{port}",
            "image_id": IMAGE_ID,
            "expected_image_id": IMAGE_ID,
            "image_tag": "closure-eval:pg-test",
            "image_identity_check": "PASS",
            "digest_check": "PASS",
            "attestation_binding": "PASS",
            "health_check": "PASS",
            "health_response": {"ok": True, "stage": stage},
        }
    return {
        "status": "PASS",
        "first_failure_stage": None,
        "first_failure_code": None,
        "stages": stages,
        "downstream": {stage: {"container_id": f"cid-{stage}-{port}", "deployed": True} for stage in STAGES},
        "downstream_after_cleanup": {},
        "cleanup": {"down_exit": 0},
    }


def make_run_meta(scenario: str, arm: str, base: str, port: int, repeat: int = 1, build_id: str = "pg-test-build") -> dict:
    return {
        "run_key": f"pg-test__{scenario}__r{repeat}__a1__{arm}",
        "pair_key": f"pg-test__{scenario}__r{repeat}__a1",
        "arm": arm,
        "repeat_index": repeat,
        "attempt": 1,
        "pair_release_id": f"PG-{scenario}-pg-test-r{repeat}",
        "artifact": {"sha256": ARTIFACT_SHA},
        "build": {
            "build_id": build_id,
            "attestation": {"mode": "github", "status": "PASS", "verify_exit": 0},
        },
        "github_run_id": "123456",
        "github_job_id": "progressive-gating",
        "source_commit": "c" * 40,
    }


def audit_for(design: dict, arm: str, base: str, port: int, repeat: int = 1):
    chain = make_chain(base, port)
    meta = make_run_meta(design["id"], arm, base, port, repeat)
    return build_audit_case(design, meta, chain), chain, meta


def write_run(root: Path, scenario: str, arm: str, repeat: int, *, base: str, port: int, decision: str, codes, evidence: str, build_id: str = "pg-test-build", formal: bool = True) -> dict:
    chain = make_chain(base, port)
    meta = make_run_meta(scenario, arm, base, port, repeat, build_id=build_id)
    design = next(item for item in _designs() if item["id"] == scenario)
    run_dir = root / "runs" / meta["run_key"]
    (run_dir / "raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "normalized").mkdir(parents=True, exist_ok=True)
    (run_dir / "verifier").mkdir(parents=True, exist_ok=True)
    write_json(run_dir / "raw" / "chain_result.json", chain)
    if design["requires_audit_case"]:
        bundle = build_audit_case(design, meta, chain)
        write_json(run_dir / "normalized" / "case.json", bundle["case"])
        semantic = semantic_sha(bundle["case"])
        write_json(run_dir / "normalized" / "collector.json", bundle["collector"])
    else:
        bundle = None
        semantic = None
    write_json(run_dir / "injection.json", {"scenario": scenario, "applied": True})
    write_json(run_dir / "verifier" / "result.json", {"machine_decision": decision, "evidence_status": evidence})
    run_meta = {
        "schema": "pg-run-1",
        "batch": "PG-FORMAL-01",
        "mode": "formal",
        "scenario": scenario,
        "scenario_family": design["scenario_family"],
        "design_sha256": _design_sha(scenario),
        "arm": arm,
        "repeat_index": repeat,
        "attempt": 1,
        "run_key": meta["run_key"],
        "pair_key": meta["pair_key"],
        "pair_release_id": meta["pair_release_id"],
        "build": {"build_id": build_id, "artifact": {"sha256": ARTIFACT_SHA}},
        "valid_execution": True,
        "formal_eligible": formal,
        "calibration": False,
        "baseline_result": "PASS",
        "first_failure_stage": None,
        "first_failure_code": None,
        "audit_status": "NOT_CONFIGURED" if arm == "P0" else "RUN",
        "audit_machine_decision": None if arm == "P0" else decision,
        "audit_evidence_status": None if arm == "P0" else evidence,
        "audit_failure_codes": [] if arm == "P0" else list(codes),
        "expected_match": True,
        "semantic_sha256": semantic,
        "input_sha256": "sha256:test-input",
        "canonical_input_sha256": "sha256:test-input",
        "github_job_id": "progressive-gating",
        "source_commit": "c" * 40,
        "workflow_sha256": "sha256:test-workflow",
        "verifier_sha256": "sha256:test-verifier",
        "collector_rule_sha256": "sha256:test-collector",
        "started_at_utc": base,
        "finished_at_utc": base,
        "evidence_paths": {},
    }
    write_json(run_dir / "run_meta.json", run_meta)
    return run_meta


def _designs():
    from tools.pg_common import load_designs

    return list(load_designs().values())


def _design_sha(scenario: str) -> str:
    from tools.pg_common import design_sha, load_designs

    return design_sha(load_designs()[scenario])


def read_csv(path: Path) -> list:
    import csv

    with Path(path).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))

"""Generate and verify progressive-gating/protocol.json.

The protocol freezes the six scenario designs, the formal/calibration
denominators, the pairing rules, the collector rule and the exact bytes of
every executable input. It is generated after all files are final and must be
regenerated whenever an input changes.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.pg_common import (
    ALL_SCENARIOS,
    CALIBRATION_SCENARIOS,
    COLLECTOR_RULE,
    INJECTOR_VERSION,
    PG_ROOT,
    QUERY_RULE_HASH,
    ROOT,
    VERIFIER_VERSION,
    design_sha,
    load_designs,
    read_json,
    sha256_file,
    utc_now,
    write_json,
)

PROTOCOL_PATH = PG_ROOT / "protocol.json"

FIXED_INPUTS = [
    ".github/workflows/progressive-gating.yml",
    "app/__main__.py",
    "infra/Dockerfile",
    "infra/compose.pg.yml",
    "scenarios/build_case.py",
    "scenarios/manifest.json",
    "scenarios/19_cases_master.csv",
    "tools/build.py",
    "tools/check_frozen_manifest.py",
    "verifier/closure_audit.py",
    "progressive-gating/README_Reproduction.txt",
]

INPUT_GLOBS = [
    "progressive-gating/cases/PG-*.json",
    "tests/*.py",
    "tests_pg/*.py",
    "tools/pg_*.py",
]


def _collect_inputs() -> list:
    paths = {ROOT / item for item in FIXED_INPUTS}
    for pattern in INPUT_GLOBS:
        paths.update(ROOT.glob(pattern))
    rows = []
    for path in sorted(paths):
        if not path.is_file():
            raise SystemExit(f"protocol input missing: {path.relative_to(ROOT)}")
        rows.append(
            {
                "path": str(path.relative_to(ROOT)),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    return rows


def _scenario_rows() -> list:
    designs = load_designs()
    rows = []
    for scenario in ALL_SCENARIOS:
        design = designs[scenario]
        rows.append(
            {
                "id": scenario,
                "scenario_family": design["scenario_family"],
                "type": design["type"],
                "title": design["title"],
                "design_sha256": design_sha(design),
                "requires_audit_case": design["requires_audit_case"],
                "baseline_expected": design["baseline_expected"],
                "audit_expected": design["audit_expected"],
                "required_evidence": design["required_evidence"],
            }
        )
    return rows


def build_protocol() -> dict:
    designs = load_designs()
    return {
        "schema": "pg-protocol-1",
        "experiment_id": "PG-STAGED-PROMOTION-01",
        "generated_at_utc": utc_now(),
        "scope": {
            "scenario_families": {
                design["scenario_family"]: design["id"]
                for design in sorted(designs.values(), key=lambda item: item["id"])
            },
            "note": "Six scenario families (N01, B01, B02, C01, C02, I01) exercise staged promotion. The existing E2 batch in this repository is not changed or re-measured.",
        },
        "variant_mapping": {
            "official_names": ["B0", "B1", "B2"],
            "implemented": {
                "P0": "B1",
                "P1": "B2",
            },
            "not_implemented": {
                "B0": "Optional third arm defined by the experiment design; out of scope for this batch.",
            },
            "description": {
                "P0": "staged promotion + minimal collector; audit NOT_CONFIGURED",
                "P1": "same staged promotion + same collector; closure audit runs after the staging gate PASS",
            },
        },
        "design": {
            "stages": ["dev", "qa", "staging"],
            "promotion": "build once -> deploy dev -> gate dev -> deploy qa -> gate qa -> deploy staging -> gate staging -> collect -> P0 not configured / P1 audit",
            "simultaneous_start_forbidden": True,
            "per_stage_gate": [
                "docker compose up -d --no-build <stage>",
                "docker inspect container identity",
                "docker exec <container> sha256sum /srv/release_app.pyz",
                "digest equals the pinned artifact digest",
                "live HTTP GET /health returns 200 and body.stage == stage",
            ],
            "identity_types": {
                "pinned_artifact": "sha256 of dist/release_app.pyz bytes written by tools/build.py",
                "deployed_artifact": "sha256 measured inside the running stage container",
                "oci_image": "Docker image config digest recorded separately; never compared numerically with the pyz digest",
                "attestation_subject": "the .pyz file; the deployed object is an OCI image, so both identities and the verified binding are recorded",
            },
            "time_model": {
                "native": ["stage deploy times", "HTTP occurrence and receipt times", "gate decision times"],
                "scripted": ["PG-SEQ Finding observed_at / Requirement accepted_at / target times as fixed offsets from the live cutoff"],
                "pairing_projection": "native stage timestamps become fixed per-stage ordinals; absolute wall-clock seconds and host ports are removed; verifier order relations are preserved; the native case.json remains the audit input",
            },
        },
        "batch_plan": {
            "formal": {
                "batch_id": "PG-FORMAL-01",
                "scenarios": list(ALL_SCENARIOS),
                "arms": ["P0", "P1"],
                "repeats": 3,
                "runs": 2 * len(ALL_SCENARIOS) * 3,
                "pairs": len(ALL_SCENARIOS) * 3,
                "builds": len(ALL_SCENARIOS) * 3,
                "workflow_runs": len(ALL_SCENARIOS) * 3,
                "attempts_per_workflow_run": 2,
                "purpose": "official progressive-gating measurement",
                "repeat_note": "three repeats per scenario are consistency checks, not three independent scenarios",
            },
            "calibration": {
                "batch_id": "PG-CAL-01",
                "scenarios": list(CALIBRATION_SCENARIOS),
                "arms": ["P0", "P1"],
                "repeats": 1,
                "runs": 2 * len(CALIBRATION_SCENARIOS),
                "pairs": len(CALIBRATION_SCENARIOS),
                "builds": len(CALIBRATION_SCENARIOS),
                "workflow_runs": len(CALIBRATION_SCENARIOS),
                "attempts_per_workflow_run": 2,
                "purpose": "pairing-mechanics calibration only; not included in the formal denominator",
            },
            "local_validation": {
                "batch_prefix": "LOCAL-",
                "purpose": "developer validation without GitHub attestation; excluded from formal and calibration denominators",
                "attestation": "NOT_AVAILABLE_LOCAL",
            },
        },
        "scenarios": _scenario_rows(),
        "collector": {
            "rule": COLLECTOR_RULE,
            "collector_rule_sha256": QUERY_RULE_HASH,
            "minimal_fields": [
                "native run identity (run key, arm, build, workflow, commit)",
                "release binding (episode, service, environment chain, approved artifact digest)",
                "candidates and dispositions (inventory digest, missing items, empty-set distinction)",
                "history and successor (cutoff, audit time, findings, successor identity, frozen snapshot digest)",
                "provenance tags: native / derived / declared / scripted / unavailable",
                "release-stage records (container ID, image ID, image tag, expected and deployed pyz digest, HTTP status, gate status)",
            ],
            "missing_vs_empty": "A missing value is recorded as unavailable or as an explicit missing item; it is never replaced by an empty set or a default PASS.",
            "evidence_statuses": ["PENDING", "OPEN", "NFI", "NOT_APPLICABLE"],
            "machine_decisions": ["CLOSED", "OPEN"],
            "nfi_rule": "NFI is a subclass of machine OPEN. It is shown separately but never added to the OPEN total a second time.",
            "injection_record": {
                "schema": "pg-injection-1",
                "injector_version": INJECTOR_VERSION,
                "fields": [
                    "change_point and declared_injection",
                    "applied and per-scenario before/after details",
                    "baseline_gate_effect and baseline_condition_impact",
                    "platform_error",
                ],
                "rule": "A platform error is not accepted as the declared injection, and an injection is not inferred from one.",
            },
        },
        "verifier": {
            "path": "verifier/closure_audit.py",
            "implementation": VERIFIER_VERSION,
            "modified": False,
            "invocation": "python -m verifier.closure_audit --input <case.json> --output <result.json> --allow-open",
            "expected_codes": {
                "PG-N01": [],
                "PG-DISP": ["A1_EFFECTIVE_DISPOSITION_COUNT"],
                "PG-SEQ": ["A2_REQUIREMENT_TEMPORAL_ORDER"],
                "PG-INFO": ["A1_SCOPE_NOT_ATTESTED"],
            },
        },
        "pairing_rules": {
            "same_build_id": True,
            "same_pinned_artifact_digest": True,
            "same_scenario_design_sha256": True,
            "same_audit_input": "semantic projection equality for audit cases; baseline outcome signature equality for baseline-block pairs",
            "same_baseline_outcome": True,
            "both_arms_valid_execution": True,
            "retry_selection": "first comparable attempt per (batch, scenario, repeat); every non-selected attempt stays in runs.csv with an exclusion reason",
            "batch_immutability": "the formal and calibration batch ids in this protocol are frozen; a configuration change requires a new protocol and a new batch",
            "arm_order": "alternates P0>P1 and P1>P0 by repeat; the order is recorded but is not a scenario variable",
            "excluded_from_formal": [
                "any attempt whose pair is not comparable",
                "non-selected retry attempts",
                "runs without GitHub attestation",
                "runs from a dirty source tree",
                "local validation and calibration batches",
            ],
        },
        "formal_eligibility": [
            "batch id starts with PG-FORMAL",
            "GitHub attestation mode with verify exit 0",
            "committed checkout (source_tree_dirty is false)",
            "no harness exception",
            "both arms of the selected pair valid and comparable",
        ],
        "denominators": {
            "formal_scenarios": len(ALL_SCENARIOS),
            "formal_pairs": len(ALL_SCENARIOS) * 3,
            "formal_runs": 2 * len(ALL_SCENARIOS) * 3,
            "audit_contrast_pairs": "only selected comparable pairs whose two baseline outcomes are PASS and whose scenario requires an audit case",
            "baseline_control_pairs": "PG-ART and PG-QA selected comparable pairs, reported separately and never mixed into the audit-contrast numerator",
            "scenario_counts_are_not_pooled": True,
        },
        "claims": [
            "Each pair is one workflow run: both arms share one build, one image and one attestation, so the only arm difference is the audit. The formal 18 pairs and calibration 3 pairs produce 21 workflow runs and 42 attempts.",
            "The same deterministic pyz digest is measured at dev, qa and staging inside running containers for passing chains.",
            "Every promotion edge is a real sequential compose deployment followed by a real digest and live HTTP health gate; the three stages are not started together and probed out of order.",
            "PG-ART and PG-QA are baseline controls: the baseline gate rejects and the downstream stage is not deployed; neither arm runs the audit.",
            "For the four audit scenarios, the P0/P1 comparison is conditional on both baselines passing and on semantic input equality.",
            "All outputs are generated from retained raw and normalized evidence; injected defects are disclosed in injection.json.",
        ],
        "non_claims": [
            "This is not a production deployment or a full production inventory.",
            "Candidates, Findings, dispositions, audit times and fault switches are synthetic test inputs generated from the frozen scenario files; no engineering dataset is read, copied or bridged.",
            "The collector scope attestation is self-declared for the bounded three-stage chain, not an independent third-party export.",
            "The OCI image digest is an identity of a different type from the pyz digest; no numerical equality between them is claimed.",
            "This batch does not re-measure the existing E2 batch in this repository and does not claim those results are reproduced.",
            "The calibration batch calibrates pairing mechanics; it is not a second independent sample.",
        ],
        "hashes": _collect_inputs(),
    }


def _check_protocol(protocol: dict) -> list:
    problems = []
    if protocol.get("schema") != "pg-protocol-1":
        problems.append("unexpected schema")
    designs = load_designs()
    rows = protocol.get("scenarios") or []
    if [row.get("id") for row in rows] != list(ALL_SCENARIOS):
        problems.append("scenario order or membership differs from the frozen list")
    for row in rows:
        design = designs.get(row.get("id"))
        if design is None:
            problems.append(f"unknown scenario {row.get('id')}")
            continue
        if row.get("design_sha256") != design_sha(design):
            problems.append(f"design hash mismatch: {row.get('id')}")
    current = {item["path"]: item["sha256"] for item in _collect_inputs()}
    recorded = {item["path"]: item["sha256"] for item in (protocol.get("hashes") or [])}
    missing = sorted(set(current) - set(recorded))
    extra = sorted(set(recorded) - set(current))
    changed = sorted(path for path in set(current) & set(recorded) if current[path] != recorded[path])
    if missing:
        problems.append(f"unhashed inputs: {missing}")
    if extra:
        problems.append(f"recorded inputs no longer present: {extra}")
    if changed:
        problems.append(f"changed inputs: {changed}")
    families = (protocol.get("scope") or {}).get("scenario_families") or {}
    expected_families = {design["scenario_family"]: design["id"] for design in designs.values()}
    if families != expected_families:
        problems.append("scenario family mapping differs from the frozen designs")
    return problems


def build(args) -> int:
    protocol = build_protocol()
    problems = _check_protocol(protocol)
    if problems:
        print("\n".join(problems))
        return 2
    write_json(PROTOCOL_PATH, protocol)
    print(json.dumps({"protocol": str(PROTOCOL_PATH.relative_to(ROOT)), "inputs": len(protocol["hashes"])}, indent=2))
    return 0


def check(args) -> int:
    if not PROTOCOL_PATH.is_file():
        print("protocol.json missing; run: python -m tools.pg_protocol build")
        return 2
    protocol = read_json(PROTOCOL_PATH)
    problems = _check_protocol(protocol)
    if problems:
        print("\n".join(problems))
        return 2
    print("PROTOCOL_OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("build")
    p.set_defaults(func=build)
    p = sub.add_parser("check")
    p.set_defaults(func=check)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

"""Run progressive-gating pairs against real Docker stages.

One invocation builds no artifact itself: it consumes the single build manifest
created by tools.pg_build. Both arms of every pair reuse that same image. P0
records NOT_CONFIGURED; P1 invokes verifier/closure_audit.py unchanged. If a
baseline gate rejects, neither arm runs the audit (NOT_RUN_UPSTREAM_BLOCKED).
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from tools.pg_case import build_audit_case, semantic_projection, semantic_sha
from tools.pg_common import (
    ALL_SCENARIOS,
    CALIBRATION_SCENARIOS,
    INJECTOR_VERSION,
    PG_ROOT,
    ROOT,
    VERIFIER_VERSION,
    design_sha,
    load_designs,
    protocol_hash,
    read_json,
    run_cmd,
    sanitize_name,
    sha,
    sha256_file,
    utc_now,
    verifier_hash,
    write_json,
)
from tools.pg_promote import PromotionRunner


def _arm_order(repeat: int, explicit: str) -> list:
    if explicit == "P0P1":
        return ["P0", "P1"]
    if explicit == "P1P0":
        return ["P1", "P0"]
    return ["P0", "P1"] if repeat % 2 else ["P1", "P0"]


def _mode_scenarios(mode: str, scenario: str | None) -> list:
    if mode == "calibration":
        return list(CALIBRATION_SCENARIOS)
    if mode == "formal":
        return list(ALL_SCENARIOS)
    if mode == "pair":
        if scenario not in ALL_SCENARIOS:
            raise SystemExit(f"pair mode requires one of {ALL_SCENARIOS}")
        return [scenario]
    raise SystemExit(mode)


def _mode_repeats(mode: str, repeats: int | None) -> int:
    if repeats is not None:
        return repeats
    return 3 if mode == "formal" else 1


def _pair_key(batch: str, scenario: str, repeat: int, attempt: int) -> str:
    return f"{sanitize_name(batch)}__{scenario}__r{repeat}__a{attempt}"


def _run_key(pair_key: str, arm: str) -> str:
    return f"{pair_key}__{arm}"


def _pair_release_id(batch: str, scenario: str, repeat: int) -> str:
    family = scenario[3:] if scenario.startswith("PG-") else scenario
    return f"PG-{family}-{sanitize_name(batch)}-r{repeat}"


def _build_tampered_image(build: dict, batch: str, out_root: Path) -> dict:
    original_path = ROOT / build["artifact"]["path"]
    pinned = build["artifact"]["sha256"]
    tamper_dir = out_root / "build" / sanitize_name(batch) / "tampered"
    tamper_dir.mkdir(parents=True, exist_ok=True)
    tampered_pyz = tamper_dir / "release_app.pyz"
    with zipfile.ZipFile(original_path, "r") as zin, zipfile.ZipFile(tampered_pyz, "w") as zout:
        for info in zin.infolist():
            zout.writestr(info, zin.read(info.filename))
        marker = zipfile.ZipInfo("pg_tamper_marker.txt", date_time=(2020, 1, 1, 0, 0, 0))
        marker.compress_type = zipfile.ZIP_DEFLATED
        marker.external_attr = 0o644 << 16
        zout.writestr(marker, b"PG-ART controlled artifact substitution\n")
    tampered_sha = sha256_file(tampered_pyz)
    if tampered_sha == pinned:
        raise RuntimeError("tampered pyz unexpectedly equals the pinned build")
    dockerfile = tamper_dir / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /srv\n"
        "COPY release_app.pyz /srv/release_app.pyz\n"
        "ENV PYTHONUNBUFFERED=1\n"
        "EXPOSE 8000\n"
        'CMD ["python", "/srv/release_app.pyz", "--port", "8000"]\n',
        encoding="utf-8",
    )
    tag = f"closure-eval:pg-{sanitize_name(batch)}-tampered"
    build_result = run_cmd(
        [
            "docker",
            "build",
            "-t",
            tag,
            "--label",
            "pg.harness=progressive-gating",
            "--label",
            f"pg.batch={batch}",
            ".",
        ],
        cwd=tamper_dir,
        timeout=900,
        log_path=tamper_dir / "docker_build.log",
    )
    if build_result["exit"] != 0:
        raise RuntimeError("tampered image build failed")
    inspect = run_cmd(
        ["docker", "image", "inspect", tag, "--format", "{{.Id}}"],
        cwd=tamper_dir,
        timeout=60,
        log_path=tamper_dir / "docker_image_inspect.log",
    )
    runnable = run_cmd(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            tag,
            "-c",
            "import zipfile; z=zipfile.ZipFile('/srv/release_app.pyz'); "
            "assert '__main__.py' in z.namelist(); print('pyz-ok')",
        ],
        cwd=tamper_dir,
        timeout=120,
        log_path=tamper_dir / "runnable_check.log",
    )
    measured = run_cmd(
        ["docker", "run", "--rm", "--entrypoint", "sha256sum", tag, "/srv/release_app.pyz"],
        cwd=tamper_dir,
        timeout=60,
        log_path=tamper_dir / "artifact_sha_check.log",
    )
    measured_sha = measured["stdout"].split()[0] if measured["exit"] == 0 and measured["stdout"].split() else None
    if runnable["exit"] != 0 or measured_sha != tampered_sha:
        raise RuntimeError("tampered image is not runnable or its measured pyz digest is wrong")
    record = {
        "original_artifact_sha256": pinned,
        "tampered_pyz_sha256": tampered_sha,
        "tampered_image_tag": tag,
        "tampered_image_id": inspect["stdout"].strip() if inspect["exit"] == 0 else None,
        "docker_build_exit": build_result["exit"],
        "runnable_check_exit": runnable["exit"],
        "measured_pyz_sha256": measured_sha,
        "dockerfile_sha256": sha256_file(dockerfile),
        "substitution": "extra pg_tamper_marker.txt zip entry; __main__.py unchanged",
    }
    write_json(tamper_dir / "tampered_manifest.json", record)
    return record


def _run_verifier(case_path: Path, verifier_dir: Path, run_dir: Path) -> dict:
    verifier_dir.mkdir(parents=True, exist_ok=True)
    result_path = verifier_dir / "result.json"
    case_rel = case_path.relative_to(ROOT)
    result_rel = result_path.relative_to(ROOT)
    display_cmd = [
        "python3",
        "-m",
        "verifier.closure_audit",
        "--input",
        str(case_rel),
        "--output",
        str(result_rel),
        "--allow-open",
    ]
    cmd = [sys.executable] + display_cmd[1:]
    result = run_cmd(cmd, cwd=ROOT, timeout=120, log_path=verifier_dir / "verifier.log")
    (verifier_dir / "verifier_exit.txt").write_text(str(result["exit"]) + "\n", encoding="utf-8")
    (verifier_dir / "implementation.txt").write_text(VERIFIER_VERSION + "\n", encoding="utf-8")
    (verifier_dir / "verifier_sha256.txt").write_text(verifier_hash() + "\n", encoding="utf-8")
    (verifier_dir / "input_file_sha256.txt").write_text(sha256_file(case_path) + "\n", encoding="utf-8")
    parsed = None
    if result_path.is_file():
        try:
            parsed = read_json(result_path)
        except (OSError, ValueError):
            parsed = None
    tool_failure = result["exit"] not in (0, 2) or parsed is None or "machine_decision" not in parsed
    audit_record = {
        "schema": "pg-audit-record-1",
        "run_key": run_dir.name,
        "command": display_cmd,
        "command_line": " ".join(display_cmd),
        "cwd": ".",
        "started_at_utc": result["started_at_utc"],
        "finished_at_utc": result["finished_at_utc"],
        "exit": result["exit"],
        "timed_out": result["timed_out"],
        "input_path": str(case_path.relative_to(run_dir)),
        "input_sha256": sha256_file(case_path),
        "output_path": str(result_path.relative_to(run_dir)) if result_path.is_file() else None,
        "output_sha256": sha256_file(result_path) if result_path.is_file() else None,
        "verifier_path": "verifier/closure_audit.py",
        "verifier_sha256": verifier_hash(),
        "implementation": VERIFIER_VERSION,
        "machine_decision": parsed.get("machine_decision") if parsed else None,
        "evidence_status": parsed.get("evidence_status") if parsed else None,
        "failure_codes": parsed.get("failure_codes") if parsed else None,
        "stdout_tail": result["stdout"][-4000:],
        "stderr_tail": result["stderr"][-4000:],
    }
    write_json(verifier_dir / "audit_record.json", audit_record)
    return {
        "exit": result["exit"],
        "result": parsed,
        "tool_failure": tool_failure,
        "log": "verifier/verifier.log",
        "result_path": "verifier/result.json",
        "audit_record": "verifier/audit_record.json",
    }


def _injection_record(design: dict, chain: dict, bundle: dict | None, build: dict, tampered: dict | None) -> dict:
    scenario = design["id"]
    stage = chain["stages"]
    applied = True
    details = {}
    if scenario == "PG-ART":
        qa = stage.get("qa", {})
        details = {
            "pinned_artifact_sha256": build["artifact"]["sha256"],
            "tampered_pyz_sha256": (tampered or {}).get("tampered_pyz_sha256"),
            "qa_image_tag": qa.get("image_tag"),
            "qa_measured_pyz_sha256": qa.get("deployed_sha256"),
            "qa_gate": qa.get("gate_status"),
            "qa_failure_code": qa.get("first_failure_code"),
            "attestation_binding": qa.get("attestation_binding"),
            "health_check": qa.get("health_check"),
        }
        applied = bool(tampered and qa.get("deployed_sha256") == tampered.get("tampered_pyz_sha256"))
    elif scenario == "PG-QA":
        qa = stage.get("qa", {})
        details = {
            "declared_env": {"FAIL_HEALTH": "1"},
            "qa_measured_pyz_sha256": qa.get("deployed_sha256"),
            "qa_expected_pyz_sha256": qa.get("expected_sha256"),
            "qa_http_status": qa.get("http_status"),
            "qa_health_response": qa.get("health_response"),
            "qa_gate": qa.get("gate_status"),
        }
        applied = qa.get("http_status") == 503
    elif scenario == "PG-DISP":
        qa_signal = "health:qa"
        raw_has = any(r["signal_id"] == qa_signal for r in (bundle or {}).get("case", {}).get("raw_signals", []))
        details = {
            "removed_signal": qa_signal,
            "raw_signal_still_present": raw_has,
            "missing_dispositions": (bundle or {}).get("missing_dispositions"),
            "gate_statuses": {s: stage.get(s, {}).get("gate_status") for s in ("dev", "qa", "staging")},
        }
        applied = raw_has and bool((bundle or {}).get("missing_dispositions"))
    elif scenario == "PG-SEQ":
        case = (bundle or {}).get("case", {})
        findings = case.get("findings", [])
        details = {
            "finding": findings[0] if findings else None,
            "cutoff": case.get("source_cutoff"),
            "audit_time": case.get("audit_time"),
            "frozen_snapshot_sha256": case.get("snapshot", {}).get("frozen_sha256"),
            "historically_visible": bool(findings and findings[0].get("observed_at", "") <= case.get("source_cutoff", "")),
        }
        applied = bool(findings)
    elif scenario == "PG-INFO":
        attestation = (bundle or {}).get("case", {}).get("scope", {}).get("collector_attestation", {})
        details = {
            "missing_fields": (bundle or {}).get("missing_fields"),
            "retained_complete": attestation.get("complete"),
            "retained_collector_version": attestation.get("collector_version"),
            "retained_inventory_sha256": attestation.get("inventory_sha256"),
            "gate_statuses": {s: stage.get(s, {}).get("gate_status") for s in ("dev", "qa", "staging")},
        }
        applied = bool((bundle or {}).get("missing_fields"))
    else:
        details = {"no_injection": True}
    return {
        "schema": "pg-injection-1",
        "injector_version": INJECTOR_VERSION,
        "scenario": scenario,
        "scenario_family": design["scenario_family"],
        "change_point": design["injection"],
        "declared_injection": design["injection"],
        "applied": applied,
        "details": details,
        "baseline_gate_effect": "EXPECTED_REJECTION" if design["type"] == "BASELINE_BLOCK" else "NONE_DECLARED",
        "baseline_condition_impact": "DECLARED" if design["type"] == "BASELINE_BLOCK" else "NONE",
        "classification": "declared_controlled_injection",
        "platform_error": False,
    }


def _run_arm(
    design: dict,
    arm: str,
    build: dict,
    batch: str,
    mode: str,
    repeat: int,
    attempt: int,
    pair_key: str,
    pair_release_id: str,
    original_image: str,
    tampered_image: str | None,
    tampered_record: dict | None,
    out_root: Path,
    github_run_id: str,
    github_run_url: str,
    github_job_id: str,
    order_label: str,
    calibration: bool,
) -> dict:
    run_key = _run_key(pair_key, arm)
    run_dir = out_root / "runs" / run_key
    for sub in ("raw", "normalized", "verifier"):
        (run_dir / sub).mkdir(parents=True, exist_ok=True)
    started = utc_now()
    ports = {
        "dev": int(os.environ.get("PG_DEV_PORT", 19081)),
        "qa": int(os.environ.get("PG_QA_PORT", 19082)),
        "staging": int(os.environ.get("PG_STAGING_PORT", 19083)),
    }
    project = sanitize_name(f"pg-{batch}-{design['id']}-r{repeat}-{arm}")
    runner = PromotionRunner(
        run_dir,
        run_key,
        arm,
        project,
        ports,
        attempt=attempt,
        repeat_index=repeat,
        github_run_id=github_run_id,
        github_job_id=github_job_id,
    )
    chain_error = None
    try:
        chain = runner.run_chain(
            design,
            original_image,
            tampered_image,
            build["artifact"]["sha256"],
            build["image"]["id"],
            (tampered_record or {}).get("tampered_image_id"),
            build.get("attestation", {}),
        )
    except Exception as exc:  # keep partial evidence; never silently pass
        chain_error = f"{type(exc).__name__}: {exc}"
        chain = {
            "status": "TOOL_FAILURE",
            "first_failure_stage": None,
            "first_failure_code": "HARNESS_EXCEPTION",
            "stages": {},
            "downstream": {},
            "cleanup": {},
            "error": chain_error,
        }
        write_json(run_dir / "raw" / "chain_result.json", chain)

    baseline_result = chain.get("status")
    baseline_expected_match = (
        baseline_result == "PASS"
        if design["type"] != "BASELINE_BLOCK"
        else (
            baseline_result == "FAIL"
            and chain.get("first_failure_stage") == design["baseline_expected"]["first_failure_stage"]
            and chain.get("first_failure_code") == design["baseline_expected"]["first_failure_code"]
            and all(v.get("deployed") is False for v in (chain.get("downstream") or {}).values())
        )
    )

    bundle = None
    audit_status = "NOT_RUN_UPSTREAM_BLOCKED"
    machine_decision = None
    evidence_status = None
    failure_codes = []
    verifier_info = None
    case = None
    semantic = None
    if design.get("requires_audit_case") and baseline_result == "PASS":
        run_meta_seed = {
            "run_key": run_key,
            "pair_key": pair_key,
            "arm": arm,
            "repeat_index": repeat,
            "attempt": attempt,
            "pair_release_id": pair_release_id,
            "artifact": {"sha256": build["artifact"]["sha256"]},
            "build": {"build_id": build["build_id"], "attestation": build.get("attestation", {})},
            "github_run_id": github_run_id,
            "github_job_id": github_job_id,
            "source_commit": build.get("source_commit"),
        }
        try:
            bundle = build_audit_case(design, run_meta_seed, chain)
            case = bundle["case"]
            write_json(run_dir / "normalized" / "case.json", case)
            write_json(run_dir / "normalized" / "collector.json", bundle["collector"])
            semantic = semantic_projection(case)
            write_json(run_dir / "normalized" / "semantic_projection.json", semantic)
            if arm == "P0":
                audit_status = "NOT_CONFIGURED"
            else:
                verifier_info = _run_verifier(run_dir / "normalized" / "case.json", run_dir / "verifier", run_dir)
                if verifier_info["tool_failure"]:
                    audit_status = "TOOL_FAILURE"
                else:
                    audit_status = "RUN"
                    machine_decision = verifier_info["result"].get("machine_decision")
                    evidence_status = verifier_info["result"].get("evidence_status")
                    failure_codes = verifier_info["result"].get("failure_codes", [])
        except Exception as exc:
            audit_status = "TOOL_FAILURE"
            chain_error = (chain_error + "; " if chain_error else "") + f"case/audit build: {type(exc).__name__}: {exc}"
            write_json(
                run_dir / "verifier" / "tool_failure.json",
                {"error": str(exc), "type": type(exc).__name__},
            )

    expected_audit = design["audit_expected"][arm]
    expected_codes = design["audit_expected"].get("codes", [])
    expected_evidence = design["audit_expected"].get("evidence_status")
    if arm == "P0":
        expected_match = baseline_expected_match and audit_status == design["audit_expected"]["P0"]
    elif design["type"] == "BASELINE_BLOCK":
        expected_match = baseline_expected_match and audit_status == design["audit_expected"]["P1"]
    else:
        expected_match = (
            baseline_expected_match
            and audit_status == "RUN"
            and machine_decision == design["audit_expected"]["P1"]
        )
        if expected_evidence:
            expected_match = expected_match and evidence_status == expected_evidence
        if expected_codes:
            expected_match = expected_match and set(expected_codes).issubset(set(failure_codes))
    injection = _injection_record(design, chain, bundle, build, tampered_record)
    write_json(run_dir / "injection.json", injection)

    finished = utc_now()
    attestation = build.get("attestation", {})
    is_calibration = calibration or batch.startswith("PG-CAL")
    formal_eligible = (
        batch.startswith("PG-FORMAL")
        and not is_calibration
        and attestation.get("mode") == "github"
        and attestation.get("status") == "PASS"
        and not build.get("source_tree_dirty", True)
        and chain_error is None
    )
    valid_execution = chain_error is None and chain.get("status") in ("PASS", "FAIL")
    run_meta = {
        "schema": "pg-run-1",
        "batch": batch,
        "mode": mode,
        "scenario": design["id"],
        "scenario_family": design["scenario_family"],
        "design_sha256": design_sha(design),
        "arm": arm,
        "baseline_variant": "B1" if arm == "P0" else "B2",
        "repeat_index": repeat,
        "attempt": attempt,
        "run_key": run_key,
        "pair_key": pair_key,
        "pair_release_id": pair_release_id,
        "arm_order": order_label,
        "github_run_id": github_run_id,
        "github_run_url": github_run_url,
        "github_job_id": github_job_id,
        "source_commit": build.get("source_commit"),
        "workflow_sha256": build.get("workflow", {}).get("sha256"),
        "verifier_sha256": verifier_hash(),
        "protocol_sha256": protocol_hash() if (PG_ROOT / "protocol.json").is_file() else None,
        "collector_rule_sha256": bundle.get("collector", {}).get("collector_rule_sha256") if bundle else None,
        "build": {
            "build_id": build.get("build_id"),
            "artifact": build.get("artifact"),
            "image": build.get("image"),
            "unit_tests": build.get("unit_tests"),
            "attestation": attestation,
            "source_tree_dirty": build.get("source_tree_dirty"),
        },
        "started_at_utc": started,
        "finished_at_utc": finished,
        "baseline_result": baseline_result,
        "baseline_expected_match": baseline_expected_match,
        "first_failure_stage": chain.get("first_failure_stage"),
        "first_failure_code": chain.get("first_failure_code"),
        "downstream": chain.get("downstream"),
        "downstream_after_cleanup": chain.get("downstream_after_cleanup"),
        "audit_status": audit_status,
        "audit_machine_decision": machine_decision,
        "audit_evidence_status": evidence_status,
        "audit_failure_codes": failure_codes,
        "audit_expected": expected_audit,
        "audit_expected_codes": expected_codes,
        "audit_expected_evidence_status": expected_evidence,
        "expected_match": expected_match,
        "input_sha256": sha256_file(run_dir / "normalized" / "case.json") if case else None,
        "canonical_input_sha256": (
            verifier_info["result"].get("input_sha256")
            if verifier_info and verifier_info.get("result")
            else (sha(case) if case else None)
        ),
        "semantic_sha256": semantic_sha(case) if case else None,
        "valid_execution": valid_execution,
        "formal_eligible": formal_eligible,
        "calibration": is_calibration,
        "chain_error": chain_error,
        "evidence_paths": {
            "raw": "raw/",
            "normalized": "normalized/",
            "verifier": "verifier/",
            "stage_events": "raw/stage_events.jsonl",
            "chain_result": "raw/chain_result.json",
            "audit_record": "verifier/audit_record.json" if verifier_info else None,
            "injection": "injection.json",
        },
    }
    write_json(run_dir / "run_meta.json", run_meta)

    sums = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file() and path.name != "sha256sums.txt":
            sums.append(f"{sha256_file(path)}  {path.relative_to(run_dir)}")
    (run_dir / "sha256sums.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")
    return run_meta


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="build_manifest.json from tools.pg_build")
    parser.add_argument("--mode", required=True, choices=["formal", "calibration", "pair"])
    parser.add_argument("--batch", required=True)
    parser.add_argument("--scenario", default=None)
    parser.add_argument("--repeats", type=int, default=None)
    parser.add_argument("--repeat-index", type=int, default=None)
    parser.add_argument("--attempt", type=int, default=1)
    parser.add_argument("--order", choices=["auto", "P0P1", "P1P0"], default="auto")
    parser.add_argument("--out-root", default="progressive-gating")
    parser.add_argument("--github-run-id", default="")
    parser.add_argument("--github-run-url", default="")
    parser.add_argument("--github-job-id", default="")
    parser.add_argument("--calibration", action="store_true")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = ROOT / manifest_path
    build = read_json(manifest_path)
    if build.get("status") != "OK":
        print(f"build manifest status is {build.get('status')!r}; refusing to run")
        return 2
    artifact_path = ROOT / build["artifact"]["path"]
    if not artifact_path.is_file() or sha256_file(artifact_path) != build["artifact"]["sha256"]:
        print("build artifact changed after the build manifest was written")
        return 2
    if build.get("unit_tests", {}).get("exit") != 0:
        print("unit tests did not pass; refusing to run")
        return 2
    attestation = build.get("attestation", {})
    if attestation.get("mode") != "github":
        print(f"attestation mode is {attestation.get('mode')!r}; runs require a GitHub-attested build")
        return 2
    if attestation.get("status") != "PASS":
        print(f"attestation status is {attestation.get('status')!r}; refusing to run")
        return 2
    if build.get("source_tree_dirty"):
        print("source tree is dirty; runs require a committed checkout")
        return 2

    designs = load_designs()
    scenarios = _mode_scenarios(args.mode, args.scenario)
    repeats = _mode_repeats(args.mode, args.repeats)
    out_root = Path(args.out_root)
    if not out_root.is_absolute():
        out_root = ROOT / out_root
    out_root.mkdir(parents=True, exist_ok=True)
    batch = args.batch
    calibration = args.calibration or args.mode == "calibration" or batch.startswith("PG-CAL")
    protocol_path = PG_ROOT / "protocol.json"
    if protocol_path.is_file():
        plan = read_json(protocol_path).get("batch_plan") or {}
        if args.mode == "formal" and batch != (plan.get("formal") or {}).get("batch_id", "PG-FORMAL-01"):
            print("formal mode must use the frozen formal batch id from protocol.json")
            return 2
        if args.mode == "calibration" and batch != (plan.get("calibration") or {}).get("batch_id", "PG-CAL-01"):
            print("calibration mode must use the frozen calibration batch id from protocol.json")
            return 2
        if args.mode in ("formal", "calibration"):
            frozen = plan.get("formal" if args.mode == "formal" else "calibration") or {}
            frozen_repeats = int(frozen.get("repeats", 3 if args.mode == "formal" else 1))
            if args.repeats is not None and args.repeats != frozen_repeats:
                print(f"{args.mode} mode repeats are frozen at {frozen_repeats} in protocol.json")
                return 2
            if args.order != "auto":
                print(f"{args.mode} mode uses the frozen alternating arm order")
                return 2
    if args.mode == "pair" and (batch.startswith("PG-FORMAL") or batch.startswith("PG-CAL")):
        plan = read_json(protocol_path).get("batch_plan") or {}
        frozen = (plan.get("formal") if batch.startswith("PG-FORMAL") else plan.get("calibration")) or {}
        if batch != frozen.get("batch_id"):
            print("pair mode batch does not match protocol.json")
            return 2
        if args.scenario not in (frozen.get("scenarios") or []):
            print("pair mode scenario is not part of the frozen batch")
            return 2
        if args.repeats is not None:
            print("pair mode uses --repeat-index, not --repeats")
            return 2
        repeat_index = args.repeat_index if args.repeat_index is not None else 1
        if repeat_index < 1 or repeat_index > int(frozen.get("repeats", 1)):
            print(f"pair repeat-index must be between 1 and {int(frozen.get('repeats', 1))}")
            return 2
        args.repeat_index = repeat_index
    if args.repeat_index is not None and args.repeat_index < 1:
        print("repeat-index must be >= 1")
        return 2

    tampered_record = None
    tampered_image = None
    if "PG-ART" in scenarios:
        tampered_record = _build_tampered_image(build, batch, out_root)
        tampered_image = tampered_record["tampered_image_tag"]

    repeat_indexes = (
        [args.repeat_index] if args.repeat_index is not None
        else list(range(1, repeats + 1))
    )
    results = []
    for scenario in scenarios:
        for repeat in repeat_indexes:
            pair_key = _pair_key(batch, scenario, repeat, args.attempt)
            release_id = _pair_release_id(batch, scenario, repeat)
            order = _arm_order(repeat, args.order)
            order_label = ">".join(order)
            for arm in order:
                try:
                    result = _run_arm(
                        designs[scenario],
                        arm,
                        build,
                        batch,
                        args.mode,
                        repeat,
                        args.attempt,
                        pair_key,
                        release_id,
                        build["image"]["tag"],
                        tampered_image,
                        tampered_record,
                        out_root,
                        args.github_run_id,
                        args.github_run_url,
                        args.github_job_id,
                        order_label,
                        calibration,
                    )
                except Exception as exc:
                    run_key = _run_key(pair_key, arm)
                    run_dir = out_root / "runs" / run_key
                    run_dir.mkdir(parents=True, exist_ok=True)
                    result = {
                        "run_key": run_key,
                        "pair_key": pair_key,
                        "scenario": scenario,
                        "scenario_family": designs[scenario]["scenario_family"],
                        "arm": arm,
                        "repeat_index": repeat,
                        "attempt": args.attempt,
                        "github_job_id": args.github_job_id,
                        "valid_execution": False,
                        "chain_error": f"{type(exc).__name__}: {exc}",
                        "baseline_result": "TOOL_FAILURE",
                        "audit_status": "TOOL_FAILURE",
                        "formal_eligible": False,
                        "calibration": calibration,
                    }
                    write_json(
                        run_dir / "run_meta.json",
                        {
                            "schema": "pg-run-1",
                            **result,
                            "batch": batch,
                            "mode": args.mode,
                            "started_at_utc": utc_now(),
                            "finished_at_utc": utc_now(),
                            "evidence_paths": {},
                        },
                    )
                results.append(result)
                print(
                    f"{result['run_key']}: baseline={result['baseline_result']} "
                    f"audit={result['audit_status']} decision={result.get('audit_machine_decision')}"
                )
    write_json(
        out_root / "build" / sanitize_name(batch) / "_run_batch_summary.json",
        {"batch": batch, "mode": args.mode, "runs": results, "generated_at_utc": utc_now()},
    )
    return 0 if all(r.get("valid_execution") for r in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())

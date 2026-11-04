"""Build the audit case and the minimal collector record from staged live evidence.

The audit case is an E2-case-1 document accepted by verifier/closure_audit.py.
The verifier itself is never modified. A2 successor/Finding timestamps are
declared scripted offsets from the live source cutoff; live HTTP occurrence and
receipt times remain native in the raw stage events.
"""
from __future__ import annotations

import copy
import datetime as dt
import re

from verifier.closure_audit import sha

from tools.pg_common import (
    COLLECTOR_RULE,
    QUERY_RULE_HASH,
    iso_utc,
    parse_ts,
    read_json,
    run_cmd,
    sha256_file,
)


def _offset_seconds(value: str, cutoff: dt.datetime) -> int:
    return int((parse_ts(value) - cutoff).total_seconds())


def _cutoff(stage_records: dict) -> dt.datetime:
    times = []
    for record in stage_records.values():
        for key in ("event_time", "ingest_time", "gate_time"):
            if record.get(key):
                times.append(parse_ts(record[key]))
    last = max(times)
    return (last + dt.timedelta(seconds=1)).replace(microsecond=0)


def _case_raw(stage_records: dict, release_id: str) -> list:
    rows = []
    for stage in ("dev", "qa", "staging"):
        record = stage_records[stage]
        payload = {
            "event_type": "health-check",
            "source_url": record["source_url"],
            "http_status": record["http_status"],
            "stage": record["stage"],
            "source": "live_HTTP_request",
            "release_id": release_id,
        }
        rows.append(
            {
                "signal_id": record["signal_id"],
                "source_id": "live_HTTP_request",
                "event_time": record["event_time"],
                "ingest_time": record["ingest_time"],
                "payload": payload,
                "payload_sha256": sha(payload),
            }
        )
    return rows


def _dispositions(stage_records: dict) -> list:
    rows = []
    for index, stage in enumerate(("dev", "qa", "staging"), start=1):
        record = stage_records[stage]
        rows.append(
            {
                "disposition_id": f"DISP-PG-{index:03d}",
                "signal_id": record["signal_id"],
                "decision": "RESOLVED",
                "decision_time": record["gate_time"],
                "actor": "CI_health_gate",
                "authorized": True,
                "effective": True,
                "reason": "digest and live HTTP health gate PASS",
            }
        )
    return rows


def _candidates(dispositions: list) -> list:
    return [
        {
            "candidate_id": f"CAND-{item['signal_id']}",
            "signal_id": item["signal_id"],
            "disposition_id": item["disposition_id"],
            "state": "RESOLVED",
        }
        for item in dispositions
    ]


def _seq_finding(release_id: str, cutoff: dt.datetime, audit: dt.datetime) -> dict:
    return {
        "finding_id": "F-PG-01",
        "observed_at": iso_utc(cutoff + dt.timedelta(hours=2)),
        "source_release_id": release_id,
        "requirement_link": {
            "requirement_id": "REQ-PG-01",
            "created_by_finding_id": "F-PG-01",
            "accepted_at": iso_utc(cutoff + dt.timedelta(hours=1)),
        },
        "target": {
            "release_id": release_id + "-SUCCESSOR",
            "service_id": "closure-demo",
            "due_at": iso_utc(audit - dt.timedelta(hours=12)),
            "verified_at": iso_utc(audit - dt.timedelta(hours=16)),
            "manifest_complete": True,
            "coverage_complete": True,
            "selected_path_valid": True,
            "closed": True,
            "test_passed": True,
        },
    }


def build_audit_case(design: dict, run_meta: dict, chain_result: dict) -> dict:
    scenario = design["id"]
    if chain_result.get("status") != "PASS":
        raise RuntimeError(f"{scenario}: audit case requires a passed staged chain")
    stage_records = chain_result["stages"]
    if set(stage_records) != {"dev", "qa", "staging"}:
        raise RuntimeError(f"{scenario}: all three stages must be present")
    for stage in ("dev", "qa", "staging"):
        if stage_records[stage].get("gate_status") != "PASS":
            raise RuntimeError(f"{scenario}: {stage} gate did not pass")

    pinned = run_meta["artifact"]["sha256"]
    measured = {stage_records[s].get("deployed_sha256") for s in stage_records}
    if measured != {pinned}:
        raise RuntimeError(f"{scenario}: deployed digests differ from pinned build: {sorted(measured)}")

    release_id = run_meta["pair_release_id"]
    cutoff_dt = _cutoff(stage_records)
    cutoff = iso_utc(cutoff_dt)
    audit = iso_utc(cutoff_dt + dt.timedelta(hours=48))
    artifact_reference = "sha256:" + pinned

    raw = _case_raw(stage_records, release_id)
    dispositions = _dispositions(stage_records)
    candidates = _candidates(dispositions)
    gates = [
        {
            "gate_id": "stage-" + stage,
            "required": True,
            "status": "PASS",
            "evaluated_at": stage_records[stage]["gate_time"],
        }
        for stage in ("dev", "qa", "staging")
    ]
    frozen = {
        "release_id": release_id,
        "cutoff": cutoff,
        "policy_version": "PG-POLICY-1",
        "artifact_reference": artifact_reference,
        "stage_source": "live_HTTP_request",
    }

    attestation = {
        "complete": True,
        "query_rule_hash": QUERY_RULE_HASH,
        "collector_version": "1.0.0",
        "source_type": "OBSERVED_CI_STAGE_HTTP_SELF_ATTESTED",
        "inventory_sha256": sha(raw),
    }
    missing_fields = []
    missing_dispositions = []
    findings = []

    if scenario == "PG-DISP":
        missing_dispositions = ["health:qa"]
        dispositions = [d for d in dispositions if d["signal_id"] != "health:qa"]
        candidates = [c for c in candidates if c["signal_id"] != "health:qa"]
    elif scenario == "PG-SEQ":
        findings = [_seq_finding(release_id, cutoff_dt, parse_ts(audit))]
    elif scenario == "PG-INFO":
        missing_fields = ["collector_attestation.query_rule_hash"]
        attestation.pop("query_rule_hash", None)

    case = {
        "schema_version": "E2-case-1",
        "release_id": release_id,
        "source_cutoff": cutoff,
        "audit_time": audit,
        "policy": {
            "version": "PG-POLICY-1",
            "waivable_gates": [],
            "waiver_approvers": [],
            "exclusion_authorities": [],
        },
        "scope": {
            "service_id": "closure-demo",
            "approved_sources": ["live_HTTP_request"],
            "finding_observation_complete": True,
            "collector_attestation": attestation,
        },
        "raw_signals": raw,
        "dispositions": dispositions,
        "candidates": candidates,
        "gates": gates,
        "artifact": {
            "expected_sha256": artifact_reference,
            "deployed_sha256": artifact_reference,
        },
        "snapshot": {
            "frozen_payload": frozen,
            "frozen_sha256": sha(frozen),
            "current_payload": copy.deepcopy(frozen),
            "frozen_at": cutoff,
        },
        "findings": findings,
        "time_model": "MIXED_LIVE_STAGE_SCRIPTED_A2",
    }
    collector = _collector(design, run_meta, chain_result, case, missing_dispositions, missing_fields)
    return {"case": case, "collector": collector, "missing_fields": missing_fields, "missing_dispositions": missing_dispositions}


def _collector(design, run_meta, chain_result, case, missing_dispositions, missing_fields) -> dict:
    stage_records = chain_result["stages"]
    recorded = []
    for stage in ("dev", "qa", "staging"):
        record = stage_records[stage]
        recorded.append(
            {
                "stage": stage,
                "signal_id": record["signal_id"],
                "container_id": record.get("container_id"),
                "image_id": record.get("image_id"),
                "image_tag": record.get("image_tag"),
                "expected_sha256": record.get("expected_sha256"),
                "deployed_sha256": record.get("deployed_sha256"),
                "http_status": record.get("http_status"),
                "gate_status": record.get("gate_status"),
                "check_finished_at_utc": record.get("gate_time"),
                "raw_event_path": "raw/stage_events.jsonl",
                "raw_log_path": f"raw/stage_logs/{stage}.log",
                "image_identity_check": record.get("image_identity_check"),
                "digest_check": record.get("digest_check"),
                "attestation_binding": record.get("attestation_binding"),
                "health_check": record.get("health_check"),
            }
        )
    provenance = {
        "raw_signals": {
            "type": "native",
            "source": "raw/stage_events.jsonl",
            "rule": "one live HTTP GET /health per deployed stage",
        },
        "dispositions": {
            "type": "derived",
            "source": "raw/stage_events.jsonl",
            "rule": "CI_health_gate PASS -> RESOLVED / effective",
        },
        "candidates_findings": {
            "type": "scripted",
            "source": "tools/pg_case.py",
            "rule": "candidate, Finding and successor identifiers are synthetic test records generated from the frozen scenario design; no engineering dataset is read or copied",
        },
        "gates": {
            "type": "derived",
            "source": "raw/stage_events.jsonl",
            "rule": "pinned pyz digest measurement + live HTTP health decision",
        },
        "artifact_sha256": {
            "type": "native",
            "source": "raw/artifact_measurements.json",
            "rule": "sha256sum /srv/release_app.pyz inside the running stage container",
        },
        "image_id": {
            "type": "native",
            "source": "raw/artifact_measurements.json",
            "rule": "docker inspect .Image; identity type is distinct from the pyz file digest",
        },
        "source_cutoff": {
            "type": "scripted",
            "source": "derived from native stage events",
            "rule": "max(native event, receipt and gate time) + 1s; fixed relative relation across arms",
        },
        "audit_time": {
            "type": "scripted",
            "rule": "source_cutoff + 48h; fixed relative relation across arms",
        },
        "finding_times": {
            "type": "scripted" if design["id"] == "PG-SEQ" else "unavailable",
            "rule": "observed_at = cutoff + 2h; accepted_at = cutoff + 1h; target times relative to audit",
        },
        "collector_attestation": {
            "type": "declared" if design["id"] != "PG-INFO" else "unavailable",
            "source": "tools/pg_case.py",
            "rule": "self-declared attestation for the bounded three-stage collector; not an independent third-party export",
        },
        "github_attestation": _attestation_provenance(run_meta),
        "stage_inventory": {
            "type": "native",
            "source": "raw/stage_events.jsonl",
            "rule": "bounded three-stage inventory; not a production inventory",
        },
    }
    return {
        "schema": "pg-collector-1",
        "scenario": design["id"],
        "run_key": run_meta["run_key"],
        "native_run": {
            "run_key": run_meta["run_key"],
            "pair_key": run_meta["pair_key"],
            "arm": run_meta["arm"],
            "repeat_index": run_meta["repeat_index"],
            "attempt": run_meta["attempt"],
            "github_run_id": run_meta.get("github_run_id"),
            "github_job_id": run_meta.get("github_job_id"),
            "source_commit": run_meta.get("source_commit"),
            "stages": recorded,
            "deployment_first_failure_stage": chain_result.get("first_failure_stage"),
            "deployment_downstream": chain_result.get("downstream"),
            "cleanup": chain_result.get("cleanup"),
        },
        "release_binding": {
            "release_episode_id": run_meta["pair_release_id"],
            "service_id": "closure-demo",
            "environment_chain": ["dev", "qa", "staging"],
            "manifest_id": sha(recorded),
            "approved_artifact_sha256": "sha256:" + run_meta["artifact"]["sha256"],
            "build_id": run_meta["build"]["build_id"],
        },
        "bounded_inventory": {
            "source_window": "stage chain dev > qa > staging, bounded to this run",
            "inventory_version": "pg-inventory-1",
            "inventory_sha256": sha(case["raw_signals"]),
            "signal_ids": [row["signal_id"] for row in case["raw_signals"]],
            "candidate_ids": [c["candidate_id"] for c in case["candidates"]],
            "disposition_ids": [d["disposition_id"] for d in case["dispositions"]],
            "missing_dispositions": missing_dispositions,
            "empty_dispositions": len(case["dispositions"]) == 0,
            "missing_fields": missing_fields,
            "empty_set_was_not_substituted_for_missing": True,
        },
        "history_successor": {
            "source_cutoff": case["source_cutoff"],
            "audit_time": case["audit_time"],
            "time_kinds": {
                "occurrence": "raw_signals[].event_time",
                "receipt": "raw_signals[].ingest_time",
                "audit": "audit_time",
            },
            "findings": case.get("findings", []),
            "finding_ids_visible_after_cutoff": [
                finding["finding_id"]
                for finding in case.get("findings", [])
                if parse_ts(finding["observed_at"]) > parse_ts(case["source_cutoff"])
            ],
            "successor_identity": [f.get("target", {}) for f in case.get("findings", [])],
            "historical_snapshot_sha256": case["snapshot"]["frozen_sha256"],
            "historical_snapshot_unchanged": case["snapshot"]["current_payload"] == case["snapshot"]["frozen_payload"],
        },
        "provenance": provenance,
        "collector_rule": COLLECTOR_RULE,
        "collector_rule_sha256": QUERY_RULE_HASH,
    }


def _attestation_provenance(run_meta):
    attestation = run_meta.get("build", {}).get("attestation", {})
    mode = attestation.get("mode")
    if mode == "github":
        return {
            "type": "native",
            "source": "build_manifest.json attestation.verify_exit / verify_json",
            "status": attestation.get("status"),
        }
    return {
        "type": "unavailable",
        "source": "no GitHub attestation in local mode",
        "status": attestation.get("status", "NOT_AVAILABLE_LOCAL"),
    }


def semantic_projection(case: dict) -> dict:
    """Project the audit input onto an arm-invariant semantic form.

    The verifier only consumes order relations for native evidence (every raw
    event, disposition and gate must not be later than the cutoff). Exact
    wall-clock seconds differ between two live runs, so the projection replaces
    native timestamps with fixed per-stage ordinals instead of keeping the
    measured deltas. Scripted A2 offsets are already relative and stay numeric.
    The native case.json is retained unchanged; this projection is used only to
    decide whether two arms received the same audit input.
    """
    cutoff = parse_ts(case["source_cutoff"])
    audit = parse_ts(case["audit_time"])
    projected = copy.deepcopy(case)
    projected.pop("source_cutoff", None)
    projected.pop("audit_time", None)
    projected["source_cutoff_offset_seconds"] = 0
    projected["audit_offset_seconds"] = int((audit - cutoff).total_seconds())
    projected["time_projection"] = {
        "rule": "native stage timestamps -> fixed per-stage ordinal offsets; scripted A2 offsets kept",
        "native_order_checks_preserved": [
            "raw event_time and ingest_time <= cutoff",
            "disposition decision_time <= cutoff",
            "gate evaluated_at <= cutoff",
            "snapshot frozen_at <= cutoff",
        ],
        "not_used_as_audit_input": True,
    }

    normalized_raw = []
    for index, row in enumerate(projected["raw_signals"]):
        ordinal = -60 + index * 10
        row["event_time"] = ordinal
        row["ingest_time"] = ordinal + 1
        payload = copy.deepcopy(row["payload"])
        if "event_time" in payload:
            payload["event_time"] = "<NORMALIZED>"
        if isinstance(payload.get("source_url"), str):
            payload["source_url"] = re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:<PORT>", payload["source_url"])
        row["payload"] = payload
        row["payload_sha256"] = sha(payload)
        normalized_raw.append(row)

    for index, row in enumerate(projected["dispositions"]):
        row["decision_time"] = -60 + index * 10 + 2
    for index, row in enumerate(projected["gates"]):
        row["evaluated_at"] = -60 + index * 10 + 3

    snapshot = projected["snapshot"]
    snapshot["frozen_at"] = 0
    frozen_payload = copy.deepcopy(snapshot["frozen_payload"])
    frozen_payload["cutoff"] = "<CUTOFF>"
    snapshot["frozen_payload"] = frozen_payload
    snapshot["current_payload"] = copy.deepcopy(frozen_payload)
    snapshot["frozen_sha256"] = "<NORMALIZED>"
    snapshot["frozen_payload_semantic_sha256"] = sha(frozen_payload)

    for finding in projected.get("findings", []):
        finding["observed_at"] = _offset_seconds(finding["observed_at"], cutoff)
        finding["requirement_link"]["accepted_at"] = _offset_seconds(
            finding["requirement_link"]["accepted_at"], cutoff
        )
        for key in ("due_at", "verified_at"):
            if key in finding.get("target", {}):
                finding["target"][key] = _offset_seconds(finding["target"][key], cutoff)

    att = projected["scope"]["collector_attestation"]
    if "inventory_sha256" in att:
        att["inventory_sha256"] = "<NORMALIZED>"
    projected["scope"]["collector_attestation"]["semantic_inventory_sha256"] = sha(normalized_raw)
    return projected


def semantic_sha(case: dict) -> str:
    return sha(semantic_projection(case))


def measure_artifact_in_image(image: str, out_path) -> dict:
    result = run_cmd(
        ["docker", "run", "--rm", "--entrypoint", "sha256sum", image, "/srv/release_app.pyz"],
        timeout=60,
        log_path=out_path,
    )
    return result

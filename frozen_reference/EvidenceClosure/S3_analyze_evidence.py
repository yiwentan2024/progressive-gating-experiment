"""Reference-profile v1.0 validator for the release-evidence contract.

The validator is standard-library only.  Snapshot closure is evaluated against
the records visible at each snapshot cutoff; coverage attestations and
candidate decisions are versioned, reconciled, and time-bound.
"""
import argparse
import csv
import hashlib
import json
import math
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCHEMA = {
    "nodes.csv": ["closure_id", "node_id", "logical_work_item_id", "node_type", "work_item_kind", "service_id", "version", "policy_version", "event_time_utc", "created_at_utc", "accepted_at_utc", "owner", "status", "artifact_digest", "accepted_revision", "reviewed", "mandatory", "immutable", "release_approved", "environment", "metadata_json"],
    "edges.csv": ["closure_id", "edge_id", "edge_type", "source_node_id", "target_node_id", "event_time_utc", "source_version", "target_version"],
    "gate_evaluations.csv": ["closure_id", "gate_evaluation_id", "target_node_id", "gate_id", "gate_mode", "phase", "attempt", "supersedes_gate_evaluation_id", "policy_version", "gate_owner", "evaluated_at_utc", "threshold_operator", "threshold_value", "observed_value", "unit", "decision", "exception_id", "resolution_time_utc"],
    "exceptions.csv": ["closure_id", "exception_id", "gate_evaluation_id", "policy_version", "approver", "scope_gate_id", "scope_service_id", "risk_class", "issue_time_utc", "expiry_time_utc", "revoked_at_utc", "rationale", "status"],
    "incidents.csv": ["closure_id", "incident_id", "deployment_id", "classification", "severity", "opened_at_utc", "reported_at_utc", "attribution_time_utc", "classifier", "classification_evidence", "finding_id", "feedback_link_time_utc", "feedback_ttl_hours", "resolved_at_utc", "resolution_validator", "resolution_evidence", "reopens_snapshot_id", "late_discovery_action"],
    "candidate_coverage.csv": ["closure_id", "coverage_id", "coverage_version", "supersedes_coverage_id", "effective_from_snapshot_id", "deployment_id", "service_id", "environment", "window_start_utc", "window_end_utc", "monitor_sources_json", "collector_id", "collector_version", "query_rule_hash", "collection_status", "raw_signal_count", "imported_candidate_count", "noncandidate_count", "rejected_count", "filter_reason_summary_json", "candidate_digest_sha256", "raw_inventory_digest_sha256", "reconciliation_digest_sha256", "source_batch_id", "responsible_actor", "attested_at_utc"],
    "raw_signal_inventory.csv": ["closure_id", "coverage_id", "raw_signal_id", "source_batch_id", "signal_digest_sha256", "observed_at_utc", "disposition", "candidate_id", "disposition_reason_code", "disposition_rationale", "disposition_decided_by", "disposition_decided_at_utc"],
    "incident_candidates.csv": ["closure_id", "candidate_id", "deployment_id", "service_id", "environment", "observed_at_utc", "admitted_at_utc", "source_batch_id", "signal_digest_sha256", "status", "incident_id", "exclusion_reason_code", "exclusion_rationale", "decision_role", "decided_by", "decided_at_utc", "reviewed_by", "reviewed_at_utc", "reopens_snapshot_id"],
    "release_manifest.csv": ["closure_id", "release_decision_id", "change_id", "selected_build_id", "selected_test_run_ids", "selected_artifact_id", "artifact_digest", "approved_at_utc", "policy_version", "evaluation_time_utc", "observation_window_hours", "mandatory_gate_ids"],
    "snapshots.csv": ["closure_id", "snapshot_id", "release_decision_id", "evaluated_at_utc", "supersedes_snapshot_id", "input_manifest_digest", "declared_status"],
}
POLICY_FIELDS = ["policy_version", "gate_id", "gate_mode", "phase", "effective_at_utc", "retired_at_utc", "owner", "value_type", "unit", "waiver_allowed", "min_observation_window_hours", "max_observation_window_hours"]
DATA_DICTIONARY_FIELDS = ["file", "field", "description", "column_required", "value_required", "nullable_when", "required_when", "type", "controlled_vocabulary_or_range", "referential_rule", "failure_code", "validation"]
GATE_OWNER_AUTHORIZATION_FIELDS = ["authorization_id", "delegator", "delegate", "policy_version", "gate_scope", "service_scope", "effective_at_utc", "retired_at_utc"]
EXCEPTION_AUTHORITY_FIELDS = ["authority_id", "subject", "role", "policy_version", "gate_scope", "service_scope", "max_risk_class", "effective_at_utc", "retired_at_utc"]
CANDIDATE_REVIEW_AUTHORITY_FIELDS = ["authorization_id", "subject", "role", "service_scope", "effective_at_utc", "retired_at_utc"]
PRINCIPAL_REGISTRY_FIELDS = ["registry_version", "alias", "principal_id", "effective_at_utc", "retired_at_utc"]
AUTHORITY_ROLES = {"release_authority", "risk_owner", "security_authority", "service_owner"}
COLLECTION_STATUSES = {"complete", "failed", "partial"}
RAW_SIGNAL_DISPOSITIONS = {"imported_candidate", "noncandidate", "rejected"}
RAW_SIGNAL_REASON_CODES = {
    "admitted_to_candidate_registry", "non_incident_signal", "outside_query_scope",
    "malformed_signal", "duplicate_raw_signal", "collector_policy_rejection",
}
CANDIDATE_STATUSES = {"attributed", "excluded", "unresolved"}
EXCLUSION_REASON_CODES = {"duplicate_signal", "non_incident_operational_event", "outside_release_window", "test_or_maintenance_activity", "monitoring_false_positive"}
CANDIDATE_DECISION_ROLES = {"incident_triager", "service_owner", "operations_lead", "governance_reviewer"}
CANDIDATE_REVIEW_ROLES = {"governance_reviewer", "operations_lead"}
NODE_TYPES = {"WorkItem", "Change", "Build", "TestRun", "Artifact", "ReleaseDecision", "Deployment", "GateEvaluation", "Exception", "Incident"}
EDGE_RULES = {
    "implements": ({"Change"}, {"WorkItem"}), "triggers": ({"Change"}, {"Build"}),
    "evaluated_by": ({"Build"}, {"TestRun"}), "produces": ({"Build"}, {"Artifact"}),
    "includes_change": ({"ReleaseDecision"}, {"Change"}), "approves": ({"ReleaseDecision"}, {"Artifact"}),
    "executes": ({"Deployment"}, {"ReleaseDecision"}), "evaluates": ({"GateEvaluation"}, {"Change", "Build", "Artifact", "ReleaseDecision", "Deployment"}),
    "authorizes": ({"Exception"}, {"GateEvaluation"}), "attributed_to": ({"Incident"}, {"Deployment"}),
    "creates_finding": ({"Incident"}, {"WorkItem"}), "derived_from": ({"WorkItem"}, {"WorkItem"}),
    "violates_or_relates_to": ({"WorkItem"}, {"WorkItem"}), "creates_requirement": ({"WorkItem"}, {"WorkItem"}),
}
DECISIONS = {"pass", "fail", "exception"}
GATE_MODES = {"required", "optional_decision", "informational"}
PHASES = {"pre_approval", "post_deployment"}
GATE_OPERATORS = {"eq", "ne", "lt", "le", "gt", "ge", "in", "policy_assertion"}
VALUE_TYPES = {"string", "integer", "number", "boolean"}
RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def parse_time(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def as_bool(value):
    return str(value).strip().lower() in {"1", "true", "yes"}


def split_ids(value):
    return [item.strip() for item in (value or "").replace(",", "|").split("|") if item.strip()]


def latency(values):
    ordered = sorted(values)
    if not ordered:
        return {"unit": "hours", "n": 0, "median": None, "minimum": None, "maximum": None, "dispersion": "not_estimable"}
    return {
        "unit": "hours", "n": len(ordered), "median": round(statistics.median(ordered), 6),
        "minimum": round(ordered[0], 6), "maximum": round(ordered[-1], 6),
        "dispersion": "not_informative" if len(ordered) < 2 else {"iqr": round(statistics.quantiles(ordered, n=4, method="inclusive")[2] - statistics.quantiles(ordered, n=4, method="inclusive")[0], 6)},
    }


def proportion(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator, "estimate": round(numerator / denominator, 6) if denominator else None}


def candidate_digest(rows):
    """Digest the admitted candidate identity set for one source batch."""
    payload = "\n".join(
        f"{row['candidate_id']}|{row['signal_digest_sha256']}"
        for row in sorted(rows, key=lambda item: item["candidate_id"])
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def raw_inventory_digest(rows):
    """Digest the complete raw-signal inventory independent of CSV row order."""
    fields = SCHEMA["raw_signal_inventory.csv"]
    payload = "\n".join(
        "|".join(str(row.get(field, "")).strip() for field in fields)
        for row in sorted(rows, key=lambda item: (item.get("raw_signal_id", ""), item.get("signal_digest_sha256", "")))
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def reconciliation_digest(row):
    """Digest the signed coverage reconciliation statement."""
    payload = "|".join(
        str(row.get(field, "")).strip()
        for field in (
            "coverage_id", "coverage_version", "supersedes_coverage_id",
            "effective_from_snapshot_id", "deployment_id", "service_id",
            "environment", "window_start_utc", "window_end_utc",
            "monitor_sources_json", "collector_id", "collector_version",
            "query_rule_hash", "source_batch_id", "responsible_actor",
            "attested_at_utc", "collection_status",
            "raw_signal_count", "imported_candidate_count", "noncandidate_count",
            "rejected_count", "filter_reason_summary_json",
            "candidate_digest_sha256", "raw_inventory_digest_sha256",
        )
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def snapshot_input_digest(
    snapshot, manifest_rows, policy_rows, owner_rows, exception_rows,
    candidate_authority_rows, gate_rows, coverage_rows, raw_signal_rows,
    candidate_rows, incident_rows, node_rows, edge_rows, principal_registry_rows=None,
):
    """Digest the deterministic input view visible at one snapshot cutoff."""
    cutoff = snapshot.get("_evaluated")

    def visible(row):
        for key in (
            "_time", "_evaluated", "_attested", "_admitted", "_decided",
            "_reviewed", "_disposition_decided", "_reported", "_attributed", "_opened", "_feedback",
            "_resolved", "_created", "_accepted",
        ):
            value = row.get(key)
            if value is not None and cutoff is not None and value > cutoff:
                return False
        return True

    selected = {
        "manifest": manifest_rows,
        "policy": [row for row in policy_rows if row.get("_effective") and cutoff and row["_effective"] <= cutoff],
        "owner_authority": [row for row in owner_rows if row.get("_effective") and cutoff and row["_effective"] <= cutoff],
        "exception_authority": [row for row in exception_rows if row.get("_effective") and cutoff and row["_effective"] <= cutoff],
        "candidate_authority": [row for row in candidate_authority_rows if row.get("_effective") and cutoff and row["_effective"] <= cutoff],
        "principal_registry": [row for row in (principal_registry_rows or []) if row.get("_effective") and cutoff and row["_effective"] <= cutoff],
        "gates": [row for row in gate_rows if visible(row)],
        "coverage": [
            row for row in coverage_rows
            if row.get("effective_from_snapshot_id") == snapshot.get("snapshot_id")
            and visible(row)
        ],
        "raw_signals": [row for row in raw_signal_rows if visible(row)],
        "candidates": [row for row in candidate_rows if visible(row)],
        "incidents": [row for row in incident_rows if visible(row)],
        "nodes": [row for row in node_rows if visible(row)],
        "edges": [row for row in edge_rows if visible(row)],
    }
    normalized = {}
    for name, rows in selected.items():
        normalized[name] = []
        for row in rows:
            normalized[name].append({
                key: value for key, value in sorted(row.items())
                if not key.startswith("_")
            })
        normalized[name].sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def analyze(root, policy_registry=None, data_dictionary=None, gate_owner_authorizations=None, exception_authorities=None, candidate_review_authorizations=None, principal_registry=None):
    root = Path(root)
    policy_registry = Path(policy_registry or root.parent / "S4_policy_registry.csv")
    registry_root = policy_registry.parent
    data_dictionary = Path(data_dictionary or registry_root / "S1_data_dictionary.csv")
    gate_owner_authorizations = Path(gate_owner_authorizations or registry_root / "S4_gate_owner_authorizations.csv")
    exception_authorities = Path(exception_authorities or registry_root / "S4_exception_authority_registry.csv")
    candidate_review_authorizations = Path(candidate_review_authorizations or registry_root / "S4_candidate_review_authorizations.csv")
    principal_registry = Path(principal_registry or registry_root / "S4_principal_registry.csv")
    errors = []
    seen_errors = set()

    def error(code, message, closure_id="", object_id=""):
        key = (code, closure_id, object_id, message)
        if key not in seen_errors:
            seen_errors.add(key)
            errors.append({"code": code, "closure_id": closure_id, "object_id": object_id, "message": message})

    def read_csv(path, required, label):
        try:
            with Path(path).open(encoding="utf-8-sig", newline="") as source:
                reader = csv.DictReader(source)
                missing = [field for field in required if field not in (reader.fieldnames or [])]
                if missing:
                    error("missing_columns", f"{label}: missing columns {missing}", object_id=label)
                    return []
                return list(reader)
        except FileNotFoundError:
            error("missing_input_file", f"required input file not found: {label}", object_id=label)
        except (OSError, csv.Error, UnicodeError) as exc:
            error("unreadable_input_file", f"{label}: {type(exc).__name__}: {exc}", object_id=label)
        return []

    tables = {name: read_csv(root / name, fields, name) for name, fields in SCHEMA.items()}
    policy_rows = read_csv(policy_registry, POLICY_FIELDS, policy_registry.name)
    dictionary_rows = read_csv(data_dictionary, DATA_DICTIONARY_FIELDS, data_dictionary.name)
    owner_authorization_rows = read_csv(gate_owner_authorizations, GATE_OWNER_AUTHORIZATION_FIELDS, gate_owner_authorizations.name)
    exception_authority_rows = read_csv(exception_authorities, EXCEPTION_AUTHORITY_FIELDS, exception_authorities.name)
    candidate_review_authority_rows = read_csv(candidate_review_authorizations, CANDIDATE_REVIEW_AUTHORITY_FIELDS, candidate_review_authorizations.name)
    principal_rows = read_csv(principal_registry, PRINCIPAL_REGISTRY_FIELDS, principal_registry.name)

    def condition_matches(record, expression):
        if not expression:
            return False
        for clause in expression.split("&"):
            clause = clause.strip()
            if "!=" in clause:
                field, expected = (part.strip() for part in clause.split("!=", 1))
                if record.get(field, "").strip() == expected:
                    return False
            elif ">" in clause:
                field, expected = (part.strip() for part in clause.split(">", 1))
                try:
                    if float(record.get(field, "")) <= float(expected):
                        return False
                except (TypeError, ValueError):
                    return False
            elif "=" in clause:
                field, expected = (part.strip() for part in clause.split("=", 1))
                if record.get(field, "").strip() not in expected.split("|"):
                    return False
            else:
                return False
        return True

    def matrix_value_valid(value, declared_type):
        if value == "":
            return True
        try:
            if declared_type == "integer":
                int(value)
            elif declared_type == "number":
                if not math.isfinite(float(value)):
                    return False
            elif declared_type == "boolean":
                if value.lower() not in {"true", "false", "1", "0", "yes", "no"}:
                    return False
            elif declared_type == "time":
                parse_time(value)
            elif declared_type == "json":
                parsed = json.loads(value, parse_constant=lambda token: (_ for _ in ()).throw(ValueError(f"non-finite JSON constant: {token}")))
                if not json_numbers_finite(parsed):
                    return False
            elif declared_type == "hash":
                if ":" not in value or not value.split(":", 1)[1].strip():
                    return False
        except (ValueError, TypeError, OverflowError, json.JSONDecodeError):
            return False
        return True

    def json_numbers_finite(value):
        """Recursively reject JSON numbers that overflow Python's finite float range."""
        if isinstance(value, bool) or value is None or isinstance(value, (str, int)):
            return True
        if isinstance(value, float):
            return math.isfinite(value)
        if isinstance(value, dict):
            return all(json_numbers_finite(item) for item in value.values())
        if isinstance(value, (list, tuple)):
            return all(json_numbers_finite(item) for item in value)
        return False

    dictionary = {}
    for row in dictionary_rows:
        key = (row["file"], row["field"])
        if key in dictionary:
            error("duplicate_data_dictionary_field", "S1 file/field rows must be unique", object_id="/".join(key))
        dictionary[key] = row
    expected_dictionary = {(name, field) for name, fields in SCHEMA.items() for field in fields}
    expected_dictionary.update((policy_registry.name, field) for field in POLICY_FIELDS)
    expected_dictionary.update((gate_owner_authorizations.name, field) for field in GATE_OWNER_AUTHORIZATION_FIELDS)
    expected_dictionary.update((exception_authorities.name, field) for field in EXCEPTION_AUTHORITY_FIELDS)
    expected_dictionary.update((candidate_review_authorizations.name, field) for field in CANDIDATE_REVIEW_AUTHORITY_FIELDS)
    expected_dictionary.update((principal_registry.name, field) for field in PRINCIPAL_REGISTRY_FIELDS)
    if set(dictionary) != expected_dictionary:
        missing = sorted(expected_dictionary - set(dictionary))
        extra = sorted(set(dictionary) - expected_dictionary)
        error("required_value_matrix_mismatch", f"S1 matrix mismatch; missing={missing}; extra={extra}", object_id=data_dictionary.name)

    matrix_fields = dict(SCHEMA)
    matrix_fields[policy_registry.name] = POLICY_FIELDS
    matrix_fields[gate_owner_authorizations.name] = GATE_OWNER_AUTHORIZATION_FIELDS
    matrix_fields[exception_authorities.name] = EXCEPTION_AUTHORITY_FIELDS
    matrix_fields[candidate_review_authorizations.name] = CANDIDATE_REVIEW_AUTHORITY_FIELDS
    matrix_fields[principal_registry.name] = PRINCIPAL_REGISTRY_FIELDS
    matrix_sources = dict(tables)
    matrix_sources[policy_registry.name] = policy_rows
    matrix_sources[gate_owner_authorizations.name] = owner_authorization_rows
    matrix_sources[exception_authorities.name] = exception_authority_rows
    matrix_sources[candidate_review_authorizations.name] = candidate_review_authority_rows
    matrix_sources[principal_registry.name] = principal_rows
    required_value_total = 0
    required_value_present = 0
    for file_name, records in matrix_sources.items():
        for record in records:
            object_id = record.get("node_id") or record.get("gate_evaluation_id") or record.get("exception_id") or record.get("incident_id") or record.get("policy_version") or file_name
            closure_id = record.get("closure_id", "")
            for field in matrix_fields[file_name]:
                rule = dictionary.get((file_name, field))
                if not rule:
                    continue
                value = (record.get(field) or "").strip()
                required = rule["value_required"] == "yes" or (rule["value_required"] == "conditional" and condition_matches(record, rule["required_when"]))
                if required:
                    required_value_total += 1
                    if value:
                        required_value_present += 1
                if required and not value:
                    error(rule["failure_code"] or "missing_required_value", f"{file_name}.{field} is value-required after trimming", closure_id, object_id)
                    continue
                if value and rule["type"] == "number":
                    try:
                        finite = math.isfinite(float(value))
                    except (TypeError, ValueError, OverflowError):
                        finite = True
                    if not finite:
                        error("invalid_nonfinite_number", f"{file_name}.{field} must be finite", closure_id, object_id)
                        continue
                if value and rule["type"] == "json":
                    try:
                        parsed_json = json.loads(value, parse_constant=lambda token: (_ for _ in ()).throw(ValueError(f"non-finite JSON constant: {token}")))
                    except (ValueError, TypeError, OverflowError, json.JSONDecodeError):
                        parsed_json = None
                    if parsed_json is not None and not json_numbers_finite(parsed_json):
                        error("invalid_nonfinite_json_number", f"{file_name}.{field} contains a non-finite parsed JSON number", closure_id, object_id)
                        continue
                if value and not matrix_value_valid(value, rule["type"]):
                    error(rule["failure_code"] or "invalid_required_value_type", f"{file_name}.{field} violates declared type {rule['type']}", closure_id, object_id)
                vocabulary = [item for item in rule["controlled_vocabulary_or_range"].split("|") if item]
                if value and vocabulary and not any(token in rule["controlled_vocabulary_or_range"] for token in (">", "<", "..")) and value not in vocabulary:
                    error(rule["failure_code"] or "invalid_controlled_value", f"{file_name}.{field} is outside the controlled vocabulary", closure_id, object_id)

    time_cache = {}
    def time_value(value, closure_id="", object_id="", field="timestamp", required=True):
        key = (value, closure_id, object_id, field, required)
        if key in time_cache:
            return time_cache[key]
        if not value:
            if required:
                error("missing_timestamp", f"{field} is required", closure_id, object_id)
            time_cache[key] = None
            return None
        try:
            result = parse_time(value)
        except (ValueError, TypeError, OverflowError):
            error("invalid_timestamp", f"invalid {field}: {value!r}", closure_id, object_id)
            result = None
        time_cache[key] = result
        return result

    principal_registry_versions = {row["registry_version"].strip() for row in principal_rows if row.get("registry_version", "").strip()}
    if len(principal_registry_versions) != 1:
        error("principal_registry_version_mismatch", "principal registry must expose one explicit registry_version", object_id=principal_registry.name)
    principal_aliases = {}
    principal_intervals = defaultdict(list)
    for row in principal_rows:
        alias = row["alias"].strip()
        principal_id = row["principal_id"].strip()
        effective = time_value(row["effective_at_utc"], object_id=alias, field="principal effective_at_utc")
        retired = time_value(row["retired_at_utc"], object_id=alias, field="principal retired_at_utc", required=False)
        row.update(_effective=effective, _retired=retired)
        if not alias or not principal_id:
            error("invalid_principal_registry_row", "principal alias and immutable principal_id are required", object_id=alias or principal_registry.name)
            continue
        if alias in principal_aliases:
            if principal_aliases[alias] != principal_id:
                error("principal_alias_conflict", "one alias cannot resolve to multiple immutable principal IDs", object_id=alias)
            else:
                error("duplicate_principal_alias", "principal aliases must be unique", object_id=alias)
            continue
        if effective and retired and retired <= effective:
            error("invalid_principal_interval", "retired_at must be later than effective_at", object_id=alias)
        principal_aliases[alias] = principal_id
        principal_intervals[alias].append((effective, retired))

    def canonical_principal(subject, moment=None, *, object_id=""):
        alias = (subject or "").strip()
        principal_id = principal_aliases.get(alias)
        if not principal_id:
            if alias:
                error("unknown_principal_alias", "reviewer/decider identity is not present in the immutable principal registry", object_id=object_id or alias)
            return None
        intervals = principal_intervals.get(alias, [])
        if moment is not None and not any(effective and effective <= moment and (not retired or moment < retired) for effective, retired in intervals):
            error("principal_not_effective", "principal alias is not effective at the decision/review time", object_id=object_id or alias)
            return None
        return principal_id

    def int_value(value, closure_id="", object_id="", field="integer", minimum=None):
        try:
            result = int(value)
            if minimum is not None and result < minimum:
                raise ValueError
            return result
        except (ValueError, TypeError, OverflowError):
            error("invalid_integer", f"invalid {field}: {value!r}", closure_id, object_id)
            return None

    def float_value(value, closure_id="", object_id="", field="number", minimum=None):
        try:
            result = float(value)
            if not math.isfinite(result):
                error("invalid_nonfinite_number", f"non-finite {field}: {value!r}", closure_id, object_id)
                return None
            if minimum is not None and result < minimum:
                raise ValueError
            return result
        except (ValueError, TypeError, OverflowError):
            error("invalid_number", f"invalid {field}: {value!r}", closure_id, object_id)
            return None

    def parse_typed_gate_value(value, value_type):
        text = (value or "").strip()
        if value_type == "string":
            return text
        if value_type == "integer":
            return int(text)
        if value_type == "number":
            result = float(text)
            if not math.isfinite(result):
                raise ValueError("number must be finite")
            return result
        if value_type == "boolean":
            lowered = text.lower()
            if lowered in {"true", "1", "yes"}:
                return True
            if lowered in {"false", "0", "no"}:
                return False
            raise ValueError("boolean must be true/false, 1/0, or yes/no")
        raise ValueError(f"unsupported value_type {value_type!r}")

    def evaluate_gate_evidence(row, policy):
        operator = row["threshold_operator"].strip()
        value_type = policy["value_type"].strip()
        if operator not in GATE_OPERATORS:
            return None, "invalid_gate_operator"
        if value_type not in VALUE_TYPES:
            return None, "invalid_gate_value_type"
        if row["unit"].strip() != policy["unit"].strip():
            return None, "gate_unit_policy_mismatch"
        try:
            observed = parse_typed_gate_value(row["observed_value"], value_type)
            if operator == "in":
                threshold = [parse_typed_gate_value(item, value_type) for item in row["threshold_value"].split("|") if item.strip()]
                if not threshold:
                    raise ValueError("membership threshold is empty")
            else:
                threshold = parse_typed_gate_value(row["threshold_value"], value_type)
        except (TypeError, ValueError, OverflowError):
            return None, "unparseable_gate_value"
        if operator in {"lt", "le", "gt", "ge"} and value_type not in {"integer", "number"}:
            return None, "invalid_gate_operator_type"
        operations = {
            "eq": lambda: observed == threshold,
            "ne": lambda: observed != threshold,
            "lt": lambda: observed < threshold,
            "le": lambda: observed <= threshold,
            "gt": lambda: observed > threshold,
            "ge": lambda: observed >= threshold,
            "in": lambda: observed in threshold,
            "policy_assertion": lambda: observed == threshold,
        }
        return bool(operations[operator]()), None

    def interval_active(row, moment):
        effective = time_value(row["effective_at_utc"], object_id=row.get("authorization_id") or row.get("authority_id", ""), field="authorization effective_at_utc")
        retired = time_value(row["retired_at_utc"], object_id=row.get("authorization_id") or row.get("authority_id", ""), field="authorization retired_at_utc", required=False)
        return bool(moment and effective and effective <= moment and (not retired or moment < retired))

    def candidate_actor_authorized(subject, role, service_id, moment):
        principal_id = canonical_principal(subject, moment, object_id=subject)
        if not principal_id:
            return False
        return any(
            canonical_principal(row["subject"], moment, object_id=row.get("authorization_id", "")) == principal_id
            and row["role"].strip() == role.strip()
            and row["service_scope"].strip() in {"*", service_id.strip()}
            and interval_active(row, moment)
            for row in candidate_review_authority_rows
        )

    def gate_owner_authorized(gate, policy, target):
        if gate["gate_owner"].strip() == policy["owner"].strip():
            return True
        for authorization in owner_authorization_rows:
            if (
                authorization["delegator"].strip() == policy["owner"].strip()
                and authorization["delegate"].strip() == gate["gate_owner"].strip()
                and authorization["policy_version"].strip() == gate["policy_version"].strip()
                and authorization["gate_scope"].strip() in {"*", gate["gate_id"].strip()}
                and target
                and authorization["service_scope"].strip() in {"*", target["service_id"].strip()}
                and interval_active(authorization, gate.get("_evaluated"))
            ):
                return True
        return False

    def exception_approver_authorized(exception, gate, target, decision_time):
        risk = RISK_ORDER.get(exception["risk_class"].strip())
        if risk is None:
            return False
        for authority in exception_authority_rows:
            maximum = RISK_ORDER.get(authority["max_risk_class"].strip())
            if (
                authority["subject"].strip() == exception["approver"].strip()
                and authority["policy_version"].strip() == exception["policy_version"].strip()
                and authority["gate_scope"].strip() in {"*", gate["gate_id"].strip()}
                and target
                and authority["service_scope"].strip() in {"*", target["service_id"].strip()}
                and maximum is not None
                and risk <= maximum
                and interval_active(authority, decision_time)
            ):
                return True
        return False

    policies = {}
    policy_versions = defaultdict(list)
    for row in policy_rows:
        key = (row["policy_version"], row["gate_id"])
        if key in policies:
            error("duplicate_policy_gate", "policy_version/gate_id must be unique", object_id="/".join(key))
            continue
        if row["gate_mode"] not in GATE_MODES or row["phase"] not in PHASES or row["value_type"] not in VALUE_TYPES:
            error("invalid_policy_classification", "invalid gate_mode or phase", object_id="/".join(key))
        effective = time_value(row["effective_at_utc"], object_id="/".join(key), field="policy effective_at_utc")
        retired = time_value(row["retired_at_utc"], object_id="/".join(key), field="policy retired_at_utc", required=False)
        minimum = float_value(row["min_observation_window_hours"], object_id="/".join(key), field="min observation window", minimum=0.000001)
        maximum = float_value(row["max_observation_window_hours"], object_id="/".join(key), field="max observation window", minimum=0.000001)
        if effective and retired and retired <= effective:
            error("invalid_policy_interval", "retired_at must be later than effective_at", object_id="/".join(key))
        if minimum is not None and maximum is not None and minimum > maximum:
            error("invalid_observation_policy_range", "minimum observation window exceeds maximum", object_id="/".join(key))
        row.update(_effective=effective, _retired=retired, _min_window=minimum, _max_window=maximum)
        policies[key] = row
        policy_versions[row["policy_version"]].append(row)
    for version, rows in policy_versions.items():
        contexts = {(r["effective_at_utc"], r["retired_at_utc"], r["min_observation_window_hours"], r["max_observation_window_hours"]) for r in rows}
        if len(contexts) != 1:
            error("inconsistent_policy_version_context", "all gates in a policy version require one effective interval and observation range", object_id=version)

    known_policy_versions = set(policy_versions)
    known_policy_gates = {row["gate_id"].strip() for row in policy_rows}
    known_policy_gate_pairs = set(policies)
    seen_authorization_ids = set()
    for row in owner_authorization_rows:
        authorization_id = row["authorization_id"].strip()
        if not authorization_id or authorization_id in seen_authorization_ids:
            error("duplicate_authorization_id", "owner authorization_id must be nonempty and globally unique", object_id=authorization_id or gate_owner_authorizations.name)
        seen_authorization_ids.add(authorization_id)
        policy_version = row["policy_version"].strip()
        gate_scope = row["gate_scope"].strip()
        if policy_version not in known_policy_versions:
            error("unknown_authorization_policy", "owner authorization references an unknown policy_version", object_id=authorization_id)
        if gate_scope != "*" and (policy_version, gate_scope) not in known_policy_gate_pairs:
            error("unknown_authorization_policy_gate", "owner authorization references an unknown policy-version/gate pair", object_id=authorization_id)
        matching_owners = {p["owner"].strip() for p in policy_versions.get(policy_version, [])}
        if gate_scope == "*":
            if len(matching_owners) != 1:
                error("ambiguous_wildcard_authorization_owner", "wildcard owner delegation requires one owner across the policy version", object_id=authorization_id)
            elif row["delegator"].strip() not in matching_owners:
                error("authorization_gate_owner_mismatch", "wildcard delegator must equal the policy version's sole owner", object_id=authorization_id)
        elif (policy_version, gate_scope) in policies and row["delegator"].strip() != policies[(policy_version, gate_scope)]["owner"].strip():
            error("authorization_gate_owner_mismatch", "gate-scoped delegator must equal that policy gate owner", object_id=authorization_id)
        effective = time_value(row["effective_at_utc"], object_id=authorization_id, field="authorization effective_at_utc")
        retired = time_value(row["retired_at_utc"], object_id=authorization_id, field="authorization retired_at_utc", required=False)
        row.update(_effective=effective, _retired=retired)
        if effective and retired and retired <= effective:
            error("invalid_authorization_interval", "retired_at must be later than effective_at", object_id=authorization_id)

    seen_authority_ids = set()
    for row in exception_authority_rows:
        authority_id = row["authority_id"].strip()
        if not authority_id or authority_id in seen_authority_ids:
            error("duplicate_authorization_id", "exception authority_id must be nonempty and globally unique", object_id=authority_id or exception_authorities.name)
        seen_authority_ids.add(authority_id)
        policy_version = row["policy_version"].strip()
        gate_scope = row["gate_scope"].strip()
        if policy_version not in known_policy_versions:
            error("unknown_authorization_policy", "exception authority references an unknown policy_version", object_id=authority_id)
        if gate_scope != "*" and (policy_version, gate_scope) not in known_policy_gate_pairs:
            error("unknown_authorization_policy_gate", "exception authority references an unknown policy-version/gate pair", object_id=authority_id)
        if row["role"].strip() not in AUTHORITY_ROLES:
            error("invalid_authorization_role", "authority role is outside the controlled vocabulary", object_id=authority_id)
        effective = time_value(row["effective_at_utc"], object_id=authority_id, field="authorization effective_at_utc")
        retired = time_value(row["retired_at_utc"], object_id=authority_id, field="authorization retired_at_utc", required=False)
        row.update(_effective=effective, _retired=retired)
        if effective and retired and retired <= effective:
            error("invalid_authorization_interval", "retired_at must be later than effective_at", object_id=authority_id)

    for row in candidate_review_authority_rows:
        authorization_id = row["authorization_id"].strip()
        if not authorization_id or authorization_id in seen_authorization_ids:
            error("duplicate_authorization_id", "candidate authorization_id must be nonempty and globally unique", object_id=authorization_id or candidate_review_authorizations.name)
        seen_authorization_ids.add(authorization_id)
        if row["role"].strip() not in CANDIDATE_DECISION_ROLES:
            error("invalid_candidate_authorization_role", "candidate authority role is outside the controlled vocabulary", object_id=authorization_id)
        effective = time_value(row["effective_at_utc"], object_id=authorization_id, field="candidate authorization effective_at_utc")
        retired = time_value(row["retired_at_utc"], object_id=authorization_id, field="candidate authorization retired_at_utc", required=False)
        row.update(_effective=effective, _retired=retired)
        if effective and retired and retired <= effective:
            error("invalid_authorization_interval", "retired_at must be later than effective_at", object_id=authorization_id)

    nodes = {}
    for row in tables["nodes.csv"]:
        node_id, closure_id = row["node_id"], row["closure_id"]
        if not node_id:
            error("missing_node_id", "node_id is required", closure_id)
            continue
        if node_id in nodes:
            error("duplicate_node_id", "node_id must be globally unique", closure_id, node_id)
            continue
        if row["node_type"] not in NODE_TYPES:
            error("invalid_node_type", "unsupported node type", closure_id, node_id)
        if row["node_type"] == "WorkItem" and row["work_item_kind"] not in {"Requirement", "Finding"}:
            error("invalid_work_item_kind", "WorkItem requires Requirement or Finding", closure_id, node_id)
        if row["node_type"] == "WorkItem" and not row["logical_work_item_id"].strip():
            error("missing_logical_work_item_id", "WorkItem requires a stable logical_work_item_id", closure_id, node_id)
        if row["node_type"] != "WorkItem" and row["logical_work_item_id"].strip():
            error("spurious_logical_work_item_id", "logical_work_item_id is permitted only for WorkItem nodes", closure_id, node_id)
        row["_time"] = time_value(row["event_time_utc"], closure_id, node_id, "node event_time_utc")
        row["_created"] = time_value(row["created_at_utc"], closure_id, node_id, "Requirement created_at_utc", required=False)
        row["_accepted"] = time_value(row["accepted_at_utc"], closure_id, node_id, "Requirement accepted_at_utc", required=False)
        if row["node_type"] == "WorkItem" and row["work_item_kind"] == "Requirement":
            if not row["_created"] or not row["_accepted"]:
                error("missing_requirement_lifecycle_time", "Requirement requires created_at_utc and accepted_at_utc", closure_id, node_id)
            elif row["_accepted"] < row["_created"]:
                error("requirement_acceptance_before_creation", "Requirement accepted_at_utc cannot precede created_at_utc", closure_id, node_id)
        elif row["created_at_utc"].strip() or row["accepted_at_utc"].strip():
            error("unexpected_requirement_lifecycle_time", "Requirement lifecycle times are reserved for Requirement WorkItems", closure_id, node_id)
        nodes[node_id] = row

    logical_versions = set()
    for row in nodes.values():
        if row["node_type"] != "WorkItem":
            continue
        key = (row["logical_work_item_id"].strip(), row["version"].strip())
        if key in logical_versions:
            error("duplicate_logical_work_item_version", "logical_work_item_id/version must identify at most one WorkItem record", row["closure_id"], row["node_id"])
        logical_versions.add(key)

    outgoing = defaultdict(list)
    incoming = defaultdict(list)
    edge_ids = set()
    for row in tables["edges.csv"]:
        closure_id, edge_id = row["closure_id"], row["edge_id"]
        if not edge_id or edge_id in edge_ids:
            error("duplicate_edge_id", "edge_id must be present and unique", closure_id, edge_id)
            continue
        edge_ids.add(edge_id)
        row["_time"] = time_value(row["event_time_utc"], closure_id, edge_id, "edge event_time_utc")
        source, target = nodes.get(row["source_node_id"]), nodes.get(row["target_node_id"])
        if not source or not target:
            error("unknown_edge_endpoint", "unknown edge endpoint", closure_id, edge_id)
            continue
        rule = EDGE_RULES.get(row["edge_type"])
        valid_domain = rule and source["node_type"] in rule[0] and target["node_type"] in rule[1]
        if row["edge_type"] == "creates_finding":
            valid_domain = valid_domain and target["work_item_kind"] == "Finding"
        if row["edge_type"] in {"derived_from", "violates_or_relates_to", "creates_requirement"}:
            valid_domain = valid_domain and source["work_item_kind"] == "Finding" and target["work_item_kind"] == "Requirement"
        if row["edge_type"] == "derived_from" and source["work_item_kind"] == "Finding" and target["work_item_kind"] == "Requirement":
            error("deprecated_finding_requirement_edge", "reference-profile v1.0 forbids derived_from for Finding-to-Requirement lineage; migrate to violates_or_relates_to", closure_id, edge_id)
        if row["edge_type"] == "implements":
            valid_domain = valid_domain and target["work_item_kind"] == "Requirement"
        if not valid_domain:
            error("domain_range_violation", "illegal edge domain/range or WorkItem kind", closure_id, edge_id)
        cross_release_requirement = row["edge_type"] == "creates_requirement" and source["closure_id"] == closure_id and source["closure_id"] != target["closure_id"]
        if (source["closure_id"] != target["closure_id"] or source["closure_id"] != closure_id) and not cross_release_requirement:
            error("cross_closure_edge", "edge crosses closure", closure_id, edge_id)
        if source["service_id"] != target["service_id"]:
            error("cross_service_contamination", "edge crosses service", closure_id, edge_id)
        if row["source_version"] != source["version"] or row["target_version"] != target["version"]:
            error("stale_version", "edge versions must match endpoints", closure_id, edge_id)
        outgoing[(row["source_node_id"], row["edge_type"])].append(row["target_node_id"])
        incoming[(row["target_node_id"], row["edge_type"])].append(row["source_node_id"])

    def require_single_edge(source_id, edge_type, target_id, code, closure_id):
        targets = outgoing.get((source_id, edge_type), [])
        if targets != [target_id]:
            error(code, f"{source_id} must have exactly one {edge_type} edge to {target_id}; found {targets}", closure_id, source_id)

    manifests_by_release = defaultdict(list)
    manifest_change_keys = set()
    for row in tables["release_manifest.csv"]:
        key = (row["release_decision_id"], row["change_id"])
        if key in manifest_change_keys:
            error("duplicate_manifest_change", "one manifest row permitted per release/change", row["closure_id"], row["change_id"])
        manifest_change_keys.add(key)
        manifests_by_release[row["release_decision_id"]].append(row)

    gates_by_closure = defaultdict(list)
    gate_by_id = {}
    attempt_keys = set()
    for row in tables["gate_evaluations.csv"]:
        closure_id, gate_id = row["closure_id"], row["gate_evaluation_id"]
        if gate_id in gate_by_id:
            error("duplicate_gate_evaluation_id", "duplicate gate evaluation", closure_id, gate_id)
            continue
        gate_by_id[gate_id] = row
        if gate_id not in nodes or nodes[gate_id]["node_type"] != "GateEvaluation":
            error("missing_gate_node", "gate row requires GateEvaluation node", closure_id, gate_id)
        require_single_edge(gate_id, "evaluates", row["target_node_id"], "gate_edge_mismatch", closure_id)
        if row["target_node_id"] not in nodes:
            error("unknown_gate_target", "unknown gate target", closure_id, gate_id)
        if row["decision"] not in DECISIONS or row["gate_mode"] not in GATE_MODES or row["phase"] not in PHASES:
            error("invalid_gate_record", "invalid decision, mode, or phase", closure_id, gate_id)
        attempt = int_value(row["attempt"], closure_id, gate_id, "gate attempt", minimum=1)
        evaluated = time_value(row["evaluated_at_utc"], closure_id, gate_id, "gate evaluated_at_utc")
        row.update(_attempt=attempt, _evaluated=evaluated)
        attempt_key = (closure_id, row["gate_id"], row["attempt"])
        if attempt_key in attempt_keys:
            error("duplicate_gate_attempt", "duplicate gate attempt", closure_id, gate_id)
        attempt_keys.add(attempt_key)
        policy = policies.get((row["policy_version"], row["gate_id"]))
        if not policy:
            error("unknown_policy_gate", "gate absent from policy registry", closure_id, gate_id)
        elif row["gate_mode"] != policy["gate_mode"] or row["phase"] != policy["phase"]:
            error("posthoc_gate_reclassification", "gate mode/phase differs from predeclared policy", closure_id, gate_id)
        if policy:
            evidence_pass, evidence_error = evaluate_gate_evidence(row, policy)
            row.update(_evidence_pass=evidence_pass, _evidence_error=evidence_error)
            if evidence_error:
                error(evidence_error, "gate threshold/operator/observation evidence is not computable under the effective policy", closure_id, gate_id)
            target = nodes.get(row["target_node_id"])
            row["_owner_authorized"] = gate_owner_authorized(row, policy, target)
        else:
            row.update(_evidence_pass=None, _evidence_error="unknown_policy_gate", _owner_authorized=False)
        gates_by_closure[closure_id].append(row)

    for closure_id, rows in gates_by_closure.items():
        groups = defaultdict(list)
        for row in rows:
            groups[row["gate_id"]].append(row)
        for gate_name, group in groups.items():
            if any(row["_attempt"] is None or row["_evaluated"] is None for row in group):
                continue
            ordered = sorted(group, key=lambda row: row["_attempt"])
            if [row["_attempt"] for row in ordered] != list(range(1, len(ordered) + 1)):
                error("nonconsecutive_gate_attempt", "attempts must be consecutive from 1", closure_id, gate_name)
            stable = {(row["target_node_id"], row["policy_version"], row["gate_mode"], row["phase"], row["gate_owner"]) for row in ordered}
            if len(stable) != 1:
                error("unauthorized_gate_retry_change", "retry cannot change target, policy, mode, phase, or owner", closure_id, gate_name)
            for index, row in enumerate(ordered):
                expected = "" if index == 0 else ordered[index - 1]["gate_evaluation_id"]
                if row["supersedes_gate_evaluation_id"] != expected:
                    error("invalid_gate_supersession", "retry must supersede immediately prior attempt", closure_id, row["gate_evaluation_id"])
                if index and row["_evaluated"] <= ordered[index - 1]["_evaluated"]:
                    error("nonmonotonic_gate_retry_time", "retry evaluated_at must strictly increase", closure_id, row["gate_evaluation_id"])

    exceptions = {}
    exception_gate_counts = Counter()
    for row in tables["exceptions.csv"]:
        closure_id, exception_id = row["closure_id"], row["exception_id"]
        if exception_id in exceptions:
            error("duplicate_exception_id", "exception_id must be unique", closure_id, exception_id)
            continue
        exceptions[exception_id] = row
        exception_gate_counts[row["gate_evaluation_id"]] += 1
        if exception_id not in nodes or nodes[exception_id]["node_type"] != "Exception":
            error("missing_exception_node", "exception row requires Exception node", closure_id, exception_id)
        require_single_edge(exception_id, "authorizes", row["gate_evaluation_id"], "exception_edge_mismatch", closure_id)
        for field in ("issue_time_utc", "expiry_time_utc"):
            time_value(row[field], closure_id, exception_id, f"exception {field}")
        time_value(row["revoked_at_utc"], closure_id, exception_id, "exception revoked_at_utc", required=False)
    for gate_id, count in exception_gate_counts.items():
        if count > 1:
            closure_id = gate_by_id.get(gate_id, {}).get("closure_id", "")
            error("duplicate_exception_for_gate", "at most one Exception row may authorize a GateEvaluation", closure_id, gate_id)

    incidents = []
    incident_ids = set()
    for row in tables["incidents.csv"]:
        closure_id, incident_id = row["closure_id"], row["incident_id"]
        if incident_id in incident_ids:
            error("duplicate_incident_id", "incident_id must be unique", closure_id, incident_id)
            continue
        incident_ids.add(incident_id)
        if incident_id not in nodes or nodes[incident_id]["node_type"] != "Incident":
            error("missing_incident_node", "incident row requires Incident node", closure_id, incident_id)
        require_single_edge(incident_id, "attributed_to", row["deployment_id"], "incident_edge_mismatch", closure_id)
        require_single_edge(incident_id, "creates_finding", row["finding_id"], "finding_edge_mismatch", closure_id)
        row["_opened"] = time_value(row["opened_at_utc"], closure_id, incident_id, "incident opened_at_utc")
        row["_reported"] = time_value(row["reported_at_utc"], closure_id, incident_id, "incident reported_at_utc")
        row["_attributed"] = time_value(row["attribution_time_utc"], closure_id, incident_id, "incident attribution_time_utc")
        row["_feedback"] = time_value(row["feedback_link_time_utc"], closure_id, incident_id, "incident feedback_link_time_utc", required=False)
        row["_resolved"] = time_value(row["resolved_at_utc"], closure_id, incident_id, "incident resolved_at_utc", required=False)
        float_value(row["feedback_ttl_hours"], closure_id, incident_id, "feedback_ttl_hours", minimum=0.000001)
        incidents.append(row)

    raw_signal_rows = []
    raw_signal_ids = set()
    for row in tables["raw_signal_inventory.csv"]:
        closure_id, raw_signal_id = row["closure_id"], row["raw_signal_id"]
        if not raw_signal_id or raw_signal_id in raw_signal_ids:
            error("duplicate_raw_signal_id", "raw_signal_id must be nonempty and globally unique", closure_id, raw_signal_id)
            continue
        raw_signal_ids.add(raw_signal_id)
        row["_observed"] = time_value(row["observed_at_utc"], closure_id, raw_signal_id, "raw signal observed_at_utc")
        row["_disposition_decided"] = time_value(
            row["disposition_decided_at_utc"], closure_id, raw_signal_id,
            "raw signal disposition_decided_at_utc",
        )
        if row["disposition"] not in RAW_SIGNAL_DISPOSITIONS:
            error("invalid_raw_signal_disposition", "raw signal disposition is outside the controlled vocabulary", closure_id, raw_signal_id)
        if row["disposition_reason_code"] not in RAW_SIGNAL_REASON_CODES:
            error("invalid_raw_signal_reason", "raw signal disposition requires a controlled reason code", closure_id, raw_signal_id)
        if not row["disposition_rationale"].strip() or not row["disposition_decided_by"].strip():
            error("incomplete_raw_signal_decision", "raw signal disposition requires rationale and decision actor", closure_id, raw_signal_id)
        if row["_observed"] and row["_disposition_decided"] and row["_disposition_decided"] < row["_observed"]:
            error("raw_signal_decision_before_observation", "raw signal disposition cannot precede observation", closure_id, raw_signal_id)
        if not SHA256_PATTERN.fullmatch(row["signal_digest_sha256"]):
            error("invalid_raw_signal_digest", "raw signal digest must use sha256:<64 lowercase hex>", closure_id, raw_signal_id)
        if row["disposition"] == "imported_candidate":
            if not row["candidate_id"].strip() or row["disposition_reason_code"] != "admitted_to_candidate_registry":
                error("invalid_imported_raw_signal", "imported raw signals require candidate_id and the admission reason code", closure_id, raw_signal_id)
        elif row["candidate_id"].strip():
            error("spurious_raw_signal_candidate", "noncandidate and rejected raw signals cannot name a candidate_id", closure_id, raw_signal_id)
        raw_signal_rows.append(row)

    candidate_coverages = []
    coverage_ids = set()
    coverage_version_keys = set()
    for row in tables["candidate_coverage.csv"]:
        closure_id, coverage_id = row["closure_id"], row["coverage_id"]
        if not coverage_id or coverage_id in coverage_ids:
            error("duplicate_candidate_coverage_id", "coverage_id must be nonempty and globally unique", closure_id, coverage_id)
            continue
        coverage_ids.add(coverage_id)
        row["_coverage_version"] = int_value(row["coverage_version"], closure_id, coverage_id, "coverage_version", minimum=1)
        version_key = (closure_id, row["deployment_id"], row["_coverage_version"])
        if version_key in coverage_version_keys:
            error("duplicate_candidate_coverage_version", "coverage_version must be unique per closure and Deployment", closure_id, coverage_id)
        coverage_version_keys.add(version_key)
        row["_window_start"] = time_value(row["window_start_utc"], closure_id, coverage_id, "coverage window_start_utc")
        row["_window_end"] = time_value(row["window_end_utc"], closure_id, coverage_id, "coverage window_end_utc")
        row["_attested"] = time_value(row["attested_at_utc"], closure_id, coverage_id, "coverage attested_at_utc")
        row["_raw_count"] = int_value(row["raw_signal_count"], closure_id, coverage_id, "raw_signal_count", minimum=0)
        row["_imported_count"] = int_value(row["imported_candidate_count"], closure_id, coverage_id, "imported_candidate_count", minimum=0)
        row["_noncandidate_count"] = int_value(row["noncandidate_count"], closure_id, coverage_id, "noncandidate_count", minimum=0)
        row["_rejected_count"] = int_value(row["rejected_count"], closure_id, coverage_id, "rejected_count", minimum=0)
        if row["collection_status"] not in COLLECTION_STATUSES:
            error("invalid_collection_status", "collection_status must be complete, failed, or partial", closure_id, coverage_id)
        if row["_window_start"] and row["_window_end"] and row["_window_end"] <= row["_window_start"]:
            error("invalid_candidate_coverage_window", "coverage window_end_utc must follow window_start_utc", closure_id, coverage_id)
        if row["_window_end"] and row["_attested"] and row["_attested"] < row["_window_end"]:
            error("coverage_attested_before_window_end", "complete coverage cannot be attested before its observation window ends", closure_id, coverage_id)
        try:
            sources = json.loads(row["monitor_sources_json"])
            if not isinstance(sources, list) or not sources or not all(isinstance(item, str) and item.strip() for item in sources):
                raise ValueError
        except (ValueError, TypeError, json.JSONDecodeError):
            error("invalid_monitor_sources", "monitor_sources_json must be a nonempty JSON string array", closure_id, coverage_id)
        try:
            reason_summary = json.loads(row["filter_reason_summary_json"])
            if not isinstance(reason_summary, dict):
                raise ValueError
            if (
                (row["_noncandidate_count"] or row["_rejected_count"])
                and not any(str(key).strip() and int(value) >= 0 for key, value in reason_summary.items())
            ):
                raise ValueError
        except (ValueError, TypeError, OverflowError, json.JSONDecodeError):
            error("invalid_filter_reason_summary", "filter_reason_summary_json must be a JSON object and explain any non-imported signals", closure_id, coverage_id)
        if (
            row["_raw_count"] is not None
            and row["_imported_count"] is not None
            and row["_noncandidate_count"] is not None
            and row["_rejected_count"] is not None
            and row["_raw_count"] != row["_imported_count"] + row["_noncandidate_count"] + row["_rejected_count"]
        ):
            error("candidate_signal_reconciliation_mismatch", "raw signals must equal imported candidates plus noncandidates plus rejected signals", closure_id, coverage_id)
        if not all(
            SHA256_PATTERN.fullmatch(row[field])
            for field in ("query_rule_hash", "candidate_digest_sha256", "raw_inventory_digest_sha256", "reconciliation_digest_sha256")
        ):
            error("invalid_candidate_coverage_digest", "coverage digests must use sha256:<64 lowercase hex>", closure_id, coverage_id)
        elif row["reconciliation_digest_sha256"] != "sha256:" + reconciliation_digest(row):
            error("candidate_reconciliation_digest_mismatch", "coverage reconciliation digest does not match the signed counts and reason summary", closure_id, coverage_id)
        candidate_coverages.append(row)

    coverage_groups = defaultdict(list)
    for row in candidate_coverages:
        coverage_groups[(row["closure_id"], row["deployment_id"])].append(row)
    for (_closure_id, _deployment_id), group in coverage_groups.items():
        if any(row["_coverage_version"] is None for row in group):
            continue
        ordered = sorted(group, key=lambda row: row["_coverage_version"])
        if ordered[0]["_coverage_version"] != 1 or ordered[0]["supersedes_coverage_id"]:
            error("invalid_candidate_coverage_chain", "coverage chain must start at version 1 with no predecessor", ordered[0]["closure_id"], ordered[0]["coverage_id"])
        for previous, current in zip(ordered, ordered[1:]):
            if current["_coverage_version"] != previous["_coverage_version"] + 1 or current["supersedes_coverage_id"] != previous["coverage_id"]:
                error("invalid_candidate_coverage_chain", "coverage versions must be consecutive and supersede the immediate predecessor", current["closure_id"], current["coverage_id"])
            if current["_attested"] and previous["_attested"] and current["_attested"] <= previous["_attested"]:
                error("nonmonotonic_candidate_coverage_time", "successor coverage must be issued after its predecessor", current["closure_id"], current["coverage_id"])

    incident_candidates = []
    candidate_ids = set()
    for row in tables["incident_candidates.csv"]:
        closure_id, candidate_id = row["closure_id"], row["candidate_id"]
        if not candidate_id or candidate_id in candidate_ids:
            error("duplicate_incident_candidate_id", "candidate_id must be nonempty and globally unique", closure_id, candidate_id)
            continue
        candidate_ids.add(candidate_id)
        if row["status"] not in CANDIDATE_STATUSES:
            error("invalid_incident_candidate_status", "candidate status must be attributed, excluded, or unresolved", closure_id, candidate_id)
        row["_observed"] = time_value(row["observed_at_utc"], closure_id, candidate_id, "candidate observed_at_utc")
        row["_admitted"] = time_value(row["admitted_at_utc"], closure_id, candidate_id, "candidate admitted_at_utc")
        row["_decided"] = time_value(row["decided_at_utc"], closure_id, candidate_id, "candidate decided_at_utc", required=False)
        row["_reviewed"] = time_value(row["reviewed_at_utc"], closure_id, candidate_id, "candidate reviewed_at_utc", required=False)
        if row["_observed"] and row["_admitted"] and row["_admitted"] < row["_observed"]:
            error("candidate_admission_before_observation", "admitted_at_utc cannot precede observed_at_utc", closure_id, candidate_id)
        if not SHA256_PATTERN.fullmatch(row["signal_digest_sha256"]):
            error("invalid_candidate_signal_digest", "signal_digest_sha256 must use sha256:<64 lowercase hex>", closure_id, candidate_id)
        if row["status"] in {"attributed", "excluded"}:
            if row["decision_role"] not in CANDIDATE_DECISION_ROLES or not row["decided_by"].strip() or not row["_decided"]:
                error("invalid_candidate_decision_authority", "decided candidates require a controlled role, actor, and time", closure_id, candidate_id)
            elif not candidate_actor_authorized(row["decided_by"], row["decision_role"], row["service_id"], row["_decided"]):
                error("unauthorized_candidate_decider", "candidate decider lacks an effective service-scoped authorization", closure_id, candidate_id)
            if row["_admitted"] and row["_decided"] and row["_decided"] < row["_admitted"]:
                error("candidate_decision_before_admission", "candidate decision cannot precede admission", closure_id, candidate_id)
        if row["status"] == "attributed" and not row["incident_id"].strip():
            error("missing_candidate_incident", "attributed candidate requires incident_id", closure_id, candidate_id)
        if row["status"] == "excluded":
            if row["exclusion_reason_code"] not in EXCLUSION_REASON_CODES:
                error("invalid_candidate_exclusion_reason", "excluded candidate requires a controlled exclusion_reason_code", closure_id, candidate_id)
            if not row["exclusion_rationale"].strip():
                error("missing_candidate_exclusion_rationale", "excluded candidate requires rationale", closure_id, candidate_id)
            if not row["reviewed_by"].strip() or not row["_reviewed"] or (row["_decided"] and row["_reviewed"] < row["_decided"]):
                error("missing_candidate_exclusion_review", "excluded candidate requires a later independent review record", closure_id, candidate_id)
            elif canonical_principal(row["reviewed_by"], row["_reviewed"], object_id=candidate_id) == canonical_principal(row["decided_by"], row["_decided"], object_id=candidate_id):
                error("candidate_review_separation_failure", "excluded candidate decision and independent review require different actors", closure_id, candidate_id)
            elif not candidate_actor_authorized(row["reviewed_by"], "governance_reviewer", row["service_id"], row["_reviewed"]):
                error("unauthorized_candidate_reviewer", "candidate reviewer lacks effective governance-review authority", closure_id, candidate_id)
            if row["_admitted"] and row["_reviewed"] and row["_reviewed"] < row["_admitted"]:
                error("candidate_review_before_admission", "candidate review cannot precede admission", closure_id, candidate_id)
        elif any(row[field].strip() for field in ("exclusion_reason_code", "exclusion_rationale", "reviewed_by", "reviewed_at_utc")):
            error("spurious_candidate_exclusion_fields", "exclusion fields are permitted only for excluded candidates", closure_id, candidate_id)
        incident_candidates.append(row)

    coverage_by_id = {row["coverage_id"]: row for row in candidate_coverages}
    candidate_by_id = {row["candidate_id"]: row for row in incident_candidates}
    raw_by_coverage = defaultdict(list)
    for row in raw_signal_rows:
        closure_id, raw_signal_id = row["closure_id"], row["raw_signal_id"]
        coverage = coverage_by_id.get(row["coverage_id"])
        if not coverage or coverage["closure_id"] != closure_id or coverage["source_batch_id"] != row["source_batch_id"]:
            error("raw_signal_coverage_mismatch", "raw signal must reference a same-closure coverage and source batch", closure_id, raw_signal_id)
            continue
        raw_by_coverage[coverage["coverage_id"]].append(row)
        if (
            row["_observed"] and coverage["_window_start"] and coverage["_window_end"]
            and not (coverage["_window_start"] <= row["_observed"] <= coverage["_window_end"])
        ):
            error("raw_signal_outside_coverage_window", "raw signal observation must fall within the inclusive coverage window", closure_id, raw_signal_id)
        if row["_disposition_decided"] and coverage["_attested"] and row["_disposition_decided"] > coverage["_attested"]:
            error("raw_signal_decision_after_attestation", "raw signal disposition must precede or equal coverage attestation", closure_id, raw_signal_id)
        if row["disposition_decided_by"].strip() != coverage["responsible_actor"].strip():
            error("raw_signal_actor_mismatch", "raw signal disposition actor must equal the coverage responsible actor", closure_id, raw_signal_id)
        if row["disposition"] == "imported_candidate":
            candidate = candidate_by_id.get(row["candidate_id"])
            if (
                not candidate
                or candidate["closure_id"] != closure_id
                or candidate["source_batch_id"] != row["source_batch_id"]
                or candidate["signal_digest_sha256"] != row["signal_digest_sha256"]
            ):
                error("raw_signal_candidate_mismatch", "imported raw signal must bind one same-batch candidate with the same digest", closure_id, raw_signal_id)

    for coverage in candidate_coverages:
        inventory = raw_by_coverage.get(coverage["coverage_id"], [])
        disposition_counts = Counter(row["disposition"] for row in inventory)
        expected_counts = {
            "imported_candidate": coverage["_imported_count"],
            "noncandidate": coverage["_noncandidate_count"],
            "rejected": coverage["_rejected_count"],
        }
        if coverage["_raw_count"] is not None and coverage["_raw_count"] != len(inventory):
            error("raw_signal_inventory_count_mismatch", "raw signal count must equal the number of inventory rows", coverage["closure_id"], coverage["coverage_id"])
        if any(expected is not None and disposition_counts[name] != expected for name, expected in expected_counts.items()):
            error("raw_signal_disposition_count_mismatch", "inventory disposition counts must equal the coverage reconciliation counts", coverage["closure_id"], coverage["coverage_id"])
        expected_inventory_digest = "sha256:" + raw_inventory_digest(inventory)
        if coverage["raw_inventory_digest_sha256"] != expected_inventory_digest:
            error("raw_inventory_digest_mismatch", "coverage raw inventory digest does not match the immutable inventory", coverage["closure_id"], coverage["coverage_id"])
        try:
            declared_summary = json.loads(coverage["filter_reason_summary_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            declared_summary = {}
        observed_summary = Counter(
            row["disposition_reason_code"] for row in inventory
            if row["disposition"] in {"noncandidate", "rejected"}
        )
        if declared_summary != dict(sorted(observed_summary.items())):
            error("raw_signal_filter_summary_mismatch", "filter reason summary must exactly reconcile noncandidate and rejected inventory rows", coverage["closure_id"], coverage["coverage_id"])
        batch_candidate_ids = {
            row["candidate_id"] for row in incident_candidates
            if row["closure_id"] == coverage["closure_id"]
            and row["deployment_id"] == coverage["deployment_id"]
            and row["source_batch_id"] == coverage["source_batch_id"]
        }
        imported_candidate_ids = {
            row["candidate_id"] for row in inventory if row["disposition"] == "imported_candidate"
        }
        if batch_candidate_ids != imported_candidate_ids:
            error("candidate_raw_signal_bijection_mismatch", "candidate batch and imported raw-signal inventory must be a bijection", coverage["closure_id"], coverage["coverage_id"])

    snapshot_ids = set()
    snapshots_by_release = defaultdict(list)
    for row in tables["snapshots.csv"]:
        closure_id, snapshot_id = row["closure_id"], row["snapshot_id"]
        if snapshot_id in snapshot_ids:
            error("duplicate_snapshot_id", "snapshot_id must be globally unique", closure_id, snapshot_id)
            continue
        snapshot_ids.add(snapshot_id)
        row["_evaluated"] = time_value(row["evaluated_at_utc"], closure_id, snapshot_id, "snapshot evaluated_at_utc")
        if row["declared_status"] not in {"open", "closed_as_of"}:
            error("invalid_snapshot_status", "declared_status must be open or closed_as_of", closure_id, snapshot_id)
        if not SHA256_PATTERN.fullmatch(row["input_manifest_digest"]):
            error("invalid_snapshot_input_manifest_digest", "snapshot input_manifest_digest must use sha256:<64 lowercase hex>", closure_id, snapshot_id)
        release = nodes.get(row["release_decision_id"])
        if not release or release["node_type"] != "ReleaseDecision" or release["closure_id"] != closure_id:
            error("snapshot_release_mismatch", "snapshot must reference its same-closure ReleaseDecision", closure_id, snapshot_id)
        snapshots_by_release[row["release_decision_id"]].append(row)
    for release_id, group in snapshots_by_release.items():
        if any(row["_evaluated"] is None for row in group):
            continue
        ordered = sorted(group, key=lambda row: row["_evaluated"])
        if ordered[0]["supersedes_snapshot_id"]:
            error("snapshot_chain_missing_root", "first snapshot must be a root", ordered[0]["closure_id"], ordered[0]["snapshot_id"])
        for index, row in enumerate(ordered[1:], 1):
            if row["_evaluated"] <= ordered[index - 1]["_evaluated"]:
                error("nonmonotonic_snapshot_time", "snapshot times must strictly increase", row["closure_id"], row["snapshot_id"])
            if row["supersedes_snapshot_id"] != ordered[index - 1]["snapshot_id"]:
                error("invalid_snapshot_supersession", "snapshot chain must be linear and supersede the immediate predecessor", row["closure_id"], row["snapshot_id"])

    snapshot_by_id = {
        row["snapshot_id"]: row
        for group in snapshots_by_release.values()
        for row in group
    }
    for coverage in candidate_coverages:
        snapshot = snapshot_by_id.get(coverage["effective_from_snapshot_id"])
        if not snapshot or snapshot["closure_id"] != coverage["closure_id"]:
            error("candidate_coverage_snapshot_mismatch", "coverage must name a same-closure effective snapshot", coverage["closure_id"], coverage["coverage_id"])
        elif coverage["_attested"] and snapshot["_evaluated"] and coverage["_attested"] > snapshot["_evaluated"]:
            error("candidate_coverage_after_snapshot", "coverage must be attested no later than its effective snapshot", coverage["closure_id"], coverage["coverage_id"])

    release_nodes = [row for row in nodes.values() if row["node_type"] == "ReleaseDecision" and as_bool(row["release_approved"])]
    boundary_counts = Counter((row["closure_id"], row["service_id"]) for row in release_nodes)
    for (closure_id, _service), count in boundary_counts.items():
        if count != 1:
            error("nonunique_release_boundary", "one approved release required per closure/service", closure_id)

    closure_results, closure_failures, incident_temporal_classification = [], [], []
    effective_gates = []
    orphan_count = exception_total = exception_invalid = feedback_total = feedback_success = feedback_censored = 0
    coverage_required_total = coverage_complete_total = 0
    latencies = {"gate_resolution": [], "incident_attribution": [], "incident_feedback_link": [], "incident_resolution": [], "release_snapshot": []}
    censored = {key: 0 for key in latencies}

    for release in sorted(release_nodes, key=lambda row: row["closure_id"]):
        closure_id, release_id = release["closure_id"], release["node_id"]
        failures = []
        manifest_rows = manifests_by_release.get(release_id, [])
        if not manifest_rows:
            failures.append("missing_release_manifest")
            closure_results.append({"closure_id": closure_id, "service_id": release["service_id"], "release_decision_id": release_id, "snapshot_id": None, "evaluated_at_utc": None, "closed_as_of": False, "failure_codes": failures})
            continue
        invariant = {(row["approved_at_utc"], row["policy_version"], row["evaluation_time_utc"], row["observation_window_hours"], row["mandatory_gate_ids"]) for row in manifest_rows}
        if len(invariant) != 1:
            failures.append("inconsistent_manifest_context")
        context = manifest_rows[0]
        approved = time_value(context["approved_at_utc"], closure_id, release_id, "manifest approved_at_utc")
        t_eval = time_value(context["evaluation_time_utc"], closure_id, release_id, "manifest evaluation_time_utc")
        policy_version = context["policy_version"]
        observation_hours = float_value(context["observation_window_hours"], closure_id, release_id, "observation_window_hours", minimum=0.000001)
        if not approved or not t_eval or t_eval < approved:
            failures.append("invalid_evaluation_cutoff")
        if release["policy_version"] != policy_version:
            failures.append("release_policy_mismatch")
        version_policies = policy_versions.get(policy_version, [])
        if not version_policies:
            failures.append("unknown_release_policy")
        elif approved:
            for policy in version_policies:
                if not policy["_effective"] or policy["_effective"] > approved or (policy["_retired"] and approved >= policy["_retired"]):
                    failures.append("policy_not_effective_at_approval"); break
            ranges = {(p["_min_window"], p["_max_window"]) for p in version_policies}
            if len(ranges) != 1 or observation_hours is None:
                failures.append("invalid_observation_window")
            else:
                minimum, maximum = next(iter(ranges))
                if minimum is None or maximum is None or not minimum <= observation_hours <= maximum:
                    failures.append("observation_window_outside_policy")

        snapshots = sorted(snapshots_by_release.get(release_id, []), key=lambda row: row["_evaluated"] or datetime.max.replace(tzinfo=timezone.utc))
        if not snapshots or not t_eval or snapshots[-1]["_evaluated"] != t_eval:
            failures.append("missing_evaluation_snapshot")

        included = set(outgoing.get((release_id, "includes_change"), []))
        manifest_changes = {row["change_id"] for row in manifest_rows}
        if included != manifest_changes:
            failures.append("manifest_change_set_mismatch")
        selected_builds = [row["selected_build_id"] for row in manifest_rows]
        selected_artifacts = [row["selected_artifact_id"] for row in manifest_rows]
        selected_tests = [test for row in manifest_rows for test in split_ids(row["selected_test_run_ids"])]
        if len(selected_builds) != len(set(selected_builds)): failures.append("duplicate_selected_build")
        if len(selected_artifacts) != len(set(selected_artifacts)): failures.append("duplicate_selected_artifact")
        if len(selected_tests) != len(set(selected_tests)): failures.append("duplicate_selected_test")
        accepted_requirement_ids = set()
        orphan = False
        for row in manifest_rows:
            change, build, artifact = nodes.get(row["change_id"]), nodes.get(row["selected_build_id"]), nodes.get(row["selected_artifact_id"])
            test_ids = split_ids(row["selected_test_run_ids"])
            tests = [nodes.get(test_id) for test_id in test_ids]
            if len(test_ids) != len(set(test_ids)):
                failures.append("duplicate_selected_test")
            if not change or change["node_type"] != "Change":
                failures.append("unknown_manifest_change"); continue
            requirements = [nodes.get(node_id) for node_id in outgoing.get((change["node_id"], "implements"), [])]
            accepted = [item for item in requirements if item and item["work_item_kind"] == "Requirement" and item["status"] == "accepted"]
            accepted_requirement_ids.update(item["node_id"] for item in accepted)
            if not accepted:
                failures.append("orphan_release"); orphan = True
            if not as_bool(change["reviewed"]): failures.append("unreviewed_change")
            if not build or build["node_type"] != "Build" or build["node_id"] not in outgoing.get((change["node_id"], "triggers"), []):
                failures.append("selected_build_not_linked")
            elif build["status"] != "success": failures.append("selected_build_not_successful")
            if not tests: failures.append("missing_selected_test")
            for test in tests:
                if not test or test["node_type"] != "TestRun" or not build or test["node_id"] not in outgoing.get((build["node_id"], "evaluated_by"), []):
                    failures.append("selected_test_not_linked")
                elif test["status"] != "pass" or not as_bool(test["mandatory"]): failures.append("selected_test_not_passing")
            if not artifact or artifact["node_type"] != "Artifact" or not build or artifact["node_id"] not in outgoing.get((build["node_id"], "produces"), []):
                failures.append("selected_artifact_not_linked")
            elif not as_bool(artifact["immutable"]): failures.append("selected_artifact_not_immutable")
            elif artifact["node_id"] not in outgoing.get((release_id, "approves"), []): failures.append("selected_artifact_not_approved")
            elif artifact["artifact_digest"] != row["artifact_digest"]: failures.append("artifact_digest_mismatch")
            # Validate only the type-level partial order.  Sibling Requirements
            # and TestRuns are unordered, so CSV/edge row order cannot affect the
            # result.
            ordered_pairs = []
            ordered_pairs.extend((item, change) for item in accepted)
            ordered_pairs.append((change, build))
            ordered_pairs.extend((build, item) for item in tests)
            ordered_pairs.extend((item, artifact) for item in tests)
            if any(
                left and right and left.get("_time") and right.get("_time")
                and left["_time"] > right["_time"]
                for left, right in ordered_pairs
            ) or (approved and any(
                item and item.get("_time") and item["_time"] > approved
                for item in accepted + [change, build] + tests + [artifact]
            )):
                failures.append("release_path_time_inversion")
        orphan_count += int(orphan)

        required_ids = set(split_ids(context["mandatory_gate_ids"]))
        declared_required = {row["gate_id"] for row in version_policies if row["gate_mode"] == "required"}
        if required_ids != declared_required:
            failures.append("required_gate_policy_mismatch")
        latest = {}
        if t_eval:
            for gate in gates_by_closure.get(closure_id, []):
                if gate["_attempt"] is None or gate["_evaluated"] is None or gate["_evaluated"] > t_eval:
                    continue
                rank = (gate["_attempt"], gate["_evaluated"], gate["gate_evaluation_id"])
                if gate["gate_id"] not in latest or rank > latest[gate["gate_id"]][0]: latest[gate["gate_id"]] = (rank, gate)
        latest = {name: pair[1] for name, pair in latest.items()}
        effective_gates.extend(latest.values())
        if required_ids - set(latest): failures.append("missing_required_gate")
        for gate in latest.values():
            target = nodes.get(gate["target_node_id"]); evaluated = gate["_evaluated"]; target_time = target.get("_time") if target else None
            if gate["policy_version"] != policy_version: failures.append("gate_policy_mismatch")
            if not gate.get("_owner_authorized"):
                failures.extend(["gate_owner_policy_mismatch", "unauthorized_gate_owner"])
            evidence_pass = gate.get("_evidence_pass")
            decision_matches = (
                (gate["decision"] == "pass" and evidence_pass is True)
                or (gate["decision"] in {"fail", "exception"} and evidence_pass is False)
            )
            if evidence_pass is not None and not decision_matches:
                failures.append("gate_decision_evidence_mismatch")
            if target_time and evaluated and evaluated < target_time: failures.append("gate_before_target")
            if approved and evaluated and gate["phase"] == "pre_approval" and evaluated > approved: failures.append("preapproval_gate_after_approval")
            if t_eval and evaluated and gate["phase"] == "post_deployment" and evaluated > t_eval: failures.append("postdeployment_gate_after_cutoff")
            if gate["gate_mode"] != "informational" and gate["decision"] == "fail": failures.append("failed_decision_gate")
            if gate["decision"] == "fail":
                resolved = time_value(gate["resolution_time_utc"], closure_id, gate["gate_evaluation_id"], "gate resolution_time_utc", required=False)
                if resolved and evaluated and resolved < evaluated:
                    failures.append("gate_resolution_time_inversion")
                elif resolved and evaluated and t_eval and resolved <= t_eval:
                    latencies["gate_resolution"].append((resolved - evaluated).total_seconds() / 3600)
                else:
                    # Missing or post-cutoff resolution is unobserved at this
                    # snapshot and is therefore right-censored.
                    censored["gate_resolution"] += 1
            if gate["decision"] == "exception":
                gate_policy = policies.get((policy_version, gate["gate_id"]))
                if gate_policy and not as_bool(gate_policy["waiver_allowed"]):
                    failures.append("nonwaivable_gate_exception")
                exception_total += 1; exception = exceptions.get(gate["exception_id"]); decision_time = approved if gate["phase"] == "pre_approval" else evaluated; valid = False
                if exception and approved and evaluated and decision_time:
                    issued = time_value(exception["issue_time_utc"], closure_id, exception["exception_id"], "exception issue_time_utc")
                    expiry = time_value(exception["expiry_time_utc"], closure_id, exception["exception_id"], "exception expiry_time_utc")
                    revoked = time_value(exception["revoked_at_utc"], closure_id, exception["exception_id"], "exception revoked_at_utc", required=False)
                    scope_matches = (
                        exception["scope_gate_id"].strip() == gate["gate_id"].strip()
                        and target
                        and exception["scope_service_id"].strip() == target["service_id"].strip()
                    )
                    record_complete = all(exception[field].strip() for field in ("exception_id", "policy_version", "approver", "scope_gate_id", "scope_service_id", "risk_class", "rationale"))
                    authority_valid = exception_approver_authorized(exception, gate, target, decision_time) if record_complete else False
                    valid = bool(exception["gate_evaluation_id"] == gate["gate_evaluation_id"] and exception["policy_version"] == policy_version and exception["status"] == "approved" and record_complete and scope_matches and authority_valid and issued and expiry and issued <= evaluated <= decision_time <= expiry and (not revoked or revoked > decision_time))
                    if record_complete and scope_matches and not authority_valid:
                        failures.append("unauthorized_exception_approver")
                if not valid: exception_invalid += 1; failures.append("invalid_exception_authorization")

        deployments = [node for node in nodes.values() if node["node_type"] == "Deployment" and release_id in outgoing.get((node["node_id"], "executes"), [])]
        if not deployments: failures.append("missing_deployment")
        deployment_ids = {node["node_id"] for node in deployments}; window_end = {}
        for deployment in deployments:
            deployed = deployment["_time"]
            if approved and deployed and deployed < approved: failures.append("deployment_before_approval")
            if deployed and observation_hours is not None:
                window_end[deployment["node_id"]] = deployed + timedelta(hours=observation_hours)
                if t_eval and t_eval < window_end[deployment["node_id"]]: failures.append("observation_window_open")
        if approved and t_eval: latencies["release_snapshot"].append((t_eval - approved).total_seconds() / 3600)

        closure_candidates = [row for row in incident_candidates if row["closure_id"] == closure_id]
        closure_coverages = [row for row in candidate_coverages if row["closure_id"] == closure_id]
        coverage_required_total += len(deployment_ids)
        coverage_by_deployment = defaultdict(list)
        coverage_by_batch = {}
        for coverage in closure_coverages:
            coverage_by_deployment[coverage["deployment_id"]].append(coverage)
            batch_key = (coverage["deployment_id"], coverage["source_batch_id"])
            if batch_key in coverage_by_batch:
                failures.append("duplicate_candidate_coverage_batch")
            coverage_by_batch[batch_key] = coverage
            batch_candidates = [
                row for row in closure_candidates
                if row["deployment_id"] == coverage["deployment_id"]
                and row["source_batch_id"] == coverage["source_batch_id"]
            ]
            if coverage["_imported_count"] != len(batch_candidates):
                failures.append("candidate_coverage_count_mismatch")
            if coverage["candidate_digest_sha256"] != "sha256:" + candidate_digest(batch_candidates):
                failures.append("candidate_coverage_digest_mismatch")
            deployment = nodes.get(coverage["deployment_id"])
            expected_end = window_end.get(coverage["deployment_id"])
            scope_valid = bool(
                deployment
                and coverage["service_id"] == release["service_id"]
                and coverage["environment"] == deployment.get("environment")
                and coverage["window_start_utc"] == deployment.get("event_time_utc")
                and expected_end
                and coverage["_window_end"] == expected_end
                and coverage["deployment_id"] in deployment_ids
                and coverage["source_batch_id"].strip()
                and coverage["responsible_actor"].strip()
            )
            if not scope_valid:
                failures.append("candidate_coverage_scope_mismatch")
        for deployment in deployments:
            final_snapshot_id = snapshots[-1]["snapshot_id"] if snapshots else ""
            rows = [
                row for row in coverage_by_deployment.get(deployment["node_id"], [])
                if row["effective_from_snapshot_id"] == final_snapshot_id
            ]
            if len(rows) != 1:
                failures.append("missing_or_duplicate_candidate_coverage")
                continue
            coverage = rows[0]
            batch_candidates = [
                row for row in closure_candidates
                if row["deployment_id"] == deployment["node_id"]
                and row["source_batch_id"] == coverage["source_batch_id"]
            ]
            batch_raw_signals = raw_by_coverage.get(coverage["coverage_id"], [])
            scope_valid = (
                coverage["service_id"] == release["service_id"]
                and coverage["environment"] == deployment.get("environment")
                and coverage["_window_start"] == deployment.get("_time")
                and deployment["node_id"] in window_end
                and coverage["_window_end"] == window_end.get(deployment["node_id"])
            )
            count_valid = coverage["_imported_count"] == len(batch_candidates)
            digest_valid = coverage["candidate_digest_sha256"] == "sha256:" + candidate_digest(batch_candidates)
            complete = bool(
                coverage["collection_status"] == "complete"
                and scope_valid and count_valid and digest_valid
                and coverage["_attested"] and coverage["_window_end"]
                and coverage["_attested"] >= coverage["_window_end"]
                and coverage["_raw_count"] is not None
                and coverage["_imported_count"] is not None
                and coverage["_noncandidate_count"] is not None
                and coverage["_rejected_count"] is not None
                and coverage["_raw_count"] == coverage["_imported_count"] + coverage["_noncandidate_count"] + coverage["_rejected_count"]
                and coverage["_raw_count"] == len(batch_raw_signals)
                and coverage["raw_inventory_digest_sha256"] == "sha256:" + raw_inventory_digest(batch_raw_signals)
                and coverage["reconciliation_digest_sha256"] == "sha256:" + reconciliation_digest(coverage)
                and coverage["_attested"] and t_eval and coverage["_attested"] <= t_eval
            )
            if complete:
                coverage_complete_total += 1
            else:
                failures.append("invalid_candidate_collection_attestation")
        for candidate in closure_candidates:
            candidate_id = candidate["candidate_id"]
            deployment = nodes.get(candidate["deployment_id"])
            observed = candidate["_observed"]
            admitted = candidate["_admitted"]
            decided = candidate["_decided"]
            reviewed = candidate["_reviewed"]
            candidate_coverage = coverage_by_batch.get((candidate["deployment_id"], candidate["source_batch_id"]))
            if candidate_coverage is None:
                failures.append("candidate_without_collection_attestation")
            else:
                if (
                    observed and candidate_coverage["_window_start"] and candidate_coverage["_window_end"]
                    and not (candidate_coverage["_window_start"] <= observed <= candidate_coverage["_window_end"])
                ):
                    failures.append("candidate_observed_outside_coverage_window")
                if admitted and candidate_coverage["_attested"] and admitted > candidate_coverage["_attested"]:
                    failures.append("candidate_admitted_after_coverage_attestation")
            if not deployment or candidate["deployment_id"] not in deployment_ids or candidate["service_id"] != release["service_id"] or candidate["environment"] != deployment.get("environment"):
                failures.append("incident_candidate_scope_mismatch")
            if deployment and observed and deployment.get("_time") and observed < deployment["_time"]:
                failures.append("incident_candidate_before_deployment")
            if t_eval and ((observed and observed > t_eval) or (admitted and admitted > t_eval) or (decided and decided > t_eval) or (reviewed and reviewed > t_eval)):
                failures.append("incident_candidate_after_cutoff")
            prior_admission_snapshots = [
                snapshot for snapshot in snapshots
                if snapshot["_evaluated"] and admitted and snapshot["_evaluated"] < admitted
            ]
            if prior_admission_snapshots:
                prior_snapshot = prior_admission_snapshots[-1]
                successors = [s for s in snapshots if s["supersedes_snapshot_id"] == prior_snapshot["snapshot_id"]]
                prior_coverages = [
                    row for row in closure_coverages
                    if row["deployment_id"] == candidate["deployment_id"]
                    and row["effective_from_snapshot_id"] == prior_snapshot["snapshot_id"]
                ]
                coverage_reissued = bool(
                    candidate_coverage
                    and len(successors) == 1
                    and candidate_coverage["effective_from_snapshot_id"] == successors[0]["snapshot_id"]
                    and candidate_coverage["supersedes_coverage_id"] in {row["coverage_id"] for row in prior_coverages}
                    and candidate_coverage["_attested"]
                    and admitted
                    and admitted <= candidate_coverage["_attested"] <= successors[0]["_evaluated"]
                )
                if not (
                    prior_snapshot["declared_status"] == "closed_as_of"
                    and candidate["reopens_snapshot_id"] == prior_snapshot["snapshot_id"]
                    and len(successors) == 1
                    and successors[0]["_evaluated"]
                    and admitted <= successors[0]["_evaluated"]
                    and coverage_reissued
                ):
                    failures.append("late_candidate_admission_without_reopen")
            elif candidate["reopens_snapshot_id"]:
                failures.append("spurious_candidate_snapshot_reopen")
            if candidate["status"] == "unresolved":
                failures.append("unresolved_incident_candidate")
            elif candidate["status"] == "attributed":
                matching = [row for row in incidents if row["incident_id"] == candidate["incident_id"] and row["deployment_id"] == candidate["deployment_id"]]
                if len(matching) != 1:
                    failures.append("incident_candidate_attribution_mismatch")

        for incident in [row for row in incidents if row["closure_id"] == closure_id and row["classification"] == "deployment_induced"]:
            feedback_total += 1; incident_id = incident["incident_id"]
            admitted_candidates = [
                row for row in closure_candidates
                if row["status"] == "attributed" and row["incident_id"] == incident_id
            ]
            if len(admitted_candidates) != 1:
                failures.append("incident_without_unique_attributed_candidate")
            opened = time_value(incident["opened_at_utc"], closure_id, incident_id, "incident opened_at_utc")
            reported = time_value(incident["reported_at_utc"], closure_id, incident_id, "incident reported_at_utc")
            attributed = time_value(incident["attribution_time_utc"], closure_id, incident_id, "incident attribution_time_utc")
            linked = time_value(incident["feedback_link_time_utc"], closure_id, incident_id, "incident feedback_link_time_utc", required=False)
            resolved = time_value(incident["resolved_at_utc"], closure_id, incident_id, "incident resolved_at_utc", required=False)
            deployment = nodes.get(incident["deployment_id"]); deployed = deployment.get("_time") if deployment else None
            if incident["deployment_id"] not in deployment_ids: failures.append("incident_wrong_deployment")
            if not deployed or not opened or not reported or not attributed or opened < deployed or reported < opened or attributed < opened or (t_eval and (reported > t_eval or attributed > t_eval)):
                failures.append("incident_time_inversion")
            if opened and attributed and attributed >= opened:
                if t_eval and attributed <= t_eval:
                    latencies["incident_attribution"].append((attributed - opened).total_seconds() / 3600)
                else:
                    censored["incident_attribution"] += 1
            late_opening = bool(opened and incident["deployment_id"] in window_end and opened > window_end[incident["deployment_id"]])
            prior = [s for s in snapshots if s["_evaluated"] and ((attributed and s["_evaluated"] < attributed) or (reported and s["_evaluated"] < reported))]
            late_attribution = bool(prior and attributed and prior[-1]["_evaluated"] < attributed)
            late_reporting = bool(prior and reported and prior[-1]["_evaluated"] < reported)
            requires_reopen = late_attribution or late_reporting
            if requires_reopen:
                prior_snapshot = prior[-1]
                successors = [s for s in snapshots if s["supersedes_snapshot_id"] == prior_snapshot["snapshot_id"]]
                valid_reopen = incident["late_discovery_action"] == "reopen" and incident["reopens_snapshot_id"] == prior_snapshot["snapshot_id"] and prior_snapshot["declared_status"] == "closed_as_of" and len(successors) == 1 and successors[0]["_evaluated"] and attributed and reported and max(attributed, reported) <= successors[0]["_evaluated"]
                if not valid_reopen: failures.append("late_attribution_without_reopen_snapshot")
            elif incident["reopens_snapshot_id"] or incident["late_discovery_action"]:
                failures.append("spurious_snapshot_reopen")
            finding = nodes.get(incident["finding_id"])
            existing_targets = outgoing.get((incident["finding_id"], "violates_or_relates_to"), [])
            created_targets = outgoing.get((incident["finding_id"], "creates_requirement"), [])
            if not finding or finding["work_item_kind"] != "Finding":
                failures.append("invalid_incident_finding")
            if not existing_targets and not created_targets:
                failures.append("missing_finding_requirement_lineage")
            elif any(target_id not in accepted_requirement_ids for target_id in existing_targets):
                failures.append("finding_requirement_outside_release")
            for target_id in created_targets:
                target = nodes.get(target_id)
                target_releases = [
                    node for node in release_nodes
                    if node["closure_id"] == (target["closure_id"] if target else "")
                    and node["service_id"] == release["service_id"]
                ]
                target_release = target_releases[0] if len(target_releases) == 1 else None
                target_approved = target_release.get("_time") if target_release else None
                earlier_accepted_version = bool(target and any(
                    node["node_type"] == "WorkItem"
                    and node["work_item_kind"] == "Requirement"
                    and node["node_id"] != target["node_id"]
                    and node["logical_work_item_id"]
                    and node["logical_work_item_id"] == target["logical_work_item_id"]
                    and node["version"] != target["version"]
                    and node.get("_accepted")
                    and target.get("_accepted")
                    and finding
                    and finding.get("_time")
                    and node["_accepted"] <= finding["_time"]
                    for node in nodes.values()
                ))
                if (
                    not target or target["closure_id"] == closure_id or not target.get("accepted_revision")
                    or not finding or not finding.get("_time") or not target.get("_created") or not target.get("_accepted")
                    or not target_approved
                    or not (finding["_time"] < target["_created"] <= target["_accepted"] <= target_approved)
                    or earlier_accepted_version
                ):
                    failures.append("retrospective_requirement_backfill")
            ttl = float_value(incident["feedback_ttl_hours"], closure_id, incident_id, "feedback_ttl_hours", minimum=0.000001)
            feedback_order_valid = bool(
                linked and reported and attributed
                and linked >= max(reported, attributed)
            )
            feedback_within_cutoff = bool(linked and t_eval and linked <= t_eval)
            if linked and reported and linked < reported:
                failures.append("feedback_before_report")
            feedback_unobserved = not linked or bool(linked and t_eval and linked > t_eval)
            if linked and t_eval and linked > t_eval:
                failures.append("feedback_after_cutoff")
            if feedback_unobserved:
                feedback_censored += 1
                censored["incident_feedback_link"] += 1
            valid_link = bool(
                finding and feedback_order_valid and feedback_within_cutoff
                and ttl is not None
                and 0 <= (linked - attributed).total_seconds() <= ttl * 3600
            )
            if valid_link:
                feedback_success += 1; latencies["incident_feedback_link"].append((linked - attributed).total_seconds() / 3600)
            else: failures.append("missing_or_late_feedback_link")
            if resolved and linked and resolved < linked:
                failures.append("resolution_before_feedback")
            if resolved and t_eval and resolved > t_eval:
                failures.append("resolution_after_cutoff")
            valid_resolution = bool(
                resolved and linked and reported and attributed
                and resolved >= linked >= max(reported, attributed)
                and t_eval and resolved <= t_eval
                and finding and finding["status"] == "closed"
                and incident["resolution_validator"] and incident["resolution_evidence"]
            )
            if valid_resolution: latencies["incident_resolution"].append((resolved - attributed).total_seconds() / 3600)
            else:
                failures.append("unresolved_deployment_incident")
                if not resolved or (t_eval and resolved > t_eval):
                    censored["incident_resolution"] += 1
            incident_temporal_classification.append({"closure_id": closure_id, "incident_id": incident_id, "late_opening": late_opening, "late_reporting": late_reporting, "late_attribution": late_attribution, "reopen_required": requires_reopen})

        # Validate every immutable snapshot against its own cutoff and its own
        # versioned input view.  A linear chain cannot legitimize an invalid
        # historical closed state.
        closure_node_rows = [row for row in nodes.values() if row["closure_id"] == closure_id]
        closure_edge_rows = [row for row in tables["edges.csv"] if row["closure_id"] == closure_id]
        # A creates_requirement edge is the one permitted cross-closure
        # lineage path.  Include only its external Requirement targets in the
        # cutoff view; unrelated closure records must remain invisible.
        external_requirement_ids = {
            edge["target_node_id"] for edge in closure_edge_rows
            if edge["edge_type"] == "creates_requirement"
            and edge["target_node_id"] in nodes
            and nodes[edge["target_node_id"]]["closure_id"] != closure_id
        }
        closure_node_rows.extend(nodes[node_id] for node_id in sorted(external_requirement_ids))
        closure_incidents = [row for row in incidents if row["closure_id"] == closure_id]
        policy_owner_rows = [
            row for row in owner_authorization_rows
            if row["policy_version"] == policy_version
        ]
        policy_exception_rows = [
            row for row in exception_authority_rows
            if row["policy_version"] == policy_version
        ]
        snapshot_results = []
        for snapshot in snapshots:
            snapshot_failures = []
            snapshot_cutoff = snapshot["_evaluated"]
            expected_digest = "sha256:" + snapshot_input_digest(
                snapshot,
                manifest_rows,
                version_policies,
                policy_owner_rows,
                policy_exception_rows,
                candidate_review_authority_rows,
                gates_by_closure.get(closure_id, []),
                closure_coverages,
                [row for row in raw_signal_rows if row["closure_id"] == closure_id],
                closure_candidates,
                closure_incidents,
                closure_node_rows,
                closure_edge_rows,
                principal_rows,
            )
            if snapshot["input_manifest_digest"] != expected_digest:
                snapshot_failures.append("snapshot_input_manifest_digest_mismatch")
            if True:
                if not snapshot_cutoff or any(
                    end and snapshot_cutoff < end for end in window_end.values()
                ):
                    snapshot_failures.append("historical_snapshot_observation_window_open")

                visible_nodes = {
                    row["node_id"]: row for row in closure_node_rows
                    if snapshot_cutoff and all(
                        not row.get(key) or row[key] <= snapshot_cutoff
                        for key in ("_time", "_created", "_accepted")
                    )
                }
                visible_edges = [
                    row for row in closure_edge_rows
                    if snapshot_cutoff and row.get("_time") and row["_time"] <= snapshot_cutoff
                    and row["source_node_id"] in visible_nodes
                    and row["target_node_id"] in visible_nodes
                ]
                visible_edge_keys = {
                    (row["source_node_id"], row["edge_type"], row["target_node_id"])
                    for row in visible_edges
                }
                release_path_valid = bool(approved and snapshot_cutoff and approved <= snapshot_cutoff)
                for manifest_row in manifest_rows:
                    change_id = manifest_row["change_id"]
                    build_id = manifest_row["selected_build_id"]
                    artifact_id = manifest_row["selected_artifact_id"]
                    test_ids = split_ids(manifest_row["selected_test_run_ids"])
                    selected_ids = {release_id, change_id, build_id, artifact_id, *test_ids}
                    release_path_valid = release_path_valid and selected_ids <= set(visible_nodes)
                    release_path_valid = release_path_valid and (
                        (release_id, "includes_change", change_id) in visible_edge_keys
                        and (change_id, "triggers", build_id) in visible_edge_keys
                        and (build_id, "produces", artifact_id) in visible_edge_keys
                        and (release_id, "approves", artifact_id) in visible_edge_keys
                        and all((build_id, "evaluated_by", test_id) in visible_edge_keys for test_id in test_ids)
                        and any(
                            source_id == change_id and edge_type == "implements"
                            and visible_nodes.get(target_id, {}).get("work_item_kind") == "Requirement"
                            and visible_nodes[target_id].get("status") == "accepted"
                            for source_id, edge_type, target_id in visible_edge_keys
                        )
                    )
                release_path_valid = release_path_valid and all(
                    (deployment["node_id"], "executes", release_id) in visible_edge_keys
                    for deployment in deployments
                    if deployment["node_id"] in visible_nodes
                )
                if not release_path_valid:
                    snapshot_failures.append("historical_snapshot_missing_release_path")

                for finding in (
                    row for row in visible_nodes.values()
                    if row.get("node_type") == "WorkItem" and row.get("work_item_kind") == "Finding"
                ):
                    has_visible_requirement = any(
                        source_id == finding["node_id"]
                        and edge_type in {"violates_or_relates_to", "creates_requirement"}
                        and visible_nodes.get(target_id, {}).get("work_item_kind") == "Requirement"
                        and visible_nodes[target_id].get("status") == "accepted"
                        for source_id, edge_type, target_id in visible_edge_keys
                    )
                    if not has_visible_requirement:
                        snapshot_failures.append("historical_snapshot_missing_finding_lineage")

                snapshot_coverages = [
                    row for row in closure_coverages
                    if row["effective_from_snapshot_id"] == snapshot["snapshot_id"]
                ]
                for deployment in deployments:
                    matching_coverage = [
                        row for row in snapshot_coverages
                        if row["deployment_id"] == deployment["node_id"]
                    ]
                    if len(matching_coverage) != 1:
                        snapshot_failures.append("historical_snapshot_missing_coverage")
                        continue
                    coverage = matching_coverage[0]
                    visible_batch = [
                        row for row in closure_candidates
                        if row["deployment_id"] == deployment["node_id"]
                        and row["source_batch_id"] == coverage["source_batch_id"]
                        and row["_admitted"] and snapshot_cutoff
                        and row["_admitted"] <= snapshot_cutoff
                    ]
                    visible_raw_signals = [
                        row for row in raw_by_coverage.get(coverage["coverage_id"], [])
                        if row["_disposition_decided"] and snapshot_cutoff
                        and row["_disposition_decided"] <= snapshot_cutoff
                    ]
                    coverage_valid = bool(
                        coverage["collection_status"] == "complete"
                        and coverage["_window_end"]
                        and coverage["_attested"]
                        and snapshot_cutoff
                        and coverage["_window_end"] <= coverage["_attested"] <= snapshot_cutoff
                        and coverage["_imported_count"] == len(visible_batch)
                        and coverage["candidate_digest_sha256"] == "sha256:" + candidate_digest(visible_batch)
                        and coverage["_raw_count"] == coverage["_imported_count"] + coverage["_noncandidate_count"] + coverage["_rejected_count"]
                        and coverage["_raw_count"] == len(visible_raw_signals)
                        and coverage["raw_inventory_digest_sha256"] == "sha256:" + raw_inventory_digest(visible_raw_signals)
                        and coverage["reconciliation_digest_sha256"] == "sha256:" + reconciliation_digest(coverage)
                    )
                    if not coverage_valid:
                        snapshot_failures.append("historical_snapshot_invalid_coverage")

                visible_candidates = [
                    row for row in closure_candidates
                    if row["_admitted"] and snapshot_cutoff and row["_admitted"] <= snapshot_cutoff
                ]
                if any(row["status"] == "unresolved" for row in visible_candidates):
                    snapshot_failures.append("historical_snapshot_unresolved_candidate")
                if any(
                    (row["_decided"] and row["_decided"] > snapshot_cutoff)
                    or (row["_reviewed"] and row["_reviewed"] > snapshot_cutoff)
                    for row in visible_candidates
                ):
                    snapshot_failures.append("historical_snapshot_future_candidate_decision")

                snapshot_latest_gates = {}
                for gate in gates_by_closure.get(closure_id, []):
                    if gate["_evaluated"] and snapshot_cutoff and gate["_evaluated"] <= snapshot_cutoff:
                        rank = (gate["_attempt"], gate["_evaluated"], gate["gate_evaluation_id"])
                        if gate["gate_id"] not in snapshot_latest_gates or rank > snapshot_latest_gates[gate["gate_id"]][0]:
                            snapshot_latest_gates[gate["gate_id"]] = (rank, gate)
                snapshot_latest_gates = {key: value[1] for key, value in snapshot_latest_gates.items()}
                if required_ids - set(snapshot_latest_gates):
                    snapshot_failures.append("historical_snapshot_missing_required_gate")
                if any(
                    gate["gate_mode"] != "informational"
                    and (
                        gate["decision"] == "fail"
                        or (
                            gate["decision"] == "pass"
                            and gate.get("_evidence_pass") is not True
                        )
                        or (
                            gate["decision"] == "exception"
                            and gate.get("_evidence_pass") is not False
                        )
                        or not gate.get("_owner_authorized")
                    )
                    for gate in snapshot_latest_gates.values()
                ):
                    snapshot_failures.append("historical_snapshot_invalid_gate")

                for incident in closure_incidents:
                    if incident["classification"] != "deployment_induced":
                        continue
                    if incident["_reported"] and snapshot_cutoff and incident["_reported"] <= snapshot_cutoff:
                        if (
                            not incident["_feedback"]
                            or not incident["_resolved"]
                            or incident["_feedback"] > snapshot_cutoff
                            or incident["_resolved"] > snapshot_cutoff
                        ):
                            snapshot_failures.append("historical_snapshot_unresolved_incident")

            recomputed_status = "closed_as_of" if not snapshot_failures else "open"
            status_match = snapshot["declared_status"] == recomputed_status
            if not status_match:
                snapshot_failures.append("historical_snapshot_status_mismatch")
                # Retain the public V20 closure code while exposing the
                # per-snapshot stable code retained from the inherited profile.
                snapshot_failures.append("snapshot_status_mismatch")
            snapshot_results.append({
                "snapshot_id": snapshot["snapshot_id"],
                "evaluated_at_utc": snapshot["evaluated_at_utc"],
                "declared_status": snapshot["declared_status"],
                "recomputed_status": recomputed_status,
                "status_match": status_match,
                "failure_codes": sorted(set(snapshot_failures)),
            })
            # Conservative-open semantics: an explicitly open snapshot may
            # legitimately recompute open because evidence is incomplete at
            # its cutoff. Integrity/digest failures still fail the closure;
            # a declared closed snapshot propagates every recomputation
            # failure, and any status mismatch is always stable evidence.
            integrity_failures = [code for code in snapshot_failures if code.endswith("digest_mismatch") or code in {"historical_snapshot_status_mismatch", "snapshot_status_mismatch"}]
            if snapshot["declared_status"] == "closed_as_of" and snapshot_failures:
                failures.extend(snapshot_failures)
                failures.append("historical_snapshot_invalid")
            elif snapshot["declared_status"] == "open" and integrity_failures:
                failures.extend(integrity_failures)

        if any(item["closure_id"] in {"", closure_id} for item in errors):
            failures.append("schema_validation_error")
        preliminary = sorted(set(failures))
        expected_status = "closed_as_of" if not preliminary else "open"
        if snapshots and snapshots[-1]["declared_status"] != expected_status:
            failures.append("snapshot_status_mismatch")
        unique = sorted(set(failures))
        for code in unique: closure_failures.append({"closure_id": closure_id, "release_decision_id": release_id, "code": code})
        closure_results.append({"closure_id": closure_id, "service_id": release["service_id"], "release_decision_id": release_id, "snapshot_id": snapshots[-1]["snapshot_id"] if snapshots else None, "evaluated_at_utc": context["evaluation_time_utc"], "closed_as_of": not unique, "failure_codes": unique, "snapshot_results": snapshot_results})

    # A later-Requirement source closure is not complete until the target
    # release episode itself is complete.  Reconcile this after all release
    # episodes have been independently evaluated so a source cannot close
    # merely because a target ReleaseDecision node was appended.
    closure_by_id = {row["closure_id"]: row for row in closure_results}
    # Index the exact Requirement implemented by each selected Change.  A
    # sibling Requirement in the same target release is never an acceptable
    # substitute for the node named by creates_requirement.
    target_requirement_implementations = {}
    for target_release in release_nodes:
        target_closure = target_release["closure_id"]
        target_release_id = target_release["node_id"]
        for manifest in manifests_by_release.get(target_release_id, []):
            change_id = manifest["change_id"]
            for edge in tables["edges.csv"]:
                if edge["closure_id"] != target_closure or edge["edge_type"] != "implements" or edge["source_node_id"] != change_id:
                    continue
                requirement = nodes.get(edge["target_node_id"])
                if requirement and requirement["node_type"] == "WorkItem" and requirement["work_item_kind"] == "Requirement":
                    target_requirement_implementations.setdefault(target_closure, set()).add(requirement["node_id"])
    for source in closure_results:
        source_id = source["closure_id"]
        source_findings = {row["finding_id"] for row in incidents if row["closure_id"] == source_id and row["classification"] == "deployment_induced"}
        target_edges = [
            edge for edge in tables["edges.csv"]
            if edge["closure_id"] == source_id and edge["edge_type"] == "creates_requirement"
            and edge["source_node_id"] in source_findings
            and edge["target_node_id"] in nodes
            and nodes[edge["target_node_id"]]["closure_id"] != source_id
        ]
        source_cutoff = parse_time(source.get("evaluated_at_utc", ""))
        for edge in target_edges:
            target_id = edge["target_node_id"]
            target_node = nodes[target_id]
            target_closure = target_node["closure_id"]
            target_result = closure_by_id.get(target_closure)
            target_manifest = manifests_by_release.get(
                next((r["node_id"] for r in release_nodes if r["closure_id"] == target_closure), ""), []
            )
            target_eval = parse_time(target_result.get("evaluated_at_utc", "")) if target_result else None
            exact_impl = target_id in target_requirement_implementations.get(target_closure, set())
            target_visible = bool(
                target_node.get("_created") and target_node.get("_accepted") and target_node.get("accepted_revision")
                and target_node.get("status") == "accepted"
                and target_eval and target_node["_created"] <= target_node["_accepted"] <= target_eval
                and source_cutoff and target_node["_accepted"] <= source_cutoff
                and edge.get("_time") and edge["_time"] <= source_cutoff
            )
            target_path_complete = bool(target_manifest and target_result and target_result["closed_as_of"] and exact_impl and target_visible)
            if not target_path_complete:
                source["failure_codes"] = sorted(set(source["failure_codes"] + ["later_requirement_target_requirement_not_implemented"]))
                source["failure_codes"] = sorted(set(source["failure_codes"] + ["later_requirement_target_episode_incomplete"]))
                source["closed_as_of"] = False
                closure_failures.append({"closure_id": source_id, "release_decision_id": source["release_decision_id"], "code": "later_requirement_target_requirement_not_implemented"})
                closure_failures.append({"closure_id": source_id, "release_decision_id": source["release_decision_id"], "code": "later_requirement_target_episode_incomplete"})

    decision_gates = [row for row in effective_gates if row["gate_mode"] in {"required", "optional_decision"}]
    computed_metrics = {
        "trace_completeness": proportion(sum(row["closed_as_of"] for row in closure_results), len(closure_results)),
        "orphan_release_rate": proportion(orphan_count, len(closure_results)),
        "decision_gate_rejection_rate": proportion(sum(row["decision"] == "fail" for row in decision_gates), len(decision_gates)),
        "feedback_link_success": {**proportion(feedback_success, feedback_total), "right_censored": feedback_censored},
        "exception_invalidity_rate": proportion(exception_invalid, exception_total),
        "latency_families": {name: {**latency(values), "right_censored": censored[name]} for name, values in latencies.items()},
    }
    valid_input = not errors
    data_quality = {
        "status": "complete" if valid_input else "invalid_input_reported",
        "required_values": {
            **proportion(required_value_present, required_value_total),
            "required": required_value_total,
            "observed": required_value_present,
            "missing": max(required_value_total - required_value_present, 0),
        },
        "candidate_coverage": {
            **proportion(coverage_complete_total, coverage_required_total),
            "required": coverage_required_total,
            "complete": coverage_complete_total,
            "invalid_or_missing": max(coverage_required_total - coverage_complete_total, 0),
        },
        "validation_error_count": len(errors),
        "outcome_metrics_suppressed": not valid_input,
        "estimability_note": (
            "counts use parseable records; invalid input suppresses outcome metrics but not this data-quality report"
        ),
    }
    return {"schema_version": "1.0.0", "error_schema_version": "1.0.0", "unit_of_analysis": "one service-bounded ReleaseDecision audit snapshot at t_eval", "valid_input": valid_input, "schema_errors": errors, "closure_results": closure_results, "closure_failures": closure_failures, "incident_temporal_classification": incident_temporal_classification, "validation_audit": {"exception_decisions": exception_total, "invalid_exception_decisions": exception_invalid, "required_value_matrix_fields": len(dictionary), "required_value_total": required_value_total, "required_value_present": required_value_present, "candidate_coverage_required": coverage_required_total, "candidate_coverage_complete": coverage_complete_total}, "data_quality": data_quality, "metrics": computed_metrics if valid_input else None}


def main():
    parser = argparse.ArgumentParser(description="Validate release-evidence contract reference profile v1.0.")
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--policy-registry")
    parser.add_argument("--data-dictionary")
    parser.add_argument("--gate-owner-authorizations")
    parser.add_argument("--exception-authorities")
    parser.add_argument("--candidate-review-authorizations")
    parser.add_argument("--principal-registry")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = analyze(args.input_dir, args.policy_registry, args.data_dictionary, args.gate_owner_authorizations, args.exception_authorities, args.candidate_review_authorizations, args.principal_registry)
    except Exception as exc:  # stable JSON even for an unforeseen internal failure
        result = {"schema_version": "1.0.0", "error_schema_version": "1.0.0", "valid_input": False, "schema_errors": [{"code": "internal_validation_error", "closure_id": "", "object_id": "", "message": f"{type(exc).__name__}: {exc}"}], "closure_results": [], "closure_failures": [], "validation_audit": {}, "data_quality": {"status": "internal_validation_error", "outcome_metrics_suppressed": True}, "metrics": None}
    Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    raise SystemExit(2 if result["schema_errors"] else 0)


if __name__ == "__main__":
    main()



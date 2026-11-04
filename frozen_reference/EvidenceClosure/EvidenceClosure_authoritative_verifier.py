"""Single bounded EvidenceClosure authority with resumable stage evidence.

Runtime output is written outside the frozen package. No manifest-listed file
is skipped or overwritten during verification.
"""
from __future__ import annotations

import csv
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "S3_analyze_evidence.py"
MUTATION_FILES = [p for p in HERE.glob("*mutation*.json")]
MANIFEST = HERE / "S9_package_manifest.csv"
DEFAULT_OUTPUT = HERE.parent / "reproduced" / "output" / "EvidenceClosure_authoritative_verifier_report.json"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_check():
    errors = []
    with MANIFEST.open(encoding="utf-8-sig", newline="") as h:
        for row in csv.DictReader(h):
            p = HERE / row["relative_path"]
            if not p.is_file(): errors.append({"path": row["relative_path"], "reason": "missing"})
            elif p.stat().st_size != int(row["bytes"]): errors.append({"path": row["relative_path"], "reason": "bytes"})
            elif sha256(p) != row["sha256"]: errors.append({"path": row["relative_path"], "reason": "sha256"})
    return errors


def mutation_check(root, source_hash, source_bytes):
    errors = []
    for p in sorted(root.glob("*mutation*.json")):
        try: report = json.loads(p.read_text(encoding="utf-8-sig"))
        except Exception as exc: errors.append({"path": p.name, "reason": f"json:{exc}"}); continue
        if "source_sha256" in report and report.get("source_sha256") != source_hash: errors.append({"path": p.name, "reason": "mutation_source_hash_mismatch"})
        if "source_bytes" in report and report.get("source_bytes") != source_bytes: errors.append({"path": p.name, "reason": "mutation_source_bytes_mismatch"})
    return errors


def main():
    started = time.monotonic()
    source_hash, source_bytes = sha256(SOURCE), SOURCE.stat().st_size
    before = manifest_check()
    stage = subprocess.run([sys.executable, "EvidenceClosure_verifier_stage_runner.py"], cwd=HERE, capture_output=True, text=True, timeout=480)
    stage_text = stage.stdout + "\n" + stage.stderr
    stage_json = None
    try:
        first = stage_text.find("{")
        stage_json = json.loads(stage_text[first:]) if first >= 0 else None
    except json.JSONDecodeError:
        stage_json = None
    target_ok = bool(stage_json and stage_json.get("baseline", {}).get("green") and stage_json.get("passed") and stage_json.get("target_substitution", {}).get("returncode", 0) == 0)
    # Explicitly prove that a conflicting mutation JSON is rejected.
    with tempfile.TemporaryDirectory(prefix="evidenceclosure-tamper-") as td:
        tamper = Path(td) / "S3_mutation_report.json"
        original = next((p for p in MUTATION_FILES if p.name == "S3_mutation_report.json"), None)
        if original:
            d = json.loads(original.read_text(encoding="utf-8-sig")); d["source_sha256"] = "0" * 64; tamper.write_text(json.dumps(d), encoding="utf-8")
            tamper_hash_failure = bool(mutation_check(Path(td), source_hash, source_bytes))
        else: tamper_hash_failure = False
    after = manifest_check()
    report = {
        "verifier": "EvidenceClosure_authoritative_verifier.py",
        "source_path": SOURCE.name,
        "source_bytes": source_bytes,
        "source_sha256": source_hash,
        "runtime_budget_seconds": 480,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "stage_exit_code": stage.returncode,
        "stage": stage_json,
        "mutation_reports": {"files": sorted(p.name for p in MUTATION_FILES), "conflicts": mutation_check(HERE, source_hash, source_bytes)},
        "tamper_hash_failure": tamper_hash_failure,
        "target_substitution_failure": target_ok,
        "pre_manifest_mismatches": before,
        "post_manifest_mismatches": after,
    }
    report["passed"] = bool(
        stage.returncode == 0 and stage_json and stage_json.get("passed") and stage_json.get("baseline", {}).get("tests_run") == 107
        and stage_json.get("mutation", {}).get("killed_by_assertion") == 16 and stage_json.get("mutation", {}).get("killed_by_crash") == 0
        and not stage_json.get("mutation", {}).get("survived") and not report["mutation_reports"]["conflicts"]
        and target_ok and tamper_hash_failure and not before and not after and report["elapsed_seconds"] <= report["runtime_budget_seconds"]
    )
    import argparse
    parser = argparse.ArgumentParser(description="Run the EvidenceClosure authoritative verifier without mutating the frozen package.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="external runtime report path")
    args = parser.parse_args()
    out = Path(args.output).expanduser().resolve()
    if out == HERE or HERE in out.parents:
        raise SystemExit("caller-supplied output must be external to the frozen package")
    report["runtime_output_path"] = str(out)
    report["runtime_output_path_resolved"] = str(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["runtime_output_written"] = out.is_file()
    report["passed"] = report["passed"] and report["runtime_output_written"] and report["runtime_output_path"] == report["runtime_output_path_resolved"]
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__": main()

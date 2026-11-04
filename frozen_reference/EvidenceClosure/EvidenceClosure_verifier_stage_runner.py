"""Bounded, resumable EvidenceClosure verifier stages.

The mutation stage is parallelized only after one green 107-test baseline gate.
Each stage writes a JSON record with exit code, runtime, exact source bytes and
its output digest; the package itself is never modified during verification.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from S3_mutation_test import MUTANTS

HERE = Path(__file__).resolve().parent
TESTS = ["S3_test_analyze_evidence.py", "S3_adversarial_review_tests.py", "S3_v18_semantic_tests.py", "S3_terminal_review_counterexamples.py"]
SOURCE = HERE / "S3_analyze_evidence.py"
SOURCE_BYTES = SOURCE.read_bytes()
SOURCE_SHA256 = hashlib.sha256(SOURCE_BYTES).hexdigest()


def run_stage(name, command, *, timeout=120):
    started = time.monotonic()
    try:
        proc = subprocess.run(command, cwd=HERE, capture_output=True, text=True, timeout=timeout)
        timed_out = False
        output = proc.stdout + "\n" + proc.stderr
        code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        output = (exc.stdout or "") + "\n" + (exc.stderr or "")
        code = 124
    elapsed = round(time.monotonic() - started, 3)
    return {"name": name, "command": command, "returncode": code, "elapsed_seconds": elapsed, "timed_out": timed_out, "output_tail": "\n".join(output.splitlines()[-20:]), "output_sha256": hashlib.sha256(output.encode("utf-8", "replace")).hexdigest()}


def test_count(text):
    m = re.search(r"Ran (\d+) tests? in", text)
    return int(m.group(1)) if m else None


def mutation_one(mutant_id, out_dir):
    out = out_dir / f"{mutant_id}.json"
    stage = run_stage(mutant_id, [sys.executable, "S3_mutation_test.py", "--cluster-a", "--mutant", mutant_id, "--skip-baseline", "--output", str(out)], timeout=120)
    if out.exists():
        try:
            report = json.loads(out.read_text(encoding="utf-8"))
            stage["status"] = "passed" if report.get("killed_by_assertion") == 1 and report.get("survived") == [] else "failed"
            stage["mutation"] = {"source_sha256": report.get("source_sha256"), "source_bytes": report.get("source_bytes"), "generated": report.get("generated"), "killed_by_assertion": report.get("killed_by_assertion"), "killed_by_crash": report.get("killed_by_crash"), "survived": report.get("survived"), "results": report.get("results", [])}
        except json.JSONDecodeError:
            stage["status"] = "failed"
    else:
        stage["status"] = "failed"
    return stage


def main():
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="evidenceclosure-stage-") as temp:
        temp = Path(temp)
        baseline = run_stage("baseline", [sys.executable, "-m", "unittest", "-v", *TESTS], timeout=120)
        baseline["tests_run"] = test_count(baseline["output_tail"])
        baseline["green"] = baseline["returncode"] == 0 and baseline["tests_run"] == 107 and not baseline["timed_out"]
        if not baseline["green"]:
            report = {"version": "EvidenceClosure", "passed": False, "source_bytes": len(SOURCE_BYTES), "source_sha256": SOURCE_SHA256, "baseline": baseline, "mutation": {"status": "aborted_red_baseline"}, "elapsed_seconds": round(time.monotonic() - started, 3)}
            print(json.dumps(report, indent=2)); raise SystemExit(2)

        analyzer = run_stage("analyzer", [sys.executable, "S3_analyze_evidence.py", "--input-dir", "S6_synthetic", "--policy-registry", "S4_policy_registry.csv", "--data-dictionary", "S1_data_dictionary.csv", "--gate-owner-authorizations", "S4_gate_owner_authorizations.csv", "--exception-authorities", "S4_exception_authority_registry.csv", "--candidate-review-authorizations", "S4_candidate_review_authorizations.csv", "--principal-registry", "S4_principal_registry.csv", "--output", str(temp / "analyzer.json")], timeout=120)
        s20 = run_stage("s20", [sys.executable, "S20_check_consistency.py", "--output", str(temp / "s20.json")], timeout=120)
        target_substitution = run_stage("target_substitution", [sys.executable, "-m", "unittest", "-q", "S3_adversarial_review_tests.ReviewDerivedAdversarialTests.test_finding_may_create_only_a_later_requirement"], timeout=60)
        mutation_ids = [mid for mid in MUTANTS if 47 <= int(mid[1:3]) <= 62]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            mutation_stages = list(pool.map(lambda mid: mutation_one(mid, temp), mutation_ids))
        mutation_ok = all(row.get("status") == "passed" for row in mutation_stages)
        mutation = {"status": "passed" if mutation_ok else "failed", "source_bytes": len(SOURCE_BYTES), "source_sha256": SOURCE_SHA256, "generated": 16, "killed_by_assertion": sum(row.get("mutation", {}).get("killed_by_assertion", 0) for row in mutation_stages), "killed_by_crash": sum(row.get("mutation", {}).get("killed_by_crash", 0) for row in mutation_stages), "survived": [mid for mid, row in zip(mutation_ids, mutation_stages) if row.get("status") != "passed"], "stages": mutation_stages}
        report = {"version": "EvidenceClosure", "source_path": SOURCE.name, "source_bytes": len(SOURCE_BYTES), "source_sha256": SOURCE_SHA256, "baseline": baseline, "analyzer": analyzer, "s20": s20, "target_substitution": target_substitution, "mutation": mutation, "elapsed_seconds": round(time.monotonic() - started, 3), "runtime_budget_seconds": 420}
        report["passed"] = bool(analyzer["returncode"] == 0 and s20["returncode"] == 0 and target_substitution["returncode"] == 0 and mutation_ok and mutation["killed_by_assertion"] == 16 and mutation["killed_by_crash"] == 0 and not mutation["survived"] and report["elapsed_seconds"] <= report["runtime_budget_seconds"])
        print(json.dumps(report, indent=2))
        raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()

# EvidenceClosure reproduction entry point

This directory is the inherited/source-baseline executable location used for the EvidenceClosure package. The EvidenceClosure name is historical lineage only; the current manuscript is EvidenceClosure.docx and its hash is recorded in the root manifest.

Run from this directory and write all runtime reports outside the frozen package:

```text
python EvidenceClosure_authoritative_verifier.py --output <external-output>/EvidenceClosure_authoritative_verifier_report.json
python S20_check_consistency.py --output <external-output>/EvidenceClosure-S20-runtime.json
python -m unittest -v S3_test_analyze_evidence.py S3_adversarial_review_tests.py S3_v18_semantic_tests.py S3_terminal_review_counterexamples.py
```

The protocol records 107/107 green baseline tests, M47–M62 16/16 assertion-killed mutations, S20 21 automated + 2 manual controls, tamper/target probes, exit code, elapsed time, and exact source hashes. These are predicate-derived reproduction results and do not claim independent field validation.

These results are not independent field validation.
Historical/source-lineage labels (including S3_v18, V20, V21, V52, V53 and v13-python) are retained only as inherited test/file identifiers; they are not current package versions or authorities.

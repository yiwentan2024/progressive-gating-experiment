# EvidenceClosure supplementary reproduction guide

This package accompanies the frozen EvidenceClosure.docx. It contains the reference implementation lineage, formal schemas, synthetic fixtures, S1--S24 protocols/results, figure assets, and reproduction metadata cited by the paper.

The current executable entry point is reproduction/EvidenceClosure/EvidenceClosure_authoritative_verifier.py. The implementation was inherited from an earlier validated technical lineage; that lineage is source history only and is not a second manuscript version.

From a clean extraction, run from reproduction/EvidenceClosure/:

python EvidenceClosure_authoritative_verifier.py --output <external-output>/EvidenceClosure_authoritative_verifier_report.json
python S20_check_consistency.py --output <external-output>/EvidenceClosure-S20-runtime.json
python -m unittest -v S3_test_analyze_evidence.py S3_adversarial_review_tests.py S3_v18_semantic_tests.py S3_terminal_review_counterexamples.py

Runtime output must be outside this frozen package. The bounded reference run records 107/107 predicate-derived conformance tests, 16/16 targeted assertion mutations, S20's 21 automated and 2 manual controls, and tamper/target probes. These are implementation-level conformance results, not independent field validation or a claim of operational effectiveness.
Historical/source-lineage labels (including S3_v18, V20, V21, V52, V53 and v13-python) are retained only as inherited test/file identifiers; they are not current package versions or authorities.

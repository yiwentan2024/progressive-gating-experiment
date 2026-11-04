# Batch Protocol — Controlled Evaluation (frozen at repo creation)

This document freezes the protocol of the evaluation batch executed from this
repository. It is committed with the repository's initial commit, together with
the preregistered expected outcomes (`protocols/oracle_locked.csv`), before any
evaluation run is dispatched.

## Batch definition

- Scenarios: the 16 controlled cases in `scenarios/manifest.json`
  (the 3 real-data cases ZH-R2/R3/R4 remain blocked pending source records
  and are outside this batch).
- Variants: B0 (staged gates), B1 (+ artifact attestation), B2 (+ closure
  audit) — one pipeline, one added capability per variant, same commit.
- Replicates: 3 per (scenario, variant) — 16 × 3 × 3 = 144 evaluation runs,
  preceded by 7 calibration runs.
- Single commit: every run executes at the exact commit that carries this
  protocol and the oracle.

## Preregistered expectations

- `protocols/oracle_locked.csv` freezes the expected B2 machine decision and
  failure codes per scenario. It is never edited after runs begin.
- Baseline rule: every non-B01/B02 scenario passes B0/B1; B01 and B02 must
  fail (expected red) in all three variants — the baseline-integrity check.

## Verification (third parties)

1. Clone this repository and run locally:
   `python -m unittest discover -s tests` and
   `python -m unittest tests.test_a2_boundaries` (boundary suite, reported
   separately), then `python -m tools.e2_local_suite` for all 16 controlled
   cases.
2. Reproduce on GitHub: create a public repository, push this tree, dispatch
   `E2 19-Case Controlled Evaluation` with the same scenario / variant /
   replicate inputs; outcomes must match `oracle_locked.csv`.
3. The B2 auditor (`verifier/closure_audit.py`) computes every decision from
   the case facts (dispositions, digests, timings, findings); it performs no
   lookup against the oracle — inspectable in source.

## Reporting boundaries

Results are reported per variant against the preregistered expectations;
replicates must agree (any variance invalidates the cell and triggers
re-execution). The frozen 107/16 reference regression (`frozen_reference/`)
and the boundary suite are reported separately and never merged into these
statistics.

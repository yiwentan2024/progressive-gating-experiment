# CI/CD Experiment: Gates, Attestation, and Closure Auditing

A small CI/CD project used for a controlled experiment. One pipeline, three variants:

- **B0** — unit tests, deterministic build, one Docker image deployed to three isolated stages (dev / qa / staging) with HTTP health gates and digest pinning.
- **B1** — B0 plus GitHub Artifact Attestations (issue, verify; a tampered artifact must fail).
- **B2** — B1 plus a dual-timepoint closure checker (historical vs. audit time).

## Contents

- `app/`, `tests/`, `tools/`, `infra/` — small HTTP service, unit tests, build / stage-check / dispatch utilities, Dockerfile + compose
- `verifier/` — closure audit checker (dual-timepoint)
- `scenarios/` — machine-readable case definitions and the case builder
- `protocols/` — 144-run controlled plan (16 × 3 × 3) and the frozen expected-outcome list
- `frozen_reference/EvidenceClosure/` — original frozen verifier package (107 tests, 16 mutations), kept byte-identical and checked against its S9 manifest. Some frozen CSVs (e.g. S7, S21) are internally ragged as received; they are reproduced byte-identically by design and are never reformatted
- `.github/workflows/` — `E2 19-Case Controlled Evaluation` (experiment entry point) and `Original Frozen Reference Reproduction` (separate regression)

Fictional sample data only; no credentials.

## Verification

Independent verification uses this repository alone:

1. **Outcome claims** — compare any run's B2 decision against the preregistered
   expectations in `protocols/oracle_locked.csv` (frozen with the initial commit).
2. **Reproduction** — run locally (`Run locally` below) or push this tree to a new
   public GitHub repository and dispatch `E2 19-Case Controlled Evaluation` with
   the same scenario / variant / replicate inputs; outcomes are identical.
3. **No pre-stored answers** — `verifier/closure_audit.py` computes every decision
   from the case facts (dispositions, digests, timings, findings); it never reads
   the oracle. Inspect the source and the test suites (`tests/`).

The batch protocol is frozen in `protocols/batch_protocol.md`.

## Run locally (Python 3.12+)

```bash
python tools/check_frozen_manifest.py                       # frozen package integrity (S9)
python -m tools.run_frozen_regression --mode smoke --out runs/original_smoke
python -m unittest discover -s tests -v
python -m tools.e2_local_suite                              # all 16 controlled cases
python -m scenarios.build_case --scenario A202 --out runs/try_A202
python -m verifier.closure_audit --input runs/try_A202/case.json --output runs/try_A202/result.json --allow-open
python -m tools.e2_dispatch --scenario ALL --variant ALL    # dry-run
```

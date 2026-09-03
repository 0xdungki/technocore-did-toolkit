# Eval Criteria: validate private seed files
**Domain:** security hardening
**Date:** 2026-09-04

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [x] From a clean checkout, `.venv/bin/python -m pytest -q` exits 0.
   - [x] The focused seed-validation tests produce the same result on two runs.

2. **Demonstrability**
   - [x] A test proves `read_seed` refuses a symlink instead of following it.
   - [x] A test proves `read_seed` refuses a group/world-accessible private seed.
   - [x] Existing 0600 seed files still derive the expected deterministic DID.

3. **Negative test**
   - [x] With the production change reverted, the focused tests fail.
   - [x] With the production change restored, the focused tests pass.

4. **User-spec match**
   - [x] Change is substantive security hardening in standalone `0xdungki/technocore-did-toolkit`.
   - [x] One commit is pushed directly by authenticated GitHub identity `0xdungki`.
   - [x] GitHub reports remote `main` at the pushed commit.

## Fail criteria (ANY = no-go)

- Existing valid 0600 seed workflows regress.
- Seed material is printed in logs or CLI output.
- Tests mock filesystem permission or symlink behavior.
- Contribution touches another owner/repository or creates a cross-account PR.
- Negative test passes against unchanged production code.

## Output location

- `eval-results/validate-seed-file/run-1.json`: RED result.
- `eval-results/validate-seed-file/run-2.json`: reverted-production negative result.
- `eval-results/validate-seed-file/run-3.json`: restored final result.

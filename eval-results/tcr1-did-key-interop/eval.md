# Eval Criteria: TCR-1 DID-key detached-proof interoperability
**Domain:** build
**Date:** 2026-08-26

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [x] `python -m pytest -q` passes from this checkout with one command.
   - [x] The committed fixture deterministically reconstructs identical canonical UTF-8 signing bytes and SHA-256.

2. **Demonstrability**
   - [x] A committed JSON fixture contains a valid Ed25519 `did:key`, domain, payload, canonicalization label, signing-input SHA-256, and canonical unpadded base64url signature.
   - [x] A real verifier accepts the valid vector without a private key or network access.

3. **Mutation boundaries**
   - [x] Changing a signed payload field is rejected.
   - [x] Changing the domain is rejected.
   - [x] Non-canonical padded base64url and a mismatched signing-input hash are rejected.

4. **Negative test**
   - [x] Removing the critical Ed25519 verification call makes the focused eval fail.
   - [x] Restoring the implementation makes the focused eval and full suite pass.

5. **User-spec match**
   - [x] Artifact is in `0xdungki/technocore-did-toolkit` and complements room transport artifact export by testing TCR-1-style DID-key detached proof verification.
   - [x] No Technocore room write, fork, unrelated repository write, or secret key is required.

## Fail criteria (ANY = no-go)

- Critical Ed25519 verification is mocked or stubbed.
- Fixture includes a non-test private seed or depends on a network service.
- Verifier labels key control as authorship, contribution truth, acceptance, payment, or eligibility.
- Test output changes for identical input.

## Output location

- `eval-results/tcr1-did-key-interop/run-N.json`
- Each run includes exact command, exit code, stdout/stderr tail, criterion result, elapsed time, and artifact paths.

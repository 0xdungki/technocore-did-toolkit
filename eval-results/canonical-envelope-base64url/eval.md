# Eval Criteria: reject noncanonical envelope base64url
**Domain:** security hardening
**Date:** 2026-09-05

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [x] `python -m pytest -q` reruns from a clean checkout after dependency installation.
   - [x] The deterministic seed/room/nonce/text vector produces the same result.

2. **Demonstrability**
   - [x] A focused test proves valid generated unpadded base64url signatures still verify.
   - [x] A focused test proves an otherwise equivalent 86-character signature containing standard-base64 `+` or `/` is rejected with a canonical-base64url error.

3. **Negative test**
   - [x] Before the fix, the new substitution test fails because the verifier accepts the noncanonical encoding.
   - [x] After restoring the fix, the focused test and full suite pass.

4. **User-spec match**
   - [x] Change is substantive security/interoperability hardening in a standalone, non-fork repository owned by `0xdungki`.
   - [x] Exactly one contribution is pushed and verified from GitHub.

## Fail criteria (ANY = no-go)

- Existing valid signatures stop verifying.
- Critical verification behavior is mocked or network-dependent.
- Test passes on baseline.
- Full suite fails or emits warnings.
- Repository ownership/authentication constraint is violated.

## Output location

- `eval-results/canonical-envelope-base64url/run-N.json`
- Include exact command, stdout/stderr tail, exit code, pass/fail, duration, and artifact paths.

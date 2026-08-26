# Eval Criteria: strict TCR-1 proof JSON canonicalization
**Domain:** build
**Date:** 2026-08-26

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [ ] `python -m pytest -q` passes from a clean checkout.
   - [ ] Repeating the focused interoperability tests yields the same result.

2. **Demonstrability**
   - [ ] A real `verify-proof` CLI invocation accepts the committed TCR-1 DID-key fixture.
   - [ ] The CLI rejects duplicate object member names before signature verification.
   - [ ] The CLI rejects non-standard JSON numeric constants (`NaN`, `Infinity`, `-Infinity`) before canonicalization.

3. **Negative test**
   - [ ] With the strict JSON-loading implementation removed, the focused eval fails.
   - [ ] With the implementation restored, the focused eval passes.

4. **User-spec match**
   - [ ] Improvement is TCR-1/DID-key interoperability-specific and does not duplicate the existing detached-signature vector.
   - [ ] No network, private key, Technocore write, room chat, fork, or other identity repository is used.
   - [ ] Commit, push, PR, and CI are performed only as GitHub login `0xdungki` against `0xdungki/technocore-did-toolkit`.

## Fail criteria (ANY = no-go)

- Duplicate keys or non-finite constants reach canonicalization/signature verification.
- Existing valid proof fixture stops verifying.
- Critical behavior is mocked or depends on an external service.
- Test passes when strict JSON loading is reverted.
- Any repository is forked or any identity other than `0xdungki` is used.

## Output location

- `eval-results/strict-proof-json/run-N.json`
- Each run records command, exit code, stdout/stderr tail, elapsed time, pass/fail, and artifact paths.

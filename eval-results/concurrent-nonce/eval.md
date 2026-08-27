# Eval Criteria: concurrent nonce allocation
**Domain:** bug fix
**Date:** 2026-08-28 (WIB)

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [ ] `.venv/bin/python -m pytest -q` passes from the repository checkout.
   - [ ] The focused concurrent-allocation test passes on three consecutive runs.

2. **Demonstrability**
   - [ ] Eight independent processes allocating against one fresh state file return eight distinct, consecutive nonces.
   - [ ] The resulting state file remains valid JSON with mode `0600`.

3. **Negative test**
   - [ ] With the inter-process lock removed, the focused test fails.
   - [ ] With the fix restored, the same focused test passes.

4. **User-spec match**
   - [ ] Change is substantive DID/TCR-1 toolkit code plus tests, not cosmetic activity.
   - [ ] One GitHub contribution only is published and verified for the WIB day.

## Fail criteria (ANY = no-go)

- Critical concurrency behavior is mocked rather than exercised with processes.
- Existing test regression.
- Nonce state can be observed as malformed JSON.
- More than one GitHub/X contribution is published today.

## Output location

- `eval-results/concurrent-nonce/run-N.json`
- Include exact command, exit code, stdout tail, pass/fail, duration, and artifact paths.

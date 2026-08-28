# Eval Criteria: TCR-1 safe-integer canonicalization
**Domain:** bug fix / interoperability
**Date:** 2026-08-29 (WIB)

## Problem
Python preserves arbitrarily large JSON integers while common JavaScript verifiers round values beyond IEEE-754's exact integer range. The toolkit currently signs/verifies its Python serialization anyway, so two conforming consumers can reconstruct different bytes for the same parsed proof.

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [ ] `.venv/bin/python -m pytest -q` passes from this checkout.
   - [ ] Focused safe-integer test passes three consecutive runs.

2. **Demonstrability**
   - [ ] A proof containing integer `9007199254740992` is rejected with a bounded interoperability error before digest/signature verification.
   - [ ] The committed fixture containing integer `1` still verifies offline.

3. **Negative test**
   - [ ] On baseline code, the focused test fails because the unsafe integer is not rejected at the canonicalization boundary.
   - [ ] With the fix restored, the focused test passes.

4. **User-spec match**
   - [ ] Change adds concrete TCR-1 interoperability utility with test-first evidence.
   - [ ] Exactly one GitHub contribution and no X post is published for the WIB day.

## Fail criteria (ANY = no-go)

- Existing fixture no longer verifies.
- Critical behavior is mocked.
- Cosmetic-only or dependency-only change.
- More than one GitHub/X contribution is published today.

## Output location

- `eval-results/tcr1-safe-integers/run-N.json`
- Include command, exit code, stdout tail, pass/fail, duration, and artifact paths.

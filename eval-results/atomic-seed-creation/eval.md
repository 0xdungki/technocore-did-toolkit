# Eval Criteria: atomic seed creation
**Domain:** security hardening
**Date:** 2026-09-02

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [ ] `python -m pytest -q` passes from the repository environment.
   - [ ] The focused seed-creation tests pass on two unchanged runs.

2. **Demonstrability**
   - [ ] A test proves key generation refuses a dangling symlink and does not create or modify the symlink target.
   - [ ] Existing seed paths remain non-overwritable and newly created seed files remain mode `0600` with 32-byte hex seed material.

3. **Negative test**
   - [ ] With the production fix reverted and the tests retained, the dangling-symlink test fails for the expected reason.
   - [ ] With the fix restored, the same test passes.

4. **User-spec match**
   - [ ] Exactly one substantive security-hardening contribution is committed and pushed to standalone repository `0xdungki/technocore-did-toolkit`.
   - [ ] The pushed GitHub artifact is verified through the GitHub API under authenticated identity `0xdungki`.

## Fail criteria (ANY = no-go)

- The security behavior is only mocked rather than exercised against the real filesystem.
- A failed creation changes an existing file or follows a symlink.
- Full regression tests fail.
- The change is cosmetic, duplicated, or pushed outside a standalone `0xdungki` repository.

## Output location

- `eval-results/atomic-seed-creation/run-N.json`
- Each result includes command, exit code, stdout/stderr tail, elapsed time, criterion status, and artifact paths.

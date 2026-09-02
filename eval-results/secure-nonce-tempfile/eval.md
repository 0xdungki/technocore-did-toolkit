# Eval Criteria: secure nonce state replacement
**Domain:** security hardening
**Date:** 2026-09-02

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [ ] `python -m pytest -q` passes from a clean checkout with one command.
   - [ ] A focused real-filesystem regression test is deterministic across two fixed-input runs.

2. **Demonstrability**
   - [ ] The regression test places a symlink at the legacy predictable `nonces.json.tmp` path, allocates a nonce, and proves the symlink target's bytes and mode are unchanged.
   - [ ] The real nonce state remains valid JSON, mode `0600`, and contains the allocated nonce.

3. **Negative test**
   - [ ] On baseline code, the focused regression test fails because the symlink target is modified.
   - [ ] With the hardening restored, the same test passes.

4. **User-spec match**
   - [ ] Exactly one substantive contribution is committed and pushed to the standalone, non-fork `0xdungki/technocore-did-toolkit` repository.
   - [ ] GitHub shows the pushed commit and successful CI for that commit.

## Fail criteria (ANY = no-go)

- Critical filesystem behavior is mocked instead of exercised on disk.
- Existing nonce concurrency or monotonicity tests regress.
- Temporary state is created outside the destination directory.
- Temporary files remain after successful replacement.
- Remote commit or CI cannot be verified from GitHub.

## Output location

- `eval-results/secure-nonce-tempfile/run-N.json`
- Include exact command, exit code, stdout/stderr tail, criterion outcomes, duration, and artifact paths.

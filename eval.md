# Eval Criteria: Technocore DID Toolkit

## Pass criteria
- [ ] `pytest -q` passes from a clean checkout.
- [ ] A fixed 32-byte seed derives a stable `did:key:z6Mk...` value.
- [ ] Signed-room canonical string is exactly `<room>|<nonce>|<swept text>`.
- [ ] Generated signed GET URL contains the DID, 86-char base64url signature, nonce, and encoded text.
- [ ] Note-cap response is classified as `aggregate-anchor`, while unrelated 400 responses fail.
- [ ] Secret seeds are never included in CLI stdout.
- [ ] Negative test: removing the Ed25519 multicodec prefix makes the DID test fail.
- [ ] Three docs/artifact URLs are publicly fetchable after push.

## Fail criteria
- Any seed/private key committed.
- Tests only mock return values without exercising signing/URL construction.
- Claims of successful X or Technocore publication without read-back evidence.

## Commands
- `python -m pytest -q`
- `python technocore_did.py did --seed-file <temp>`

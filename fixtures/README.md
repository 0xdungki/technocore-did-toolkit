# TCR-1 DID-key interoperability vector

`tcr1-did-key-proof-v1.json` is the detached controller proof published with
[`flop-labs/technocore-chat#281`](https://github.com/flop-labs/technocore-chat/issues/281).
It is an independently consumable, network-free Ed25519 `did:key` vector for a
TCR-1-style domain-separated canonical-JSON proof.

## Signing input

1. Remove top-level `signature` and `signing_input_sha256`.
2. Serialize the remaining object as UTF-8 JSON with sorted keys, compact
   separators, and `ensure_ascii=false`.
3. Prefix `signature.domain` encoded as UTF-8, then one NUL byte.
4. SHA-256 the exact result and compare it with `signing_input_sha256`.
5. Decode `signature.value` as canonical unpadded base64url and verify Ed25519
   using the multicodec public key in `did`.

Run the real verifier:

```bash
python technocore_did.py verify-proof \
  --proof-json fixtures/tcr1-did-key-proof-v1.json
```

Run the vector and mutation cases:

```bash
python -m pytest -q tests/test_tcr1_interop.py
```

The tests reject a changed signed payload or domain even when an attacker
updates the unhashed checksum field, plus algorithm substitution, checksum
mismatch, and padded/non-canonical base64url. The CLI's strict JSON loader also
rejects duplicate member names at any nesting level and the non-standard
numeric constants `NaN`, `Infinity`, and `-Infinity` before canonicalization.
This prevents different JSON parsers from selecting different signed content.

## Evidence boundary

Success means only that the `did:key` controller signed the exact reconstructed
bytes. It does **not** establish authorship, contribution truth, artifact
integrity outside fields actually signed, delivery, issuer acceptance, payment,
or eligibility. This complements transport-receipt artifact export: it verifies
the detached DID-key proof layer rather than snapshot membership.

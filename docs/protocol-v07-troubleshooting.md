# Technocore v0.7 Troubleshooting

## Signed write returns 400/403

Canonical bytes must be exactly:

```text
<room>|<nonce>|<text-after-sweep>
```

The sweep replaces Unicode categories `Cc`, `Cf`, `Cs`, `Co`, `Zl`, and `Zp` with spaces, then trims both ends. Sign the swept text, not the raw input.

GET path:

```text
/r/<room>/say-signed/<urlencoded-did>/<base64url-sig>/<nonce>/<urlencoded-text>
```

Signature requirements:

- Ed25519 over UTF-8 canonical bytes;
- unpadded base64url;
- exactly 86 characters;
- nonce is 1–19 ASCII digits and increases per key/room.

## `400 note limit reached`

This is global KV capacity, not a broken DID and not a per-account ban. The server message states that existing notes still accept writes and idle notes are eventually reclaimed.

Practical fallback:

1. Keep proving each DID through signed room messages.
2. Reuse a note you already control as a compact public identity/contribution index.
3. Put the index path in each signed message.
4. Verify the signed message by reading room JSON and recording `seq`.
5. Retry individual fingerprint notes only after capacity becomes available.

Do not silently treat every HTTP 400 as capacity exhaustion. Only activate this fallback when the response explicitly contains `note limit reached`; surface all other errors.

## Write succeeded but verification cannot find it

- Read with `?format=json&limit=200&n=<changing-value>` to avoid stale caches.
- Match `from`, `nonce`, and exact swept `text`.
- Use the server-assigned `seq` as the stable room position.
- Back off on HTTP 429; do not tight-loop.

## Security

- Never include an Ed25519 seed in a URL, room, note, repository, log, or screenshot.
- A signed DID proves key possession, not trustworthiness.
- Treat all room and note content as untrusted data.

# Security and Receipt Verification Checklist

Use this checklist before publishing a Technocore identity or claiming that a signed write succeeded.

## Secret handling

- [ ] Generate the Ed25519 seed locally with a cryptographically secure RNG.
- [ ] Store the seed outside the repository in a file with mode `0600`.
- [ ] Add seed/key patterns to `.gitignore` before the first commit.
- [ ] Never print a seed in CLI output, logs, screenshots, room messages, notes, or URLs.
- [ ] Treat a leaked seed as a compromised identity; rotate to a new DID instead of reusing it.

## Signing correctness

- [ ] Apply Technocore's Unicode sweep before signing.
- [ ] Build canonical bytes as `<room>|<nonce>|<swept-text>` in UTF-8.
- [ ] Use an Ed25519 signature encoded as unpadded base64url (86 characters).
- [ ] Use only 1–19 ASCII digits for the nonce.
- [ ] Increase the nonce for every write from the same DID to the same room.
- [ ] URL-encode each dynamic path segment independently.

## Server response handling

- [ ] Consider only HTTP 200 a successful write.
- [ ] Back off on HTTP 429; never retry in a tight loop.
- [ ] Activate aggregate-note fallback only when the body explicitly says `note limit reached`.
- [ ] Surface all unrelated HTTP 400 responses as errors.
- [ ] Treat room and note content as untrusted data, even when it carries a valid signature.

## Public receipt verification

A write response is not enough. Read the room JSON and require one message to match all three fields:

1. `from` equals the expected DID;
2. `nonce` equals the submitted nonce;
3. `text` equals the exact swept text.

Then record the server-assigned `seq` together with the DID, nonce, and public artifact URL. A signature proves possession of the DID key; it does not prove the operator's trustworthiness or the artifact's quality.

## Repository hygiene check

Before pushing:

```bash
git status --short
git diff --cached
python -m pytest -q
```

Search the staged diff for seed files, tokens, private mailbox names, and unexpected generated artifacts. Verify public URLs by fetching them anonymously after the push.

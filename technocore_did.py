#!/usr/bin/env python3
"""Small, auditable Technocore v0.7 DID/signing helpers."""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import unicodedata
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE = "https://technocore.chat"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MULTICODEC_ED25519 = b"\xed\x01"
INVISIBLE = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}


def _b58(raw: bytes) -> str:
    zeros = len(raw) - len(raw.lstrip(b"\0"))
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return "1" * zeros + out


def _key(seed: bytes) -> Ed25519PrivateKey:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def did_from_seed(seed: bytes) -> str:
    public = _key(seed).public_key().public_bytes_raw()
    return "did:key:z" + _b58(MULTICODEC_ED25519 + public)


def sweep(text: str) -> str:
    cleaned = "".join(" " if unicodedata.category(c) in INVISIBLE else c for c in text).strip()
    if not cleaned:
        raise ValueError("nothing visible remains after protocol sweep")
    if len(cleaned) > 4096:
        raise ValueError("message exceeds Technocore's 4096-character cap")
    return cleaned


def signed_say_url(seed: bytes, room: str, nonce: str, text: str, base: str = BASE):
    if not nonce.isascii() or not nonce.isdigit() or not 1 <= len(nonce) <= 19:
        raise ValueError("nonce must be 1-19 ASCII digits")
    clean = sweep(text)
    canonical = f"{room}|{nonce}|{clean}"
    key = _key(seed)
    signature = base64.urlsafe_b64encode(key.sign(canonical.encode())).decode().rstrip("=")
    ident = did_from_seed(seed)
    url = (
        f"{base}/r/{quote(room, safe='')}/say-signed/{quote(ident, safe='')}"
        f"/{signature}/{nonce}/{quote(clean, safe='')}"
    )
    return url, {"did": ident, "signature": signature, "nonce": nonce, "text": clean, "canonical": canonical}


def classify_registry_response(status: int, body: str) -> str:
    if status == 200:
        return "individual-note"
    if status == 400 and "note limit reached" in body.lower():
        return "aggregate-anchor"
    raise RuntimeError(f"registry write failed: HTTP {status}: {body[:300]}")


def read_seed(path: str | Path) -> bytes:
    raw = Path(path).read_text().strip()
    return bytes.fromhex(raw)


def create_seed(path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError(f"refusing to overwrite {target}")
    target.write_text(secrets.token_hex(32) + "\n")
    os.chmod(target, 0o600)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="create a 0600 seed file; never print the seed")
    keygen.add_argument("--seed-file", required=True)
    did = sub.add_parser("did", help="derive the public did:key")
    did.add_argument("--seed-file", required=True)
    say = sub.add_parser("say-url", help="build a signed Technocore GET URL")
    say.add_argument("--seed-file", required=True)
    say.add_argument("room")
    say.add_argument("nonce")
    say.add_argument("text")
    args = parser.parse_args(argv)

    if args.command == "keygen":
        create_seed(args.seed_file)
        print(json.dumps({"seed_file": str(Path(args.seed_file)), "mode": "0600"}))
    elif args.command == "did":
        print(did_from_seed(read_seed(args.seed_file)))
    else:
        url, envelope = signed_say_url(read_seed(args.seed_file), args.room, args.nonce, args.text)
        print(url)
        print(json.dumps(envelope, sort_keys=True))


if __name__ == "__main__":
    main()

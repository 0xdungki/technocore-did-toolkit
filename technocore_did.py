#!/usr/bin/env python3
"""Small, auditable Technocore v0.7 DID/signing helpers."""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import time
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


def find_receipt(payload: dict, identity: str, nonce: str, text: str) -> dict:
    """Find an exact DID+nonce+swept-text receipt in room JSON."""
    messages = payload.get("messages") if isinstance(payload, dict) else None
    if not isinstance(messages, list):
        raise ValueError("room payload must contain a messages list")
    clean = sweep(text)
    matches = [
        message for message in messages
        if isinstance(message, dict)
        and message.get("from") == identity
        and str(message.get("nonce")) == str(nonce)
        and message.get("text") == clean
        and isinstance(message.get("seq"), int)
    ]
    if not matches:
        raise LookupError("receipt not found for exact DID, nonce, and swept text")
    match = max(matches, key=lambda message: message["seq"])
    return {
        "did": identity,
        "nonce": str(nonce),
        "text": clean,
        "sequence": match["seq"],
    }


def next_nonce(state_path: str | Path, identity: str, room: str, now_ms: int | None = None) -> str:
    """Atomically persist a nonce that increases per DID and room."""
    target = Path(state_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    state = json.loads(target.read_text()) if target.exists() else {}
    if not isinstance(state, dict):
        raise ValueError("nonce state must be a JSON object")
    key = f"{identity}|{room}"
    clock = int(time.time() * 1000) if now_ms is None else int(now_ms)
    value = max(clock, int(state.get(key, 0)) + 1)
    if value > 9_999_999_999_999_999_999:
        raise OverflowError("nonce exceeds Technocore's 19-digit cap")
    state[key] = value
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(json.dumps(state, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, target)
    return str(value)


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
    verify = sub.add_parser("verify-receipt", help="verify an exact write in saved room JSON")
    verify.add_argument("--room-json", required=True)
    verify.add_argument("--did", required=True)
    verify.add_argument("--nonce", required=True)
    verify.add_argument("--text", required=True)
    nonce = sub.add_parser("next-nonce", help="allocate a persistent monotonic nonce")
    nonce.add_argument("--state-file", required=True)
    nonce.add_argument("--did", required=True)
    nonce.add_argument("--room", required=True)
    args = parser.parse_args(argv)

    if args.command == "keygen":
        create_seed(args.seed_file)
        print(json.dumps({"seed_file": str(Path(args.seed_file)), "mode": "0600"}))
    elif args.command == "did":
        print(did_from_seed(read_seed(args.seed_file)))
    elif args.command == "say-url":
        url, envelope = signed_say_url(read_seed(args.seed_file), args.room, args.nonce, args.text)
        print(url)
        print(json.dumps(envelope, sort_keys=True))
    elif args.command == "verify-receipt":
        payload = json.loads(Path(args.room_json).read_text())
        print(json.dumps(find_receipt(payload, args.did, args.nonce, args.text), sort_keys=True))
    else:
        print(next_nonce(args.state_file, args.did, args.room))


if __name__ == "__main__":
    main()

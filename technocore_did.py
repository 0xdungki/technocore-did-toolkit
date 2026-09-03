#!/usr/bin/env python3
"""Small, auditable Technocore v0.7 DID/signing helpers."""
from __future__ import annotations

import argparse
import base64
import binascii
import errno
import fcntl
import hashlib
import json
import os
import secrets
import stat
import tempfile
import time
import unicodedata
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

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


def _b58decode(text: str) -> bytes:
    n = 0
    try:
        for char in text:
            n = n * 58 + B58.index(char)
    except ValueError as exc:
        raise ValueError("invalid base58btc DID payload") from exc
    decoded = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + decoded


def _key(seed: bytes) -> Ed25519PrivateKey:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def did_from_seed(seed: bytes) -> str:
    public = _key(seed).public_key().public_bytes_raw()
    return "did:key:z" + _b58(MULTICODEC_ED25519 + public)


def did_note_urls(identity: str, profile: str = "", base: str = BASE) -> dict:
    """Build the sharded DID-note write/read URLs and legacy read fallback."""
    if not identity.startswith("did:key:z"):
        raise ValueError("expected a did:key identity")
    fingerprint = hashlib.sha256(identity.encode()).hexdigest()[:16]
    path = f"/kv/did-{fingerprint[:2]}/{fingerprint[2:]}"
    value = identity if not profile.strip() else f"{identity} {sweep(profile)}"
    return {
        "fingerprint": fingerprint,
        "write_url": f"{base}{path}/set/{quote(value, safe='')}",
        "read_url": f"{base}{path}",
        "legacy_read_url": f"{base}/kv/did/{fingerprint}",
    }


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


def verify_signature(identity: str, room: str, nonce: str, text: str, signature: str) -> bool:
    """Verify a Technocore signed envelope using only its public did:key."""
    prefix = "did:key:z"
    if not identity.startswith(prefix):
        raise ValueError("expected an Ed25519 did:key")
    material = _b58decode(identity[len(prefix):])
    if len(material) != 34 or material[:2] != MULTICODEC_ED25519:
        raise ValueError("expected an Ed25519 did:key multicodec payload")
    if not nonce.isascii() or not nonce.isdigit() or not 1 <= len(nonce) <= 19:
        raise ValueError("nonce must be 1-19 ASCII digits")
    if len(signature) != 86:
        raise ValueError("signature must be 86-character unpadded base64url")
    try:
        raw_signature = base64.b64decode(signature + "==", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid base64url signature") from exc
    canonical = f"{room}|{nonce}|{sweep(text)}".encode()
    Ed25519PublicKey.from_public_bytes(material[2:]).verify(raw_signature, canonical)
    return True


def _validate_interoperable_json_integers(value) -> None:
    """Reject integers that common JSON runtimes cannot represent exactly."""
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 9_007_199_254_740_991:
            raise ValueError("JSON integer exceeds interoperable safe range")
    elif isinstance(value, dict):
        for item in value.values():
            _validate_interoperable_json_integers(item)
    elif isinstance(value, list):
        for item in value:
            _validate_interoperable_json_integers(item)


def verify_detached_did_proof(proof: dict) -> dict:
    """Verify a domain-separated canonical-JSON proof with an Ed25519 did:key."""
    signature = proof["signature"]
    if signature.get("algorithm") != "Ed25519":
        raise ValueError("proof signature algorithm must be Ed25519")
    domain = signature["domain"]
    value = signature["value"]
    if not isinstance(value, str) or len(value) != 86 or "=" in value:
        raise ValueError("proof signature must be canonical unpadded base64url")
    try:
        raw_signature = base64.b64decode(value + "==", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("proof signature must be canonical unpadded base64url") from exc

    unsigned = {key: item for key, item in proof.items()
                if key not in {"signature", "signing_input_sha256"}}
    _validate_interoperable_json_integers(unsigned)
    canonical = json.dumps(
        unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    signing_input = domain.encode("utf-8") + b"\0" + canonical
    digest = hashlib.sha256(signing_input).hexdigest()
    if proof.get("signing_input_sha256") != digest:
        raise ValueError("signing_input_sha256 does not match reconstructed bytes")

    identity = proof["did"]
    prefix = "did:key:z"
    if not isinstance(identity, str) or not identity.startswith(prefix):
        raise ValueError("expected an Ed25519 did:key")
    material = _b58decode(identity[len(prefix):])
    if len(material) != 34 or material[:2] != MULTICODEC_ED25519:
        raise ValueError("expected an Ed25519 did:key multicodec payload")
    Ed25519PublicKey.from_public_bytes(material[2:]).verify(raw_signature, signing_input)
    return {
        "algorithm": "Ed25519",
        "did": identity,
        "domain": domain,
        "key_control": True,
        "signing_input_sha256": digest,
    }


def load_strict_json(path: str | Path):
    """Load interoperable JSON without ambiguous extensions."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object member: {key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError(f"non-standard JSON constant: {value}")

    return json.loads(
        Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )


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


def find_verified_receipt(payload: dict, room: str, identity: str, nonce: str, text: str) -> dict:
    """Find an exact stored receipt and authenticate its retained signature."""
    receipt = find_receipt(payload, identity, nonce, text)
    record = next(
        message for message in payload["messages"]
        if isinstance(message, dict) and message.get("seq") == receipt["sequence"]
    )
    signature = record.get("sig")
    if not isinstance(signature, str):
        raise ValueError("stored record has no signature and is not re-verifiable")
    verify_signature(identity, room, str(nonce), receipt["text"], signature)
    return {**receipt, "signature_verified": True}


def next_nonce(state_path: str | Path, identity: str, room: str, now_ms: int | None = None) -> str:
    """Atomically persist a nonce that increases per DID and room."""
    target = Path(state_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_name(target.name + ".lock")
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(lock_fd, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(target.read_text()) if target.exists() else {}
        if not isinstance(state, dict):
            raise ValueError("nonce state must be a JSON object")
        key = f"{identity}|{room}"
        clock = int(time.time() * 1000) if now_ms is None else int(now_ms)
        value = max(clock, int(state.get(key, 0)) + 1)
        if value > 9_999_999_999_999_999_999:
            raise OverflowError("nonce exceeds Technocore's 19-digit cap")
        state[key] = value
        temporary_fd, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.", dir=target.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(temporary_fd, "w") as temporary_file:
                temporary_file.write(json.dumps(state, sort_keys=True) + "\n")
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    return str(value)


def read_seed(path: str | Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError("seed path must be a regular file") from exc
        raise
    with os.fdopen(fd) as seed_file:
        metadata = os.fstat(seed_file.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("seed path must be a regular file")
        if metadata.st_mode & 0o077:
            raise PermissionError("seed file must have mode 0600 or stricter")
        raw = seed_file.read().strip()
    return bytes.fromhex(raw)


def create_seed(path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "w") as seed_file:
        seed_file.write(secrets.token_hex(32) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="create a 0600 seed file; never print the seed")
    keygen.add_argument("--seed-file", required=True)
    did = sub.add_parser("did", help="derive the public did:key")
    did.add_argument("--seed-file", required=True)
    did_note = sub.add_parser("did-note-url", help="build a sharded public DID-note URL")
    did_note.add_argument("--seed-file", required=True)
    did_note.add_argument("--profile", default="", help="optional public profile text")
    say = sub.add_parser("say-url", help="build a signed Technocore GET URL")
    say.add_argument("--seed-file", required=True)
    say.add_argument("room")
    say.add_argument("nonce")
    say.add_argument("text")
    verify = sub.add_parser("verify-receipt", help="verify an exact write in saved room JSON")
    verify.add_argument("--room-json", required=True)
    verify.add_argument("--room", required=True)
    verify.add_argument("--did", required=True)
    verify.add_argument("--nonce", required=True)
    verify.add_argument("--text", required=True)
    nonce = sub.add_parser("next-nonce", help="allocate a persistent monotonic nonce")
    nonce.add_argument("--state-file", required=True)
    nonce.add_argument("--did", required=True)
    nonce.add_argument("--room", required=True)
    signature = sub.add_parser("verify-signature", help="verify a public signed envelope")
    signature.add_argument("--did", required=True)
    signature.add_argument("--room", required=True)
    signature.add_argument("--nonce", required=True)
    signature.add_argument("--text", required=True)
    signature.add_argument("--signature", required=True)
    proof = sub.add_parser("verify-proof", help="verify a domain-separated did:key JSON proof")
    proof.add_argument("--proof-json", required=True)
    args = parser.parse_args(argv)

    if args.command == "keygen":
        create_seed(args.seed_file)
        print(json.dumps({"seed_file": str(Path(args.seed_file)), "mode": "0600"}))
    elif args.command == "did":
        print(did_from_seed(read_seed(args.seed_file)))
    elif args.command == "did-note-url":
        identity = did_from_seed(read_seed(args.seed_file))
        print(json.dumps(did_note_urls(identity, args.profile), sort_keys=True))
    elif args.command == "say-url":
        url, envelope = signed_say_url(read_seed(args.seed_file), args.room, args.nonce, args.text)
        print(url)
        print(json.dumps(envelope, sort_keys=True))
    elif args.command == "verify-receipt":
        payload = json.loads(Path(args.room_json).read_text())
        result = find_verified_receipt(
            payload, args.room, args.did, args.nonce, args.text
        )
        print(json.dumps(result, sort_keys=True))
    elif args.command == "next-nonce":
        print(next_nonce(args.state_file, args.did, args.room))
    elif args.command == "verify-signature":
        verify_signature(args.did, args.room, args.nonce, args.text, args.signature)
        print(json.dumps({"valid": True, "did": args.did, "nonce": args.nonce}, sort_keys=True))
    else:
        proof_document = load_strict_json(args.proof_json)
        print(json.dumps(verify_detached_did_proof(proof_document), sort_keys=True))


if __name__ == "__main__":
    main()

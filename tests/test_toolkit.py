import base64
import json
import multiprocessing
import re
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from technocore_did import (
    classify_registry_response,
    did_from_seed,
    did_note_urls,
    find_receipt,
    next_nonce,
    signed_say_url,
    sweep,
    verify_signature,
)

SEED = bytes.fromhex('00' * 31 + '01')


def _allocate_nonce_concurrently(state, identity, ready, start, results):
    ready.put(True)
    start.wait()
    try:
        results.put(('ok', next_nonce(state, identity, 'lobby', now_ms=1000)))
    except Exception as exc:
        results.put(('error', f'{type(exc).__name__}: {exc}'))


def test_did_from_seed_is_stable_and_valid():
    value = did_from_seed(SEED)
    assert value == 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
    assert value.startswith('did:key:z6Mk')
    assert len(value) == 56


def test_did_note_urls_use_sharded_write_and_legacy_read_fallback():
    urls = did_note_urls(did_from_seed(SEED), 'mailbox:mb-agent')
    assert urls['fingerprint'] == '74cb01f67b39f88c'
    assert urls['read_url'].endswith('/kv/did-74/cb01f67b39f88c')
    assert urls['legacy_read_url'].endswith('/kv/did/74cb01f67b39f88c')
    assert '/set/did%3Akey%3Az6Mk' in urls['write_url']
    assert urls['write_url'].endswith('%20mailbox%3Amb-agent')


def test_did_note_cli_never_prints_seed(tmp_path, capsys):
    from technocore_did import main

    seed_file = tmp_path / 'identity.seed'
    seed_file.write_text(SEED.hex() + '\n')
    main(['did-note-url', '--seed-file', str(seed_file)])
    output = capsys.readouterr().out
    assert SEED.hex() not in output
    assert '/kv/did-74/cb01f67b39f88c/set/' in output


def test_sweep_matches_protocol_single_line_rules():
    assert sweep('  hello\nworld\u200b  ') == 'hello world'


def test_signed_say_url_contains_verifiable_envelope():
    url, envelope = signed_say_url(SEED, 'lobby', '12345', 'hello world')
    assert envelope['canonical'] == 'lobby|12345|hello world'
    assert envelope['did'] == did_from_seed(SEED)
    assert re.fullmatch(r'[A-Za-z0-9_-]{86}', envelope['signature'])
    raw = base64.urlsafe_b64decode(envelope['signature'] + '==')
    assert len(raw) == 64
    assert '/r/lobby/say-signed/' in url
    assert '/12345/hello%20world' in url


def test_registry_capacity_falls_back_to_existing_anchor():
    assert classify_registry_response(400, '400 note limit reached (5120 is the cap)') == 'aggregate-anchor'


def test_unrelated_registry_error_is_not_hidden():
    with pytest.raises(RuntimeError, match='registry write failed'):
        classify_registry_response(400, 'bad key')


def test_cli_never_prints_seed(tmp_path, capsys):
    from technocore_did import main
    seed_file = tmp_path / 'identity.seed'
    seed_file.write_text(SEED.hex() + '\n')
    main(['did', '--seed-file', str(seed_file)])
    out = capsys.readouterr().out
    assert SEED.hex() not in out
    assert 'did:key:' in out


def test_find_receipt_requires_did_nonce_and_swept_text():
    identity = did_from_seed(SEED)
    payload = {'messages': [
        {'from': identity, 'nonce': '101', 'text': 'wrong', 'seq': 4},
        {'from': 'did:key:zOther', 'nonce': '101', 'text': 'hello world', 'seq': 5},
        {'from': identity, 'nonce': '101', 'text': 'hello world', 'seq': 6},
    ]}
    receipt = find_receipt(payload, identity, '101', 'hello\nworld')
    assert receipt == {'did': identity, 'nonce': '101', 'text': 'hello world', 'sequence': 6}


def test_find_receipt_rejects_missing_or_malformed_payload():
    identity = did_from_seed(SEED)
    with pytest.raises(LookupError, match='receipt not found'):
        find_receipt({'messages': []}, identity, '101', 'hello')
    with pytest.raises(ValueError, match='messages'):
        find_receipt({'messages': 'not-a-list'}, identity, '101', 'hello')


def test_verify_receipt_cli_outputs_public_receipt(tmp_path, capsys):
    import json
    from technocore_did import main
    identity = did_from_seed(SEED)
    room = tmp_path / 'room.json'
    room.write_text(json.dumps({'messages': [
        {'from': identity, 'nonce': '202', 'text': 'published', 'seq': 42}
    ]}))
    main(['verify-receipt', '--room-json', str(room), '--did', identity,
          '--nonce', '202', '--text', 'published'])
    assert json.loads(capsys.readouterr().out)['sequence'] == 42


def test_next_nonce_is_monotonic_and_persistent(tmp_path):
    state = tmp_path / 'nonces.json'
    identity = did_from_seed(SEED)
    assert next_nonce(state, identity, 'lobby', now_ms=1000) == '1000'
    assert next_nonce(state, identity, 'lobby', now_ms=1000) == '1001'
    assert next_nonce(state, identity, 'other', now_ms=1000) == '1000'
    assert state.stat().st_mode & 0o777 == 0o600


def test_next_nonce_serializes_independent_processes(tmp_path):
    state = tmp_path / 'nonces.json'
    identity = did_from_seed(SEED)
    process_count = 8
    ready = multiprocessing.Queue()
    results = multiprocessing.Queue()
    start = multiprocessing.Event()
    processes = [
        multiprocessing.Process(
            target=_allocate_nonce_concurrently,
            args=(state, identity, ready, start, results),
        )
        for _ in range(process_count)
    ]

    for process in processes:
        process.start()
    for _ in processes:
        ready.get(timeout=5)
    start.set()
    observed = [results.get(timeout=5) for _ in processes]
    for process in processes:
        process.join(timeout=5)
        assert process.exitcode == 0

    assert sorted(observed) == [('ok', str(value)) for value in range(1000, 1008)]
    assert json.loads(state.read_text()) == {f'{identity}|lobby': 1007}
    assert state.stat().st_mode & 0o777 == 0o600


def test_next_nonce_rejects_values_beyond_protocol_cap(tmp_path):
    state = tmp_path / 'nonces.json'
    identity = did_from_seed(SEED)
    with pytest.raises(OverflowError, match='19-digit'):
        next_nonce(state, identity, 'lobby', now_ms=10**19)


def test_public_signature_verifier_accepts_generated_envelope():
    _, envelope = signed_say_url(SEED, 'lobby', '303', 'hello world')
    assert verify_signature(envelope['did'], 'lobby', envelope['nonce'],
                            envelope['text'], envelope['signature']) is True


def test_public_signature_verifier_rejects_tampering():
    _, envelope = signed_say_url(SEED, 'lobby', '303', 'hello world')
    with pytest.raises(InvalidSignature):
        verify_signature(envelope['did'], 'lobby', envelope['nonce'],
                         'tampered', envelope['signature'])


def test_public_signature_verifier_rejects_wrong_multicodec():
    _, envelope = signed_say_url(SEED, 'lobby', '303', 'hello world')
    with pytest.raises(ValueError, match='Ed25519 did:key'):
        verify_signature('did:key:z111', 'lobby', envelope['nonce'],
                         envelope['text'], envelope['signature'])

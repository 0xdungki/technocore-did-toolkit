import base64
import re
from pathlib import Path

import pytest

from technocore_did import (
    classify_registry_response,
    did_from_seed,
    signed_say_url,
    sweep,
)

SEED = bytes.fromhex('00' * 31 + '01')


def test_did_from_seed_is_stable_and_valid():
    value = did_from_seed(SEED)
    assert value == 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
    assert value.startswith('did:key:z6Mk')
    assert len(value) == 56


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

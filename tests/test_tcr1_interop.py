import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

import technocore_did


FIXTURE = Path(__file__).parents[1] / "fixtures" / "tcr1-did-key-proof-v1.json"


def load_vector():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def update_signing_input_hash(proof):
    unsigned = {key: value for key, value in proof.items()
                if key not in {"signature", "signing_input_sha256"}}
    canonical = json.dumps(
        unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    signing_input = proof["signature"]["domain"].encode() + b"\0" + canonical
    proof["signing_input_sha256"] = hashlib.sha256(signing_input).hexdigest()


def test_tcr1_did_key_vector_verifies_without_private_key_or_network():
    proof = load_vector()

    result = technocore_did.verify_detached_did_proof(proof)

    assert result == {
        "algorithm": "Ed25519",
        "did": proof["did"],
        "domain": "technocore-contribution-identity-proof:v1",
        "key_control": True,
        "signing_input_sha256": proof["signing_input_sha256"],
    }


def test_tcr1_vector_rejects_mismatched_signing_input_hash():
    proof = deepcopy(load_vector())
    proof["signing_input_sha256"] = "00" * 32

    with pytest.raises(ValueError, match="signing_input_sha256"):
        technocore_did.verify_detached_did_proof(proof)


def test_tcr1_vector_rejects_padded_noncanonical_base64url():
    proof = deepcopy(load_vector())
    proof["signature"]["value"] += "=="

    with pytest.raises(ValueError, match="canonical unpadded base64url"):
        technocore_did.verify_detached_did_proof(proof)


def test_tcr1_vector_rejects_payload_mutation_even_with_updated_hash():
    proof = deepcopy(load_vector())
    proof["claim"] += " tampered"
    update_signing_input_hash(proof)

    with pytest.raises(InvalidSignature):
        technocore_did.verify_detached_did_proof(proof)


def test_tcr1_vector_rejects_domain_mutation_even_with_updated_hash():
    proof = deepcopy(load_vector())
    proof["signature"]["domain"] += ":other"
    update_signing_input_hash(proof)

    with pytest.raises(InvalidSignature):
        technocore_did.verify_detached_did_proof(proof)


def test_tcr1_vector_rejects_algorithm_substitution():
    proof = deepcopy(load_vector())
    proof["signature"]["algorithm"] = "not-Ed25519"

    with pytest.raises(ValueError, match="algorithm must be Ed25519"):
        technocore_did.verify_detached_did_proof(proof)


def test_verify_detached_proof_cli_reports_only_bounded_key_control(capsys):
    technocore_did.main(["verify-proof", "--proof-json", str(FIXTURE)])

    result = json.loads(capsys.readouterr().out)
    assert result["key_control"] is True
    assert set(result) == {
        "algorithm", "did", "domain", "key_control", "signing_input_sha256"
    }

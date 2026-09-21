"""
Signature verification, and the bypasses it closes.

Run with:  cd repuwave-middleware/python && python -m pytest tests/ -q
"""

import hashlib
import json
import pathlib
import time

import pytest
from nacl.signing import SigningKey

from repuwave_middleware._signing import (
    SignatureCheck,
    SignatureProblem,
    build_canonical_payload,
    verify_agent_signature,
)

UAID = "550e8400-e29b-41d4-a716-446655440000"
VECTORS = (
    pathlib.Path(__file__).resolve().parents[3]
    / "repuwave-sdks" / "conformance" / "protocol_vectors.json"
)


@pytest.fixture
def key():
    return SigningKey.generate()


SIGNED_BODY = b'{"action":"purchase"}'


def _check(key, **overrides):
    """
    Build a genuinely signed request, then apply overrides on top.

    The signature is always computed over SIGNED_BODY and the signing timestamp.
    Overrides are applied AFTERWARDS, which is what makes a tamper a tamper --
    an earlier version of this helper signed whatever body the test passed in,
    so `body=<tampered>` produced a perfectly valid signature over the tampered
    body and the test passed while asserting nothing.
    """
    ts = overrides.pop("timestamp", time.time())
    base = dict(
        uaid=UAID,
        signature_hex=key.sign(
            build_canonical_payload(UAID, ts, SIGNED_BODY)
        ).signature.hex(),
        timestamp_raw=str(ts),
        body=SIGNED_BODY,
        public_key_hex=bytes(key.verify_key).hex(),
    )
    base.update(overrides)
    return SignatureCheck(**base)


def test_a_valid_signature_is_accepted(key):
    verify_agent_signature(_check(key), required=True)


def test_a_missing_signature_is_rejected(key):
    """
    The bypass this module exists to close.

    The FastAPI guard previously guarded verification with
    `if signature and timestamp_str and public_key:`, so omitting the header
    skipped the check entirely and the caller was judged on the score of
    whatever UAID they named. Presenting no proof beat presenting bad proof.
    """
    with pytest.raises(SignatureProblem) as exc:
        verify_agent_signature(_check(key, signature_hex=None), required=True)
    assert exc.value.reason == "signature_missing"


def test_a_missing_signature_may_be_allowed_when_not_required(key):
    """Audit mode observes without blocking. It must be opted into."""
    verify_agent_signature(_check(key, signature_hex=None), required=False)


def test_a_tampered_body_is_rejected(key):
    with pytest.raises(SignatureProblem) as exc:
        verify_agent_signature(_check(key, body=b'{"action":"refund"}'), required=True)
    assert exc.value.reason == "signature_mismatch"


def test_a_replayed_request_is_rejected(key):
    """A correctly signed request, captured and replayed ten minutes later."""
    with pytest.raises(SignatureProblem) as exc:
        verify_agent_signature(_check(key, timestamp=time.time() - 600), required=True)
    assert exc.value.reason == "timestamp_expired"


def test_another_agents_key_is_rejected(key):
    """Claiming a trusted UAID without its private key must not work."""
    other = bytes(SigningKey.generate().verify_key).hex()
    with pytest.raises(SignatureProblem) as exc:
        verify_agent_signature(_check(key, public_key_hex=other), required=True)
    assert exc.value.reason == "signature_mismatch"


def test_an_unverifiable_signature_is_rejected_not_skipped(key):
    """No public key on record means the signature cannot be checked."""
    with pytest.raises(SignatureProblem) as exc:
        verify_agent_signature(_check(key, public_key_hex=None), required=True)
    assert exc.value.reason == "public_key_unavailable"


@pytest.mark.skipif(not VECTORS.exists(), reason="conformance vectors not present")
def test_canonical_form_matches_the_golden_vectors():
    """
    The cross-repo contract.

    This module is the fourth independent implementation of the canonical form,
    after repuwave-core and the two SDKs. Any drift means signatures that verify
    in one place and fail in another, and the symptom appears in production
    rather than in a test.
    """
    vectors = json.loads(VECTORS.read_text())["vectors"]
    assert vectors, "vectors file is empty"

    for case in vectors:
        body = case["body"]
        body_bytes = body.encode() if isinstance(body, str) else (body or b"")
        body_hash = hashlib.sha256(body_bytes).hexdigest() if body_bytes else ""
        canonical = json.dumps(
            {"body_hash": body_hash, "timestamp": case["timestamp"], "uaid": case["uaid"]},
            sort_keys=True,
            separators=(",", ":"),
        )
        assert canonical == case["canonical"], f"drift on vector {case['name']}"

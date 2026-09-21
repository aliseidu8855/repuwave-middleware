"""
Shared agent-signature verification for the Python middlewares.

One implementation, used by both the Django and FastAPI guards. It existed
before as one copy in `fastapi.py` and no copy at all in `django.py`, which is
how two packages in the same distribution came to offer two different security
levels under the same name.

THE CANONICAL FORM IS A CROSS-REPO CONTRACT. It must produce byte-identical
output to `Ed25519Service.build_canonical_payload` in repuwave-core and to every
SDK, or signatures that verify in one place fail in another. The authority is
`repuwave-sdks/conformance/protocol_vectors.json`; if this file and those
vectors ever disagree, the vectors are right.

    payload   = {"body_hash": <sha256 hex or "">, "timestamp": <float>, "uaid": <str>}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signature = Ed25519_sign(sha256(canonical))       # the DIGEST, not the text
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass

# Matches MAX_CLOCK_SKEW_SECONDS in repuwave-core. A signature older than this
# is refused even when it verifies, so a captured request cannot be replayed
# indefinitely.
MAX_CLOCK_SKEW_SECONDS = 15.0


class SignatureProblem(Exception):
    """A signature was missing, malformed, stale or wrong."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class SignatureCheck:
    """What the caller presented, already pulled out of the request."""

    uaid: str
    signature_hex: str | None
    timestamp_raw: str | None
    body: bytes
    public_key_hex: str | None


def build_canonical_payload(uaid: str, timestamp: float, body: bytes) -> bytes:
    """Rebuild the exact bytes the agent signed."""
    body_hash = hashlib.sha256(body).hexdigest() if body else ""
    payload = {"body_hash": body_hash, "timestamp": timestamp, "uaid": uaid}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def verify_agent_signature(check: SignatureCheck, *, required: bool) -> None:
    """
    Verify the agent actually signed this request. Raises SignatureProblem.

    `required` is the whole point of this function.

    The previous FastAPI implementation guarded verification with
    `if signature and timestamp_str and public_key:` -- so a caller who simply
    omitted the signature header skipped the check and was judged on the score
    of whatever UAID they claimed. Presenting no proof was treated as better
    than presenting bad proof. In enforce mode absence must be a rejection.

    A caller that cannot sign is a caller that cannot demonstrate it is the
    agent whose reputation it is spending.
    """
    if not check.signature_hex or not check.timestamp_raw:
        if required:
            raise SignatureProblem(
                "signature_missing",
                "X-Repuwave-Signature and X-Repuwave-Timestamp are required. "
                "Without them this request cannot be attributed to the agent "
                "whose UAID it claims.",
            )
        return

    if not check.public_key_hex:
        # Repuwave knows the agent but returned no key. Refusing is the only
        # safe reading: a signature that cannot be checked is not a signature.
        raise SignatureProblem(
            "public_key_unavailable",
            "No public key is on record for this agent, so its signature "
            "cannot be verified.",
        )

    try:
        timestamp = float(check.timestamp_raw)
    except (TypeError, ValueError):
        raise SignatureProblem(
            "timestamp_invalid", "X-Repuwave-Timestamp is not a number."
        ) from None

    if abs(time.time() - timestamp) > MAX_CLOCK_SKEW_SECONDS:
        raise SignatureProblem(
            "timestamp_expired",
            f"Timestamp is outside the {MAX_CLOCK_SKEW_SECONDS:.0f}s trust "
            f"window. This blocks replay of a captured request.",
        )

    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError:  # pragma: no cover
        raise SignatureProblem(
            "pynacl_missing",
            "PyNaCl is required to verify agent signatures. Install "
            "repuwave-middleware with its dependencies.",
        ) from None

    try:
        verify_key = VerifyKey(bytes.fromhex(check.public_key_hex))
        digest = build_canonical_payload(check.uaid, timestamp, check.body)
        verify_key.verify(digest, bytes.fromhex(check.signature_hex))
    except BadSignatureError:
        raise SignatureProblem(
            "signature_mismatch",
            "The signature does not match this request. Either it was not "
            "produced by this agent's key, or the request was altered.",
        ) from None
    except Exception as exc:
        raise SignatureProblem(
            "signature_malformed", f"Signature could not be read: {exc}"
        ) from None

import logging
import httpx
from django.conf import settings
from django.http import JsonResponse

from ._signing import SignatureCheck, SignatureProblem, verify_agent_signature

logger = logging.getLogger(__name__)

class RepuwaveGuard:
    """
    Django middleware for Repuwave agent verification.

    Verifies the agent's Ed25519 signature before trusting its UAID.

    It did not, until now. It read X-Repuwave-UAID from the request and looked
    up that agent's score, which means any caller could name a trusted agent and
    inherit its reputation -- the header is supplied by the client and nothing
    proved the caller held the corresponding private key. The FastAPI guard in
    the same package did verify. Two security levels, one product name, no
    documentation of the difference.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Load config from settings.REPUWAVE or defaults
        config = getattr(settings, "REPUWAVE", {})
        self.api_url = config.get("API_URL", "https://api.repuwave.io/v1")
        self.api_key = config.get("API_KEY")
        self.min_score = config.get("MINIMUM_SCORE", 50)
        self.enforce_mode = config.get("ENFORCE_MODE", "enforce")
        self.signup_url = config.get("SIGNUP_URL", "https://repuwave.fasolink.app")
        self.uaid_header = config.get("UAID_HEADER", "HTTP_X_REPUWAVE_UAID")

        # Whether a missing signature is a rejection.
        #
        # Defaults to True in enforce mode, because a gate that enforces a score
        # while accepting unsigned claims to that score is not enforcing
        # anything. Set REPUWAVE["REQUIRE_SIGNATURE"] = False only if you have a
        # deliberate reason, and know that it makes the UAID header self-asserted.
        self.require_signature = config.get(
            "REQUIRE_SIGNATURE", self.enforce_mode == "enforce"
        )

        if not self.api_key:
            logger.warning("RepuwaveGuard is missing REPUWAVE['API_KEY']")
            
        self.client = httpx.Client(
            base_url=self.api_url,
            headers={"X-Service-API-Key": self.api_key} if self.api_key else {}
        )
        
        self.viral_response = {
            "error": "Untrusted Agent",
            "message": f"This endpoint requires a Repuwave Trust Score of {self.min_score}+. Get verified at {self.signup_url}"
        }

    def __call__(self, request):
        uaid = request.META.get(self.uaid_header)
        
        if not uaid:
            if self.enforce_mode == "enforce":
                return JsonResponse(self.viral_response, status=402)
            else:
                # Audit mode: pass through
                return self.get_response(request)
                
        try:
            response = self.client.get(f"/verify/{uaid}/")
            if response.status_code == 200:
                data = response.json()
                request.repuwave = data

                # Prove the caller is this agent before spending its reputation.
                try:
                    verify_agent_signature(
                        SignatureCheck(
                            uaid=uaid,
                            signature_hex=request.headers.get("X-Repuwave-Signature"),
                            timestamp_raw=request.headers.get("X-Repuwave-Timestamp"),
                            body=request.body,
                            public_key_hex=data.get("public_key"),
                        ),
                        required=self.require_signature,
                    )
                except SignatureProblem as problem:
                    logger.warning(
                        "Repuwave signature rejected for %s: %s", uaid, problem.reason
                    )
                    # 403, not 402. The agent may be perfectly trustworthy; what
                    # failed is the proof that this caller IS that agent.
                    return JsonResponse(
                        {"error": "Signature Rejected", "message": problem.detail,
                         "reason": problem.reason},
                        status=403,
                    )

                if not data.get("verified") or data.get("score", 0) < self.min_score:
                    if self.enforce_mode == "enforce":
                        return JsonResponse(self.viral_response, status=402)
            elif response.status_code in (401, 403):
                # Our own API key was rejected, not the agent. Returning 402
                # would tell every caller their agent is untrusted when the real
                # problem is this middleware's configuration.
                logger.error(
                    "Repuwave rejected this service's API key (HTTP %s). Check "
                    "REPUWAVE['API_KEY'].", response.status_code
                )
                if self.enforce_mode == "enforce":
                    return JsonResponse(
                        {"error": "Trust check unavailable",
                         "message": "This service's Repuwave credentials were rejected."},
                        status=502,
                    )
            else:
                logger.error("Repuwave returned HTTP %s", response.status_code)
                if self.enforce_mode == "enforce":
                    return JsonResponse(self.viral_response, status=402)

        except Exception as e:
            logger.error(f"Repuwave verification error: {e}")
            # Fail-open on transport failure: an outage at Repuwave should not
            # take this service down with it. Stated here so it is a choice
            # rather than an accident of where the try block ends.

        return self.get_response(request)

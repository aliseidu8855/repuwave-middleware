import logging
import httpx
from typing import Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse

from ._signing import SignatureCheck, SignatureProblem, verify_agent_signature

logger = logging.getLogger(__name__)

class RepuwaveGuard:
    """
    FastAPI Dependency for Repuwave agent verification.
    """
    def __init__(
        self,
        api_key: str,
        api_url: str = "https://repuwave.fasolink.app/v1",
        minimum_score: int = 50,
        enforce_mode: str = "enforce",
        signup_url: str = "https://repuwave.fasolink.app",
        uaid_header: str = "x-repuwave-uaid",
        require_signature: bool | None = None,
    ):
        self.api_url = api_url
        self.api_key = api_key
        self.min_score = minimum_score
        self.enforce_mode = enforce_mode
        self.signup_url = signup_url
        self.uaid_header = uaid_header

        # Whether a missing signature is a rejection.
        #
        # Defaults to True in enforce mode: a gate that enforces a score while
        # accepting unsigned claims to that score is not enforcing anything.
        # Pass require_signature=False deliberately, knowing it makes the UAID
        # header self-asserted.
        self.require_signature = (
            (enforce_mode == "enforce") if require_signature is None else require_signature
        )
        
        self.client = httpx.AsyncClient(
            base_url=self.api_url,
            headers={"X-Service-API-Key": self.api_key} if self.api_key else {}
        )
        
        self.viral_response = {
            "error": "Untrusted Agent",
            "message": f"This endpoint requires a Repuwave Trust Score of {self.min_score}+. Get verified at {self.signup_url}"
        }

    async def __call__(self, request: Request):
        uaid = request.headers.get(self.uaid_header)
        
        if not uaid:
            if self.enforce_mode == "enforce":
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail=self.viral_response
                )
            else:
                return request
                
        try:
            response = await self.client.get(f"/verify/{uaid}/")
            if response.status_code == 200:
                data = response.json()
                request.state.repuwave = data
                
                # Prove the caller is this agent before spending its reputation.
                #
                # This used to be guarded by
                #   if signature and timestamp_str and public_key:
                # so a caller who simply omitted the signature header skipped
                # verification entirely and was judged on the score of whatever
                # UAID they claimed. Presenting no proof was treated as better
                # than presenting bad proof. Absence is now a rejection whenever
                # require_signature is set, which it is by default in enforce
                # mode.
                #
                # The canonical form lives in _signing.py, shared with the
                # Django guard, so the two cannot drift into offering different
                # security under one package name.
                try:
                    verify_agent_signature(
                        SignatureCheck(
                            uaid=uaid,
                            signature_hex=request.headers.get("x-repuwave-signature"),
                            timestamp_raw=request.headers.get("x-repuwave-timestamp"),
                            body=await request.body(),
                            public_key_hex=data.get("public_key"),
                        ),
                        required=self.require_signature,
                    )
                except SignatureProblem as problem:
                    logger.warning(
                        "Repuwave signature rejected for %s: %s", uaid, problem.reason
                    )
                    # 403, not 402: the agent may be trustworthy. What failed is
                    # the proof that this caller IS that agent.
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail={
                            "error": "Signature Rejected",
                            "message": problem.detail,
                            "reason": problem.reason,
                        },
                    ) from None
                
                if not data.get("verified") or data.get("score", 0) < self.min_score:
                    if self.enforce_mode == "enforce":
                        raise HTTPException(
                            status_code=status.HTTP_402_PAYMENT_REQUIRED,
                            detail=self.viral_response
                        )
            else:
                logger.error(f"Core API returned {response.status_code}: {response.text}")
                if response.status_code == 403:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=response.json()
                    )
                if self.enforce_mode == "enforce":
                    raise HTTPException(
                        status_code=status.HTTP_402_PAYMENT_REQUIRED,
                        detail=self.viral_response
                    )
                    
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Repuwave verification error: {e}")
            # Fail-open
            
        return request

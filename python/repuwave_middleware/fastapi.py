import logging
import httpx
from typing import Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

class RepuwaveGuard:
    """
    FastAPI Dependency for Repuwave agent verification.
    """
    def __init__(
        self,
        api_key: str,
        api_url: str = "https://api.repuwave.io/v1",
        minimum_score: int = 50,
        enforce_mode: str = "enforce",
        signup_url: str = "https://repuwave.fasolink.app",
        uaid_header: str = "x-repuwave-uaid"
    ):
        self.api_url = api_url
        self.api_key = api_key
        self.min_score = minimum_score
        self.enforce_mode = enforce_mode
        self.signup_url = signup_url
        self.uaid_header = uaid_header
        
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
                
                # Check cryptographic signature
                signature = request.headers.get("x-repuwave-signature")
                timestamp_str = request.headers.get("x-repuwave-timestamp")
                
                if signature and timestamp_str and data.get("public_key"):
                    import time
                    from nacl.signing import VerifyKey
                    import hashlib
                    import json
                    from nacl.exceptions import BadSignatureError
                    
                    try:
                        timestamp = float(timestamp_str)
                        if abs(time.time() - timestamp) > 15.0:
                            raise HTTPException(
                                status_code=status.HTTP_403_FORBIDDEN,
                                detail={"error": "Trust Window Expired", "message": "Timestamp outside 15s trust window"}
                            )
                        
                        # Reconstruct canonical payload
                        body = await request.body()
                        body_hash = hashlib.sha256(body).hexdigest() if body else ""
                        payload_dict = {"uaid": uaid, "timestamp": timestamp, "body_hash": body_hash}
                        canonical_payload = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
                        payload_hash = hashlib.sha256(canonical_payload.encode("utf-8")).digest()
                        
                        verify_key = VerifyKey(bytes.fromhex(data["public_key"]))
                        verify_key.verify(payload_hash, bytes.fromhex(signature))
                    except BadSignatureError:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail={"error": "Signature Mismatch", "message": "Invalid agent signature"}
                        )
                    except HTTPException:
                        raise
                    except Exception as e:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail={"error": "Invalid Signature Format", "message": str(e)}
                        )
                
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

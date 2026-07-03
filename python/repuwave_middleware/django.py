import logging
import httpx
from django.conf import settings
from django.http import JsonResponse

logger = logging.getLogger(__name__)

class RepuwaveGuard:
    """
    Django middleware for Repuwave agent verification.
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
                
                if not data.get("verified") or data.get("score", 0) < self.min_score:
                    if self.enforce_mode == "enforce":
                        return JsonResponse(self.viral_response, status=402)
            else:
                if self.enforce_mode == "enforce":
                    return JsonResponse(self.viral_response, status=402)
                    
        except Exception as e:
            logger.error(f"Repuwave verification error: {e}")
            # Fail-open
            
        return self.get_response(request)

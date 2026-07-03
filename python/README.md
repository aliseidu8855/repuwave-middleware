# Repuwave Python Middleware

Service-side interceptors for Python applications (Django and FastAPI) to natively enforce Repuwave's trust scores.

## Installation

```bash
pip install repuwave-middleware
```

## Django Usage

In your `settings.py`:

```python
MIDDLEWARE = [
    # ... other middleware
    "repuwave_middleware.django.RepuwaveGuard",
]

REPUWAVE = {
    "API_KEY": "your-service-api-key",
    "API_URL": "https://api.repuwave.io/v1",
    "MINIMUM_SCORE": 70,
    "ENFORCE_MODE": "enforce", # or "audit"
    "SIGNUP_URL": "https://repuwave.fasolink.app",
    "UAID_HEADER": "HTTP_X_REPUWAVE_UAID",
}
```

## FastAPI Usage

```python
from fastapi import FastAPI, Depends
from repuwave_middleware.fastapi import RepuwaveGuard

app = FastAPI()
repuwave_guard = RepuwaveGuard(
    api_key="your-service-api-key",
    minimum_score=70,
    enforce_mode="enforce"
)

@app.get("/protected", dependencies=[Depends(repuwave_guard)])
def protected_route():
    return {"status": "success"}
```

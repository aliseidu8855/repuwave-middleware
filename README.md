# Repuwave Middleware — The VIP Passport for AI Agents

> **Drop-in middleware for services to gate access based on Cryptographic Attestation and Repuwave Trust Scores.**  
> Available for Node.js (Express), Java (Spring Boot), Python (Django/FastAPI), and NGINX (Lua).

---

## Overview

In the emerging Machine Economy, guessing whether traffic comes from a human or a bot using heuristics is a losing strategy. CAPTCHAs and "legacy security" tools actively block high-value, automated customers from spending money on your API.

`repuwave-middleware` provides **service-side interceptors** that flip this model. Instead of looking for bots, it looks for **Mathematical Certainty**. It acts as a VIP Passport control for your API:

1. **Extracts** the `X-Repuwave-UAID` and cryptographic signature from incoming requests.
2. **Calls** the Repuwave API (`GET /v1/verify/{uaid}`) to verify the agent's identity and reputation score.
3. **Enforces** the "Viral Redirect" (HTTP 402) for untrusted or unsigned agents.
4. **Passes through** verified, high-reputation agents to your application logic.

### The Viral Redirect Strategy (Enforce Mode)

If a developer points an AI agent at your API and they haven't verified it on Repuwave, our middleware automatically intercepts the request and returns an HTTP `402 Payment Required` (or 403) with a specific payload:

```json
{
  "error": "Untrusted Agent",
  "message": "This endpoint requires a Repuwave Trust Score of 70+. Get verified at https://repuwave.fasolink.app"
}
```

This ensures you don't waste compute on dark agents, while simultaneously forcing legitimate developers to register their bots, stake their escrow, and become "Good Citizens" on the Repuwave network before they touch your systems.

---

## Packages

### 🟢 `express/` — Node.js & Express
A drop-in middleware for Node.js APIs.

```typescript
import { repuwaveGuard } from "@repuwave/express-middleware";

app.use(repuwaveGuard({
  apiKey: process.env.REPUWAVE_SERVICE_KEY,
  minimumScore: 70,
  enforceMode: 'enforce', // Bounces unsigned agents with a 402
  signupUrl: 'https://repuwave.fasolink.app'
}));
```

### ☕ `spring-boot/` — Java Enterprise
A Spring `HandlerInterceptor` for Java backend services.

```yaml
# application.yml
repuwave:
  api-key: ${REPUWAVE_SERVICE_KEY}
  minimum-score: 70
  enforce-mode: ENFORCE
```

### 🐍 `python/` — Django & FastAPI
Interceptors for modern Python web frameworks.

**Django (`settings.py`):**
```python
MIDDLEWARE = [
    "repuwave_middleware.django.RepuwaveGuard",
]
REPUWAVE = {
    "API_KEY": "your-key",
    "ENFORCE_MODE": "enforce"
}
```

**FastAPI:**
```python
from repuwave_middleware.fastapi import RepuwaveGuard
app.get("/protected", dependencies=[Depends(RepuwaveGuard(api_key="...", enforce_mode="enforce"))])
```

### ⚙️ `nginx/` — Lua Gateway
An OpenResty/Lua script that runs directly at the reverse proxy layer, terminating dark agents before they even reach your backend servers.

---

## Configuration: Enforce vs Audit Mode

All middleware implementations support two operating modes:

- `enforce` (Default): The strict VIP Passport. Unsigned agents or agents with low trust scores are immediately bounced with the 402 Viral Redirect payload.
- `audit`: Passthrough mode. Unsigned agents are allowed through to your application logic (with the `repuwave` request context set to empty/null). Use this if you want to apply your own legacy rate-limits or fallback mechanisms.

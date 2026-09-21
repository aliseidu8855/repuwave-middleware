# Repuwave Middleware

> **Server-side interceptors that check an incoming agent's signature and trust score
> before your application code runs.**
> Express, Spring Boot, Django, FastAPI, NGINX (Lua) and HAProxy.

---

## Overview

Heuristic bot detection has a structural problem: the signals that catch scrapers also
catch the automated customers you want. A CAPTCHA cannot tell the difference between an
agent buying something and an agent scraping something.

`repuwave-middleware` asks a different question. Rather than guessing whether traffic is
automated, it checks whether the agent signed the request and what its record looks like.
Automation stops being the thing you screen for:

1. **Extracts** the `X-Repuwave-UAID` and cryptographic signature from incoming requests.
2. **Calls** the Repuwave API (`GET /v1/verify/{uaid}`) to verify the agent's identity and reputation score.
3. **Rejects** unsigned agents, or agents below your score threshold, with HTTP 402 and a payload telling the developer how to get verified.
4. **Passes through** verified, high-reputation agents to your application logic.

### Enforce mode, and what it returns

An unverified agent gets an actionable rejection rather than a silent 403. The point is
that the developer on the other end can read the response and fix it themselves, without
opening a support ticket with you:

```json
{
  "error": "Untrusted Agent",
  "message": "This endpoint requires a Repuwave Trust Score of 70+. Get verified at https://repuwave.fasolink.app"
}
```

You stop spending compute on unidentified traffic, and the developer gets a specific
next step instead of a dead end.

**Set `signupUrl` to your own docs if you prefer.** The default points at Repuwave, which
is convenient for us and not necessarily right for you — it is a configuration value, not
a requirement.

---

## Packages

### `express/` — Node.js and Express
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

### `spring-boot/` — Java

> **Known broken, and not currently supported. Do not deploy it.**
>
> Two separate problems. It reads a client-supplied `X-Repuwave-UAID` header and
> blocks on the score without verifying any signature, so anyone who knows a
> UAID passes the gate — and UAIDs are public, listed in the key directory. And
> since `GET /v1/verify/{uaid}/` began checking signatures on 21 September 2026,
> it no longer forwards what that endpoint requires, so every call now returns
> 401 and the gate refuses all traffic.
>
> The fix is small: take the agent's `X-Repuwave-Signature`,
> `X-Repuwave-Timestamp` and, for requests with a body, the sha256 of that body,
> and forward all three to `verify` — as `python/`, `express/` and `nginx/` now
> do. It is not done here because this repository has no Java toolchain in CI,
> and shipping unverified code into a security path is how the first problem
> arrived. **It needs a Java build in CI before it can be trusted again.**

A Spring `HandlerInterceptor` for Java backend services.

```yaml
# application.yml
repuwave:
  api-key: ${REPUWAVE_SERVICE_KEY}
  minimum-score: 70
  enforce-mode: ENFORCE
```

### `python/` — Django & FastAPI
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

### `nginx/` — Lua Gateway
An OpenResty/Lua script that runs directly at the reverse proxy layer, terminating dark agents before they even reach your backend servers.

---

## Configuration: Enforce vs Audit Mode

All middleware implementations support two operating modes:

- `enforce` (Default): The strict VIP Passport. Unsigned agents or agents with low trust scores are immediately bounced with the 402 Viral Redirect payload.
- `audit`: Passthrough mode. Unsigned agents are allowed through to your application logic (with the `repuwave` request context set to empty/null). Use this if you want to apply your own legacy rate-limits or fallback mechanisms.

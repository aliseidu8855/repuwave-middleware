# Repuwave NGINX Configuration

> **API Gateway and reverse proxy for the Repuwave infrastructure.**

---

## Overview

NGINX serves as the **primary ingress gateway** for all Repuwave traffic. It handles:

| Responsibility | Implementation |
|---------------|---------------|
| **Rate Limiting** | Sliding window per `Service_API_Key` — configurable via `NGINX_RATE_LIMIT` env var (default: 100 req/s) |
| **TLS Termination** | SSL certificates via Let's Encrypt / cert-manager. All internal traffic is plain HTTP. |
| **Reverse Proxy** | Routes `/v1/` to Django backend (port 8000), `/` to React dashboard (port 3000 in dev, static in prod) |
| **Security Headers** | HSTS, X-Content-Type-Options, X-Frame-Options, CSP |
| **Compression** | gzip for JSON responses and static assets |
| **Request Limits** | Max body size: 1MB, connection timeout: 60s |

## Upstream Architecture

```
Client Request
      │
      ▼
┌──────────────┐
│    NGINX     │
│  (Port 80/443)│
├──────────────┤
│ /v1/*   ──────►  Django API (Port 8000)
│ /health ──────►  Django API (Port 8000)
│ /admin  ──────►  Django API (Port 8000)
│ /*      ──────►  React Dashboard (static files or port 3000)
└──────────────┘
```

## Files

| File | Purpose |
|------|---------|
| `repuwave.conf` | Main server block, upstream definitions, location routing, header hygiene |
| `security.conf` | Security headers (HSTS, CSP, X-Frame-Options, Referrer-Policy) |
| `rate-limiting.conf` | Rate limit zones, burst allowances, status codes |
| `../haproxy/repuwave.cfg` | HAProxy alternative that computes a real JA3 fingerprint |

## Trust boundary — spoofable headers

The Django `AntiAbuseMiddleware` trusts `X-JA3-Fingerprint` to block banned TLS
clients. **This header must be set by the edge and blanked on the way in** —
`repuwave.conf` does exactly that (`proxy_set_header X-JA3-Fingerprint
$repuwave_ja3`, defaulting to `""`). Without a JA3-capable frontend the
fingerprint is simply empty and the JA3 blocklist stays inert; IP rate limiting
and the app-layer velocity throttle still apply.

NGINX cannot compute a true JA3 (MD5 of the TLS ClientHello) unaided. For real
JA3, either front NGINX with the HAProxy config in `../haproxy/repuwave.cfg`
(or a CDN/WAF that injects a JA3), or build NGINX with a JA3 module and wire its
variable into the `map $repuwave_ja3` block.

`X-Repuwave-UAID` is legitimately client-set (agent SDKs send it), so it is
passed through unchanged and treated by the app as an **unauthenticated claim**:
it drives request throttling only and never triggers a reputation penalty.

## Configuration

Key environment variables consumed by the NGINX config:

| Variable | Description | Default |
|----------|-------------|---------|
| `NGINX_RATE_LIMIT` | Requests per second per service key | `100` |
| `NGINX_WORKER_PROCESSES` | Worker process count | `auto` |
| `NGINX_WORKER_CONNECTIONS` | Connections per worker | `1024` |
| `API_UPSTREAM` | Django backend address | `api:8000` |
| `DASHBOARD_UPSTREAM` | Dashboard address (dev) | `dashboard:3000` |

Full NGINX configuration files will be generated in **Section D (DevOps)**.

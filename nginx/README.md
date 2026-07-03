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

## Files (Section D)

| File | Purpose |
|------|---------|
| `repuwave.conf` | Main server block, upstream definitions, location routing |
| `security.conf` | Security headers (HSTS, CSP, X-Frame-Options, Referrer-Policy) |
| `rate-limiting.conf` | Rate limit zones, burst allowances, status codes |

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

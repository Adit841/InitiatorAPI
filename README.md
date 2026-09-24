# SentinelAPI

Zero-Trust API Vulnerability Scanner — hackathon MVP.

> *"Find the API vulnerability before the breach headline does."*

Scans a **sandboxed** demo API (never production without authorization) for high-impact authz and data-exposure issues, then shows severity-ranked findings with reproduction steps.

## Structure

| Path | Role |
|---|---|
| `/api` | Intentionally vulnerable demo API + OpenAPI spec |
| `/scanner` | OpenAPI-driven vulnerability scanner |
| `/dashboard` | Findings report UI (Vite + React) |

## Quick start (3 terminals)

```bash
npm run install:all

# Terminal 1
npm run api

# Terminal 2
npm run scan

# Terminal 3
npm run dashboard
```

- API: http://localhost:4000 (`GET /health`, `GET /openapi.json`)
- Dashboard: http://localhost:5173

See [DEMO.md](./DEMO.md) for the judge walkthrough.

## Seeded accounts

Password for both: `test1234`

| Email | userId | Order |
|---|---|---|
| alice@test.com | u1 | o1 Laptop, 899 |
| bob@test.com | u2 | o2 Phone, 499 |

## What the scanner checks

1. **OpenAPI ingest** — loads `/openapi.json` (or `OPENAPI_PATH` / `OPENAPI_URL`)
2. **IDOR / BOLA** — Alice → Bob's `GET /orders/{id}` and `GET /users/{id}/profile`
3. **Excessive data exposure** — `GET /profile/me` sensitive fields
4. **Auth misconfiguration** — unauthenticated probes + JWT missing `exp`
5. **Rate limiting** — burst traffic without 429/Retry-After
6. **Control** — `GET /orders/mine` should remain secure

Findings are written to `scanner/output/findings.json` and synced into the dashboard via `npm run scan`.

## CI

GitHub Actions (`.github/workflows/ci.yml`) starts the demo API, runs the scanner, uploads `findings.json`, and builds the dashboard on push/PR to `main`.

## Ethics / scope

Only test against this sandboxed demo API or other APIs you are **explicitly authorized** to assess. Do not point SentinelAPI at third-party production systems.

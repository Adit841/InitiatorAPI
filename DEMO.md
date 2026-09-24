# SentinelAPI — Demo Script (≈3 minutes)

> Ethics: only scan the local sandboxed demo API (`localhost:4000`), never production without authorization.

## One-time setup

```bash
npm run install:all
```

## Live demo flow

**Terminal 1 — API**
```bash
npm run api
```

**Terminal 2 — Scan**
```bash
npm run scan
```

**Terminal 3 — Dashboard**
```bash
npm run dashboard
```

Open http://localhost:5173

## Talking points (judges)

1. **Problem** — API breaches from IDOR / data exposure / weak auth; startups lack continuous scanning.
2. **Sandbox API** — intentionally vulnerable store with OpenAPI at `/openapi.json`.
3. **Scanner** — ingests OpenAPI, authenticates two users, tests:
   - Broken object-level authorization (orders + profiles)
   - Excessive data exposure (`passwordHash`, etc.)
   - Auth misconfig (JWT without `exp`, unauthenticated probes)
   - Missing rate limiting
   - Control path that stays secure (`/orders/mine`)
4. **Findings** — severity-ranked JSON with evidence + reproduction + recommendation.
5. **Dashboard** — engineer-friendly triage UI for stakeholders.
6. **CI** — GitHub Action runs the same scan on every push.

## Expected vulnerable findings

| ID | Issue | Severity |
|---|---|---|
| SEN-003 | Excessive data exposure on `/profile/me` | critical |
| SEN-001 | IDOR on `/orders/:id` | high |
| SEN-002 | IDOR on `/users/:id/profile` | high |
| SEN-006 | JWT never expires | medium |
| SEN-007 | Missing rate limiting | medium |

SEN-004 (control) and SEN-005 (auth required) should stay **secure**.

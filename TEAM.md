# Team Contribution Details

**Project:** InitiatorAPI — Zero-Trust API Vulnerability Scanner  
**Team size:** 4  
**Repo modules:** `/api` · `/scanner` · `/dashboard` · presentation

## Contribution matrix

| Member | Primary ownership | Concrete contributions |
|---|---|---|
| **Aditya Gour** | Scanner (`/scanner`) | OpenAPI ingest + attack-plan generation; dual-identity login; IDOR / BOLA, data-exposure, auth-misconfig, and rate-limit checks; ranked `findings.json` with evidence, reproduction steps, and recommendations |
| **Aman Kumar Chauhan** | Demo API (`/api`) | Intentionally vulnerable Express storefront + JWT auth; seeded dual-user dataset for cross-user tests; OpenAPI 3 contract at `GET /openapi.json`; vulnerable + secure control paths the scanner targets |
| **Dilip Kumawat** | Dashboard (`/dashboard`) | Vite + React findings triage UI; severity / status filters; evidence, reproduction, and recommendation views; sync of scanner output into the dashboard |
| **Anjali Kumari** | Presentation | Round 2 PPT/PDF (problem, solution, architecture, features, demo screenshots, future scope); slide readiness before Round 1 ends |

## Ownership by module

### Demo API (`/api`) — Aman Kumar Chauhan
- Intentionally vulnerable Express storefront + JWT auth
- Seeded dual-user dataset for cross-user IDOR tests
- OpenAPI 3 contract served at `GET /openapi.json`
- Vulnerable paths and secure control path (`GET /orders/mine`)

### Scanner (`/scanner`) — Aditya Gour
- OpenAPI ingest + attack-plan generation
- Dual-identity login and vulnerability checks
- Ranked `findings.json` with evidence, reproduction, recommendations

### Dashboard (`/dashboard`) — Dilip Kumawat
- Vite + React findings triage UI
- Severity / status filters and finding detail views
- Sync of scanner output for the demo UI

### Presentation — Anjali Kumari
- Mandatory 8–10 slide PPT/PDF for Round 2
- Problem, solution, architecture, key features, demo screenshots, future scope

## How to present this to judges (30 seconds)

> Four people, one pipeline: Aman owns the sandboxed API and OpenAPI contract, Aditya owns the scanner that plans and proves findings, Dilip owns the triage dashboard, and Anjali owns the presentation deck — so judges see both a working product and a clear story.

## Round 2 role hint (optional)

| Role | Who |
|---|---|
| Live demo driver / narrator | Aditya Gour (scanner) + Dilip Kumawat (dashboard) |
| Architecture / API questions | Aman Kumar Chauhan |
| Slide support | Anjali Kumari |

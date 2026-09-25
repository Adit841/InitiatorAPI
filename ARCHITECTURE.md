# InitiatorAPI — System Architecture

Zero-Trust API vulnerability scanner: a sandboxed demo API, an OpenAPI-driven scanner, a findings dashboard, and CI that runs the same pipeline on every push.

## Diagram (PPT-ready)

Use the **PNG** in PowerPoint (opens everywhere):

![InitiatorAPI system architecture](./docs/architecture.png)

| File | Use |
|---|---|
| [`docs/architecture.png`](./docs/architecture.png) | Drop into PPT / PDF |
| [`docs/architecture.svg`](./docs/architecture.svg) | Editable vector (open in browser) |
| [`docs/architecture.html`](./docs/architecture.html) | Preview in Chrome/Safari |

## High-level system (editable Mermaid)

```mermaid
flowchart LR
  subgraph Local["Local / demo environment"]
    API["Demo API<br/>Express · :4000<br/>OpenAPI + intentional vulns"]
    Scanner["Scanner<br/>Node CLI"]
    Dashboard["Dashboard<br/>Vite + React · :5173"]
    Findings[("findings.json")]
  end

  subgraph CI["GitHub Actions"]
    GHA["scan-and-build workflow"]
  end

  Engineer["Engineer / Judge"] -->|"start"| API
  Engineer -->|"npm run scan"| Scanner
  Scanner -->|"GET /openapi.json<br/>auth as 2 users<br/>run checks"| API
  Scanner -->|"write ranked report"| Findings
  Findings -->|"sync"| Dashboard
  Engineer -->|"triage UI"| Dashboard
  GHA -->|"same pipeline"| API
  GHA -->|"upload artifact"| Findings
```

## Component roles

| Component | Path | Responsibility |
|---|---|---|
| Demo API | `/api` | Intentionally vulnerable storefront with JWT auth, seeded users, and a published OpenAPI contract at `GET /openapi.json` |
| Scanner | `/scanner` | Ingests OpenAPI, authenticates two users, runs IDOR / exposure / auth / rate-limit checks, writes severity-ranked findings |
| Dashboard | `/dashboard` | Engineer-facing triage UI over `findings.json` (severity filter, evidence, reproduction, recommendations) |
| CI | `.github/workflows/ci.yml` | Starts API → runs scanner → syncs findings → uploads artifact → builds dashboard |

## Scan data flow

```mermaid
sequenceDiagram
  participant Eng as Engineer
  participant API as Demo API
  participant Sc as Scanner
  participant FS as findings.json
  participant UI as Dashboard

  Eng->>API: npm run api
  Eng->>Sc: npm run scan
  Sc->>API: GET /health
  Sc->>API: GET /openapi.json
  Sc->>Sc: planFromSpec (IDOR / protected / exposure targets)
  Sc->>API: POST /auth/login (aditya)
  Sc->>API: POST /auth/login (aman)
  Sc->>API: IDOR, exposure, auth, rate-limit probes
  Sc->>FS: write ranked report
  Sc->>UI: sync-findings → public/findings.json
  Eng->>UI: open :5173 and triage
```

## What the scanner checks

```mermaid
flowchart TB
  OpenAPI["OpenAPI ingest"] --> Plan["Attack plan"]
  Plan --> IDOR["IDOR / BOLA<br/>orders + profiles"]
  Plan --> Exposure["Excessive data exposure<br/>/profile/me"]
  Plan --> Auth["Auth misconfig<br/>unauth probes + JWT exp"]
  Plan --> Rate["Rate limiting<br/>burst without 429"]
  Plan --> Control["Control path<br/>/orders/mine stays secure"]
  IDOR --> Report["findings.json"]
  Exposure --> Report
  Auth --> Report
  Rate --> Report
  Control --> Report
```

## Trust & scope boundary

- **In scope:** the local sandbox API (`localhost:4000`) and any API the operator is **explicitly authorized** to assess.
- **Out of scope:** unauthorized third-party / production systems.
- The scanner never mutates production data in the demo path; it authenticates as seeded users and reads endpoints defined by the OpenAPI plan.

## Tech stack

| Layer | Stack |
|---|---|
| API | Node.js, Express, JWT, bcrypt, OpenAPI 3 JSON |
| Scanner | Node.js CLI, native `fetch`, modular checks (`lib/checks.js`) |
| Dashboard | Vite, React |
| CI | GitHub Actions (Node 20), artifact upload of `findings.json` |

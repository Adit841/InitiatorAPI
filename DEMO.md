# InitiatorAPI — 7-Minute Demo Script

> Ethics line (say once, early): *We only scan our local sandboxed demo API — never production without authorization.*

**Before you walk on stage:** three terminals ready, `npm run install:all` already done, dashboard cold-start tested once.

| Terminal | Command | URL |
|---|---|---|
| 1 | `npm run api` | http://localhost:4000 |
| 2 | *(keep free for scan)* | — |
| 3 | `npm run dashboard` | http://localhost:5173 |

Optional: keep [ARCHITECTURE.md](./ARCHITECTURE.md) open on a spare tab if a judge asks for the diagram.

---

## Minute 0:00–0:45 — Brief introduction (stand + 1 slide)

**Say:**

> Most API breaches are not fancy hacks. User A reads User B’s order, or a profile endpoint leaks a password hash. Big companies have AppSec teams. Startups ship an OpenAPI spec and hope.
>
> We built **InitiatorAPI**. It reads the OpenAPI contract, logs in as two real users, and finds the authz and data-exposure bugs that cause breaches — with severity, proof, and a fix. Same scan runs in CI.

**Show:** title slide only. Do **not** narrate the whole deck.

---

## Minute 0:45–1:30 — Architecture + solution (1–2 slides max)

**Say (point at diagram):**

> Three pieces. A **sandboxed demo API** with intentional vulns and a real OpenAPI spec. A **scanner** that plans attacks from that spec. A **dashboard** where engineers triage findings. GitHub Actions runs the identical pipeline on every push.

**Do:** flash [ARCHITECTURE.md](./ARCHITECTURE.md) / architecture slide → immediately cut to live terminals.

---

## Minute 1:30–5:30 — Live demo (core of the slot)

### 1:30–2:00 — Sandbox API is alive

**Do:** Terminal 1 already running. Hit `GET /health` and briefly show `/openapi.json` (title + a couple of paths).

**Say:**

> This is our intentional vulnerable store. Two seeded users — Aditya and Aman. OpenAPI is the contract the scanner trusts.

### 2:00–3:30 — Run the scan

**Do:** Terminal 2 → `npm run scan`. Let console output scroll.

**Talk over the output (don’t wait in silence):**

> Scanner loads OpenAPI, builds a plan, authenticates both users, then checks:
> 1. IDOR on orders and profiles  
> 2. Excessive data exposure on `/profile/me`  
> 3. Auth misconfig — JWT without expiry, unauthenticated probes  
> 4. Missing rate limiting  
> 5. Control path `/orders/mine` — should stay secure  

Point at the console summary when findings print.

### 3:30–5:30 — Dashboard + end-to-end journey

**Do:** Open http://localhost:5173. Expand **INI-003** (critical exposure) and **INI-001** (order IDOR).

**Say while clicking:**

> Engineer journey: run scan → open dashboard → sort by severity → expand a finding → see evidence, reproduction steps, and the recommendation. INI-004 and INI-005 stay secure — so it’s not a noisy “everything is broken” tool.

**Optional 20s flex:** mention CI runs the same scan and uploads `findings.json` as an artifact (show Actions tab only if already open; don’t navigate cold).

---

## Minute 5:30–6:30 — Technical walkthrough (no deep rabbit holes)

**Say:**

> Important engineering choices:
> - **OpenAPI-first** — the attack plan comes from the contract, not a hardcoded URL list  
> - **Dual identity** — real BOLA needs User A vs User B, not a single token  
> - **Evidence-backed findings** — every vulnerable hit has proof + repro + fix  
> - **CI parity** — local `npm run scan` and GitHub Actions share the same path  
> - **Ethics baked in** — sandbox by default; authorize before pointing elsewhere  

**Future scope (15s):** authenticated write/stateful checks, more OWASP API Top 10 coverage, SARIF export for GitHub code scanning, SaaS target onboarding with scoped tokens.

---

## Minute 6:30–7:00 — Close + handoff to Q&A

**Say:**

> That’s InitiatorAPI end-to-end: contract in, ranked findings out, triage UI for the engineer, CI on every push. Happy to take questions on detection, architecture, or scope.

Stop talking. Smile. Wait for judges.

---

## Expected findings (memorize)

| ID | Issue | Severity | Status |
|---|---|---|---|
| INI-003 | Excessive data exposure on `/profile/me` | critical | vulnerable |
| INI-001 | IDOR on `/orders/:id` | high | vulnerable |
| INI-002 | IDOR on `/users/:id/profile` | high | vulnerable |
| INI-006 | JWT never expires | medium | vulnerable |
| INI-007 | Missing rate limiting | medium | vulnerable |
| INI-004 | Control `/orders/mine` | — | **secure** |
| INI-005 | Auth required on protected GETs | — | **secure** |

## If something breaks mid-demo

1. **API down** → `npm run api`, wait for `/health`.
2. **Scan fails** → confirm Terminal 1 is up; rerun `npm run scan`.
3. **Dashboard empty** → rerun `npm run scan` (it syncs findings); hard-refresh `:5173`.
4. **Nuclear fallback** → open `scanner/output/findings.json` and narrate INI-001 + INI-003 from the file.

## Role split during the 7 minutes (adjust to your team)

| Role | Who | Job |
|---|---|---|
| Driver | _______________ | Runs terminals + clicks dashboard |
| Narrator | _______________ | Speaks the script; owns timing |
| Backup | _______________ | Watches clock; jumps in on Q&A / architecture |

## Seeded accounts (if a judge asks)

Password for both: `test1234`

| Email | userId | Order |
|---|---|---|
| aditya@test.com | u1 | o1 Laptop, 899 |
| aman@test.com | u2 | o2 Phone, 499 |

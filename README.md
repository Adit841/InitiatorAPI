# SentinelAPI

Zero-Trust API Vulnerability Scanner — built for [hackathon name].

## Structure
- /api        → vulnerable demo API (Dev A)
- /scanner    → vulnerability scanner engine (Dev B)
- /dashboard  → findings report dashboard (Dev C)

## Team
- Dev A: API
- Dev B: Scanner
- Dev C: Dashboard
- PPT/Docs: [name]

## Demo API (Dev A)

```bash
cd api
npm install
npm run dev
```

Runs at `http://localhost:4000`. `GET /health` returns `{ "ok": true }`.

Seeded accounts (password `test1234` for both):

| Email | userId | Order |
|---|---|---|
| alice@test.com | u1 | o1 Laptop, 899 |
| bob@test.com | u2 | o2 Phone, 499 |

Protected routes need `Authorization: Bearer <token>` from `POST /auth/login` or `POST /auth/register`. Both return `{ userId, token }`.

| Route | Expected behavior |
|---|---|
| `GET /orders/:id` | Vulnerable. Any logged-in user can read any order, including `address`. |
| `GET /users/:id/profile` | Vulnerable. Any logged-in user can read any profile (`userId`, `name`, `email`, `phone`). |
| `GET /profile/me` | Vulnerable. Own profile, but also returns `passwordHash`, `internalNotes`, and `role`. |
| `GET /orders/mine` | Control. Only the caller's orders, and only `orderId`, `item`, `amount`. |

## Scanner (Dev B)

```bash
# API must already be running on :4000
cd scanner
npm run scan
```

Writes ranked findings to `scanner/output/findings.json` for the dashboard.

Checks:
1. IDOR on `GET /orders/:id` (Alice → Bob's `o2`)
2. IDOR on `GET /users/:id/profile` (Alice → Bob's `u2`)
3. Excessive data exposure on `GET /profile/me`
4. Control: `GET /orders/mine` should be secure (nothing flagged)

## Dashboard (Dev C)

```bash
# After a scan has written scanner/output/findings.json
cd dashboard
npm install
npm run sync-findings
npm run dev
```

Opens at `http://localhost:5173`. Shows severity summary, filters, and expandable finding cards (evidence, reproduction steps, recommendations).


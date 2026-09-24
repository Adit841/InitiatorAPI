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


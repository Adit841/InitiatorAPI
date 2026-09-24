const { request } = require("./http");

const SENSITIVE_FIELDS = ["passwordHash", "internalNotes", "role", "password", "ssn", "secret"];

function finding(partial) {
  return {
    id: partial.id,
    title: partial.title,
    severity: partial.severity,
    category: partial.category,
    status: partial.status,
    endpoint: partial.endpoint,
    description: partial.description,
    evidence: partial.evidence || {},
    reproduction: partial.reproduction || [],
    recommendation: partial.recommendation || "",
  };
}

function decodeJwtPayload(token) {
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    const json = Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/** Alice requests Bob's order by ID — ownership should block this. */
async function checkOrderIdor(baseUrl, alice, bobOrderId) {
  const path = `/orders/${bobOrderId}`;
  const res = await request(baseUrl, path, { token: alice.token });

  if (res.status === 200 && res.data?.orderId === bobOrderId && res.data?.userId !== alice.userId) {
    return finding({
      id: "SEN-001",
      title: "Broken object-level authorization on orders",
      severity: "high",
      category: "idor",
      status: "vulnerable",
      endpoint: "GET /orders/:id",
      description:
        "An authenticated user can read another user's order by guessing or enumerating the order ID. The API never checks that the order belongs to the caller.",
      evidence: {
        actor: alice.email,
        requestedOrderId: bobOrderId,
        responseStatus: res.status,
        returnedUserId: res.data.userId,
        returnedFields: Object.keys(res.data),
      },
      reproduction: [
        `POST /auth/login with { "email": "${alice.email}", "password": "<alice-password>" }`,
        `GET ${path} with Authorization: Bearer <alice-token>`,
        `Observe 200 and order owned by userId ${res.data.userId}, not ${alice.userId}`,
      ],
      recommendation:
        "Before returning an order, verify order.userId === authenticated userId. Return 403 or 404 when ownership fails.",
    });
  }

  return finding({
    id: "SEN-001",
    title: "Broken object-level authorization on orders",
    severity: "info",
    category: "idor",
    status: "secure",
    endpoint: "GET /orders/:id",
    description: "Cross-user order access was denied or did not return another user's order.",
    evidence: { responseStatus: res.status, body: res.data },
    reproduction: [],
    recommendation: "",
  });
}

/** Alice requests Bob's profile by ID. */
async function checkProfileIdor(baseUrl, alice, bobUserId) {
  const path = `/users/${bobUserId}/profile`;
  const res = await request(baseUrl, path, { token: alice.token });

  if (res.status === 200 && res.data?.userId === bobUserId && bobUserId !== alice.userId) {
    return finding({
      id: "SEN-002",
      title: "Broken object-level authorization on user profiles",
      severity: "high",
      category: "idor",
      status: "vulnerable",
      endpoint: "GET /users/:id/profile",
      description:
        "Any authenticated user can fetch another user's profile by ID. There is no ownership or permission check on the :id path parameter.",
      evidence: {
        actor: alice.email,
        requestedUserId: bobUserId,
        responseStatus: res.status,
        returnedEmail: res.data.email,
        returnedFields: Object.keys(res.data),
      },
      reproduction: [
        `POST /auth/login as ${alice.email}`,
        `GET ${path} with Authorization: Bearer <alice-token>`,
        `Observe 200 with another user's profile (email: ${res.data.email})`,
      ],
      recommendation:
        "Allow profile access only for the authenticated user, or enforce an explicit admin/peer permission model. Reject cross-user reads with 403.",
    });
  }

  return finding({
    id: "SEN-002",
    title: "Broken object-level authorization on user profiles",
    severity: "info",
    category: "idor",
    status: "secure",
    endpoint: "GET /users/:id/profile",
    description: "Cross-user profile access was denied.",
    evidence: { responseStatus: res.status, body: res.data },
    reproduction: [],
    recommendation: "",
  });
}

/** Own profile should not return password hashes or internal fields. */
async function checkExcessiveDataExposure(baseUrl, alice) {
  const path = "/profile/me";
  const res = await request(baseUrl, path, { token: alice.token });
  const leaked = SENSITIVE_FIELDS.filter((f) => res.data && Object.prototype.hasOwnProperty.call(res.data, f));

  if (res.status === 200 && leaked.length > 0) {
    return finding({
      id: "SEN-003",
      title: "Excessive data exposure on current-user profile",
      severity: "critical",
      category: "excessive_data_exposure",
      status: "vulnerable",
      endpoint: "GET /profile/me",
      description:
        "The current-user profile endpoint returns sensitive server-side fields that should never reach a client, including credential material and internal metadata.",
      evidence: {
        actor: alice.email,
        responseStatus: res.status,
        leakedFields: leaked,
        allFields: Object.keys(res.data || {}),
      },
      reproduction: [
        `POST /auth/login as ${alice.email}`,
        `GET ${path} with Authorization: Bearer <alice-token>`,
        `Inspect JSON for unexpected fields: ${leaked.join(", ")}`,
      ],
      recommendation:
        "Return a strict DTO with only userId, name, and email (plus any intentional public fields). Never serialize passwordHash, internalNotes, or role by default.",
    });
  }

  return finding({
    id: "SEN-003",
    title: "Excessive data exposure on current-user profile",
    severity: "info",
    category: "excessive_data_exposure",
    status: "secure",
    endpoint: "GET /profile/me",
    description: "No sensitive fields were detected on /profile/me.",
    evidence: { responseStatus: res.status, fields: res.data && Object.keys(res.data) },
    reproduction: [],
    recommendation: "",
  });
}

/**
 * Control case: /orders/mine must only return the caller's orders
 * with minimal safe fields. A correct scanner reports this as secure.
 */
async function checkOrdersMineControl(baseUrl, alice) {
  const path = "/orders/mine";
  const res = await request(baseUrl, path, { token: alice.token });
  const orders = res.data?.orders;
  const issues = [];

  if (res.status !== 200 || !Array.isArray(orders)) {
    issues.push("Unexpected response shape or status");
  } else {
    for (const order of orders) {
      if (order.userId && order.userId !== alice.userId) {
        issues.push(`Returned order belonging to ${order.userId}`);
      }
      const keys = Object.keys(order).sort();
      const allowed = ["amount", "item", "orderId"];
      const extra = keys.filter((k) => !allowed.includes(k));
      if (extra.length) issues.push(`Extra fields on order: ${extra.join(", ")}`);
    }
  }

  const bobOnly = Array.isArray(orders) && orders.some((o) => o.orderId === "o2");
  if (bobOnly) issues.push("Alice's /orders/mine included Bob's order o2");

  if (issues.length === 0) {
    return finding({
      id: "SEN-004",
      title: "Ownership check on /orders/mine (control)",
      severity: "info",
      category: "control",
      status: "secure",
      endpoint: "GET /orders/mine",
      description:
        "Control case passed. The endpoint filters by the authenticated user and returns only safe fields (orderId, item, amount). No vulnerability reported.",
      evidence: {
        actor: alice.email,
        responseStatus: res.status,
        orderCount: orders.length,
        sample: orders[0] || null,
      },
      reproduction: [
        `POST /auth/login as ${alice.email}`,
        `GET ${path} with Authorization: Bearer <alice-token>`,
        "Confirm only the caller's orders appear, with no address/userId/password fields",
      ],
      recommendation: "Keep this ownership filter as the pattern for other object endpoints.",
    });
  }

  return finding({
    id: "SEN-004",
    title: "Ownership check on /orders/mine (control)",
    severity: "high",
    category: "control",
    status: "vulnerable",
    endpoint: "GET /orders/mine",
    description: "Control endpoint failed ownership or field-minimization checks.",
    evidence: { issues, body: res.data },
    reproduction: [`GET ${path} as ${alice.email} and inspect response`],
    recommendation: "Filter by req.user.userId and strip sensitive fields before responding.",
  });
}

/** Protected routes from OpenAPI must reject unauthenticated callers. */
async function checkMissingAuth(baseUrl, protectedGets) {
  const targets = (protectedGets || []).slice(0, 6);
  if (targets.length === 0) {
    return finding({
      id: "SEN-005",
      title: "Unauthenticated access to protected endpoints",
      severity: "info",
      category: "auth_misconfig",
      status: "secure",
      endpoint: "OpenAPI protected GETs",
      description: "No protected GET operations were discovered in the OpenAPI plan.",
      evidence: {},
      reproduction: [],
      recommendation: "",
    });
  }

  const open = [];
  const samples = [];
  for (const target of targets) {
    const res = await request(baseUrl, target.path, { method: target.method });
    samples.push({ path: target.path, status: res.status });
    if (res.status === 200) open.push(target.path);
  }

  if (open.length > 0) {
    return finding({
      id: "SEN-005",
      title: "Protected endpoints accept unauthenticated requests",
      severity: "high",
      category: "auth_misconfig",
      status: "vulnerable",
      endpoint: open.map((p) => `GET ${p}`).join(", "),
      description:
        "One or more operations marked as authenticated in the OpenAPI spec returned 200 without a Bearer token.",
      evidence: { openEndpoints: open, samples },
      reproduction: open.map((p) => `GET ${p} with no Authorization header → observe 200`),
      recommendation: "Enforce authentication middleware on every protected route; return 401 when the token is missing.",
    });
  }

  return finding({
    id: "SEN-005",
    title: "Protected endpoints reject unauthenticated requests",
    severity: "info",
    category: "auth_misconfig",
    status: "secure",
    endpoint: "OpenAPI protected GETs",
    description: "Unauthenticated probes against protected GET operations were rejected (non-200).",
    evidence: { samples },
    reproduction: [
      `GET ${targets[0].path} with no Authorization header`,
      "Confirm 401/403 rather than a successful data response",
    ],
    recommendation: "Keep auth middleware consistent across all tagged secure operations.",
  });
}

/** JWT without exp is a weak auth configuration. */
async function checkJwtExpiry(alice) {
  const payload = decodeJwtPayload(alice.token);
  if (payload && payload.exp === undefined) {
    return finding({
      id: "SEN-006",
      title: "JWT access tokens never expire",
      severity: "medium",
      category: "auth_misconfig",
      status: "vulnerable",
      endpoint: "POST /auth/login",
      description:
        "Issued JWTs omit the exp claim, so stolen tokens remain valid indefinitely. This weakens zero-trust session controls.",
      evidence: {
        actor: alice.email,
        claims: Object.keys(payload),
        hasExp: false,
      },
      reproduction: [
        `POST /auth/login as ${alice.email}`,
        "Decode the JWT payload (base64url middle segment)",
        "Observe missing exp claim",
      ],
      recommendation: "Sign tokens with a short exp (and optional refresh flow). Reject expired tokens in auth middleware.",
    });
  }

  return finding({
    id: "SEN-006",
    title: "JWT access tokens include expiry",
    severity: "info",
    category: "auth_misconfig",
    status: "secure",
    endpoint: "POST /auth/login",
    description: "Issued JWT includes an exp claim.",
    evidence: { hasExp: true, exp: payload?.exp },
    reproduction: [],
    recommendation: "",
  });
}

/** Burst requests should eventually see 429 / Retry-After if rate limiting exists. */
async function checkRateLimiting(baseUrl, alice, rateLimitTargets) {
  const target = (rateLimitTargets && rateLimitTargets[0]) || { path: "/orders/mine", method: "GET" };
  const burst = 40;
  const statuses = [];
  let sawRetryAfter = false;

  for (let i = 0; i < burst; i += 1) {
    const res = await fetch(baseUrl + target.path, {
      method: target.method || "GET",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${alice.token}`,
      },
    });
    statuses.push(res.status);
    if (res.headers.get("retry-after")) sawRetryAfter = true;
  }

  const limited = statuses.filter((s) => s === 429 || s === 503).length;
  if (limited === 0 && !sawRetryAfter) {
    return finding({
      id: "SEN-007",
      title: "Missing rate limiting on authenticated endpoint",
      severity: "medium",
      category: "rate_limiting",
      status: "vulnerable",
      endpoint: `${target.method || "GET"} ${target.template || target.path}`,
      description:
        "A rapid burst of authenticated requests completed without 429/503 responses or Retry-After headers, indicating no effective rate limiting.",
      evidence: {
        path: target.path,
        burstSize: burst,
        uniqueStatuses: [...new Set(statuses)],
        successCount: statuses.filter((s) => s >= 200 && s < 300).length,
      },
      reproduction: [
        `POST /auth/login as ${alice.email}`,
        `Send ${burst} rapid ${target.method || "GET"} ${target.path} requests with the same Bearer token`,
        "Observe no 429/503 and no Retry-After header",
      ],
      recommendation:
        "Add per-IP and per-user rate limits (e.g. express-rate-limit). Return 429 with Retry-After under abuse.",
    });
  }

  return finding({
    id: "SEN-007",
    title: "Rate limiting observed on authenticated endpoint",
    severity: "info",
    category: "rate_limiting",
    status: "secure",
    endpoint: `${target.method || "GET"} ${target.template || target.path}`,
    description: "Burst traffic received throttling signals (429/503 or Retry-After).",
    evidence: { limited, sawRetryAfter, uniqueStatuses: [...new Set(statuses)] },
    reproduction: [],
    recommendation: "",
  });
}

function resolveIdorIds(plan, bob) {
  let orderId = "o2";
  let userId = bob.userId;

  for (const t of plan.idorTargets || []) {
    if (t.template.includes("/orders/")) {
      const m = t.path && t.path.match(/\/orders\/([^/]+)/);
      if (m) orderId = decodeURIComponent(m[1]);
    }
    if (t.template.includes("/users/") && t.template.includes("/profile")) {
      const m = t.path && t.path.match(/\/users\/([^/]+)\/profile/);
      if (m) userId = decodeURIComponent(m[1]);
    }
  }

  return { orderId, userId };
}

async function runAllChecks(baseUrl, alice, bob, plan = {}) {
  const { orderId, userId } = resolveIdorIds(plan, bob);

  const findings = await Promise.all([
    checkOrderIdor(baseUrl, alice, orderId),
    checkProfileIdor(baseUrl, alice, userId),
    checkExcessiveDataExposure(baseUrl, alice),
    checkOrdersMineControl(baseUrl, alice),
    checkMissingAuth(baseUrl, plan.protectedGets),
    checkJwtExpiry(alice),
    checkRateLimiting(baseUrl, alice, plan.rateLimitTargets),
  ]);
  return findings;
}

module.exports = { runAllChecks, SENSITIVE_FIELDS };

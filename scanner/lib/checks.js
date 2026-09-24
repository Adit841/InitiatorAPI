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

  // Cross-check: Alice should not be able to pull Bob's order id from "mine"
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

async function runAllChecks(baseUrl, alice, bob) {
  const findings = await Promise.all([
    checkOrderIdor(baseUrl, alice, "o2"),
    checkProfileIdor(baseUrl, alice, bob.userId),
    checkExcessiveDataExposure(baseUrl, alice),
    checkOrdersMineControl(baseUrl, alice),
  ]);
  return findings;
}

module.exports = { runAllChecks, SENSITIVE_FIELDS };

const path = require("path");
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const { users, orders } = require("./seed");

const app = express();
app.use(cors());
app.use(express.json());

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// OpenAPI contract for the scanner (capability: ingest API definition)
app.get("/openapi.json", (req, res) => {
  res.sendFile(path.join(__dirname, "openapi.json"));
});

const SECRET = "hackathon-secret-key";
const TOKEN_TTL = "15m";

// Simple in-memory rate limit (per IP) — enough for the demo secure branch
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 20;
const rateBuckets = new Map();

function rateLimit(req, res, next) {
  const key = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.start >= RATE_WINDOW_MS) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  if (bucket.count > RATE_MAX) {
    const retryAfter = Math.ceil((RATE_WINDOW_MS - (now - bucket.start)) / 1000);
    res.set("Retry-After", String(retryAfter));
    return res.status(429).json({ error: "Too many requests" });
  }
  next();
}

app.use(rateLimit);

// ---- Auth middleware ----
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });
  try {
    const token = header.split(" ")[1];
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

function credentials(req) {
  const body = req.body && typeof req.body === "object" ? req.body : {};
  return {
    email: typeof body.email === "string" ? body.email : "",
    password: typeof body.password === "string" ? body.password : "",
    name: typeof body.name === "string" ? body.name : "",
  };
}

function signToken(userId, email) {
  return jwt.sign({ userId, email }, SECRET, { expiresIn: TOKEN_TTL });
}

function publicProfile(user) {
  return {
    userId: user.userId,
    name: user.name,
    email: user.email,
    phone: user.phone,
  };
}

// ---- Auth routes ----
app.post("/auth/register", (req, res) => {
  const { email, password, name } = credentials(req);
  if (!email || !password || !name) {
    return res.status(400).json({ error: "email, password, and name are required" });
  }
  if (users.some(u => u.email === email)) {
    return res.status(409).json({ error: "Email already registered" });
  }
  const userId = "u" + (users.length + 1);
  users.push({
    userId, email, name, phone: "0000000000",
    passwordHash: bcrypt.hashSync(password, 8), internalNotes: "", role: "user",
  });
  const token = signToken(userId, email);
  res.status(201).json({ userId, token });
});

app.post("/auth/login", (req, res) => {
  const { email, password } = credentials(req);
  if (!email || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }
  const user = users.find(u => u.email === email);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const token = signToken(user.userId, user.email);
  res.json({ userId: user.userId, token });
});

// Registered before /orders/:id so "mine" is not captured as an order id.
app.get("/orders/mine", auth, (req, res) => {
  const mine = orders
    .filter(o => o.userId === req.user.userId)
    .map(o => ({ orderId: o.orderId, item: o.item, amount: o.amount }));
  res.json({ orders: mine });
});

app.get("/orders/:id", auth, (req, res) => {
  const order = orders.find(o => o.orderId === req.params.id);
  if (!order) return res.status(404).json({ error: "Not found" });
  // FIX: block cross-user order reads (IDOR)
  if (order.userId !== req.user.userId) {
    return res.status(403).json({ error: "Forbidden" });
  }
  res.json(order);
});

app.get("/users/:id/profile", auth, (req, res) => {
  const user = users.find(u => u.userId === req.params.id);
  if (!user) return res.status(404).json({ error: "Not found" });
  // FIX: only allow reading your own profile
  if (user.userId !== req.user.userId) {
    return res.status(403).json({ error: "Forbidden" });
  }
  res.json(publicProfile(user));
});

app.get("/profile/me", auth, (req, res) => {
  const user = users.find(u => u.userId === req.user.userId);
  if (!user) return res.status(404).json({ error: "Not found" });
  // FIX: return a safe DTO — never passwordHash / internalNotes / role
  res.json(publicProfile(user));
});

app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Invalid JSON" });
  }
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

app.listen(4000, () => console.log("API running on http://localhost:4000 (secure branch)"));

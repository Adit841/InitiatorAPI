async function request(baseUrl, path, { method = "GET", token, body } = {}) {
  const res = await fetch(baseUrl + path, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }

  return { status: res.status, data, ok: res.ok };
}

async function login(baseUrl, email, password) {
  const res = await request(baseUrl, "/auth/login", {
    method: "POST",
    body: { email, password },
  });
  if (!res.ok || !res.data?.token) {
    throw new Error(`Login failed for ${email}: ${res.status} ${JSON.stringify(res.data)}`);
  }
  return { userId: res.data.userId, token: res.data.token, email };
}

module.exports = { request, login };

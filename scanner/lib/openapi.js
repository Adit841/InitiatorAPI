const path = require("path");
const fs = require("fs");

function requiresAuth(operation, pathItem) {
  const security = operation.security !== undefined ? operation.security : pathItem.security;
  if (security === undefined) return true;
  if (!Array.isArray(security) || security.length === 0) return false;
  return security.some((entry) => Object.keys(entry || {}).length > 0);
}

function paramExample(operation, name) {
  const params = operation.parameters || [];
  const match = params.find((p) => p.name === name && p.in === "path");
  if (!match) return null;
  if (match.example !== undefined) return String(match.example);
  if (match.schema?.example !== undefined) return String(match.schema.example);
  return null;
}

function expandPath(template, examples) {
  return template.replace(/\{([^}]+)\}/g, (_, name) => {
    if (examples[name] === undefined) {
      throw new Error(`Missing example for path param {${name}} in ${template}`);
    }
    return encodeURIComponent(examples[name]);
  });
}

/**
 * Load OpenAPI 3.x from a local file or remote URL.
 * Prefer OPENAPI_PATH / OPENAPI_URL, then {target}/openapi.json.
 */
async function loadOpenApi({ target, filePath, url }) {
  if (filePath) {
    const abs = path.resolve(filePath);
    const raw = fs.readFileSync(abs, "utf8");
    return { spec: JSON.parse(raw), source: `file:${abs}` };
  }

  const endpoints = [];
  if (url) endpoints.push(url);
  if (target) endpoints.push(`${target.replace(/\/$/, "")}/openapi.json`);

  let lastError;
  for (const endpoint of endpoints) {
    try {
      const res = await fetch(endpoint);
      if (!res.ok) {
        lastError = new Error(`HTTP ${res.status} from ${endpoint}`);
        continue;
      }
      const spec = await res.json();
      if (!spec?.openapi && !spec?.swagger) {
        lastError = new Error(`Not an OpenAPI document: ${endpoint}`);
        continue;
      }
      return { spec, source: endpoint };
    } catch (err) {
      lastError = err;
    }
  }

  throw new Error(
    `Could not load OpenAPI spec. Provide OPENAPI_PATH, OPENAPI_URL, or serve /openapi.json. ${lastError?.message || ""}`
  );
}

/**
 * Build a scan plan from the OpenAPI document.
 * Uses path-parameter examples for cross-user probes and tags for check routing.
 */
function planFromSpec(spec) {
  const paths = spec.paths || {};
  const plan = {
    title: spec.info?.title || "API",
    version: spec.info?.version || "",
    pathCount: Object.keys(paths).length,
    protectedGets: [],
    idorTargets: [],
    exposureTargets: [],
    controlTargets: [],
    rateLimitTargets: [],
  };

  for (const [template, pathItem] of Object.entries(paths)) {
    for (const method of Object.keys(pathItem)) {
      if (!["get", "post", "put", "patch", "delete"].includes(method)) continue;
      const operation = pathItem[method];
      if (!operation || typeof operation !== "object") continue;

      const tags = (operation.tags || []).map((t) => t.toLowerCase());
      const authRequired = requiresAuth(operation, pathItem);
      const pathParams = (operation.parameters || [])
        .filter((p) => p.in === "path")
        .map((p) => p.name);

      const examples = {};
      for (const name of pathParams) {
        const ex = paramExample(operation, name);
        if (ex !== null) examples[name] = ex;
      }

      let concretePath = null;
      try {
        concretePath = pathParams.length ? expandPath(template, examples) : template;
      } catch {
        concretePath = null;
      }

      const entry = {
        method: method.toUpperCase(),
        template,
        path: concretePath,
        operationId: operation.operationId || `${method}_${template}`,
        tags,
        authRequired,
      };

      if (method === "get" && authRequired && concretePath) {
        plan.protectedGets.push(entry);
      }

      if (method === "get" && pathParams.length && concretePath && (tags.includes("idor") || pathParams.length > 0)) {
        if (tags.includes("idor") || /\{id\}|\{userId\}|\{orderId\}/i.test(template)) {
          plan.idorTargets.push(entry);
        }
      }

      if (tags.includes("excessive_data_exposure") && concretePath) {
        plan.exposureTargets.push(entry);
      }

      if (tags.includes("control") && concretePath) {
        plan.controlTargets.push(entry);
      }

      if (method === "get" && authRequired && concretePath && !pathParams.length) {
        plan.rateLimitTargets.push(entry);
      }
    }
  }

  if (plan.rateLimitTargets.length === 0 && plan.protectedGets.length) {
    plan.rateLimitTargets = plan.protectedGets.filter((e) => !e.template.includes("{")).slice(0, 1);
  }

  return plan;
}

module.exports = { loadOpenApi, planFromSpec };

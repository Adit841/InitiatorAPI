const path = require("path");
const { login } = require("./lib/http");
const { loadOpenApi, planFromSpec } = require("./lib/openapi");
const { runAllChecks } = require("./lib/checks");
const { buildReport, writeReport, printConsole } = require("./lib/report");

const TARGET = process.env.TARGET_URL || process.argv[2] || "http://localhost:4000";
const OUT_DIR = process.env.OUT_DIR || path.join(__dirname, "output");
const OPENAPI_PATH = process.env.OPENAPI_PATH || "";
const OPENAPI_URL = process.env.OPENAPI_URL || "";

const USERS = {
  alice: { email: "alice@test.com", password: "test1234" },
  bob: { email: "bob@test.com", password: "test1234" },
};

async function main() {
  console.log(`Target: ${TARGET}`);
  console.log("Scope: sandboxed / explicitly provided APIs only — never scan production without authorization.\n");

  const health = await fetch(`${TARGET}/health`).then((r) => r.json()).catch(() => null);
  if (!health?.ok) {
    console.error("API is not reachable. Start it with: cd api && npm run dev");
    process.exit(1);
  }

  const { spec, source } = await loadOpenApi({
    target: TARGET,
    filePath: OPENAPI_PATH || undefined,
    url: OPENAPI_URL || undefined,
  });
  const plan = planFromSpec(spec);
  console.log(`OpenAPI: ${plan.title} v${plan.version} (${plan.pathCount} paths) from ${source}`);
  console.log(
    `Plan: ${plan.idorTargets.length} IDOR targets, ${plan.protectedGets.length} auth-protected GETs, ` +
      `${plan.exposureTargets.length} exposure targets\n`
  );

  const alice = await login(TARGET, USERS.alice.email, USERS.alice.password);
  const bob = await login(TARGET, USERS.bob.email, USERS.bob.password);
  console.log(`Authenticated as ${alice.email} (${alice.userId}) and ${bob.email} (${bob.userId})`);

  const findings = await runAllChecks(TARGET, alice, bob, plan);
  const report = buildReport({
    target: TARGET,
    findings,
    openapi: { source, title: plan.title, version: plan.version, pathCount: plan.pathCount },
  });
  const outPath = writeReport(report, OUT_DIR);

  printConsole(report);
  console.log(`Wrote ${outPath}`);
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});

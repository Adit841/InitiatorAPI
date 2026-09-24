const path = require("path");
const { login } = require("./lib/http");
const { runAllChecks } = require("./lib/checks");
const { buildReport, writeReport, printConsole } = require("./lib/report");

const TARGET = process.env.TARGET_URL || process.argv[2] || "http://localhost:4000";
const OUT_DIR = process.env.OUT_DIR || path.join(__dirname, "output");

const USERS = {
  alice: { email: "alice@test.com", password: "test1234" },
  bob: { email: "bob@test.com", password: "test1234" },
};

async function main() {
  console.log(`Target: ${TARGET}`);

  const health = await fetch(`${TARGET}/health`).then((r) => r.json()).catch(() => null);
  if (!health?.ok) {
    console.error("API is not reachable. Start it with: cd api && npm run dev");
    process.exit(1);
  }

  const alice = await login(TARGET, USERS.alice.email, USERS.alice.password);
  const bob = await login(TARGET, USERS.bob.email, USERS.bob.password);
  console.log(`Authenticated as ${alice.email} (${alice.userId}) and ${bob.email} (${bob.userId})`);

  const findings = await runAllChecks(TARGET, alice, bob);
  const report = buildReport({ target: TARGET, findings });
  const outPath = writeReport(report, OUT_DIR);

  printConsole(report);
  console.log(`Wrote ${outPath}`);
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});

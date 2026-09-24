const fs = require("fs");
const path = require("path");

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function summarize(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length, vulnerable: 0, secure: 0 };
  for (const f of findings) {
    if (summary[f.severity] !== undefined) summary[f.severity] += 1;
    if (f.status === "vulnerable") summary.vulnerable += 1;
    if (f.status === "secure") summary.secure += 1;
  }
  return summary;
}

function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    if (a.status !== b.status) return a.status === "vulnerable" ? -1 : 1;
    return (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
  });
}

function buildReport({ target, findings }) {
  const sorted = sortFindings(findings);
  return {
    tool: "SentinelAPI Scanner",
    scannedAt: new Date().toISOString(),
    target,
    summary: summarize(sorted),
    findings: sorted,
  };
}

function writeReport(report, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, "findings.json");
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
  return outPath;
}

function printConsole(report) {
  console.log(`\nSentinelAPI scan → ${report.target}`);
  console.log(`Scanned at ${report.scannedAt}`);
  console.log(
    `Summary: ${report.summary.vulnerable} vulnerable, ${report.summary.secure} secure ` +
      `(critical=${report.summary.critical}, high=${report.summary.high}, info=${report.summary.info})\n`
  );

  for (const f of report.findings) {
    const badge = f.status === "vulnerable" ? "VULN" : "OK  ";
    console.log(`[${badge}] ${f.severity.toUpperCase().padEnd(8)} ${f.id}  ${f.endpoint}`);
    console.log(`       ${f.title}`);
    if (f.status === "vulnerable") {
      console.log(`       ${f.description}`);
      console.log(`       Repro: ${f.reproduction[f.reproduction.length - 1] || ""}`);
    }
    console.log("");
  }
}

module.exports = { buildReport, writeReport, printConsole };

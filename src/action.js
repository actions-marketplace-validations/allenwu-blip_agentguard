/**
 * action.js — the GitHub Action entrypoint (a thin wrapper over the same
 * analysis the CLI uses).
 *
 * It reads `INPUT_*` env vars (how composite/JS actions receive inputs),
 * runs `analyzeProject`, applies config, writes `$GITHUB_OUTPUT`, optionally
 * writes a SARIF file, and sets the step exit code per `fail-on`.
 *
 * FAIL-OPEN: any internal error prints a loud annotation and exits 0 — a
 * broken linter must never break the host pipeline. NO network. NEVER
 * executes the scanned project. Zero dependencies beyond this package.
 */

import process from "node:process";
import { appendFileSync, writeFileSync } from "node:fs";
import { analyzeProject } from "./analyze.js";
import { formatHuman, formatJson, formatSarif, countBySeverity } from "./format.js";
import { loadConfig, applyConfig } from "./config.js";
import { version } from "./index.js";

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };

function input(name, dflt = "") {
  const v = process.env[`INPUT_${name.toUpperCase().replace(/-/g, "_")}`];
  return v == null || v === "" ? dflt : v;
}
function isTrue(v) {
  return String(v).toLowerCase() === "true";
}
function setOutput(name, value) {
  const f = process.env.GITHUB_OUTPUT;
  const line = `${name}=${String(value).replace(/\n/g, " ")}\n`;
  if (f) {
    try {
      appendFileSync(f, line);
      return;
    } catch {
      /* fall through to stdout */
    }
  }
  process.stdout.write(`::set-output name=${name}::${value}\n`);
}

function main() {
  const VER = version();
  let report;
  try {
    const paths = input("path", ".").split(/\s+/).filter(Boolean);
    const cfgPathRaw = input("config", "");
    const cfgPath = cfgPathRaw || ".agentguardrc.json";
    const loaded = loadConfig(
      // loadConfig handles a missing file gracefully; only pass the explicit
      // one OR the conventional default name (it no-ops if absent).
      cfgPathRaw || cfgPath,
    );
    report = analyzeProject(paths.length ? paths : ["."], {
      includeTests: isTrue(input("include-tests", "false")),
    });
    report.errors = [...loaded.errors, ...report.errors];
    report.findings = applyConfig(report.findings, loaded.config);
  } catch (e) {
    process.stdout.write(
      `::warning title=agentguard::internal error — failing OPEN (exit 0). ${e && e.message ? e.message : e}\n`,
    );
    process.exit(0);
  }

  const counts = countBySeverity(report.findings);
  try {
    if (isTrue(input("sarif", "false"))) {
      const file = input("sarif-file", "agentguard.sarif");
      writeFileSync(file, formatSarif(report, VER));
      setOutput("sarif-file", file);
      process.stdout.write(`agentguard: wrote SARIF to ${file}\n`);
    }
    if (isTrue(input("json", "false"))) {
      process.stdout.write(formatJson(report, VER));
    } else {
      process.stdout.write(formatHuman(report, { color: false, version: VER }) + "\n");
    }
    // GitHub annotations so findings surface inline on the PR.
    for (const f of report.findings) {
      const lvl = f.severity === "critical" || f.severity === "high" ? "error" : "warning";
      process.stdout.write(
        `::${lvl} file=${f.file},line=${f.line},col=${f.column},title=agentguard ${f.ruleId}::${f.message}. ${f.why} Fix: ${f.remediation}\n`,
      );
    }
  } catch (e) {
    process.stdout.write(
      `::warning title=agentguard::internal error while formatting — failing OPEN (exit 0). ${e && e.message ? e.message : e}\n`,
    );
    process.exit(0);
  }

  setOutput("total", report.findings.length);
  setOutput("critical", counts.critical);
  setOutput("high", counts.high);
  setOutput("medium", counts.medium);
  setOutput("low", counts.low);

  const failOn = String(input("fail-on", "high")).toLowerCase();
  if (!(failOn in SEV_RANK) || failOn === "none") {
    setOutput("gate", "pass");
    process.exit(0);
  }
  const threshold = SEV_RANK[failOn];
  const tripped =
    (counts.critical && SEV_RANK.critical >= threshold) ||
    (counts.high && SEV_RANK.high >= threshold) ||
    (counts.medium && SEV_RANK.medium >= threshold) ||
    (counts.low && SEV_RANK.low >= threshold);
  setOutput("gate", tripped ? "fail" : "pass");
  process.exit(tripped ? 1 : 0);
}

try {
  main();
} catch (e) {
  process.stdout.write(
    `::warning title=agentguard::unexpected error — failing OPEN (exit 0). ${e && e.message ? e.message : e}\n`,
  );
  process.exit(0);
}

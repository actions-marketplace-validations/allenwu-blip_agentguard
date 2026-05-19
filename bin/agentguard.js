#!/usr/bin/env node
/**
 * agentguard CLI.
 *
 *   npx agentguard <path...> [--json|--sarif] [--fail-on <sev>]
 *                            [--config <file>] [--include-tests]
 *                            [--sarif-file <path>] [--no-color]
 *
 * Human report by default; `--json` and `--sarif` (v2.1.0, for GitHub code
 * scanning) are machine-readable. Exit codes make it a usable CI gate.
 *
 * FAIL-OPEN by design: if agentguard ITSELF errors (a bug, an unreadable
 * tree), it prints a loud diagnostic and exits 0. A broken linter must not
 * block every build. For HARD enforcement, run with `--fail-on` as a
 * required status check so a missing/zero result is visible.
 *
 * Exit codes:
 *   0  scan completed, gate not tripped.  ALSO: internal error (fail-open).
 *   1  scan completed and a finding met/exceeded --fail-on (default: high).
 *   2  usage error (bad arguments).
 *
 * NO network. NO API key. NEVER executes the scanned project.
 */

import process from "node:process";
import { writeFileSync, existsSync } from "node:fs";
import { analyzeProject } from "../src/analyze.js";
import { formatHuman, formatJson, formatSarif, countBySeverity } from "../src/format.js";
import { loadConfig, applyConfig } from "../src/config.js";
import { version } from "../src/index.js";

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
const VER = version();

function usage() {
  return `agentguard v${VER} — static linter for MISSING guards on AI-agent tool calls

USAGE
  npx agentguard <path...> [options]

  <path...>            one or more files or directories to scan (an agent
                       codebase: tool-calling source). Defaults to "."

OPTIONS
  --json               machine-readable JSON instead of the human report
  --sarif              SARIF v2.1.0 to stdout (GitHub code scanning)
  --sarif-file <path>  write SARIF to a file (implies SARIF generation)
  --fail-on <sev>      exit 1 if any finding is >= sev:
                       critical | high | medium | low | none  (default: high)
  --config <file>      path to a JSON config (severities / ignore / allow).
                       Auto-loaded from ./.agentguardrc.json if present.
  --include-tests      also scan test/spec/fixture files (off by default —
                       agent handlers in tests are usually intentional demos)
  --no-color           disable ANSI color
  -h, --help           this help
  -v, --version        print version

WHAT IT DOES
  Parses your code with a real JS/TS AST (not regex) and flags a
  side-effectful sink (shell/exec, sensitive fs write/read, outbound
  network, dynamic eval) that is reachable from an AGENT TOOL HANDLER with
  the model-controlled input flowing into it AND no guard on the path
  (input schema/validation, allowlist/denylist, or human-confirmation).
  Guarded code and non-agent code are intentionally SILENT — low false
  positives is the product. See the README "conservative philosophy".`;
}

function parseArgs(argv) {
  const opts = {
    paths: [],
    json: false,
    sarif: false,
    sarifFile: null,
    failOn: "high",
    config: null,
    includeTests: false,
    color: process.stdout.isTTY === true,
    help: false,
    versionOnly: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "-h":
      case "--help":
        opts.help = true;
        break;
      case "-v":
      case "--version":
        opts.versionOnly = true;
        break;
      case "--json":
        opts.json = true;
        break;
      case "--sarif":
        opts.sarif = true;
        break;
      case "--sarif-file":
        opts.sarifFile = argv[++i];
        opts.sarif = true;
        break;
      case "--fail-on":
        opts.failOn = String(argv[++i] || "").toLowerCase();
        break;
      case "--config":
        opts.config = argv[++i];
        break;
      case "--include-tests":
        opts.includeTests = true;
        break;
      case "--no-color":
        opts.color = false;
        break;
      case "--color":
        opts.color = true;
        break;
      default:
        if (a && a.startsWith("--")) return { error: `unknown option: ${a}` };
        if (a) opts.paths.push(a);
    }
  }
  if (opts.paths.length === 0) opts.paths = ["."];
  if (!(opts.failOn in SEV_RANK)) {
    return { error: `--fail-on must be one of: ${Object.keys(SEV_RANK).join(", ")}` };
  }
  return { opts };
}

// Resolve the config path: an explicit --config wins; otherwise auto-load
// ./.agentguardrc.json (or .agentguardrc) if present. Config is OPTIONAL —
// a missing file is not an error (loadConfig degrades to defaults).
function resolveConfigPath(explicit) {
  if (explicit) return explicit;
  for (const c of [".agentguardrc.json", ".agentguardrc"]) {
    if (existsSync(c)) return c;
  }
  return null;
}

async function main() {
  const { opts, error } = parseArgs(process.argv.slice(2));
  if (error) {
    process.stderr.write(`error: ${error}\n\n${usage()}\n`);
    process.exit(2);
  }
  if (opts.help) {
    process.stdout.write(usage() + "\n");
    process.exit(0);
  }
  if (opts.versionOnly) {
    process.stdout.write(VER + "\n");
    process.exit(0);
  }

  // ---- Everything below is wrapped: a crash here FAILS OPEN (exit 0). ----
  let report;
  let config = { severities: {}, ignore: [], allow: [] };
  let configErrors = [];
  try {
    const cfgPath = resolveConfigPath(opts.config);
    const loaded = loadConfig(cfgPath);
    config = loaded.config;
    configErrors = loaded.errors;

    report = analyzeProject(opts.paths, { includeTests: opts.includeTests });
    report.errors = [...configErrors, ...report.errors];
    report.findings = applyConfig(report.findings, config);
  } catch (e) {
    // Fail-open: loud diagnostic, exit 0, never break the host pipeline.
    process.stderr.write(
      `agentguard: internal error — failing OPEN (exit 0). This is a bug; ` +
        `please report it with the input. Details: ${e && e.stack ? e.stack : e}\n`,
    );
    process.exit(0);
  }

  try {
    if (opts.sarif) {
      const sarif = formatSarif(report, VER);
      if (opts.sarifFile) {
        writeFileSync(opts.sarifFile, sarif);
        process.stderr.write(`agentguard: wrote SARIF to ${opts.sarifFile}\n`);
      } else {
        process.stdout.write(sarif);
      }
    }
    if (opts.json) {
      process.stdout.write(formatJson(report, VER));
    } else if (!opts.sarif || opts.sarifFile) {
      process.stdout.write(formatHuman(report, { color: opts.color, version: VER }) + "\n");
    }
  } catch (e) {
    process.stderr.write(
      `agentguard: internal error while formatting — failing OPEN (exit 0). ${e && e.stack ? e.stack : e}\n`,
    );
    process.exit(0);
  }

  // ---- Gate ----
  if (opts.failOn === "none") process.exit(0);
  const threshold = SEV_RANK[opts.failOn];
  const counts = countBySeverity(report.findings);
  const tripped =
    (counts.critical && SEV_RANK.critical >= threshold) ||
    (counts.high && SEV_RANK.high >= threshold) ||
    (counts.medium && SEV_RANK.medium >= threshold) ||
    (counts.low && SEV_RANK.low >= threshold);
  process.exit(tripped ? 1 : 0);
}

main().catch((e) => {
  // Last-resort fail-open.
  process.stderr.write(
    `agentguard: unexpected error — failing OPEN (exit 0). ${e && e.stack ? e.stack : e}\n`,
  );
  process.exit(0);
});

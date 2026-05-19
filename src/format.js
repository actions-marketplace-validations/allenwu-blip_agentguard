/**
 * format.js — pure presenters: human report, --json, SARIF v2.1.0.
 *
 * No I/O. Deterministic field order so snapshots/SARIF diffs are stable.
 */

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

// ─────────────────────────────── human ──────────────────────────────────

const COLORS = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
};
function paint(on, c, s) {
  return on ? `${COLORS[c]}${s}${COLORS.reset}` : s;
}
const SEV_COLOR = { critical: "red", high: "red", medium: "yellow", low: "cyan" };

/**
 * @param {{roots:string[],findings:object[],scannedFiles:string[],errors:string[]}} report
 * @param {{color?:boolean, version?:string}} [opt]
 * @returns {string}
 */
export function formatHuman(report, opt = {}) {
  const color = !!opt.color;
  const L = [];
  const { findings, scannedFiles, errors } = report;
  L.push(
    paint(color, "bold", `agentguard${opt.version ? " v" + opt.version : ""}`) +
      paint(color, "gray", `  —  scanned ${scannedFiles.length} file(s)`),
  );
  L.push("");

  if (findings.length === 0) {
    L.push(paint(color, "bold", "  No unguarded agent tool-call sinks found.") + "");
    L.push(
      paint(
        color,
        "gray",
        "  (agentguard only reports a sink reachable from model-controlled tool input with no validation/allowlist/confirmation on the path. Guarded and non-agent code is intentionally silent — see README \"conservative philosophy\".)",
      ),
    );
  } else {
    const counts = countBySeverity(findings);
    L.push(
      paint(color, "bold", `  ${findings.length} finding(s): `) +
        `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low`,
    );
    L.push("");
    for (const f of findings) {
      const sev = paint(color, SEV_COLOR[f.severity] || "yellow", f.severity.toUpperCase().padEnd(8));
      L.push(`  ${sev} ${paint(color, "bold", f.ruleId)}  ${f.file}:${f.line}:${f.column}`);
      L.push(`    ${paint(color, "bold", f.message)}`);
      L.push(`    ${paint(color, "gray", "sink:")} ${f.sink}`);
      L.push(`    ${paint(color, "gray", "why: ")} ${wrap(f.why, 4)}`);
      L.push(`    ${paint(color, "gray", "fix: ")} ${wrap(f.remediation, 4)}`);
      L.push("");
    }
  }

  if (errors.length) {
    L.push(paint(color, "yellow", `  ${errors.length} diagnostic(s) (scan continued — fail-open):`));
    for (const e of errors.slice(0, 20)) L.push(paint(color, "gray", `    - ${e}`));
    if (errors.length > 20) L.push(paint(color, "gray", `    (+${errors.length - 20} more)`));
    L.push("");
  }
  return L.join("\n");
}

function wrap(s, indent) {
  const width = 76;
  const pad = " ".repeat(indent);
  const words = String(s).split(/\s+/);
  let line = "";
  const out = [];
  for (const w of words) {
    if ((line + " " + w).trim().length > width) {
      out.push(line.trim());
      line = w;
    } else line += " " + w;
  }
  if (line.trim()) out.push(line.trim());
  return out.join("\n" + pad);
}

export function countBySeverity(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) if (c[f.severity] != null) c[f.severity]++;
  return c;
}

// ──────────────────────────────── json ──────────────────────────────────

export function formatJson(report, version = "0.1.0") {
  const counts = countBySeverity(report.findings);
  return (
    JSON.stringify(
      {
        tool: "agentguard",
        version,
        roots: report.roots,
        summary: {
          total: report.findings.length,
          ...counts,
          scannedFiles: report.scannedFiles.length,
          errors: report.errors.length,
        },
        findings: report.findings.map((f) => ({
          id: f.id,
          ruleId: f.ruleId,
          severity: f.severity,
          file: f.file,
          line: f.line,
          column: f.column,
          sink: f.sink,
          message: f.message,
          why: f.why,
          remediation: f.remediation,
        })),
        errors: report.errors,
      },
      null,
      2,
    ) + "\n"
  );
}

// ─────────────────────────────── SARIF ──────────────────────────────────
// SARIF `level` ∈ error|warning|note|none; fine-grained severity rides in
// properties.security-severity (0.0–10.0, GitHub code-scanning convention).

const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note" };
const SECURITY_SEVERITY = { critical: "9.5", high: "8.0", medium: "5.0", low: "3.0" };

/**
 * SARIF v2.1.0 — the format `github/codeql-action/upload-sarif` ingests so
 * findings render in the GitHub "Code scanning" tab. Pure, deterministic
 * field order. partialFingerprints carries the stable finding id so GitHub
 * de-dupes/tracks a finding across runs.
 *
 * @param {object} report
 * @param {string} [version]
 * @returns {string} SARIF JSON
 */
export function formatSarif(report, version = "0.1.0") {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const seen = new Map();
  for (const f of findings) {
    if (!seen.has(f.ruleId)) {
      seen.set(f.ruleId, {
        id: f.ruleId,
        name: f.ruleId,
        shortDescription: { text: f.message },
        fullDescription: { text: f.why },
        defaultConfiguration: { level: SARIF_LEVEL[f.severity] || "warning" },
        properties: {
          tags: ["security", "ai-agent", "tool-calling"],
          "security-severity": SECURITY_SEVERITY[f.severity] || "5.0",
        },
      });
    }
  }
  const rules = [...seen.values()];
  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));

  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
    level: SARIF_LEVEL[f.severity] || "warning",
    message: { text: `${f.message}. ${f.why} Fix: ${f.remediation}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: String(f.file).replace(/\\/g, "/").replace(/^\.\//, ""),
            uriBaseId: "SRCROOT",
          },
          region: {
            startLine: Math.max(1, Number(f.line) || 1),
            startColumn: Math.max(1, Number(f.column) || 1),
          },
        },
      },
    ],
    partialFingerprints: { agentguardFindingId: f.id },
    properties: { severity: f.severity },
  }));

  const sarif = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "agentguard",
            informationUri: "https://github.com/portfolio-foundry/agent-guard-lint",
            version,
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            toolExecutionNotifications: (report.errors || []).map((e) => ({
              level: "warning",
              message: { text: String(e) },
            })),
          },
        ],
        columnKind: "utf16CodeUnits",
      },
    ],
  };
  return JSON.stringify(sarif, (_k, v) => (v === undefined ? undefined : v), 2) + "\n";
}

export { SEVERITY_RANK };

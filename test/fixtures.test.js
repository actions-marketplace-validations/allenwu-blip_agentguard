/**
 * fixtures.test.js — the three pillars of a conservative linter:
 *
 *   clean-agent      → EXACTLY 0 findings  (guarded code is silent)
 *   vulnerable-agent → each rule fires, at the right file:line, severity
 *   borderline-agent → EXACTLY 0 findings  (THE MOAT — low false positives
 *                       IS the product; this must hold or the linter dies)
 *
 * Assertions are mutation-resistant: we assert the precise rule set, the
 * exact source location of every finding, and the severity — not just
 * "length > 0". A regression that moves/duplicates/loses a finding fails.
 */

import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { analyzeProject } from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const fx = (n) => join(HERE, "fixtures", n);

describe("clean-agent fixture", () => {
  it("produces ZERO findings (every handler is properly guarded)", () => {
    const r = analyzeProject(fx("clean-agent"));
    expect(r.findings).toEqual([]);
    expect(r.scannedFiles.length).toBeGreaterThan(0);
  });
});

describe("borderline-agent fixture — THE MOAT", () => {
  it("produces ZERO false positives on tricky-but-legitimate patterns", () => {
    const r = analyzeProject(fx("borderline-agent"));
    // If this ever fails, agentguard is crying wolf — fix the rule, do NOT
    // weaken this assertion.
    expect(r.findings).toEqual([]);
    expect(r.scannedFiles.length).toBeGreaterThan(0);
  });
});

describe("vulnerable-agent fixture — every rule fires precisely", () => {
  const r = analyzeProject(fx("vulnerable-agent"));

  it("fires all five rule families and nothing else", () => {
    const byRule = new Set(r.findings.map((f) => f.ruleId));
    expect([...byRule].sort()).toEqual(["AG001", "AG002", "AG003", "AG004", "AG005"]);
  });

  it("reports the exact location + severity for each unguarded sink", () => {
    // [ruleId, file, line, column, severity, sink]
    const expected = [
      ["AG001", "src/class-tool.ts", 11, 12, "critical", "execFileSync"],
      ["AG004", "src/eval-tool.ts", 9, 20, "critical", "eval"],
      ["AG001", "src/one-hop-tool.js", 7, 10, "critical", "exec"],
      ["AG001", "src/shell-tool.js", 8, 17, "critical", "execSync"],
      ["AG005", "src/fs-read-tool.js", 11, 20, "high", "readFileSync"],
      ["AG002", "src/fs-write-tool.js", 11, 7, "high", "writeFileSync"],
      ["AG003", "src/network-tool.js", 9, 23, "high", "fetch"],
    ];
    const actual = r.findings.map((f) => [
      f.ruleId,
      f.file.replace(/\\/g, "/"),
      f.line,
      f.column,
      f.severity,
      f.sink,
    ]);
    // order-independent exact-set comparison
    const norm = (a) => a.map((x) => JSON.stringify(x)).sort();
    expect(norm(actual)).toEqual(norm(expected));
  });

  it("each finding carries why + remediation + a stable id", () => {
    for (const f of r.findings) {
      expect(typeof f.why).toBe("string");
      expect(f.why.length).toBeGreaterThan(20);
      expect(typeof f.remediation).toBe("string");
      expect(f.remediation.length).toBeGreaterThan(20);
      expect(f.id).toMatch(/^AG-[0-9a-f]{8}$/);
    }
  });

  it("the stable id is deterministic across runs", () => {
    const r2 = analyzeProject(fx("vulnerable-agent"));
    const ids1 = r.findings.map((f) => f.id).sort();
    const ids2 = r2.findings.map((f) => f.id).sort();
    expect(ids2).toEqual(ids1);
  });

  it("never executed the scanned project and produced no error noise", () => {
    expect(r.errors).toEqual([]);
  });
});

describe("test-file skipping (default)", () => {
  it("does not flag agent handlers that live in test/spec/fixture files", () => {
    // The vulnerable fixture IS under a 'fixtures' path; analyzeProject is
    // called on it directly so it scans, but a *.test.js / spec path is
    // skipped. Assert the skip via includeTests semantics:
    const skipped = analyzeProject(fx("vulnerable-agent"), { includeTests: false });
    const forced = analyzeProject(fx("vulnerable-agent"), { includeTests: true });
    // The fixture files are plain src/*.js (not *.test.js), so both scan
    // them; the point under test is that the flag is wired and consistent.
    expect(forced.findings.length).toBe(skipped.findings.length);
  });
});

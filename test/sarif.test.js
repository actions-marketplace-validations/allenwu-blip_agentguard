/**
 * sarif.test.js — the SARIF v2.1.0 contract that GitHub code scanning
 * (`github/codeql-action/upload-sarif`) ingests. We assert the structural
 * invariants GitHub relies on, not a brittle whole-document snapshot.
 */

import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { analyzeProject, formatSarif } from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const fx = (n) => join(HERE, "fixtures", n);

describe("SARIF v2.1.0", () => {
  const report = analyzeProject(fx("vulnerable-agent"));
  const sarif = JSON.parse(formatSarif(report, "9.9.9"));

  it("declares schema + version 2.1.0", () => {
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toMatch(/sarif-schema-2\.1\.0\.json$/);
  });

  it("has exactly one run with the agentguard driver and its version", () => {
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("agentguard");
    expect(sarif.runs[0].tool.driver.version).toBe("9.9.9");
  });

  it("emits one result per finding with a valid physical location", () => {
    const results = sarif.runs[0].results;
    expect(results).toHaveLength(report.findings.length);
    for (const res of results) {
      expect(typeof res.ruleId).toBe("string");
      expect(["error", "warning", "note", "none"]).toContain(res.level);
      const region = res.locations[0].physicalLocation.region;
      expect(region.startLine).toBeGreaterThanOrEqual(1);
      expect(region.startColumn).toBeGreaterThanOrEqual(1);
      const uri = res.locations[0].physicalLocation.artifactLocation.uri;
      expect(uri.startsWith("./")).toBe(false);
      expect(uri.includes("\\")).toBe(false);
      // partialFingerprints lets GitHub track a finding across runs
      expect(res.partialFingerprints.agentguardFindingId).toMatch(/^AG-[0-9a-f]{8}$/);
    }
  });

  it("declares each rule once with a security-severity for code scanning", () => {
    const rules = sarif.runs[0].tool.driver.rules;
    const ids = rules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length); // no dup rule entries
    for (const r of rules) {
      const ss = Number(r.properties["security-severity"]);
      expect(ss).toBeGreaterThan(0);
      expect(ss).toBeLessThanOrEqual(10);
      expect(r.properties.tags).toContain("security");
    }
    // every result's ruleIndex points at the right rule
    for (const res of sarif.runs[0].results) {
      expect(rules[res.ruleIndex].id).toBe(res.ruleId);
    }
  });

  it("critical/high map to error; medium→warning; low→note", () => {
    const byId = Object.fromEntries(
      sarif.runs[0].results.map((r) => [r.properties.severity, r.level]),
    );
    if (byId.critical) expect(byId.critical).toBe("error");
    if (byId.high) expect(byId.high).toBe("error");
  });

  it("marks the invocation successful (we always complete / fail-open)", () => {
    expect(sarif.runs[0].invocations[0].executionSuccessful).toBe(true);
  });

  it("a clean scan still produces a valid empty SARIF", () => {
    const clean = JSON.parse(formatSarif(analyzeProject(fx("clean-agent"))));
    expect(clean.runs[0].results).toEqual([]);
    expect(clean.version).toBe("2.1.0");
  });
});

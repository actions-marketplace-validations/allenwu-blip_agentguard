/**
 * cli.test.js — the CLI as a user invokes it: exit codes (CI gate),
 * --json / --sarif / --fail-on, and the fail-OPEN contract.
 */

import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const BIN = join(HERE, "..", "bin", "agentguard.js");
const fx = (n) => join(HERE, "fixtures", n);

function cli(args) {
  try {
    const stdout = execFileSync(process.execPath, [BIN, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { code: 0, stdout };
  } catch (e) {
    return { code: e.status ?? 1, stdout: e.stdout || "", stderr: e.stderr || "" };
  }
}

describe("exit codes (the CI gate)", () => {
  it("clean fixture → exit 0", () => {
    const r = cli([fx("clean-agent"), "--no-color"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("No unguarded agent tool-call sinks found");
  });

  it("borderline fixture → exit 0 (no false positives)", () => {
    const r = cli([fx("borderline-agent"), "--no-color"]);
    expect(r.code).toBe(0);
  });

  it("vulnerable fixture with default --fail-on high → exit 1", () => {
    const r = cli([fx("vulnerable-agent"), "--no-color"]);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("AG001");
  });

  it("--fail-on none never gates (exit 0 even with findings)", () => {
    const r = cli([fx("vulnerable-agent"), "--fail-on", "none", "--no-color"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("finding(s)");
  });

  it("--fail-on critical gates only on critical (vulnerable has criticals → 1)", () => {
    const r = cli([fx("vulnerable-agent"), "--fail-on", "critical", "--no-color"]);
    expect(r.code).toBe(1);
  });

  it("bad --fail-on value → usage error exit 2", () => {
    const r = cli([fx("clean-agent"), "--fail-on", "bogus"]);
    expect(r.code).toBe(2);
  });

  it("unknown option → usage error exit 2", () => {
    const r = cli(["--frobnicate"]);
    expect(r.code).toBe(2);
  });
});

describe("--json", () => {
  it("emits valid, schema-stable JSON", () => {
    const r = cli([fx("vulnerable-agent"), "--json", "--fail-on", "none"]);
    const j = JSON.parse(r.stdout);
    expect(j.tool).toBe("agentguard");
    expect(j.summary.total).toBe(7);
    expect(j.summary.critical).toBe(4);
    expect(j.summary.high).toBe(3);
    expect(Array.isArray(j.findings)).toBe(true);
    for (const f of j.findings) {
      expect(f).toHaveProperty("id");
      expect(f).toHaveProperty("ruleId");
      expect(f).toHaveProperty("severity");
      expect(f).toHaveProperty("file");
      expect(f).toHaveProperty("line");
      expect(f).toHaveProperty("remediation");
    }
  });
});

describe("--help / --version", () => {
  it("--version prints the package version and exits 0", () => {
    const r = cli(["--version"]);
    expect(r.code).toBe(0);
    expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });
  it("--help exits 0 and explains the conservative philosophy", () => {
    const r = cli(["--help"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/conservative/i);
    expect(r.stdout).toMatch(/SARIF/);
  });
});

describe("fail-OPEN contract", () => {
  it("a non-existent path does not crash the process (exit 0, diagnostic)", () => {
    const r = cli(["./definitely/not/here", "--no-color"]);
    // path-does-not-exist is a diagnostic, scan continues, no findings → 0
    expect(r.code).toBe(0);
    expect(r.stdout + (r.stderr || "")).toMatch(/does not exist/);
  });
});

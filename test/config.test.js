/**
 * config.test.js — optional config: severity remap, rule-off, ignore globs,
 * accepted-id allowlist. And: a malformed config never throws (fail-open).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { writeFileSync, rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, applyConfig, DEFAULT_CONFIG } from "../src/config.js";

const F = [
  { id: "AG-aaaaaaaa", ruleId: "AG001", severity: "critical", file: "src/a.js" },
  { id: "AG-bbbbbbbb", ruleId: "AG003", severity: "high", file: "legacy/old.js" },
  { id: "AG-cccccccc", ruleId: "AG005", severity: "high", file: "src/b.ts" },
];

describe("loadConfig", () => {
  let dir;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "agcfg-"));
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("returns defaults when no path is given", () => {
    expect(loadConfig(null).config).toEqual(DEFAULT_CONFIG);
  });

  it("missing config file → defaults + diagnostic, never throws", () => {
    const { config, errors } = loadConfig(join(dir, "nope.json"));
    expect(config).toEqual(DEFAULT_CONFIG);
    expect(errors.join()).toMatch(/not found/);
  });

  it("invalid JSON → defaults + diagnostic, never throws", () => {
    const p = join(dir, "bad.json");
    writeFileSync(p, "{ not valid");
    const { config, errors } = loadConfig(p);
    expect(config).toEqual(DEFAULT_CONFIG);
    expect(errors.join()).toMatch(/invalid config JSON/);
  });

  it("parses severities / ignore / allow and rejects invalid severities", () => {
    const p = join(dir, "ok.json");
    writeFileSync(
      p,
      JSON.stringify({
        severities: { AG003: "medium", AG005: "off", AG001: "not-a-sev" },
        ignore: ["legacy/**"],
        allow: ["AG-aaaaaaaa"],
      }),
    );
    const { config, errors } = loadConfig(p);
    expect(config.severities.AG003).toBe("medium");
    expect(config.severities.AG005).toBe("off");
    expect(config.severities.AG001).toBeUndefined();
    expect(config.ignore).toEqual(["legacy/**"]);
    expect(config.allow).toEqual(["AG-aaaaaaaa"]);
    expect(errors.join()).toMatch(/invalid severity/);
  });
});

describe("applyConfig", () => {
  it("remaps severity for a rule", () => {
    const out = applyConfig(F, { severities: { AG003: "low" }, ignore: [], allow: [] });
    expect(out.find((f) => f.ruleId === "AG003").severity).toBe("low");
  });

  it('drops findings for a rule set to "off"', () => {
    const out = applyConfig(F, { severities: { AG005: "off" }, ignore: [], allow: [] });
    expect(out.some((f) => f.ruleId === "AG005")).toBe(false);
    expect(out).toHaveLength(2);
  });

  it("drops paths matching an ignore glob (anchored, ** and *)", () => {
    const out = applyConfig(F, { severities: {}, ignore: ["legacy/**"], allow: [] });
    expect(out.some((f) => f.file.startsWith("legacy/"))).toBe(false);
    const out2 = applyConfig(F, { severities: {}, ignore: ["src/*.js"], allow: [] });
    expect(out2.some((f) => f.file === "src/a.js")).toBe(false);
    expect(out2.some((f) => f.file === "src/b.ts")).toBe(true); // *.js only
  });

  it("drops accepted (allowlisted) finding ids without hiding others", () => {
    const out = applyConfig(F, { severities: {}, ignore: [], allow: ["AG-aaaaaaaa"] });
    expect(out.some((f) => f.id === "AG-aaaaaaaa")).toBe(false);
    expect(out).toHaveLength(2);
  });

  it("is a no-op with the default empty config", () => {
    expect(applyConfig(F, DEFAULT_CONFIG)).toEqual(F);
  });
});

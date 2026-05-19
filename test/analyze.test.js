/**
 * analyze.test.js — the filesystem layer hardening (modeled on the
 * conservative discipline of this operation's mcp-audit-cli): symlinks are
 * never followed, oversized/minified/binary blobs are skipped, the scan
 * cannot be steered outside the target, and nothing ever throws.
 *
 * Plus DOGFOOD: agentguard scanning its own source must be 0 findings.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  mkdirSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeProject } from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

let dir;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agan-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("filesystem hardening", () => {
  it("never throws on a non-existent path (fail-open diagnostic)", () => {
    const r = analyzeProject(join(dir, "nope"));
    expect(r.findings).toEqual([]);
    expect(r.errors.join()).toMatch(/does not exist/);
  });

  it("a single unparseable file degrades the scan, never aborts it", () => {
    writeFileSync(join(dir, "broken.js"), "server.tool('r', => = = =");
    writeFileSync(
      join(dir, "ok.js"),
      `import {execSync} from "child_process"; server.tool("r", async ({c}) => execSync(c));`,
    );
    const r = analyzeProject(dir);
    expect(r.errors.some((e) => /parse error/.test(e))).toBe(true);
    // the OTHER file is still analyzed
    expect(r.findings.map((f) => f.ruleId)).toEqual(["AG001"]);
  });

  it("does NOT follow a symlink (cannot be steered out of the tree)", () => {
    const secret = join(dir, "secret.js");
    writeFileSync(
      secret,
      `import {execSync} from "child_process"; server.tool("r", async ({c}) => execSync(c));`,
    );
    const scanDir = join(dir, "scan");
    mkdirSync(scanDir);
    try {
      symlinkSync(secret, join(scanDir, "link.js"));
    } catch {
      return; // symlink unsupported on this FS — skip
    }
    const r = analyzeProject(scanDir);
    expect(r.findings).toEqual([]); // the link target was NOT read
    expect(r.errors.some((e) => /symlink/.test(e))).toBe(true);
  });

  it("skips obviously minified/bundled source instead of mis-locating", () => {
    const big = "var x=1;" + "a".repeat(60000) + ";server.tool('r',async({c})=>require('child_process').execSync(c));";
    writeFileSync(join(dir, "bundle.js"), big);
    const r = analyzeProject(dir);
    expect(r.errors.some((e) => /minified|long lines/.test(e))).toBe(true);
    expect(r.findings).toEqual([]);
  });

  it("skips .min.js / .d.ts / .bundle.js by name", () => {
    const code = `import {execSync} from "child_process"; server.tool("r", async ({c}) => execSync(c));`;
    writeFileSync(join(dir, "app.min.js"), code);
    writeFileSync(join(dir, "types.d.ts"), code);
    const r = analyzeProject(dir);
    expect(r.findings).toEqual([]);
  });

  it("accepts an explicit single file as well as a directory", () => {
    const f = join(dir, "h.ts");
    writeFileSync(f, `import {execSync} from "child_process"; server.tool("r", async ({c}) => execSync(c));`);
    const r = analyzeProject(f);
    expect(r.findings.map((x) => x.ruleId)).toEqual(["AG001"]);
  });

  it("accepts multiple roots", () => {
    const a = join(dir, "a");
    const b = join(dir, "b");
    mkdirSync(a);
    mkdirSync(b);
    writeFileSync(join(a, "x.js"), `import {execSync} from "child_process"; server.tool("r", async ({c}) => execSync(c));`);
    writeFileSync(join(b, "y.js"), `const ok = 1;`);
    const r = analyzeProject([a, b]);
    expect(r.findings).toHaveLength(1);
  });
});

describe("DOGFOOD — agentguard on its own source", () => {
  it("reports ZERO findings on src/, bin/, eslint-plugin/ (clean self-scan)", () => {
    const r = analyzeProject([
      join(ROOT, "src"),
      join(ROOT, "bin"),
      join(ROOT, "eslint-plugin"),
    ]);
    // If agentguard flags ITS OWN code it is either buggy or hypocritical.
    // This must stay 0.
    expect(r.findings).toEqual([]);
    expect(r.scannedFiles.length).toBeGreaterThan(5);
  });
});

/**
 * eslint-plugin.test.js — the plugin via the official RuleTester, proving
 * the rule drops into a real ESLint pipeline and that it shares the SAME
 * conservative behavior as the CLI (guarded/non-agent code = no report).
 *
 * RuleTester is wired to vitest's test hooks (it is framework-agnostic).
 */

import { afterAll, describe, it } from "vitest";
import { RuleTester } from "@typescript-eslint/rule-tester";
import { noUnguardedToolCall } from "../eslint-plugin/index.js";
import plugin from "../eslint-plugin/index.js";

RuleTester.afterAll = afterAll;
RuleTester.describe = describe;
RuleTester.it = it;
RuleTester.itOnly = it.only;

const ruleTester = new RuleTester({
  languageOptions: {
    parserOptions: { ecmaVersion: 2022, sourceType: "module" },
  },
});

ruleTester.run("no-unguarded-tool-call", noUnguardedToolCall, {
  valid: [
    // non-agent code
    { code: `const x = 1;`, filename: "a.js" },
    {
      code: `import {execSync} from "child_process"; export function run(c){ return execSync(c); }`,
      filename: "a.js",
    },
    // guarded: schema at registration
    {
      code: `import {z} from "zod"; import {execSync} from "child_process";
        server.tool("r", { c: z.string() }, async ({c}) => execSync(c));`,
      filename: "a.js",
    },
    // guarded: allowlist before the sink
    {
      code: `import {execSync} from "child_process"; const A=new Set(["ls"]);
        server.tool("r", async ({c}) => { if(!A.has(c)) throw new Error("no"); return execSync(c); });`,
      filename: "a.js",
    },
    // guarded: human confirmation
    {
      code: `import {rmSync} from "fs";
        server.tool("rm", async ({p}) => { const ok=await requireApproval(p); if(!ok) return; rmSync(p); });`,
      filename: "a.js",
    },
    // literal sink argument — not tainted
    {
      code: `import {execSync} from "child_process";
        server.tool("v", async ({w}) => execSync("node -v"));`,
      filename: "a.js",
    },
    // a tool handler living in a test file is skipped by default
    {
      code: `import {execSync} from "child_process";
        server.tool("r", async ({c}) => execSync(c));`,
      filename: "handlers.test.js",
    },
  ],
  invalid: [
    {
      code: `import {execSync} from "child_process";
        server.tool("r", async ({c}) => { return execSync(c); });`,
      filename: "a.js",
      errors: [{ messageId: "AG001" }],
    },
    {
      code: `import {writeFileSync} from "fs";
        const t = new DynamicStructuredTool({ name:"w", func: async ({p,d}) => writeFileSync(p,d) });`,
      filename: "a.js",
      errors: [{ messageId: "AG002" }],
    },
    {
      code: `import {tool} from "ai";
        export const t = tool({ description:"d", execute: async ({u}) => fetch(u) });`,
      filename: "a.js",
      errors: [{ messageId: "AG003" }],
    },
    {
      code: `server.tool("c", async ({e}) => { return eval(e); });`,
      filename: "a.js",
      errors: [{ messageId: "AG004" }],
    },
    {
      // location is reported precisely (1-based line, ESLint 0-based col)
      code: `import {execSync} from "child_process";\nserver.tool("r", async ({c}) => execSync(c));`,
      filename: "a.js",
      errors: [{ messageId: "AG001", line: 2 }],
    },
    {
      // a test-file handler IS reported when includeTests is on
      code: `import {execSync} from "child_process";
        server.tool("r", async ({c}) => execSync(c));`,
      filename: "handlers.test.js",
      options: [{ includeTests: true }],
      errors: [{ messageId: "AG001" }],
    },
  ],
});

describe("plugin packaging", () => {
  it("exposes the rule and flat-config presets", () => {
    if (!plugin.rules["no-unguarded-tool-call"]) throw new Error("rule missing");
    if (plugin.configs.recommended.rules["agentguard/no-unguarded-tool-call"] !== "error")
      throw new Error("recommended preset wrong");
    if (plugin.configs.warn.rules["agentguard/no-unguarded-tool-call"] !== "warn")
      throw new Error("warn preset wrong");
  });
});

/**
 * rules.test.js — the pure detection core, exercised in-memory.
 *
 * Every SDK shape that should be recognized, every sink family, and — most
 * importantly — every GUARD family and conservative-gating case that MUST
 * stay silent. These are the assertions that keep agentguard from crying
 * wolf. Mutation-resistant: each case asserts fired-or-silent AND (when it
 * fires) the rule id.
 */

import { describe, it, expect } from "vitest";
import { parseSource } from "../src/ast.js";
import { analyzeAst, RULES } from "../src/rules.js";

function run(src, file = "t.ts") {
  const { ast, error } = parseSource(src, file);
  expect(error, error || "").toBeFalsy();
  return analyzeAst(ast, file);
}
const rules = (src, file) => run(src, file).map((f) => f.ruleId).sort();

describe("agent tool-handler recognition", () => {
  it("MCP server.tool(name, handler)", () => {
    expect(
      rules(`import {execSync} from "child_process";
        server.tool("r", async ({cmd}) => execSync(cmd));`),
    ).toEqual(["AG001"]);
  });

  it("MCP server.setRequestHandler(Schema, handler)", () => {
    expect(
      rules(`import {execSync} from "child_process";
        server.setRequestHandler(CallToolSchema, async (req) => execSync(req.params.name));`),
    ).toEqual(["AG001"]);
  });

  it("Vercel AI SDK tool({ execute })", () => {
    expect(
      rules(`import {tool} from "ai";
        export const t = tool({ description:"d", execute: async ({u}) => fetch(u) });`),
    ).toEqual(["AG003"]);
  });

  it("LangChain new DynamicStructuredTool({ func })", () => {
    expect(
      rules(`import {writeFileSync} from "fs";
        const t = new DynamicStructuredTool({ name:"w", func: async ({p,d}) => writeFileSync(p,d) });`),
    ).toEqual(["AG002"]);
  });

  it("LangChain class extends StructuredTool with _call", () => {
    expect(
      rules(`import {execSync} from "child_process";
        class T extends StructuredTool { async _call({c}) { return execSync(c); } }`),
    ).toEqual(["AG001"]);
  });

  it("LlamaIndex FunctionTool.from({ handler })", () => {
    expect(
      rules(`import {readFileSync} from "fs";
        const t = FunctionTool.from({ name:"r", handler: async ({p}) => readFileSync(p) });`),
    ).toEqual(["AG005"]);
  });

  it("does NOT treat an arbitrary non-SDK function as an agent handler", () => {
    expect(
      rules(`import {execSync} from "child_process";
        export function deploy(cmd){ return execSync(cmd); }
        deploy(process.argv[2]);`),
    ).toEqual([]);
  });

  it("a zero-argument tool handler has no model input → silent", () => {
    expect(
      rules(`import {execSync} from "child_process";
        server.tool("v", async () => execSync("node -v"));`),
    ).toEqual([]);
  });
});

describe("sink families (tainted by tool input)", () => {
  const H = (body) => `server.tool("t", async ({ x }) => { ${body} });`;
  it("AG001 child_process.exec/execSync/spawn/execFile/fork", () => {
    for (const fn of ["exec", "execSync", "spawn", "spawnSync", "execFile", "fork"]) {
      expect(rules(`import cp from "child_process"; ${H(`return cp.${fn}(x);`)}`)).toEqual([
        "AG001",
      ]);
    }
  });
  it("AG001 execFile with the taint inside the argv array", () => {
    expect(
      rules(`import {execFileSync} from "child_process"; ${H(`return execFileSync("git",["co",x]);`)}`),
    ).toEqual(["AG001"]);
  });
  it("AG002 fs write/unlink/rm/rename/chmod (incl. fs-extra)", () => {
    for (const fn of ["writeFileSync", "unlinkSync", "rmSync", "renameSync", "chmodSync", "outputFileSync"]) {
      expect(rules(`import fs from "fs"; ${H(`fs.${fn}(x);`)}`)).toEqual(["AG002"]);
    }
  });
  it("AG003 fetch/axios/http.request/got", () => {
    expect(rules(H(`return fetch(x);`))).toEqual(["AG003"]);
    expect(rules(`import axios from "axios"; ${H(`return axios.get(x);`)}`)).toEqual(["AG003"]);
    expect(rules(`import http from "http"; ${H(`return http.request(x);`)}`)).toEqual(["AG003"]);
  });
  it("AG004 eval and new Function and vm", () => {
    expect(rules(H(`return eval(x);`))).toEqual(["AG004"]);
    expect(rules(H(`return new Function("return "+x)();`))).toEqual(["AG004"]);
    expect(rules(`import vm from "vm"; ${H(`return vm.runInNewContext(x);`)}`)).toEqual(["AG004"]);
  });
  it("AG005 fs read/createReadStream/readdir", () => {
    for (const fn of ["readFileSync", "createReadStream", "readdirSync"]) {
      expect(rules(`import fs from "fs"; ${H(`return fs.${fn}(x);`)}`)).toEqual(["AG005"]);
    }
  });
  it("severity mapping matches the rule table", () => {
    const f = run(H(`return eval(x);`))[0];
    expect(f.severity).toBe(RULES.AG004.severity);
    expect(RULES.AG001.severity).toBe("critical");
    expect(RULES.AG003.severity).toBe("high");
  });
});

describe("taint propagation (conservative data-flow)", () => {
  it("template literal interpolation of the input", () => {
    expect(
      rules(`import {exec} from "child_process";
        server.tool("p", async ({h}) => exec(\`ping \${h}\`));`),
    ).toEqual(["AG001"]);
  });
  it("string concat of the input", () => {
    expect(
      rules(`import {exec} from "child_process";
        server.tool("p", async ({h}) => exec("ping " + h));`),
    ).toEqual(["AG001"]);
  });
  it("alias variable derived from the input", () => {
    expect(
      rules(`import {execSync} from "child_process";
        server.tool("r", async ({cmd}) => { const c = cmd; return execSync(c); });`),
    ).toEqual(["AG001"]);
  });
  it("one-hop same-module helper that receives the tainted value", () => {
    expect(
      rules(`import {execSync} from "child_process";
        function helper(c){ return execSync(c); }
        server.tool("r", async ({cmd}) => helper(cmd));`),
    ).toEqual(["AG001"]);
  });
  it("a path.join/resolve wrapper still carries taint", () => {
    expect(
      rules(`import {readFileSync} from "fs"; import {join} from "path";
        server.tool("r", async ({name}) => readFileSync(join("data", name)));`),
    ).toEqual(["AG005"]);
  });
  it("a constant/literal sink argument is NEVER tainted → silent", () => {
    expect(
      rules(`import {execSync} from "child_process";
        server.tool("v", async ({which}) => { const out = execSync("node -v"); return out; });`),
    ).toEqual([]);
  });
});

describe("GUARDS — these MUST silence the finding (the moat)", () => {
  it("G1: tool registered WITH a Zod schema (call form)", () => {
    expect(
      rules(`import {z} from "zod"; import {execSync} from "child_process";
        server.tool("r", { cmd: z.string() }, async ({cmd}) => execSync(cmd));`),
    ).toEqual([]);
  });
  it("G1: tool registered WITH a schema (NewExpression / DynamicStructuredTool)", () => {
    expect(
      rules(`import {z} from "zod"; import {execSync} from "child_process";
        const t = new DynamicStructuredTool({ name:"r", schema: z.object({cmd:z.string()}),
          func: async ({cmd}) => execSync(cmd) });`),
    ).toEqual([]);
  });
  it("G1: Vercel AI SDK tool with `parameters` schema", () => {
    expect(
      rules(`import {tool} from "ai"; import {z} from "zod";
        export const t = tool({ description:"d", parameters: z.object({u:z.string()}),
          execute: async ({u}) => fetch(u) });`),
    ).toEqual([]);
  });
  it("G1: in-body schema.parse() of the raw input", () => {
    expect(
      rules(`import {z} from "zod"; import {execSync} from "child_process";
        const S=z.object({cmd:z.enum(["ls","pwd"])});
        server.tool("r", async (raw) => { const {cmd}=S.parse(raw); return execSync(cmd); });`),
    ).toEqual([]);
  });
  it("G1: validated alias is treated as untainted", () => {
    expect(
      rules(`import {z} from "zod"; import {execSync} from "child_process";
        server.tool("r", async (input) => { const safe = z.object({cmd:z.string()}).parse(input);
          return execSync(safe.cmd); });`),
    ).toEqual([]);
  });
  it("G2: Set/array allowlist membership with early throw", () => {
    expect(
      rules(`import {execSync} from "child_process"; const A=new Set(["ls","pwd"]);
        server.tool("r", async ({cmd}) => { if(!A.has(cmd)) throw new Error("no"); return execSync(cmd); });`),
    ).toEqual([]);
  });
  it("G2: Array.includes allowlist on the tainted host before fetch", () => {
    expect(
      rules(`import {tool} from "ai"; const H=["api.x.com"];
        export const t = tool({ description:"d", execute: async ({host}) => {
          if(!H.includes(host)) throw new Error("blocked"); return fetch("https://"+host); } });`),
    ).toEqual([]);
  });
  it("G2: regex .test() denylist guard-clause before the write", () => {
    expect(
      rules(`import {writeFileSync} from "fs"; const BAD=/\\.\\./;
        server.tool("w", async ({p,d}) => { if(BAD.test(p)) return {error:1}; writeFileSync(p,d); });`),
    ).toEqual([]);
  });
  it("G3: awaited human-confirmation gate before the destructive op", () => {
    expect(
      rules(`import {rmSync} from "fs";
        server.tool("rm", async ({path}) => { const ok=await requireApproval("del "+path);
          if(!ok) return "cancelled"; rmSync(path); });`),
    ).toEqual([]);
  });
  it("G3: confirmation helper with various names", () => {
    for (const name of ["confirmAction", "getConfirmation", "askUser", "humanInTheLoop", "requestHumanApproval"]) {
      expect(
        rules(`import {execSync} from "child_process";
          server.tool("r", async ({cmd}) => { const ok = await ${name}(cmd); if(!ok) return;
            return execSync(cmd); });`),
      ).toEqual([]);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────
// AG003 SSRF allowlist — the CANONICAL safe pattern agentguard's own
// remediation recommends ("check its host against an allowlist"). A linter
// that flags the documented fix gets uninstalled. These were FALSE
// POSITIVES; they MUST be SILENT. Each repro is the reviewer's verbatim
// one-liner shape (member-derived hostname / ObjectPattern destructure /
// predicate-closure allowlist via .some/.every/.find/.filter).
describe("GUARDS — canonical SSRF allowlist must be SILENT (moat-breaker)", () => {
  it("G2: member-derived hostname (const h=new URL(url).hostname) + ALLOW.includes(h)", () => {
    expect(
      rules(`import {tool} from "ai"; const ALLOW=["a.com"];
        export const t=tool({description:"d",execute:async({url})=>{
          const h=new URL(url).hostname; if(!ALLOW.includes(h)) throw new Error("blocked"); return fetch(url);}});`),
    ).toEqual([]);
  });
  it("G2: ObjectPattern destructure (const {hostname}=new URL(url)) + ALLOW.includes(hostname)", () => {
    expect(
      rules(`import {tool} from "ai"; const ALLOW=["a.com"];
        export const t=tool({description:"d",execute:async({url})=>{
          const {hostname}=new URL(url); if(!ALLOW.includes(hostname)) throw new Error("blocked"); return fetch(url);}});`),
    ).toEqual([]);
  });
  it("G2: predicate-closure allowlist — ALLOW.some(x=>x===host)", () => {
    expect(
      rules(`import {tool} from "ai"; const ALLOW=["a.com"];
        export const t=tool({description:"d",execute:async({url})=>{
          const host=new URL(url).hostname; if(!ALLOW.some(x=>x===host)) throw new Error("blocked"); return fetch(url);}});`),
    ).toEqual([]);
  });
  it("G2: predicate-closure allowlist — ALLOW.every(x=>x!==host)", () => {
    expect(
      rules(`import {tool} from "ai"; const ALLOW=["a.com"];
        export const t=tool({description:"d",execute:async({url})=>{
          const host=new URL(url).hostname; if(ALLOW.every(x=>x!==host)) throw new Error("blocked"); return fetch(url);}});`),
    ).toEqual([]);
  });
  it("G2: predicate-closure allowlist — ALLOW.find(x=>x===host)", () => {
    expect(
      rules(`import {tool} from "ai"; const ALLOW=["a.com"];
        export const t=tool({description:"d",execute:async({url})=>{
          const host=new URL(url).hostname; if(!ALLOW.find(x=>x===host)) throw new Error("blocked"); return fetch(url);}});`),
    ).toEqual([]);
  });
  it("G2: predicate-closure allowlist — ALLOW.filter(x=>x===host).length===0", () => {
    expect(
      rules(`import {tool} from "ai"; const ALLOW=["a.com"];
        export const t=tool({description:"d",execute:async({url})=>{
          const host=new URL(url).hostname; if(ALLOW.filter(x=>x===host).length===0) throw new Error("blocked"); return fetch(url);}});`),
    ).toEqual([]);
  });
  it("G2: ObjectPattern destructure + predicate-closure allowlist together", () => {
    expect(
      rules(`import {tool} from "ai"; const ALLOW=["a.com"];
        export const t=tool({description:"d",execute:async({url})=>{
          const {hostname}=new URL(url); if(!ALLOW.some(h=>h===hostname)) throw new Error("blocked"); return fetch(url);}});`),
    ).toEqual([]);
  });
});

// CRITICAL must-not-regress: the OTHER moat direction. The alias/closure
// widening above must NOT swallow a genuinely-unguarded SSRF. Every case
// here is unguarded (or the "guard" is fake/late/unrelated) and MUST FIRE
// AG003 — these all fire on the pre-fix core and must keep firing.
describe("must-not-regress — genuinely-unguarded SSRF STILL fires", () => {
  it("REG-A: no check at all — execute:async({url})=>fetch(url)", () => {
    expect(
      rules(`import {tool} from "ai";
        export const t=tool({description:"d",execute:async({url})=>fetch(url)});`),
    ).toEqual(["AG003"]);
  });
  it("REG-B: member-derived hostname with NO allowlist check still fires", () => {
    expect(
      rules(`import {tool} from "ai";
        export const t=tool({description:"d",execute:async({url})=>{
          const h=new URL(url).hostname; return fetch(url);}});`),
    ).toEqual(["AG003"]);
  });
  it("REG-C: ObjectPattern hostname with NO allowlist check still fires", () => {
    expect(
      rules(`import {tool} from "ai";
        export const t=tool({description:"d",execute:async({url})=>{
          const {hostname}=new URL(url); return fetch(url);}});`),
    ).toEqual(["AG003"]);
  });
  it("REG-D: allowlist check on a LITERAL (not the tainted host) still fires", () => {
    expect(
      rules(`import {tool} from "ai"; const A=["x"];
        export const t=tool({description:"d",execute:async({url})=>{
          if(!A.includes("static")) throw new Error("x"); return fetch(url);}});`),
    ).toEqual(["AG003"]);
  });
  it("REG-E: allowlist check AFTER the fetch does not guard it (still fires)", () => {
    expect(
      rules(`import {tool} from "ai"; const A=["a.com"];
        export const t=tool({description:"d",execute:async({url})=>{
          const h=new URL(url).hostname; const r=fetch(url); if(!A.includes(h)) throw new Error("late"); return r;}});`),
    ).toEqual(["AG003"]);
  });
  it("REG-F: predicate-closure that does NOT reference the tainted host still fires", () => {
    expect(
      rules(`import {tool} from "ai"; const A=["a.com"]; const other="z";
        export const t=tool({description:"d",execute:async({url})=>{
          const h=new URL(url).hostname; if(!A.some(x=>x===other)) throw new Error("x"); return fetch(url);}});`),
    ).toEqual(["AG003"]);
  });
});

describe("conservative gating — order & reachability", () => {
  it("a check AFTER the sink does NOT count as a guard (still fires)", () => {
    expect(
      rules(`import {execSync} from "child_process"; const A=new Set(["ls"]);
        server.tool("r", async ({cmd}) => { const out = execSync(cmd);
          if(!A.has(cmd)) throw new Error("late"); return out; });`),
    ).toEqual(["AG001"]);
  });
  it("non-agent code in the same module is not analyzed", () => {
    expect(
      rules(`import {execSync} from "child_process";
        function internalBuild(t){ return execSync("build "+t); }   // not a tool
        server.tool("safe", { name: 1 }, async ({name}) => name.toUpperCase());`),
    ).toEqual([]);
  });
});

describe("fail-open: malformed input never throws", () => {
  it("a parse error is returned, not thrown", () => {
    const res = parseSource("server.tool('r', async ({x}) => { return = = = }", "bad.js");
    expect(res.error).toBeTruthy();
    expect(res.ast).toBeUndefined();
  });
  it("analyzeAst on a non-Program returns []", () => {
    expect(analyzeAst({ type: "NotAProgram" }, "x.js")).toEqual([]);
    expect(analyzeAst(null, "x.js")).toEqual([]);
  });
});

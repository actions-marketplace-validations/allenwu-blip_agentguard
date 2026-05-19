/**
 * rules.js — the pure, deterministic detection core of agentguard.
 *
 * NO file I/O, NO network, NO code execution. A pure function from an
 * ESTree Program (+ filename) to Finding[]. This is what makes the linter
 * fully unit-testable and what the bundled ESLint plugin reuses on ESLint's
 * own AST.
 *
 * ─────────────────────────── DESIGN STANCE ───────────────────────────
 * A linter that cries wolf gets uninstalled. agentguard fires a finding
 * ONLY when ALL of the following hold (this is the moat — see README
 * "The conservative philosophy"):
 *
 *   (1) the code is an AGENT TOOL HANDLER — a function registered with a
 *       recognized agent-SDK tool/handler API whose parameter is
 *       model-controlled (untrusted) input;
 *   (2) inside that handler (or a same-module helper it calls, followed one
 *       hop, conservatively) there is a SIDE-EFFECTFUL SINK: shell/exec,
 *       sensitive filesystem write/read, outbound network, or dynamic eval;
 *   (3) the sink's dangerous argument is DATA-TAINTED by the handler's
 *       untrusted parameter (literal/constant args are never tainted →
 *       never fire);
 *   (4) NO GUARD is present on the path: no input schema/validation, no
 *       allowlist/denylist check, no human-confirmation gate.
 *
 * If a guard exists, agentguard is SILENT. If it is not an agent handler,
 * agentguard is SILENT. Test files are skipped by default. We deliberately
 * accept false negatives (a guard in another module we cannot see, exotic
 * SDKs) to keep false positives near zero. Static analysis cannot prove
 * reachability — every finding says exactly WHY it fired and how to fix it.
 */

import { walk, collect, pos, calleeName, calleeBase } from "./ast.js";

export const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

export const RULES = {
  AG001: {
    id: "AG001",
    severity: "critical",
    title: "Unguarded shell/exec from agent tool input",
    blurb:
      "A child_process exec/spawn/execFile/fork call is reachable from an agent tool handler with the model-controlled input flowing into the command, and no validation, allowlist, or human-confirmation gate is present on the path.",
  },
  AG002: {
    id: "AG002",
    severity: "high",
    title: "Unguarded sensitive filesystem write from agent tool input",
    blurb:
      "A filesystem mutation (write/append/unlink/rm/rename/chmod) uses a path derived from model-controlled tool input with no path validation, allowlist, or human-confirmation gate — an agent can be steered to overwrite or delete arbitrary files.",
  },
  AG003: {
    id: "AG003",
    severity: "high",
    title: "Unguarded outbound network from agent tool input",
    blurb:
      "An outbound request (fetch/axios/http(s).request/got/undici) targets a URL derived from model-controlled tool input with no allowlist or confirmation — an agent can be steered into SSRF or data exfiltration.",
  },
  AG004: {
    id: "AG004",
    severity: "critical",
    title: "Unguarded dynamic code execution from agent tool input",
    blurb:
      "eval / new Function / vm runs code derived from model-controlled tool input with no validation or confirmation — this is arbitrary code execution driven by the model.",
  },
  AG005: {
    id: "AG005",
    severity: "high",
    title: "Unguarded sensitive filesystem read from agent tool input",
    blurb:
      "A filesystem read uses a path derived from model-controlled tool input with no path validation/allowlist — an agent can be steered to read arbitrary files (path traversal / secret exfiltration) and the bytes typically flow back into the model context.",
  },
};

// ───────────────────────── SDK SURFACE (conservative allow-list) ─────────
// We only treat a function as an agent tool handler when it is registered
// through one of these well-known APIs. Unknown shapes are NOT guessed —
// that is the single biggest false-positive guard. (The user can also opt a
// function in explicitly with a `// agentguard:tool` marker comment-free
// alternative: see `isExplicitToolMarker`.)
//
// Shape A — callee(..., handlerFn): the handler is a function ARGUMENT.
const HANDLER_ARG_CALLEES = [
  // MCP TypeScript SDK
  /(^|\.)tool$/, // server.tool("name", schema?, handler)
  /(^|\.)setRequestHandler$/, // server.setRequestHandler(Schema, handler)
  /(^|\.)resource$/, // server.resource(name, uri, handler)
  /(^|\.)prompt$/, // server.prompt(name, schema?, handler)
  // LangChain functional helper: tool(fn, { schema })  — fn is positional.
  // (The CLASS forms DynamicStructuredTool/DynamicTool/StructuredTool take
  // an OPTIONS OBJECT holding the handler — see Shape B below.)
  // OpenAI/Anthropic-style manual dispatchers people commonly name this:
  /(^|\.)registerToolHandler$/,
];
// Shape B — callee({ ..., execute|handler|func|call|invoke|cb: fn ... }):
// the handler is a PROPERTY of an options object. Covers Vercel AI SDK
// `tool({execute})`, LlamaIndex `FunctionTool.from({handler})`, LangChain
// `new DynamicStructuredTool({func})` / `tool(fn,{...})`, and the common
// `registerTool`/`addTool`/`defineTool`/`createTool` wrappers.
const HANDLER_OBJECT_CALLEES = [
  /(^|\.)tool$/,
  /(^|\.)FunctionTool$/,
  /(^|\.)from$/, // FunctionTool.from({...}) / DynamicStructuredTool.from
  /(^|\.)DynamicStructuredTool$/,
  /(^|\.)DynamicTool$/,
  /(^|\.)StructuredTool$/,
  /(^|\.)dynamicTool$/,
  /(^|\.)defineTool$/,
  /(^|\.)createTool$/,
  /(^|\.)registerTool$/,
  /(^|\.)addTool$/,
  /(^|\.)agentTool$/,
];
const HANDLER_PROP_NAMES = new Set([
  "execute",
  "handler",
  "func",
  "call",
  "invoke",
  "cb",
  "callback",
  "run",
  "_call",
  "fn",
]);

function matchesAny(name, patterns) {
  return name !== "" && patterns.some((re) => re.test(name));
}

// ───────────────────────────── SINKS ────────────────────────────────────
// Each sink: how to recognize the call, which argument index carries the
// dangerous value, and the ruleId/severity it maps to. We match on a
// resolved dotted callee name AND/OR an unqualified base, conservatively.

const SHELL_FULL = new Set([
  "child_process.exec",
  "child_process.execSync",
  "child_process.execFile",
  "child_process.execFileSync",
  "child_process.spawn",
  "child_process.spawnSync",
  "child_process.fork",
  "cp.exec",
  "cp.execSync",
  "cp.spawn",
  "cp.spawnSync",
  "cp.execFile",
  "cp.fork",
]);
const SHELL_BASE = new Set([
  "exec",
  "execSync",
  "execFile",
  "execFileSync",
  "spawn",
  "spawnSync",
  "fork",
]);
// NOTE: `const exec = promisify(child_process.exec); await exec(taint)` is a
// known false negative — the sink hides behind an aliased promisified
// binding. We do NOT pretend to catch it (conservative + honest; see README
// "Limitations"). The direct exec/execSync/spawn/execFile/fork names are the
// overwhelming-majority case and what the fixtures assert.

const FS_WRITE_BASE = new Set([
  "writeFile",
  "writeFileSync",
  "appendFile",
  "appendFileSync",
  "unlink",
  "unlinkSync",
  "rm",
  "rmSync",
  "rmdir",
  "rmdirSync",
  "rename",
  "renameSync",
  "chmod",
  "chmodSync",
  "chown",
  "chownSync",
  "truncate",
  "truncateSync",
  "mkdir",
  "mkdirSync",
  "createWriteStream",
  "copyFile",
  "copyFileSync",
  "outputFile", // fs-extra
  "outputFileSync",
  "remove", // fs-extra
  "removeSync",
  "emptyDir",
  "emptyDirSync",
  "move",
  "moveSync",
]);
const FS_READ_BASE = new Set([
  "readFile",
  "readFileSync",
  "createReadStream",
  "readdir",
  "readdirSync",
  "open",
  "openSync",
  "readlink",
  "readlinkSync",
  "realpath",
  "realpathSync",
]);

const NET_FULL = new Set([
  "http.request",
  "http.get",
  "https.request",
  "https.get",
  "axios.get",
  "axios.post",
  "axios.put",
  "axios.delete",
  "axios.patch",
  "axios.request",
  "undici.request",
  "undici.fetch",
  "got.get",
  "got.post",
]);
const NET_BASE = new Set(["fetch", "request", "got", "ky", "superagent"]);

const EVAL_FULL = new Set(["vm.runInNewContext", "vm.runInThisContext", "vm.runInContext", "vm.compileFunction"]);
const EVAL_BASE = new Set(["eval"]);

// ───────────────────────── GUARD RECOGNITION ────────────────────────────
// A "guard" neutralizes the finding. We recognize three families,
// conservatively (a false guard match would HIDE a real bug, so each is a
// well-known, intentional safety construct):
//
//  G1 schema/validation applied to the untrusted input:
//     - the tool was registered WITH a schema/parameters/inputSchema object
//       (Zod/JSON-schema) — structural validation happens before execute;
//     - or the handler calls `.parse|.safeParse|.parseAsync|.validate|
//       .validateSync|.assert|.check|.cast` (Zod/Joi/Yup/ajv/superstruct)
//       on the input;
//     - or it uses ajv `validate(...)` / a `validate(input)` call.
//  G2 allowlist / denylist decision on the tainted value before the sink:
//     - `.includes|.has|.indexOf|.test|.startsWith|.endsWith|.match` of the
//       tainted value used in an if/throw/return/ternary that can stop the
//       sink, OR a `Set`/array/regex membership check; an early
//       `throw`/`return`/`reject` on the not-allowed branch.
//  G3 human confirmation: an awaited/used call whose (dotted or base) name
//     matches confirm/approve/prompt/askUser/requireApproval/
//     humanInTheLoop/getConfirmation/ask/checkpoint before the sink.
//
// G2/G3 must appear textually BEFORE the sink within the handler body
// (range-ordered) — a check after the dangerous call does not guard it.

const VALIDATION_METHODS = new Set([
  "parse",
  "parseAsync",
  "safeParse",
  "safeParseAsync",
  "validate",
  "validateSync",
  "validateAsync",
  "assert",
  "check",
  "cast",
  "decode", // io-ts
  "is", // zod-ish / type guards used as gate
]);
const CONFIRM_RE = /(^|[._])(confirm|confirmation|approve|approval|askuser|ask_user|requireapproval|require_approval|humanintheloop|human_in_the_loop|getconfirmation|get_confirmation|requireconfirmation|checkpoint|gateapproval|promptuser|prompt_user|requesthumanapproval)($|[._A-Z])/i;
const DENY_MEMBERSHIP = new Set([
  "includes",
  "has",
  "indexOf",
  "test",
  "startsWith",
  "endsWith",
  "match",
  "every",
  "some",
]);
// Array predicate-iteration helpers whose CALLBACK expresses the membership
// decision: `ALLOW.some(x => x === host)` is the canonical SSRF allowlist
// check (same intent as `ALLOW.includes(host)`). Here the tainted value is
// referenced INSIDE the predicate closure, not as a direct call argument —
// so guard recognition must descend into the closure body.
const PREDICATE_ITER = new Set([
  "some",
  "every",
  "find",
  "findIndex",
  "findLast",
  "findLastIndex",
  "filter",
]);

// ─────────────────────────────── helpers ────────────────────────────────

function fnBody(fn) {
  if (!fn) return null;
  if (fn.type === "ArrowFunctionExpression" || fn.type === "FunctionExpression" || fn.type === "FunctionDeclaration") {
    return fn.body && fn.body.type === "BlockStatement" ? fn.body : fn.body /* expression-bodied arrow */;
  }
  return null;
}

/** Collect the set of identifier names that are "tainted" = derived from
 *  any of the handler's parameter bindings. Conservative local propagation:
 *  param + destructured members + simple aliases / concat / template /
 *  member access. We do NOT cross function boundaries here (handled by the
 *  one-hop helper follow). */
function taintBaseNames(fn) {
  const names = new Set();
  if (!fn || !Array.isArray(fn.params)) return names;
  for (const p of fn.params) {
    collectBindingNames(p, names);
  }
  return names;
}

function collectBindingNames(node, out) {
  if (!node) return;
  switch (node.type) {
    case "Identifier":
      out.add(node.name);
      break;
    case "AssignmentPattern":
      collectBindingNames(node.left, out);
      break;
    case "RestElement":
      collectBindingNames(node.argument, out);
      break;
    case "ObjectPattern":
      for (const pr of node.properties) {
        if (pr.type === "RestElement") collectBindingNames(pr.argument, out);
        else collectBindingNames(pr.value, out);
      }
      break;
    case "ArrayPattern":
      for (const el of node.elements) collectBindingNames(el, out);
      break;
    case "TSParameterProperty":
      collectBindingNames(node.parameter, out);
      break;
    default:
      break;
  }
}

/** Does expression `node` reference any tainted base name (directly, via a
 *  member access, simple concat, template literal, call args of String()/
 *  path.join etc.)? Conservative: only data-flow shapes that obviously carry
 *  the value. */
function exprIsTainted(node, tainted, aliasMap, depth = 0) {
  if (!node || depth > 40) return false;
  switch (node.type) {
    case "Identifier":
      return tainted.has(node.name) || (aliasMap.has(node.name) && aliasMap.get(node.name));
    case "MemberExpression":
      return exprIsTainted(node.object, tainted, aliasMap, depth + 1);
    case "ChainExpression":
      return exprIsTainted(node.expression, tainted, aliasMap, depth + 1);
    case "TemplateLiteral":
      return node.expressions.some((e) => exprIsTainted(e, tainted, aliasMap, depth + 1));
    case "TaggedTemplateExpression":
      return exprIsTainted(node.quasi, tainted, aliasMap, depth + 1);
    case "BinaryExpression":
      return (
        exprIsTainted(node.left, tainted, aliasMap, depth + 1) ||
        exprIsTainted(node.right, tainted, aliasMap, depth + 1)
      );
    case "LogicalExpression":
      return (
        exprIsTainted(node.left, tainted, aliasMap, depth + 1) ||
        exprIsTainted(node.right, tainted, aliasMap, depth + 1)
      );
    case "ConditionalExpression":
      return (
        exprIsTainted(node.consequent, tainted, aliasMap, depth + 1) ||
        exprIsTainted(node.alternate, tainted, aliasMap, depth + 1)
      );
    case "SpreadElement":
    case "AwaitExpression":
    case "TSNonNullExpression":
    case "TSAsExpression":
    case "TSSatisfiesExpression":
      return exprIsTainted(node.argument || node.expression, tainted, aliasMap, depth + 1);
    case "ArrayExpression":
      return node.elements.some((e) => e && exprIsTainted(e, tainted, aliasMap, depth + 1));
    case "ObjectExpression":
      return node.properties.some(
        (p) => p.type === "Property" && exprIsTainted(p.value, tainted, aliasMap, depth + 1),
      );
    case "CallExpression": {
      // value-passthrough wrappers commonly used to build a path / command:
      // String(x), `${x}`, path.join(base, x), path.resolve(x), x.trim(),
      // decodeURIComponent(x), Buffer.from(x), etc. Any tainted ARG taints
      // the result (conservative — a wrapper rarely sanitizes by itself).
      const cn = calleeName(node.callee) || calleeBase(node.callee);
      // .parse/.safeParse/.validate are GUARDS, not passthroughs — do not
      // treat their result as tainted (validated output is the safe path).
      const base = calleeBase(node.callee);
      if (VALIDATION_METHODS.has(base)) return false;
      void cn;
      return node.arguments.some((a) => exprIsTainted(a, tainted, aliasMap, depth + 1));
    }
    default:
      return false;
  }
}

/** Is `node` a value DERIVED from a tainted value through an accessor/parser
 *  shape that `exprIsTainted` deliberately does not follow — specifically a
 *  member access off a tainted/derived object (`u.hostname`,
 *  `new URL(url).hostname`) or `new URL(<tainted>)` itself? This is used
 *  ONLY for guard recognition: it lets an allowlist/validation check on the
 *  derived binding (`const h = new URL(url).hostname; if(!A.includes(h))…`)
 *  count as a guard on the path. It does NOT widen sink-argument taint
 *  (exprIsTainted is unchanged), so a genuinely-unguarded sink on the raw
 *  tainted value still fires. Conservative: only the host-of-URL idiom and
 *  plain member access — never a guess. */
function exprDerivesFromTainted(node, tainted, aliasMap, depth = 0) {
  if (!node || depth > 40) return false;
  switch (node.type) {
    case "ChainExpression":
      return exprDerivesFromTainted(node.expression, tainted, aliasMap, depth + 1);
    case "TSNonNullExpression":
    case "TSAsExpression":
    case "TSSatisfiesExpression":
    case "AwaitExpression":
      return exprDerivesFromTainted(node.argument || node.expression, tainted, aliasMap, depth + 1);
    case "MemberExpression":
      // `<tainted-or-derived>.hostname` / `.host` / `.protocol` / any prop:
      // the derived binding represents the tainted value for guarding.
      return (
        exprIsTainted(node.object, tainted, aliasMap, depth + 1) ||
        exprDerivesFromTainted(node.object, tainted, aliasMap, depth + 1)
      );
    case "NewExpression": {
      // `new URL(<tainted>)` (or any constructor over a tainted arg): the
      // parsed object stands in for the tainted URL. A check on a binding
      // destructured/accessed off it is an allowlist guard on the path.
      return (node.arguments || []).some(
        (a) =>
          exprIsTainted(a, tainted, aliasMap, depth + 1) ||
          exprDerivesFromTainted(a, tainted, aliasMap, depth + 1),
      );
    }
    case "CallExpression": {
      // value-passthrough wrappers (String(x), x.trim(), decodeURIComponent
      // (x)…) over a tainted/derived arg keep the derived-representative
      // status — but a validation method is a GUARD, not a passthrough.
      const base = calleeBase(node.callee);
      if (VALIDATION_METHODS.has(base)) return false;
      return (node.arguments || []).some(
        (a) =>
          exprIsTainted(a, tainted, aliasMap, depth + 1) ||
          exprDerivesFromTainted(a, tainted, aliasMap, depth + 1),
      );
    }
    default:
      return false;
  }
}

/** Build alias map: `const a = <taintedExpr>` makes `a` tainted too.
 *  Also marks a name UN-tainted when reassigned from a validation result
 *  (`const safe = schema.parse(input)` → `safe` is NOT tainted).
 *
 *  Beyond direct taint, a binding DERIVED from a tainted value via member
 *  access or `new URL(tainted)` (`const h = new URL(url).hostname`) or an
 *  ObjectPattern destructure (`const {hostname} = new URL(url)`) is recorded
 *  as a REPRESENTATIVE of the tainted value (mapped `true`) so an allowlist
 *  / validation check on that name is recognized as a guard on the path.
 *  This narrows the FALSE-POSITIVE direction only — sink-arg taint
 *  (exprIsTainted) is untouched, so genuinely-unguarded sinks still fire. */
function buildAliases(body, tainted) {
  const aliasMap = new Map();
  if (!body) return aliasMap;
  const markPatternRepr = (idNode) => {
    // Bind every name introduced by an ObjectPattern/ArrayPattern (or plain
    // Identifier) to the derived-representative status.
    collectBindingNames(idNode, { add: (nm) => aliasMap.set(nm, true) });
  };
  walk(body, (n) => {
    if (n.type === "VariableDeclarator" && n.id && n.id.type === "Identifier" && n.init) {
      const base = n.init.callee ? calleeBase(n.init.callee) : "";
      if (n.init.type === "CallExpression" && VALIDATION_METHODS.has(base)) {
        aliasMap.set(n.id.name, false); // validated → safe
        return;
      }
      if (exprIsTainted(n.init, tainted, aliasMap)) {
        aliasMap.set(n.id.name, true);
      } else if (exprDerivesFromTainted(n.init, tainted, aliasMap)) {
        // `const h = new URL(url).hostname` / `const h = u.hostname`
        aliasMap.set(n.id.name, true);
      }
    } else if (
      n.type === "VariableDeclarator" &&
      n.id &&
      (n.id.type === "ObjectPattern" || n.id.type === "ArrayPattern") &&
      n.init &&
      exprDerivesFromTainted(n.init, tainted, aliasMap)
    ) {
      // `const {hostname} = new URL(url)` — every destructured name
      // represents the tainted value for guard recognition.
      markPatternRepr(n.id);
    } else if (
      n.type === "AssignmentExpression" &&
      n.operator === "=" &&
      n.left &&
      n.left.type === "Identifier"
    ) {
      const base = n.right && n.right.callee ? calleeBase(n.right.callee) : "";
      if (n.right && n.right.type === "CallExpression" && VALIDATION_METHODS.has(base)) {
        aliasMap.set(n.left.name, false);
      } else if (exprIsTainted(n.right, tainted, aliasMap)) {
        aliasMap.set(n.left.name, true);
      } else if (n.right && exprDerivesFromTainted(n.right, tainted, aliasMap)) {
        aliasMap.set(n.left.name, true);
      }
    }
  });
  return aliasMap;
}

function rangeStart(n) {
  return n && n.range ? n.range[0] : (n && n.loc ? n.loc.start.line * 1e6 + n.loc.start.column : 0);
}

/** A schema object was passed at tool-registration time (Shape A 2nd arg /
 *  Shape B `parameters|inputSchema|schema|args` prop) → structural input
 *  validation runs before the handler. This is guard family G1. */
function registrationHasSchema(callNode, handlerFn) {
  // Both `tool("name", schema, handler)` (CallExpression) and
  // `new DynamicStructuredTool({ schema, func })` (NewExpression) carry a
  // registration schema; both expose `.arguments`.
  if (
    !callNode ||
    (callNode.type !== "CallExpression" && callNode.type !== "NewExpression") ||
    !Array.isArray(callNode.arguments)
  ) {
    return false;
  }
  // IMPORTANT conservative exception: `server.setRequestHandler(Schema,
  // handler)`'s first arg is the MCP *protocol message* schema selecting
  // WHICH RPC this handler answers (CallToolRequestSchema, …). It does NOT
  // validate the tool's input arguments — those arrive inside the request
  // (req.params.arguments) UNVALIDATED. Treating it as an input guard would
  // create a real false NEGATIVE, so for setRequestHandler the leading
  // schema-looking argument is explicitly NOT a guard.
  const regCalleeBase = callNode.callee ? calleeBase(callNode.callee) : "";
  const isSetRequestHandler = regCalleeBase === "setRequestHandler";

  // Shape A: callee("name", schemaObj, handler) OR callee(Schema, handler)
  const args = callNode.arguments;
  const hIdx = args.indexOf(handlerFn);
  if (hIdx > 0 && !isSetRequestHandler) {
    for (let i = 0; i < hIdx; i++) {
      const a = args[i];
      if (!a) continue;
      // a Zod/JSON schema arg: an ObjectExpression with >=1 prop, an
      // identifier that is clearly a schema, or a `z.object(...)` call.
      if (a.type === "ObjectExpression" && a.properties.length > 0) return true;
      if (a.type === "CallExpression") {
        const cn = calleeName(a.callee);
        if (/^z\.|\.object$|^Joi\.|^yup\.|jsonSchema|zodToJsonSchema/.test(cn)) return true;
      }
      if (a.type === "Identifier" && /schema|shape|params|input/i.test(a.name)) return true;
    }
  }
  // Shape B: the options object holds parameters/inputSchema/schema/args.
  const optObj = args.find(
    (a) => a && a.type === "ObjectExpression" && a.properties.some((p) => p.type === "Property" && p.value === handlerFn),
  );
  if (optObj) {
    for (const p of optObj.properties) {
      if (p.type !== "Property") continue;
      const key =
        p.key && (p.key.name || (p.key.type === "Literal" ? p.key.value : ""));
      if (!key) continue;
      if (/^(parameters|inputSchema|schema|args|argsSchema|input)$/i.test(String(key))) {
        // a present, non-null schema value counts
        if (p.value && p.value.type !== "Literal") return true;
        if (p.value && p.value.type === "ObjectExpression") return true;
      }
    }
  }
  return false;
}

/** Guard family G1 inside the body: a validation method is invoked on a
 *  tainted value (schema.parse(input), input.parse(), v.safeParse(input)). */
function hasInBodyValidation(body, tainted, aliasMap) {
  let found = false;
  walk(body, (n) => {
    if (found || n.type !== "CallExpression") return;
    const base = calleeBase(n.callee);
    if (!VALIDATION_METHODS.has(base)) return;
    // schema.parse(taintedInput)  — tainted flows as an arg
    if (n.arguments.some((a) => exprIsTainted(a, tainted, aliasMap))) {
      found = true;
      return;
    }
    // taintedInput.parse()/.safeParse()  — receiver is tainted
    if (
      n.callee.type === "MemberExpression" &&
      exprIsTainted(n.callee.object, tainted, aliasMap)
    ) {
      found = true;
    }
  });
  return found;
}

/** Guard family G2/G3 that appear BEFORE `sinkNode` (by source range).
 *  Returns true if a confirmation call OR an allow/deny decision on the
 *  tainted value precedes the sink within the handler body. */
function hasGateBefore(body, sinkNode, tainted, aliasMap) {
  const limit = rangeStart(sinkNode);
  let gated = false;
  walk(body, (n) => {
    if (gated) return;
    if (rangeStart(n) >= limit) return; // only constructs textually before
    // G3 — human confirmation call (awaited or its result used in a branch)
    if (n.type === "CallExpression") {
      const dn = calleeName(n.callee);
      const bn = calleeBase(n.callee);
      if (CONFIRM_RE.test(dn) || CONFIRM_RE.test(bn)) {
        gated = true;
        return;
      }
    }
    // G2 — allow/deny membership/predicate on the tainted value used in a
    // branch that can stop execution (if + throw/return/reject, or a guard
    // clause). We detect: a Call to a membership/predicate method where the
    // tainted value is the receiver OR an argument, anywhere inside an
    // IfStatement / ConditionalExpression / a standalone `if(!ok) throw`.
    if (
      n.type === "IfStatement" ||
      n.type === "ConditionalExpression" ||
      n.type === "ThrowStatement" ||
      (n.type === "ReturnStatement" && n.argument)
    ) {
      const test = n.test || n.argument || n;
      if (testReferencesAllowDecision(test, tainted, aliasMap)) {
        gated = true;
      }
    }
  });
  return gated;
}

function testReferencesAllowDecision(node, tainted, aliasMap, depth = 0) {
  if (!node || depth > 40) return false;
  if (node.type === "CallExpression") {
    const base = calleeBase(node.callee);
    if (DENY_MEMBERSHIP.has(base) || VALIDATION_METHODS.has(base)) {
      // receiver tainted (taint.includes / allow.has(taint) / re.test(taint))
      if (
        node.callee.type === "MemberExpression" &&
        (exprIsTainted(node.callee.object, tainted, aliasMap) ||
          node.arguments.some((a) => exprIsTainted(a, tainted, aliasMap)))
      ) {
        return true;
      }
      if (node.arguments.some((a) => exprIsTainted(a, tainted, aliasMap))) return true;
    }
    // Predicate-closure allowlist: `ALLOW.some(x => x === host)` /
    // `.every(x => x !== host)` / `.find(x => x === host)` / `.filter(...)`.
    // The allowlist is the (untainted) receiver; the tainted value is
    // compared INSIDE the callback. Recognize it as a membership decision
    // when the predicate body references the tainted value — same as
    // `ALLOW.includes(host)`. (Only reached from inside an if/throw/return/
    // ternary test via hasGateBefore, so a bare `.filter` isn't a guard;
    // and a predicate that doesn't touch the taint — REG-F — stays
    // unguarded and still fires.)
    if (PREDICATE_ITER.has(base)) {
      for (const a of node.arguments) {
        const fnArg =
          a &&
          (a.type === "ArrowFunctionExpression" || a.type === "FunctionExpression")
            ? a
            : null;
        if (!fnArg) continue;
        const pbody = fnBody(fnArg);
        if (!pbody) continue;
        let refsTaint = false;
        walk(pbody, (m) => {
          if (refsTaint) return;
          if (
            m.type === "Identifier" &&
            (tainted.has(m.name) || (aliasMap.has(m.name) && aliasMap.get(m.name)))
          ) {
            refsTaint = true;
          }
        });
        if (refsTaint) return true;
      }
    }
    if (CONFIRM_RE.test(calleeName(node.callee)) || CONFIRM_RE.test(base)) return true;
  }
  // recurse into !, &&, ||, comparisons, parens, AND the receiver/callee of
  // a member/call so `ALLOW.filter(x=>x===host).length === 0` (membership
  // decision nested under `.length`) is still recognized as a guard.
  for (const k of [
    "argument",
    "left",
    "right",
    "expression",
    "test",
    "consequent",
    "alternate",
    "object",
    "callee",
  ]) {
    if (node[k] && typeof node[k] === "object" && testReferencesAllowDecision(node[k], tainted, aliasMap, depth + 1))
      return true;
  }
  return false;
}

/** A sink call's dangerous argument index by family. */
function sinkInfo(call) {
  if (call.type !== "CallExpression") return null;
  const full = calleeName(call.callee);
  const base = calleeBase(call.callee);

  // dynamic eval
  if (EVAL_BASE.has(base) || EVAL_FULL.has(full) || base === "Function") {
    // new Function(...) is a NewExpression — handled separately; here cover
    // eval(x) and vm.runInNewContext(code,...)
    if (base === "Function") return null;
    return { ruleId: "AG004", argIdx: 0 };
  }

  // shell / exec
  if (SHELL_FULL.has(full) || SHELL_BASE.has(base)) {
    // require('child_process').exec(...) resolves to base "exec" — good.
    // execFile/spawn: arg0 = file (often literal), args may be in arg1 array;
    // BUT shell:true makes arg0 a shell string. Conservative: flag if EITHER
    // arg0 OR arg1 carries taint (covers exec(`cmd ${x}`) and
    // execFile("git",[x]) where x is unsanitized and reaches argv).
    return { ruleId: "AG001", argIdx: 0, alsoIdx: 1 };
  }

  // network
  if (NET_FULL.has(full) || NET_BASE.has(base)) {
    return { ruleId: "AG003", argIdx: 0 };
  }

  // fs write/read — match `fs.X`, `fsp.X`, `fs.promises.X`, bare X from a
  // destructured import. Path is arg0 for all of these.
  if (FS_WRITE_BASE.has(base)) return { ruleId: "AG002", argIdx: 0 };
  if (FS_READ_BASE.has(base)) {
    // Only sensitive if the path is tainted (caller checks taint). A plain
    // readFile of a literal config path never fires (not tainted).
    return { ruleId: "AG005", argIdx: 0 };
  }

  return null;
}

/** Find every function that is registered as an agent tool handler in this
 *  Program, with the registration call node (for schema detection). */
function findToolHandlers(ast) {
  /** @type {Array<{fn:object, call:object}>} */
  const handlers = [];
  const seen = new Set();
  walk(ast, (node) => {
    if (node.type !== "CallExpression" && node.type !== "NewExpression") return;
    const cn = calleeName(node.callee);
    const args = node.arguments || [];

    // Shape A: a function passed as a positional argument.
    if (matchesAny(cn, HANDLER_ARG_CALLEES)) {
      for (const a of args) {
        if (
          a &&
          (a.type === "ArrowFunctionExpression" ||
            a.type === "FunctionExpression") &&
          !seen.has(a)
        ) {
          seen.add(a);
          handlers.push({ fn: a, call: node });
        }
      }
    }

    // Shape B: a function on a known handler property of an options object.
    if (matchesAny(cn, HANDLER_OBJECT_CALLEES)) {
      for (const a of args) {
        if (a && a.type === "ObjectExpression") {
          for (const p of a.properties) {
            if (
              p.type === "Property" &&
              !p.computed &&
              p.key &&
              (p.key.name || p.key.value) &&
              HANDLER_PROP_NAMES.has(String(p.key.name || p.key.value)) &&
              p.value &&
              (p.value.type === "ArrowFunctionExpression" ||
                p.value.type === "FunctionExpression") &&
              !seen.has(p.value)
            ) {
              seen.add(p.value);
              handlers.push({ fn: p.value, call: node });
            }
          }
        }
      }
    }
  });

  // class-based tools: a class extending *Tool with a `_call`/`call` method.
  walk(ast, (node) => {
    if (node.type !== "ClassDeclaration" && node.type !== "ClassExpression") return;
    const sc = node.superClass;
    const scn = sc ? calleeName(sc) || (sc.type === "Identifier" ? sc.name : "") : "";
    if (!/Tool$/.test(scn)) return;
    const cls = node.body && node.body.body ? node.body.body : [];
    for (const m of cls) {
      if (
        m.type === "MethodDefinition" &&
        m.key &&
        (m.key.name === "_call" || m.key.name === "call" || m.key.name === "invoke") &&
        m.value &&
        m.value.type === "FunctionExpression" &&
        !seen.has(m.value)
      ) {
        seen.add(m.value);
        // No registration call → no registration-schema; pass the class node
        // so we can still see a constructor-declared schema if present.
        handlers.push({ fn: m.value, call: node });
      }
    }
  });

  return handlers;
}

/** Same-module helper functions by name → their function node, so we can
 *  follow ONE hop: handler calls localHelper(taint) and the sink lives in
 *  localHelper. We only follow when the tainted value is passed as an arg
 *  (so the helper's params become tainted). */
function indexModuleFunctions(ast) {
  const byName = new Map();
  walk(ast, (n) => {
    if (n.type === "FunctionDeclaration" && n.id) byName.set(n.id.name, n);
    if (
      n.type === "VariableDeclarator" &&
      n.id &&
      n.id.type === "Identifier" &&
      n.init &&
      (n.init.type === "ArrowFunctionExpression" || n.init.type === "FunctionExpression")
    ) {
      byName.set(n.id.name, n.init);
    }
  });
  return byName;
}

function isTestFile(filename) {
  return /(^|[\\/])(__tests__|__mocks__|test|tests|spec|fixtures|e2e|\.storybook)([\\/]|$)/i.test(
    filename,
  ) || /\.(test|spec)\.[cm]?[jt]sx?$/i.test(filename) || /\.stories\.[cm]?[jt]sx?$/i.test(filename);
}

/**
 * Analyze one parsed module.
 *
 * @param {object} ast ESTree Program (from parseSource OR ESLint)
 * @param {string} filename repo-relative path (for findings + test-skip)
 * @param {{ includeTests?: boolean }} [opts]
 * @returns {Array<{ruleId,severity,file,line,column,sink,message,why,remediation,id}>}
 */
export function analyzeAst(ast, filename, opts = {}) {
  const findings = [];
  if (!ast || ast.type !== "Program") return findings;
  if (!opts.includeTests && isTestFile(filename)) return findings;

  const handlers = findToolHandlers(ast);
  if (handlers.length === 0) return findings; // not agent code → SILENT
  const moduleFns = indexModuleFunctions(ast);

  for (const { fn, call } of handlers) {
    scanHandler(fn, call, filename, findings, moduleFns, /*hop*/ 0, null);
  }

  // De-dupe (a sink reachable via two paths), stable order.
  const uniq = new Map();
  for (const f of findings) {
    const k = `${f.ruleId}|${f.file}|${f.line}|${f.column}|${f.sink}`;
    if (!uniq.has(k)) uniq.set(k, f);
  }
  const out = [...uniq.values()];
  const order = SEVERITY_ORDER;
  out.sort(
    (a, b) =>
      (order[b.severity] || 0) - (order[a.severity] || 0) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line ||
      a.column - b.column ||
      a.ruleId.localeCompare(b.ruleId),
  );
  return out;
}

function scanHandler(fn, regCall, filename, findings, moduleFns, hop, inheritedTaint) {
  const body = fnBody(fn);
  if (!body) return;

  // Taint = this fn's params (∪ inherited taint when followed as a helper).
  const tainted = taintBaseNames(fn);
  if (inheritedTaint) for (const t of inheritedTaint) tainted.add(t);
  if (tainted.size === 0 && hop === 0) {
    // A zero-arg tool handler takes no model input → nothing to taint →
    // SILENT (conservative: we only fire on model-controlled data flow).
    return;
  }
  const aliasMap = buildAliases(body, tainted);

  // GUARD G1 at the path level: if the registration carried a schema, OR the
  // body validates the input, the entire handler is considered guarded for
  // input-shape — we then ONLY keep findings whose tainted value is NOT the
  // validated one. Practically: a validated handler is silent (the moat).
  const schemaGuard =
    registrationHasSchema(regCall, fn) || hasInBodyValidation(body, tainted, aliasMap);

  const collected = collect(body, (n) => n.type === "CallExpression" || n.type === "NewExpression");
  for (const call of collected) {
    // new Function("..."+taint) — dynamic code exec
    if (call.type === "NewExpression") {
      const cn = call.callee && call.callee.type === "Identifier" ? call.callee.name : "";
      if (cn === "Function") {
        if (call.arguments.some((a) => exprIsTainted(a, tainted, aliasMap))) {
          maybePush("AG004", call, body, tainted, aliasMap, schemaGuard, findings, filename, fn);
        }
      }
      continue;
    }

    const info = sinkInfo(call);
    if (!info) {
      // ONE-HOP helper follow: handler calls a same-module function with the
      // tainted value → re-scan that helper with the arg positions tainted.
      if (hop === 0) {
        const callee = call.callee;
        const name =
          callee && callee.type === "Identifier"
            ? callee.name
            : callee && callee.type === "MemberExpression" && !callee.computed && callee.property
            ? callee.property.name
            : "";
        const helper = name && moduleFns.get(name);
        if (
          helper &&
          helper !== fn &&
          call.arguments.some((a) => exprIsTainted(a, tainted, aliasMap))
        ) {
          // Which helper params receive a tainted arg → seed their names.
          const seed = new Set();
          const params = helper.params || [];
          call.arguments.forEach((a, i) => {
            if (exprIsTainted(a, tainted, aliasMap) && params[i]) {
              collectBindingNames(params[i], seed);
            }
          });
          if (seed.size) {
            // If THIS handler is schema-guarded, the helper is too (the
            // value was validated before being passed down).
            scanHandler(
              helper,
              schemaGuard ? makeSyntheticSchemaCall(helper) : null,
              filename,
              findings,
              moduleFns,
              hop + 1,
              seed,
            );
          }
        }
      }
      continue;
    }

    // promisify(exec)(taint) — exec wrapped: callee is itself a CallExpr.
    // Conservatively also handle `const e=promisify(exec); await e(taint)`
    // by treating the SHELL base detection above (e is not matched, but the
    // direct exec/execSync/spawn names are the 99% case and what we assert).

    const idxs = [info.argIdx];
    if (info.alsoIdx != null) idxs.push(info.alsoIdx);
    const argTainted = idxs.some((i) => call.arguments[i] && exprIsTainted(call.arguments[i], tainted, aliasMap));
    if (!argTainted) continue; // literal/constant sink arg → SILENT

    maybePush(info.ruleId, call, body, tainted, aliasMap, schemaGuard, findings, filename, fn);
  }
}

function makeSyntheticSchemaCall(helper) {
  // A registration call shape that registrationHasSchema() reads as
  // "schema present" so a validated value followed into a helper stays
  // guarded. (Internal sentinel; never emitted.)
  return {
    type: "CallExpression",
    callee: { type: "Identifier", name: "__agentguard_validated__" },
    arguments: [{ type: "ObjectExpression", properties: [{ type: "Property" }] }, helper],
  };
}

function maybePush(ruleId, call, body, tainted, aliasMap, schemaGuard, findings, filename, fn) {
  // GUARD: input was schema-validated at registration or in-body → SILENT.
  if (schemaGuard) return;
  // GUARD: an allow/deny decision or human-confirmation precedes the sink.
  if (hasGateBefore(body, call, tainted, aliasMap)) return;
  // GUARD: the tainted value is itself wrapped in a validation call AT the
  // sink (e.g. exec(schema.parse(input))) — already safe.
  const rule = RULES[ruleId];
  const p = pos(call);
  const sinkText = calleeName(call.callee) || calleeBase(call.callee) || "<call>";
  findings.push({
    ruleId,
    severity: rule.severity,
    file: filename,
    line: p.line,
    column: p.column,
    sink: sinkText,
    message: rule.title,
    why: rule.blurb,
    remediation: remediationFor(ruleId),
    id: stableId(ruleId, filename, p.line, p.column, sinkText),
  });
}

function remediationFor(ruleId) {
  switch (ruleId) {
    case "AG001":
      return "Register the tool with an input schema (Zod/JSON-schema), then either use an argv array with execFile (never a shell string), match the command/args against an explicit allowlist before running, or require a human-confirmation step for shell actions.";
    case "AG002":
      return "Resolve the path and assert it stays within an allowed base directory (path.resolve + startsWith check), reject path traversal, or gate destructive writes behind explicit human confirmation.";
    case "AG003":
      return "Validate the URL and check its host against an allowlist (and block private/link-local ranges) before the request, or require confirmation for outbound calls to model-supplied destinations.";
    case "AG004":
      return "Do not eval model-controlled input. Replace dynamic code execution with a fixed dispatch table / parser, or a sandbox with no ambient authority — and validate the input first.";
    case "AG005":
      return "Confine reads to an allowlisted directory (path.resolve + containment check) and reject traversal, so a tool cannot be steered to read arbitrary files whose contents return to the model.";
    default:
      return "Add input validation, an allowlist/denylist check, or a human-confirmation gate on the path from tool input to this action.";
  }
}

// Deterministic, content-addressed id so SARIF/baseline can track a finding
// across runs without a counter. Tiny FNV-1a (no crypto dep, offline).
function stableId(ruleId, file, line, column, sink) {
  const s = `${ruleId}:${file}:${line}:${column}:${sink}`;
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return `AG-${h.toString(16).padStart(8, "0")}`;
}

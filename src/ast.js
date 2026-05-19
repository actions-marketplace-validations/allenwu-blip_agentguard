/**
 * ast.js — the ONLY place that turns source text into an AST, plus a tiny
 * generic ESTree walker.
 *
 * agentguard is AST-based on purpose. A regex/line linter for "is this tool
 * call guarded?" cries wolf constantly (a `// exec(` in a comment, an
 * `exec` substring, a guard three lines away it cannot see) and gets
 * uninstalled. We parse with `@typescript-eslint/typescript-estree`, which
 * yields a normal ESTree for `.js/.jsx/.mjs/.cjs/.ts/.tsx` — the exact AST
 * shape ESLint produces, so the bundled ESLint plugin reuses the SAME pure
 * rule core on ESLint's tree without re-parsing.
 *
 * NO file I/O and NO code execution here (parsing only). A parse error is
 * returned, never thrown — a single unparseable file degrades the scan, it
 * never aborts CI.
 */

import { parse as tsParse } from "@typescript-eslint/typescript-estree";

/**
 * Parse source into an ESTree Program with `loc` (1-based line, 0-based
 * column) and `range`. `jsx` is enabled so `.tsx/.jsx` agent UIs parse.
 * Returns `{ ast }` or `{ error }` — callers must handle `error` (fail-open).
 *
 * @param {string} code
 * @param {string} [filename] used only for nicer parser diagnostics
 * @returns {{ ast: object } | { error: string }}
 */
export function parseSource(code, filename = "<input>") {
  try {
    const ast = tsParse(code, {
      loc: true,
      range: true,
      jsx: true,
      // No type-checking program: pure syntactic parse, fully offline, fast,
      // and never resolves/executes the scanned project's tsconfig.
      comment: false,
      tokens: false,
      errorOnUnknownASTType: false,
      // Be permissive: experimental/legacy syntax shouldn't abort a scan.
      allowInvalidAST: false,
    });
    return { ast };
  } catch (e) {
    return { error: `parse error in ${filename}: ${e && e.message ? e.message : String(e)}` };
  }
}

// Keys that are never child AST nodes — skipping them keeps the walk O(nodes)
// and avoids cycles via `parent` back-references.
const NON_CHILD_KEYS = new Set([
  "parent",
  "loc",
  "range",
  "start",
  "end",
  "type",
  "raw",
  "value",
  "name",
  "operator",
  "kind",
  "sourceType",
  "regex",
  "bigint",
  "optional",
  "computed",
  "prefix",
  "delegate",
  "async",
  "generator",
  "static",
  "method",
  "shorthand",
  "directive",
]);

/**
 * Depth-first pre-order walk. `visit(node, parent)` is called for every node
 * (parent is null for the root). Pure; no allocation beyond the stack.
 *
 * @param {object} root an ESTree node
 * @param {(node:object, parent:(object|null))=>void} visit
 */
export function walk(root, visit) {
  if (!root || typeof root !== "object") return;
  const stack = [[root, null]];
  while (stack.length) {
    const [node, parent] = stack.pop();
    if (!node || typeof node !== "object" || typeof node.type !== "string") continue;
    visit(node, parent);
    for (const key in node) {
      if (NON_CHILD_KEYS.has(key)) continue;
      const v = node[key];
      if (Array.isArray(v)) {
        for (let i = v.length - 1; i >= 0; i--) {
          const c = v[i];
          if (c && typeof c === "object" && typeof c.type === "string") stack.push([c, node]);
        }
      } else if (v && typeof v === "object" && typeof v.type === "string") {
        stack.push([v, node]);
      }
    }
  }
}

/**
 * Collect every descendant (inclusive) that satisfies `pred`, pre-order.
 * @param {object} root
 * @param {(n:object)=>boolean} pred
 * @returns {object[]}
 */
export function collect(root, pred) {
  const out = [];
  walk(root, (n) => {
    if (pred(n)) out.push(n);
  });
  return out;
}

/**
 * 1-based line / 1-based column for human + SARIF output. ESTree `loc`
 * columns are 0-based; we add 1 so it matches what editors show.
 * @param {object} node
 * @returns {{ line:number, column:number }}
 */
export function pos(node) {
  const l = node && node.loc && node.loc.start;
  return {
    line: l && Number.isFinite(l.line) ? l.line : 1,
    column: l && Number.isFinite(l.column) ? l.column + 1 : 1,
  };
}

/**
 * Resolve a callee to a dotted name string for matching:
 *   foo            -> "foo"
 *   a.b.c          -> "a.b.c"
 *   a?.b()         -> "a.b"
 *   a["b"]         -> "a.b"   (only static string/identifier members)
 * Returns "" if it cannot be resolved to a stable static name.
 * @param {object} node a callee expression
 * @returns {string}
 */
export function calleeName(node) {
  if (!node) return "";
  if (node.type === "ChainExpression") return calleeName(node.expression);
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") {
    const objName = calleeName(node.object);
    let prop = "";
    if (!node.computed && node.property && node.property.type === "Identifier") {
      prop = node.property.name;
    } else if (
      node.computed &&
      node.property &&
      node.property.type === "Literal" &&
      typeof node.property.value === "string"
    ) {
      prop = node.property.value;
    } else {
      return "";
    }
    return objName ? `${objName}.${prop}` : prop;
  }
  return "";
}

/** The unqualified last segment of a callee name ("a.b.c" -> "c"). */
export function calleeBase(node) {
  const n = calleeName(node);
  if (!n) {
    // a().b()  — property on a non-name object: still expose the prop.
    if (
      node &&
      node.type === "MemberExpression" &&
      !node.computed &&
      node.property &&
      node.property.type === "Identifier"
    ) {
      return node.property.name;
    }
    return "";
  }
  const i = n.lastIndexOf(".");
  return i === -1 ? n : n.slice(i + 1);
}

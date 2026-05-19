/**
 * analyze.js — the ONLY place that touches the filesystem.
 *
 * Walks a local directory, reads source files, parses them (ast.js) and
 * runs the pure detection core (rules.js). It NEVER executes the scanned
 * project and NEVER does network I/O. Any error (unreadable file, parse
 * failure) is collected into `errors` and returned — analyzeProject does
 * not throw, so the CLI/Action can fail OPEN and never break host CI.
 *
 * Hardening mirrors the conservative discipline of this operation's
 * mcp-audit-cli: symlinks are never followed, the scan cannot be steered
 * outside the target tree, oversized/minified/binary blobs are skipped (a
 * bundle is not the audited source), and output is bounded.
 */

import {
  readFileSync,
  readdirSync,
  statSync,
  lstatSync,
  existsSync,
  realpathSync,
} from "node:fs";
import { join, relative, sep, resolve } from "node:path";
import { parseSource } from "./ast.js";
import { analyzeAst } from "./rules.js";

const SOURCE_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"]);
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  ".nuxt",
  ".cache",
  "out",
  "vendor",
  ".turbo",
  ".yarn",
]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_FILES = 6000;
const MAX_DEPTH = 40;

function looksMinified(txt) {
  if (txt.length < 50000) return false;
  let longest = 0;
  let cur = 0;
  for (let i = 0; i < txt.length; i++) {
    if (txt.charCodeAt(i) === 10) {
      if (cur > longest) longest = cur;
      cur = 0;
    } else cur++;
  }
  if (cur > longest) longest = cur;
  return longest > 5000;
}

function looksBinary(txt) {
  const n = Math.min(txt.length, 4096);
  for (let i = 0; i < n; i++) if (txt.charCodeAt(i) === 0) return true;
  return false;
}

function* walkTree(root, errors) {
  let canonRoot;
  try {
    canonRoot = realpathSync(root);
  } catch {
    canonRoot = resolve(root);
  }
  const stack = [{ dir: root, depth: 0 }];
  let count = 0;
  while (stack.length) {
    const { dir, depth } = stack.pop();
    if (depth > MAX_DEPTH) {
      errors.push(`max directory depth (${MAX_DEPTH}) reached at ${dir}; subtree skipped`);
      continue;
    }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      errors.push(`cannot read directory ${dir}: ${e.message}`);
      continue;
    }
    for (const ent of entries) {
      const full = join(dir, ent.name);
      if (ent.isSymbolicLink()) {
        errors.push(`skipped symlink (not followed): ${relative(root, full) || ent.name}`);
        continue;
      }
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name) || ent.name.startsWith(".")) continue;
        let realFull;
        try {
          realFull = realpathSync(full);
        } catch {
          realFull = resolve(full);
        }
        if (realFull !== canonRoot && !realFull.startsWith(canonRoot + sep)) {
          errors.push(`skipped path outside scan root: ${relative(root, full) || ent.name}`);
          continue;
        }
        stack.push({ dir: full, depth: depth + 1 });
      } else if (ent.isFile()) {
        if (++count > MAX_FILES) {
          errors.push(`file cap (${MAX_FILES}) reached; scan truncated`);
          return;
        }
        yield full;
      }
    }
  }
}

function safeRead(file, errors) {
  try {
    const st = lstatSync(file);
    if (st.isSymbolicLink()) {
      errors.push(`skipped symlink file (not followed): ${file}`);
      return null;
    }
    if (st.size > MAX_FILE_BYTES) {
      errors.push(
        `skipped large file (> ${MAX_FILE_BYTES} bytes): ${file} (likely a bundle/minified artifact)`,
      );
      return null;
    }
    const txt = readFileSync(file).toString("utf8");
    if (looksBinary(txt)) {
      errors.push(`skipped binary/non-text file: ${file}`);
      return null;
    }
    return txt;
  } catch (e) {
    errors.push(`cannot read file ${file}: ${e.message}`);
    return null;
  }
}

/**
 * @param {string|string[]} rootDirs one or more paths (file or directory).
 * @param {{ includeTests?: boolean }} [opts]
 * @returns {{ roots:string[], findings:object[], scannedFiles:string[], errors:string[] }}
 */
export function analyzeProject(rootDirs, opts = {}) {
  const roots = Array.isArray(rootDirs) ? rootDirs : [rootDirs];
  const errors = [];
  const findings = [];
  const scannedFiles = [];

  for (const rootDir of roots) {
    if (!existsSync(rootDir)) {
      errors.push(`path does not exist: ${rootDir}`);
      continue;
    }
    let st;
    try {
      st = statSync(rootDir);
    } catch (e) {
      errors.push(`cannot stat ${rootDir}: ${e.message}`);
      continue;
    }

    const files = [];
    if (st.isFile()) {
      files.push({ full: rootDir, base: rootDir });
    } else if (st.isDirectory()) {
      for (const f of walkTree(rootDir, errors)) files.push({ full: f, base: rootDir });
    } else {
      errors.push(`not a file or directory: ${rootDir}`);
      continue;
    }

    for (const { full, base } of files) {
      const baseName = full.split(sep).pop();
      const dot = full.slice(full.lastIndexOf("."));
      if (!SOURCE_EXT.has(dot)) continue;
      if (/\.min\.[cm]?js$/.test(baseName) || /\.d\.ts$/.test(baseName) || /\.bundle\.[cm]?js$/.test(baseName))
        continue;
      const rel =
        st.isFile() ? baseName : relative(base, full) || baseName;
      const txt = safeRead(full, errors);
      if (txt == null) continue;
      if (looksMinified(txt)) {
        errors.push(
          `skipped minified/obfuscated source (very long lines): ${rel} — audit the original, not the bundle`,
        );
        continue;
      }
      const parsed = parseSource(txt, rel);
      if (parsed.error) {
        errors.push(parsed.error);
        continue;
      }
      scannedFiles.push(rel);
      try {
        for (const fnd of analyzeAst(parsed.ast, rel, opts)) findings.push(fnd);
      } catch (e) {
        // A rule bug must never break the host build (fail-open contract).
        errors.push(`internal rule error on ${rel}: ${e && e.message ? e.message : String(e)}`);
      }
    }
  }

  if (errors.length > 200) {
    const extra = errors.length - 200;
    errors.length = 200;
    errors.push(`(+${extra} more diagnostics suppressed)`);
  }

  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  findings.sort(
    (a, b) =>
      (order[b.severity] || 0) - (order[a.severity] || 0) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line ||
      a.column - b.column ||
      a.ruleId.localeCompare(b.ruleId),
  );

  return { roots, findings, scannedFiles, errors };
}

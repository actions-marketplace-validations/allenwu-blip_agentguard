/**
 * agentguard — public programmatic API.
 *
 * Static AST linter for MISSING guards on AI-agent tool calls. Pure core
 * (rules.js) + a filesystem analyzer (analyze.js) + presenters
 * (format.js). No network, no code execution, no LLM.
 */

export { analyzeProject } from "./analyze.js";
export { analyzeAst, RULES, SEVERITY_ORDER } from "./rules.js";
export { parseSource } from "./ast.js";
export { formatHuman, formatJson, formatSarif, countBySeverity } from "./format.js";
export { loadConfig, applyConfig, DEFAULT_CONFIG } from "./config.js";
export { captureFeedback, loadFeedback } from "./feedback.js";

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

/** Resolve the package version from package.json (no hardcoded drift). */
export function version() {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8"));
    return pkg.version || "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/**
 * eslint-plugin-agentguard
 *
 * Drops agentguard's conservative AST detection into an existing ESLint
 * pipeline so it runs on every lint, in editors and CI, with no extra step.
 *
 * It reuses the EXACT same pure detection core as the CLI (../src/rules.js)
 * — ESLint's `Program` node IS an ESTree Program, so we analyze it directly
 * with NO re-parse and NO divergence between the CLI and the plugin. (Use
 * `@typescript-eslint/parser` in your ESLint config to lint .ts/.tsx; plain
 * espree covers .js/.jsx.)
 *
 * One rule: `agentguard/no-unguarded-tool-call`. It fires ONLY when a
 * side-effectful sink is reachable from an agent tool handler with the
 * model-controlled input on the path and NO guard (schema/validation,
 * allowlist/denylist, or human-confirmation). Guarded and non-agent code is
 * intentionally silent — see the README "conservative philosophy".
 *
 * No network, no code execution, no LLM.
 */

import { analyzeAst, RULES } from "../src/rules.js";

const REPO = "https://github.com/portfolio-foundry/agent-guard-lint";

// One messageId per ruleId so a project can target a specific finding class
// with an eslint-disable comment without silencing the others.
const messages = {};
for (const id of Object.keys(RULES)) {
  messages[id] = `${RULES[id].title}: {{why}} Fix: {{remediation}}`;
}

/** @type {import('eslint').Rule.RuleModule} */
const noUnguardedToolCall = {
  meta: {
    type: "problem",
    docs: {
      description:
        "Flag a side-effectful sink (shell/exec, sensitive fs write/read, outbound network, dynamic eval) reachable from an AI-agent tool handler with model-controlled input on the path and no validation/allowlist/confirmation guard.",
      recommended: true,
      url: `${REPO}#eslint-plugin`,
    },
    // No autofix: a missing guard is a design decision the human must make
    // (which allowlist? confirm or validate?). A wrong autofix here is worse
    // than the finding. We only report.
    schema: [
      {
        type: "object",
        properties: {
          includeTests: {
            type: "boolean",
            description:
              "Also analyze test/spec/fixture files (default false — agent handlers in tests are usually intentional demos).",
          },
        },
        additionalProperties: false,
      },
    ],
    messages,
  },

  create(context) {
    const opts = (context.options && context.options[0]) || {};
    const filename =
      (context.filename || (context.getFilename && context.getFilename()) || "<input>");

    return {
      "Program:exit"(programNode) {
        let findings;
        try {
          findings = analyzeAst(programNode, filename, {
            includeTests: opts.includeTests === true,
          });
        } catch {
          // FAIL-OPEN: a rule bug must never break the host lint run.
          return;
        }
        for (const f of findings) {
          context.report({
            // ESLint loc: 1-based line, 0-based column. analyzeAst returns
            // 1-based column (editor convention) — convert back.
            loc: {
              start: {
                line: f.line,
                column: Math.max(0, (f.column || 1) - 1),
              },
            },
            messageId: f.ruleId,
            data: { why: f.why, remediation: f.remediation },
          });
        }
      },
    };
  },
};

const plugin = {
  meta: {
    name: "eslint-plugin-agentguard",
    version: "0.1.0",
  },
  rules: {
    "no-unguarded-tool-call": noUnguardedToolCall,
  },
};

// Flat-config presets (ESLint 9+). `recommended` turns the rule on as an
// error; `warn` as a warning. Consumers can also wire the rule by hand.
plugin.configs = {
  recommended: {
    name: "agentguard/recommended",
    plugins: { agentguard: plugin },
    rules: { "agentguard/no-unguarded-tool-call": "error" },
  },
  warn: {
    name: "agentguard/warn",
    plugins: { agentguard: plugin },
    rules: { "agentguard/no-unguarded-tool-call": "warn" },
  },
};

export default plugin;
export { noUnguardedToolCall };

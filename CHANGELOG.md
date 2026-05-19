# Changelog

All notable changes to `agentguard` are documented here. This project
adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — unreleased

Initial release.

### Added

- **AST-based detection core** (`@typescript-eslint/typescript-estree`, not
  regex) for missing guards on AI-agent tool calls. Five rules:
  - `AG001` (critical) — unguarded `child_process` exec/spawn/execFile/fork
  - `AG002` (high) — unguarded sensitive filesystem write
  - `AG003` (high) — unguarded outbound network to a tool-input URL
  - `AG004` (critical) — unguarded dynamic `eval`/`new Function`/`vm`
  - `AG005` (high) — unguarded sensitive filesystem read
- **Conservative, provenance-gated** firing: only when a sink is reachable
  from a recognized agent tool handler, the model-controlled input is
  data-tainted onto the sink, and no guard (input schema/validation,
  allowlist/denylist, or human-confirmation) is on the path. Silent on
  guarded code, non-agent code, and test files by default.
- Recognized SDK surfaces: MCP (`server.tool`, `setRequestHandler`),
  LangChain (`DynamicStructuredTool`/`StructuredTool`/`tool(fn,{…})`, class
  `_call`), Vercel AI SDK (`tool({execute})`), LlamaIndex
  (`FunctionTool.from`), and common `defineTool`/`createTool`/`registerTool`
  wrappers. One-hop same-module helper following.
- **Standalone CLI** (`npx agentguard <path…>`): human report, `--json`,
  `--sarif` (v2.1.0 for GitHub code scanning), `--fail-on`, `--config`,
  `--include-tests`. Exit-code CI gate. **Fails open** on internal error.
- **ESLint plugin** (`agentguard/eslint-plugin`) reusing the exact same
  detection core (no re-parse), with `recommended`/`warn` flat-config
  presets and per-rule message ids.
- **GitHub Action** (thin wrapper): inputs/outputs, inline PR annotations,
  SARIF, fails open.
- Optional `.agentguardrc.json`: per-rule severity, rule-off, path-ignore
  globs, accepted-finding-id allowlist.
- Verbatim misfire-feedback contract (`FEEDBACK.md`, issue template,
  `agentguard-feedback` label, `src/feedback.js`).
- Test suite (offline, no key): clean=0, vulnerable=every rule fires at the
  right location & severity, borderline-legit=0 false positives, ESLint
  plugin via `RuleTester`, SARIF schema, config, feedback, filesystem
  hardening, and a dogfood self-scan (0 findings).

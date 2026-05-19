# agentguard

**A building inspector for the missing safety railings around your AI agent's
tools.**

When you give an AI agent tools, the AI decides what to pass into them — and
those values can end up running shell commands, touching your files, hitting
the network, or executing code. The safety railing is a check on the way in:
validate the input, check it against an allow/deny list, or ask a human first.
agentguard reads your code and points at the dangerous tool actions that have
**no such railing** — while staying quiet about the ones you've **already**
guarded, so it doesn't nag you about safe code.

```bash
npx agentguard ./src
```

It comes three ways so it fits wherever you already work: a **standalone
command-line tool** (plain / `--json` / `--sarif` output), an **ESLint
plugin** (it slots into the linter most JS projects already run), and a thin
**GitHub Action**. No install ceremony, no config required, no API key, no
network, no AI involved. It **never runs** the code it checks — it only reads
it.

---

## Why this exists

When you give an LLM (a large language model — the kind of AI behind chat
assistants) a set of tools, every tool handler is a way in for an attacker:
the model — or anything that can steer it, like a prompt injection hidden in a
web page it fetched, a poisoned document, or a malicious sub-agent — chooses
the arguments, and those arguments flow into a shell command, the filesystem,
the network, or code execution. The single most effective defense is a
**railing on that path**: validate the input, check it against an allow/deny
list, or require a human to confirm before the action happens.

A [Show HN post that scanned 16 open-source AI-agent
repos](https://news.ycombinator.com/item?id=47947356) reported that
**76% of tool calls had no guards at all.**

> That **76% figure is from that outside scan — this tool did not measure or
> reproduce it.** agentguard also does not publish any accuracy number for
> itself (a code-reading tool like this cannot honestly claim one — see
> [Limitations](#limitations)). It exists so you can run a deliberately
> cautious check on your own code, in seconds, and see your unguarded tool
> actions before they ship.

## What it detects

This is the developer reference. agentguard reads your code with a **real
JS/TS parser** — it builds an AST (an abstract syntax tree, the structured
form of your code a compiler uses) rather than crude text matching. It then
flags something **only when all of these are true**:

1. the function is an **agent tool handler** — registered through an
   agent framework API it recognizes (MCP `server.tool` / `setRequestHandler`,
   LangChain `DynamicStructuredTool` / `StructuredTool` / `tool(fn,{…})`,
   Vercel AI SDK `tool({execute})`, LlamaIndex `FunctionTool.from`,
   `defineTool`/`createTool`/`registerTool`-style wrappers);
2. a **dangerous operation** (a "sink" — a spot where input causes a real
   side effect: a shell command, a file write, a network call, code
   execution) is reachable inside it, or in a same-file helper it calls,
   followed one hop;
3. the dangerous argument actually traces back to the handler's
   model-controlled input (a fixed/constant argument never counts, so it
   never fires);
4. **no railing is present on that path**.

| Rule | Severity | What it flags |
|------|----------|---------------|
| `AG001` | critical | Unguarded `child_process` exec/spawn/execFile/fork from tool input |
| `AG002` | high | Unguarded sensitive filesystem **write** (write/unlink/rm/rename/chmod, incl. `fs-extra`) from tool input |
| `AG003` | high | Unguarded outbound **network** (fetch/axios/http(s)/got/undici) to a tool-input URL |
| `AG004` | critical | Unguarded **dynamic code execution** (`eval` / `new Function` / `vm`) of tool input |
| `AG005` | high | Unguarded sensitive filesystem **read** (path traversal / secret exfiltration) of a tool-input path |

Each finding reports: rule id, severity, `file:line:column`, the exact
**sink**, **why** it fired, and a concrete **remediation**.

### What counts as a railing (a "guard") — and makes agentguard stay silent

A "guard" is the railing referred to above. agentguard recognizes three
families of them. If one is on the path, the finding does **not** fire:

- **Input validation / schema (G1)** — the tool is registered *with* a
  schema (Zod / JSON-schema / `parameters` / `inputSchema`), or the handler
  runs `.parse` / `.safeParse` / `.validate` / `.assert` / `.cast` (Zod /
  Joi / Yup / ajv / superstruct / io-ts) on the input. A value reassigned
  from a validation result is treated as untainted.
- **Allowlist / denylist (G2)** — a membership/predicate decision on the
  tainted value (`Set.has`, `Array.includes`, a regex `.test`,
  `startsWith`/`endsWith`, …) that can stop the sink (an `if` + `throw` /
  `return` / `reject`, a guard clause, a ternary) **before** the sink.
- **Human confirmation (G3)** — an awaited/used call whose name matches
  `confirm` / `approve` / `requireApproval` / `askUser` / `humanInTheLoop` /
  `checkpoint` / … **before** the sink.

A check that appears **after** the dangerous call does not count — order and
reachability are respected.

## The conservative philosophy (the whole point)

> **A linter that cries wolf gets uninstalled.** Low false positives is not
> a nice-to-have here — it _is_ the product.

agentguard deliberately accepts **false negatives** to keep **false
positives near zero**:

- It is **silent on guarded code**, on **non-agent code**, and on **test /
  spec / fixture files** by default.
- It only fires when the model-controlled value plausibly **reaches** the
  sink (literal/constant arguments never fire).
- It does **not** guess unknown SDK shapes. If your tool is registered
  through an API it doesn't recognize, it stays silent rather than guess.
- It is **intra-module** and conservative about data flow. A guard in
  another file it can't see will produce a false negative — that is the
  intended trade.

If agentguard ever flags code you believe is safe, that's the bug that
matters most to us — please [report it](#feedback). We tune toward silence,
not noise.

## Install / run

Zero-install via `npx`. A local path is scanned fully offline.

```bash
# scan your agent's source
npx agentguard ./src

# multiple paths
npx agentguard ./src ./packages/agent

# machine-readable for tooling / CI
npx agentguard ./src --json

# SARIF v2.1.0 (a standard scan-results format GitHub understands) —
# upload it so findings show in GitHub's code scanning tab
npx agentguard ./src --sarif > agentguard.sarif

# stricter gate: any high or critical fails the command
npx agentguard ./src --fail-on high     # (high is the default)

# include test files in the scan (off by default)
npx agentguard ./src --include-tests
```

### Exit codes (so you can wire it into CI)

CI ("continuous integration" — the automated checks that run on every code
push) reads these exit codes:

| code | meaning |
|------|---------|
| `0`  | scan completed, gate not tripped. **Also** internal error — see below. |
| `1`  | scan completed and a finding met/exceeded `--fail-on` (default `high`). |
| `2`  | usage error (bad arguments). |

**Fails open on purpose:** if agentguard itself breaks (a bug, a folder it
can't read, a file it can't parse), it prints a loud error and **exits 0**. A
linter that is itself broken must never block every build. A single
unparseable file degrades the scan; it never aborts it. If you want it to be a
*hard* stop, make it a **required** check with `--fail-on` set, so a missing
or zero result is visible rather than silently passing.

## Use it as an ESLint plugin

The plugin reuses the **exact same detection core** as the CLI — ESLint's
`Program` node *is* an ESTree Program, so there is no re-parse and no
behavioral drift between the CLI and the plugin.

ESLint **flat config** (`eslint.config.js`, ESLint 9+):

```js
import agentguard from "agentguard/eslint-plugin";

export default [
  // turn the rule on as an error everywhere
  agentguard.configs.recommended,

  // …or wire it by hand for more control:
  {
    plugins: { agentguard },
    rules: {
      "agentguard/no-unguarded-tool-call": ["error", { includeTests: false }],
    },
  },
];
```

To lint TypeScript, use `@typescript-eslint/parser` for your `.ts`/`.tsx`
files as usual; plain espree covers `.js`/`.jsx`. The single rule
`agentguard/no-unguarded-tool-call` reports one message per finding, keyed
by the rule id (`AG001`…`AG005`) so you can `eslint-disable` a specific
class without silencing the rest. There is **no autofix** — choosing the
right guard (which allowlist? validate or confirm?) is a human decision, and
a wrong autofix here is worse than the finding.

## Use it as a GitHub Action

```yaml
# .github/workflows/agentguard.yml
name: agentguard
on: [push, pull_request]
jobs:
  agentguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: portfolio-foundry/agent-guard-lint@v0   # or a pinned SHA
        with:
          path: "src"
          fail-on: "high"
          sarif: "true"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agentguard.sarif
```

The Action emits inline PR annotations, sets outputs
(`total`/`critical`/`high`/`medium`/`low`/`gate`/`sarif-file`), and **fails
open** on internal error. No tokens or secrets required.

## Configuration (optional)

agentguard works with **zero config**. To tune it, add
`.agentguardrc.json` at the repo root (or pass `--config <file>`):

```json
{
  "severities": { "AG003": "medium", "AG005": "off" },
  "ignore": ["legacy/**", "scripts/*.js"],
  "allow": ["AG-1a2b3c4d"]
}
```

- `severities` — remap a rule's severity, or set it to `"off"`.
- `ignore` — path globs to skip (anchored; `*` = non-`/`, `**` = anything).
  Note: the moat is _low false positives_, not silencing — prefer fixing or
  `allow`-listing a reviewed finding over broad `ignore`.
- `allow` — stable finding ids (the `AG-xxxxxxxx` in `--json`) that you have
  reviewed and accepted; they stop gating without hiding *new* findings.

## Limitations (read this)

agentguard is **conservative static analysis**, not a prover. It is honest
about what it cannot do:

- **Static analysis cannot prove reachability.** Whether a sink is *actually*
  reachable from untrusted input at runtime is undecidable in general.
  agentguard uses AST heuristics and a deliberately shallow, intra-module
  taint model; it is intentionally tuned to **miss** rather than to **cry
  wolf**.
- **One-hop, same-module helper following only.** A sink behind a deep call
  chain, or in another module, or behind dynamic dispatch, is a false
  negative by design.
- **Known-SDK recognition only.** If your tools are registered through an
  API agentguard doesn't recognize, it stays silent (no guessing). Open an
  issue with the shape and we'll consider adding it conservatively.
- **Guards it can't see are assumed absent → it errs toward _not_ firing**,
  but a guard implemented in a way it doesn't model (e.g. a custom validator
  with an unrecognized name) can still yield a false negative.
- **Language scope:** JavaScript and TypeScript (`.js .jsx .mjs .cjs .ts
  .tsx .mts .cts`). Minified/bundled/`.d.ts` files are skipped (a bundle is
  not the audited source).
- **No autofix, no severity inflation, no invented metrics.** It reports
  what it can defend.

A clean agentguard run means "no *unguarded* tool-call sink that this
conservative analysis can see" — **not** "this agent is safe." Use it as one
fast layer, not the only one.

## What it does NOT do

No network. No telemetry. No API key. No LLM/AI. It never executes the code
it scans, never resolves your `tsconfig`/project, and the analysis core is a
pure function (`source → findings`) — which is why the whole thing is unit
tested offline.

## Development

```bash
npm ci
npm test           # full suite, offline, no key
npm run dogfood    # agentguard scans its own source → must be 0 findings
```

The test suite proves the three pillars on committed fixtures:
**clean = 0**, **vulnerable = every rule fires at the right location &
severity**, **borderline-legit = 0 false positives** (the moat). It also
runs the ESLint plugin through the official `RuleTester` and validates the
SARIF v2.1.0 shape GitHub code scanning ingests.

## Feedback

False positives and false negatives are the most useful thing you can send.
See **[FEEDBACK.md](FEEDBACK.md)**. The zero-friction path: open an issue and
add the **`agentguard-feedback`** label (there's an issue template). What you
write is captured and read **exactly as written** — not summarized.

## License

[MIT](LICENSE).

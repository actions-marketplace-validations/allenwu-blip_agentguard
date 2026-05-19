# PUBLISH — agent-guard-lint / agentguard (Allen-only owner gates)

Built & independently reviewed: real Node 20 command-line tool + ESLint plugin + GitHub Action, 110 tests green from a clean install, real code parsing (a true JS/TS parser, not text matching) via @typescript-eslint/typescript-estree, deliberately cautious design (flags only when no railing is on the AI-controlled path), no AI, no network, no API key. **AI never does the steps below — they are identity/publish, only you.**

## Gate 1 — Publish the free CLI + ESLint plugin + Action (drives adoption; $0 cost)

1. Create a **public GitHub repo** under your account/org (e.g. `<owner>/agentguard`).
2. In `products/agent-guard-lint/package.json`: set `"private": false` (required before `npm publish`; the `npx` + Action path works regardless, but the registry refuses while private).
3. Replace every `<OWNER>` placeholder in `README.md` and `examples/` with your real GitHub owner handle.
4. Push the `products/agent-guard-lint/` contents to that repo root; tag a release (`v0` + a SHA-pinned tag); enable **GitHub Marketplace** listing for the Action (`action.yml` is present).
5. Create label **`agentguard-feedback`** in that repo (the primary channel where real user reports come in, stored word-for-word, for this bet).
6. Publish to npm for `npx @allenwu06/agentguard` and ESLint plugin import support: `npm publish --access public`.
   - The ESLint plugin is exported at the `./eslint-plugin` subpath — no separate package needed.

→ After this, teams can `uses: <owner>/agentguard@v0` in CI, `npx @allenwu06/agentguard ./src` from the terminal, and `import agentguard from '@allenwu06/agentguard/eslint-plugin'` in their ESLint config. **This is the real signal start.**

### npm name note

The package is published as `@allenwu06/agentguard` (npm scope = npm username allenwu06; reason: npm name-similarity policy blocks the bare name `agentguard`). Registry URL: <https://www.npmjs.com/package/@allenwu06/agentguard>.

## Gate 2 — payment account (only if/when monetizing; the revenue gate)

**Free launch needs ZERO payment setup.** The free CLI + plugin + Action collects $0 by design. A paid tier (hosted scan dashboard, org-wide policy enforcement, IDE extension) would need a **merchant-of-record account in your name** (MoR — a service like Paddle / Lemon Squeezy / Polar that sells on your behalf and handles tax). No payment code exists in this product — that is a deliberate later layer.

## Budget note

Free CLI/plugin/Action = no hosting cost. Any paid hosted tier = real spend; ratify before committing.

## What stays automated (not you)

Building, tests, reviews, feedback collection — all AI, feedback-paced. You: the gates above + reading RATIFY packets + pressing KILL/SCALE.

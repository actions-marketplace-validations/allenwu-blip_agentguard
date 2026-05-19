# Reporting a misfire (false positive / false negative)

`agentguard` is **conservative** static analysis. It will sometimes get it
wrong:

- **False positive** — it flagged a tool call that is actually guarded /
  safe. **This is the bug that matters most to us.** The entire product
  thesis is low false positives; a single confirmed FP is a higher-priority
  fix than several missed cases.
- **False negative** — it missed a genuinely unguarded sink reachable from
  agent tool input.

Both directions matter, but FP reports directly defend the moat — please
send them.

## The one-line, zero-friction way

**Add the `agentguard-feedback` label** to an issue (open one and apply it,
or use the issue template). Maintainers watch that label. If you adopt
agentguard in your own org, create that label once so your team has a
consistent appeal path.

## The structured way

Open an **"agentguard misfire report"** issue
(`.github/ISSUE_TEMPLATE/misfire.yml`). It asks for the misfire type, the
rule id (e.g. `AG001`), and what happened **in your own words**.

## The verbatim guarantee

Whatever you write is **captured and read exactly as written** — no
summarization, no paraphrasing, no "cleaning up". Tuning a conservative
linter on second-hand paraphrases corrupts the signal, so the raw text is
the artifact. This is the same contract implemented in code in
[`src/feedback.js`](src/feedback.js) (tested in
[`test/feedback.test.js`](test/feedback.test.js)): append-only,
order-preserving, and a single corrupt record never drops the rest.
`product` is recorded as `agentguard`.

## What helps most

- The **rule id** and the exact `file:line:column` agentguard reported (or,
  for a false negative, the location it *should* have flagged).
- A **minimal code snippet** that reproduces it (sanitize anything secret).
- For a **false positive**: what guard is actually on the path that
  agentguard didn't recognize (which schema/allowlist/confirmation, and how
  it's written) — this is exactly what we need to teach it.
- For a **false negative**: why the sink is reachable from untrusted tool
  input and what guard is missing.
- Your invocation (`--fail-on`, `--include-tests`, version) if non-default,
  and whether you hit it via the CLI, the ESLint plugin, or the Action.

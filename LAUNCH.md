# LAUNCH — agent-guard-lint (agentguard)

**DRAFT — operator reviews and posts. Public technical claims are yours to send.**
All claims below are drawn from the reviewed README only. The 76% figure is from
the cited external HN scan — attribute it correctly or omit it. Do not add
benchmarks, precision/recall figures, or detection-rate claims not already in the README.

---

## Show HN title

```
Show HN: agentguard – static AST linter that flags missing guards on AI-agent tool calls
```

## Show HN body

```
When you give an AI agent tools, the AI decides what gets passed into them.
Anything that can steer the AI — a prompt injection in a fetched page, a
poisoned document, a malicious sub-agent — can therefore steer those values
into a shell command, your filesystem, the network, or code execution. The
single most effective defense is a railing on the way in: validate the input,
check an allow/deny list, or require a human to confirm.

npx agentguard ./src

agentguard is a building inspector for those missing railings. It finds tool
handlers in MCP, LangChain, Vercel AI SDK, LlamaIndex and similar frameworks;
spots the dangerous operations inside them (shell, filesystem, network, code
execution); checks whether the dangerous value actually traces back to
AI-controlled input; and flags it only when all of that holds AND there is no
railing already on the path. It stays silent on code you have already guarded.

Five rules: unguarded exec/spawn (AG001, critical), unguarded filesystem write
(AG002, high), unguarded outbound network to a tool-input URL (AG003, high),
unguarded dynamic eval (AG004, critical), unguarded filesystem read/path
traversal (AG005, high). Findings include file:line:col, the exact sink, why
it fired, and a concrete remediation.

A Show HN that scanned 16 open-source AI-agent repos found 76% of tool calls
had no guards — that figure is from that external scan, not from this tool.
agentguard lets you run the equivalent check on your own repo, offline, in seconds.

No API key. No network. No LLM. Ships as a CLI, an ESLint plugin, and a GitHub
Action. Conservative by design — literal-argument sinks never fire.

110 tests green from a clean install. MIT.

GitHub: [link]
```

---

## One-paragraph repo description

```
agentguard is a code-reading tool that flags missing safety railings on
AI-agent tool calls. It uses a real JS/TS parser (not text matching) to find
tool handlers, trace AI-controlled arguments to dangerous operations (shell,
filesystem, network, code execution), and flag one only when no railing is
present on the path. Deliberately cautious: it stays silent on already-guarded
code and on fixed/constant arguments. Ships as a standalone command-line tool,
an ESLint plugin, and a GitHub Action. No API key, no network, no AI involved.
MIT license.
```

---

## Honest 2-3 line blurb
(For the Marketplace listing, a pinned issue, or a README TL;DR)

```
agentguard is conservative static analysis — it will miss things (obfuscated
indirection, runtime-only behaviour, transitive dependencies) and may flag false
positives on unusual but safe patterns. No precision/recall or detection-rate
numbers are claimed. The 76% figure in the README is from an external scan of
16 repos, not produced or reproduced by this tool.
```

---

## Notes for operator before posting

- Replace `<owner>` and `[link]` placeholders with real values once the repo is public.
- The 76% figure must be attributed to the cited Show HN scan (HN item 47947356);
  do not present it as a claim about agentguard's detection capability.
- If published to npm before posting, substitute the real `npx agentguard` invocation.
- Do not add precision/recall numbers or percentage-of-repos-with-findings claims —
  the README explicitly disclaims these.
- A terminal screenshot of a real finding (AG001/AG002/etc.) from a fixture scan
  is the most useful visual to add before posting.

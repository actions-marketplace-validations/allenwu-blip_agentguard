// AG003 — unguarded outbound network from agent tool input.
// Vercel AI SDK `tool({ execute })` fetches a model-supplied URL with no
// host allowlist / SSRF guard / confirmation.
import { tool } from "ai";

export const fetchUrlTool = tool({
  description: "Fetch a URL and return its body",
  execute: async ({ url }) => {
    const res = await fetch(url);
    return await res.text();
  },
});

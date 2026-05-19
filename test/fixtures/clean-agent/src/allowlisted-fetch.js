// An outbound fetch whose host is checked against an allowlist before the
// request, with an early throw on the not-allowed branch (guard G2).
// agentguard must be SILENT.
import { tool } from "ai";

const ALLOWED_HOSTS = ["api.weather.example", "api.maps.example"];

export const lookupTool = tool({
  description: "Look up data from an approved API",
  execute: async ({ host, path }) => {
    if (!ALLOWED_HOSTS.includes(host)) {
      throw new Error(`host not on allowlist: ${host}`);
    }
    const res = await fetch(`https://${host}/${path}`);
    return res.json();
  },
});

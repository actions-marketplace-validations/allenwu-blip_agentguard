// The CANONICAL SSRF allowlist defense — the exact fix agentguard's own
// AG003 remediation recommends ("check its host against an allowlist before
// the request"). Three idiomatic spellings that a real codebase uses:
//
//   1. member-derived host:  const h = new URL(url).hostname
//   2. ObjectPattern host:   const { hostname } = new URL(url)
//   3. predicate-closure:    ALLOW.some(x => x === host)  (.every/.find/...)
//
// All are properly guarded. agentguard MUST be SILENT here — a linter that
// flags the documented safe pattern gets uninstalled (this is the moat).
import { tool } from "ai";

const ALLOW = ["api.weather.example", "api.maps.example"];

// 1 — host derived through a member access off `new URL(url)`, allowlisted
//     with Array.includes and an early throw on the not-allowed branch.
export const fetchByMember = tool({
  description: "Fetch from an approved host (member-derived hostname)",
  execute: async ({ url }) => {
    const host = new URL(url).hostname;
    if (!ALLOW.includes(host)) {
      throw new Error(`host not on allowlist: ${host}`);
    }
    const res = await fetch(url);
    return res.text();
  },
});

// 2 — host destructured out of `new URL(url)` (ObjectPattern), allowlisted
//     with a predicate-closure membership check.
export const fetchByDestructure = tool({
  description: "Fetch from an approved host (destructured hostname)",
  execute: async ({ url }) => {
    const { hostname } = new URL(url);
    if (!ALLOW.some((h) => h === hostname)) {
      throw new Error("blocked");
    }
    return fetch(url).then((r) => r.json());
  },
});

// 3 — `.every` negative-membership form of the same allowlist decision.
export const fetchByEvery = tool({
  description: "Fetch from an approved host (.every allowlist form)",
  execute: async ({ url }) => {
    const host = new URL(url).hostname;
    if (ALLOW.every((h) => h !== host)) {
      return { error: "host not allowed" };
    }
    const res = await fetch(url);
    return res.text();
  },
});

// 4 — `.filter(...).length === 0` form, host destructured.
export const fetchByFilter = tool({
  description: "Fetch from an approved host (.filter allowlist form)",
  execute: async ({ url }) => {
    const { hostname } = new URL(url);
    if (ALLOW.filter((h) => h === hostname).length === 0) {
      throw new Error("blocked");
    }
    return fetch(url);
  },
});

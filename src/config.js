/**
 * config.js — optional, deterministic config. Pure functions + one tiny
 * read of an explicitly-passed config path. Never reaches the network.
 *
 * Config is OPTIONAL: agentguard works with zero config. A project may add
 * `.agentguardrc.json` (or pass --config) to:
 *   - tune per-rule severity (`severities: { AG003: "medium" }`),
 *   - turn a rule off (`severities: { AG005: "off" }`),
 *   - ignore path globs (`ignore: ["legacy/**"]`) — note: the moat is low
 *     false positives, not silencing; ignore is an escape hatch, used
 *     sparingly,
 *   - allowlist findings by stable id (`allow: ["AG-1a2b3c4d"]`) so a
 *     reviewed, accepted finding stops gating without hiding new ones.
 */

import { readFileSync, existsSync } from "node:fs";

const VALID_SEV = new Set(["critical", "high", "medium", "low", "off"]);

// Frozen so an accidental mutation of the shared default throws loudly in
// tests instead of silently leaking state across scans.
export const DEFAULT_CONFIG = Object.freeze({
  severities: Object.freeze({}), // ruleId -> severity|"off"
  ignore: Object.freeze([]), // path globs (minimal glob: * and **)
  allow: Object.freeze([]), // stable finding ids to treat as accepted
});

/** A deep, mutable copy of the defaults. loadConfig builds ON this so it
 *  never mutates the shared frozen DEFAULT_CONFIG (or its nested objects). */
function freshDefault() {
  return { severities: {}, ignore: [], allow: [] };
}

/**
 * Load + validate config from an explicit path. Returns
 * `{ config, errors }`. A malformed config never throws (fail-open) — it
 * degrades to defaults with a diagnostic.
 * @param {string|null} file
 */
export function loadConfig(file) {
  const errors = [];
  if (!file) return { config: freshDefault(), errors };
  if (!existsSync(file)) {
    errors.push(`config not found: ${file} (continuing with defaults)`);
    return { config: freshDefault(), errors };
  }
  let raw;
  try {
    raw = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    errors.push(`invalid config JSON in ${file}: ${e.message} (continuing with defaults)`);
    return { config: freshDefault(), errors };
  }
  const config = freshDefault();
  if (raw && typeof raw === "object") {
    if (raw.severities && typeof raw.severities === "object") {
      for (const [k, v] of Object.entries(raw.severities)) {
        if (VALID_SEV.has(v)) config.severities[k] = v;
        else errors.push(`config: ignoring invalid severity "${v}" for ${k}`);
      }
    }
    if (Array.isArray(raw.ignore)) config.ignore = raw.ignore.filter((s) => typeof s === "string");
    if (Array.isArray(raw.allow)) config.allow = raw.allow.filter((s) => typeof s === "string");
  } else {
    errors.push(`config: expected an object in ${file} (continuing with defaults)`);
  }
  return { config, errors };
}

// Minimal, anchored glob → RegExp: supports `**` (any path incl. /), `*`
// (any non-/ run), `?` (one non-/). Everything else is literal. Matches the
// whole repo-relative path.
function globToRe(glob) {
  let re = "^";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        re += ".*";
        i++;
        if (glob[i + 1] === "/") i++;
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(re + "$");
}

/**
 * Apply config to raw findings: re-map severity, drop "off" rules, drop
 * ignored paths, and drop allow-listed (accepted) ids. Returns the filtered,
 * possibly re-severitied findings. Pure.
 * @param {object[]} findings
 * @param {object} config
 */
export function applyConfig(findings, config) {
  const ignoreRes = (config.ignore || []).map(globToRe);
  const allow = new Set(config.allow || []);
  const out = [];
  for (const f of findings) {
    const sev = config.severities && config.severities[f.ruleId];
    if (sev === "off") continue;
    if (allow.has(f.id)) continue;
    const norm = String(f.file).replace(/\\/g, "/").replace(/^\.\//, "");
    if (ignoreRes.some((re) => re.test(norm))) continue;
    out.push(sev && sev !== "off" ? { ...f, severity: sev } : f);
  }
  return out;
}

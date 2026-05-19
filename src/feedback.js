/**
 * feedback.js — verbatim misfire collector.
 *
 * A developer's report of a false positive (a finding that is actually
 * safe — guarded code we wrongly flagged) or a false negative (a real
 * unguarded sink we missed) is stored EXACTLY as written: no trim, no
 * normalize, no summarize, no transform. Tuning a conservative linter on
 * paraphrased complaints corrupts the signal, so the raw text IS the
 * artifact. The primary, zero-friction channel is the `agentguard-feedback`
 * issue label + the issue template (see FEEDBACK.md); this module is the
 * same contract in code for local logs.
 *
 * Tiny and dependency-free.
 */

import { appendFileSync, existsSync, readFileSync } from "node:fs";

/**
 * Append one verbatim feedback record as a single JSON line. `text` is
 * written EXACTLY as given (no .trim(), no normalization).
 * @param {string} sink path to the .jsonl feedback log
 * @param {{source:string, text:string, extra?:object}} rec
 */
export function captureFeedback(sink, { source, text, extra }) {
  const record = {
    ts: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    product: "agentguard",
    source,
    text, // verbatim — do not transform
    extra: extra || {},
  };
  appendFileSync(sink, JSON.stringify(record) + "\n", "utf8");
}

/**
 * Read records grouped by source, preserving order and exact text. A single
 * corrupt line is skipped — it never aborts the read.
 * @param {string} sink
 * @returns {Record<string, Array<object>>}
 */
export function loadFeedback(sink) {
  const out = {};
  if (!existsSync(sink)) return out;
  const raw = readFileSync(sink, "utf8");
  for (const line of raw.split("\n")) {
    if (line.trim() === "") continue;
    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      continue; // skip one corrupt record; never abort
    }
    const key = rec.source || "unknown";
    (out[key] ||= []).push(rec);
  }
  return out;
}

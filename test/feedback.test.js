/**
 * feedback.test.js — the verbatim guarantee: a misfire report is stored and
 * read EXACTLY as written (no trim/normalize), order-preserving, and a
 * single corrupt record never drops the rest.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, appendFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureFeedback, loadFeedback } from "../src/feedback.js";

let dir, sink;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agfb-"));
  sink = join(dir, "feedback.jsonl");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("captureFeedback / loadFeedback", () => {
  it("stores text byte-for-byte (no trim, no normalization)", () => {
    const raw = "  AG001 fired on `execSync(SAFE)` \n\twhere SAFE is a const — FALSE POSITIVE  ";
    captureFeedback(sink, { source: "false-positive", text: raw, extra: { ruleId: "AG001" } });
    const back = loadFeedback(sink);
    expect(back["false-positive"][0].text).toBe(raw);
    expect(back["false-positive"][0].product).toBe("agentguard");
    expect(back["false-positive"][0].extra.ruleId).toBe("AG001");
  });

  it("preserves order and groups by source", () => {
    captureFeedback(sink, { source: "false-positive", text: "first" });
    captureFeedback(sink, { source: "false-negative", text: "second" });
    captureFeedback(sink, { source: "false-positive", text: "third" });
    const back = loadFeedback(sink);
    expect(back["false-positive"].map((r) => r.text)).toEqual(["first", "third"]);
    expect(back["false-negative"].map((r) => r.text)).toEqual(["second"]);
  });

  it("a single corrupt line is skipped, the rest survive", () => {
    captureFeedback(sink, { source: "x", text: "good-1" });
    appendFileSync(sink, "this is not json\n");
    captureFeedback(sink, { source: "x", text: "good-2" });
    const back = loadFeedback(sink);
    expect(back["x"].map((r) => r.text)).toEqual(["good-1", "good-2"]);
  });

  it("each record is exactly one JSON line (append-only)", () => {
    captureFeedback(sink, { source: "x", text: "a\nb" }); // newline INSIDE text
    captureFeedback(sink, { source: "x", text: "c" });
    const lines = readFileSync(sink, "utf8").split("\n").filter(Boolean);
    expect(lines).toHaveLength(2); // the embedded \n is JSON-escaped
    expect(JSON.parse(lines[0]).text).toBe("a\nb");
  });

  it("missing sink → empty object, never throws", () => {
    expect(loadFeedback(join(dir, "nope.jsonl"))).toEqual({});
  });
});

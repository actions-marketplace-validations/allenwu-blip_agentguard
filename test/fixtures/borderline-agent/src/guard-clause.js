// BORDERLINE: a guard-clause style early return + a denylist regex on the
// tainted path BEFORE the write. The check is structurally a few lines
// before the sink. agentguard sees the allow/deny decision precedes the
// sink (guard G2) → SILENT.
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

const TRAVERSAL = /(^|[\\/])\.\.([\\/]|$)/;

export function registerNoteTool(server) {
  server.tool("save_note", async ({ name, body }) => {
    if (TRAVERSAL.test(name)) {
      return { error: "path traversal rejected" };
    }
    const full = resolve("notes", name);
    if (!full.startsWith(resolve("notes"))) {
      return { error: "outside notes dir" };
    }
    writeFileSync(full, body);
    return { ok: true };
  });
}

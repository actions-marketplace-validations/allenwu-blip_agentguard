// BORDERLINE: the raw input is parsed through a Zod schema in-body and the
// VALIDATED result (a new binding) is what flows to the sink. A taint
// tracker that doesn't understand that `.parse()` is a guard would flag the
// exec. agentguard must be SILENT (in-body validation = guard G1, and the
// validated alias is treated as untainted).
import { z } from "zod";
import { execFileSync } from "node:child_process";

const Schema = z.object({
  tool: z.enum(["eslint", "prettier", "tsc"]),
  file: z.string().regex(/^[\w./-]+$/),
});

export function registerLintTool(server: { tool: (n: string, h: (raw: unknown) => unknown) => void }) {
  server.tool("lint", async (raw) => {
    const safe = Schema.parse(raw);
    return execFileSync(safe.tool, [safe.file]).toString();
  });
}

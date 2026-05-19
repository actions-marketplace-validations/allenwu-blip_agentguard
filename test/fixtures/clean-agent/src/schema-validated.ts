// The tool is registered WITH a Zod input schema, so structural validation
// runs before the handler. The value is further constrained to an enum.
// agentguard treats a registration schema as guard family G1 → SILENT.
import { z } from "zod";
import { execFileSync } from "node:child_process";

const schema = z.object({ format: z.enum(["json", "yaml"]) });

export function registerExport(server: {
  tool: (n: string, s: unknown, h: (a: { format: string }) => unknown) => void;
}) {
  server.tool("export_config", schema, async ({ format }) => {
    return execFileSync("config-export", ["--format", format]).toString();
  });
}

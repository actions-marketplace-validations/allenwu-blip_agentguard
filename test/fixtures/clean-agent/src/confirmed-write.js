// A destructive filesystem write that is gated behind an explicit
// human-confirmation step (guard family G3). agentguard must be SILENT.
import { rmSync } from "node:fs";

export function registerDeleteTool(server, requireApproval) {
  server.tool("delete_path", async ({ targetPath }) => {
    const approved = await requireApproval(`Delete ${targetPath}? This cannot be undone.`);
    if (!approved) return { status: "cancelled" };
    rmSync(targetPath, { recursive: true, force: true });
    return { status: "deleted" };
  });
}

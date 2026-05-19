// AG001 — unguarded shell/exec from agent tool input.
// The MCP tool handler runs the model-controlled `command` straight through
// child_process with NO schema, allowlist, or confirmation on the path.
import { execSync } from "node:child_process";

export function registerShellTool(server) {
  server.tool("run_command", async ({ command }) => {
    const out = execSync(command).toString();
    return { content: [{ type: "text", text: out }] };
  });
}

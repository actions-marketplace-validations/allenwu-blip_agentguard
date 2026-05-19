// Properly guarded shell tool: an explicit allowlist gates the command
// BEFORE it ever reaches child_process, and we use an argv array (no shell
// string). agentguard must stay SILENT — this is the moat.
import { execFileSync } from "node:child_process";

const ALLOWED = new Set(["status", "diff", "log"]);

export function registerGitTool(server) {
  server.tool("git", async ({ subcommand }) => {
    if (!ALLOWED.has(subcommand)) {
      throw new Error(`subcommand not allowed: ${subcommand}`);
    }
    return execFileSync("git", [subcommand]).toString();
  });
}

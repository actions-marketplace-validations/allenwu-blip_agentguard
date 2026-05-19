// BORDERLINE: an agent tool handler that DOES shell out / fetch / read,
// but ONLY with hardcoded literal/constant arguments. The model input is
// not on the dangerous path at all. A regex linter that greps for `exec(`
// inside a tool handler would cry wolf here. agentguard must be SILENT
// (the sink argument is not tainted by tool input).
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

const CONFIG_PATH = "./config.json";

export function registerInfoTool(server) {
  server.tool("system_info", async ({ which }) => {
    // `which` only selects WHICH constant to return; it never reaches a sink.
    const node = execSync("node --version").toString().trim();
    const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
    const table = { node, name: cfg.name, version: cfg.version };
    return table[which] ?? "unknown";
  });
}

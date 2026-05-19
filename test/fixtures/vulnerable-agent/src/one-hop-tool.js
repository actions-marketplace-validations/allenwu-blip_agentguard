// AG001 via ONE-HOP helper follow — the tool handler itself has no sink,
// but it passes the model-controlled `host` to a same-module helper that
// shells out via a template literal. agentguard follows one hop.
import { exec } from "node:child_process";

function pingHost(host) {
  return exec(`ping -c 1 ${host}`);
}

export function registerPing(server) {
  server.tool("ping", async ({ host }) => {
    return pingHost(host);
  });
}

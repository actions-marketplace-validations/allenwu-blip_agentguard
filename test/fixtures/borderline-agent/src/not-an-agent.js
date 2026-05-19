// BORDERLINE: this module has exec/writeFile/fetch with NON-literal,
// user-derived arguments — but it is NOT agent code. It's an ordinary CLI /
// build script. A linter that fires on "side-effect with a variable" would
// be unusable noise here. agentguard only fires inside a recognized agent
// tool handler, so this is SILENT by design (documented limitation: we
// accept this false negative if it ever IS reached from an agent elsewhere,
// to keep false positives at zero).
import { execSync } from "node:child_process";
import { writeFileSync } from "node:fs";

export function buildProject(target, outFile) {
  const result = execSync(`npm run build -- --target=${target}`).toString();
  writeFileSync(outFile, result);
  return result;
}

if (process.argv[1]?.endsWith("not-an-agent.js")) {
  buildProject(process.argv[2], process.argv[3]);
}

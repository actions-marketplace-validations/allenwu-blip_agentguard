// AG002 — unguarded sensitive filesystem write from agent tool input.
// A LangChain DynamicStructuredTool whose `func` writes to a model-supplied
// path with no path containment / allowlist / confirmation.
import { writeFileSync } from "node:fs";

export function makeWriteTool(DynamicStructuredTool) {
  return new DynamicStructuredTool({
    name: "save_file",
    description: "Save text to a file",
    func: async ({ path, contents }) => {
      writeFileSync(path, contents);
      return `wrote ${path}`;
    },
  });
}

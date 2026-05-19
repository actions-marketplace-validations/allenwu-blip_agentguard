// AG005 — unguarded sensitive filesystem read from agent tool input.
// LlamaIndex-style FunctionTool whose handler reads a model-supplied path
// (path traversal) and returns the bytes to the model — no containment.
import { readFileSync } from "node:fs";

export function makeReadTool(FunctionTool) {
  return FunctionTool.from({
    name: "read_file",
    description: "Read a file and return its contents",
    handler: async ({ filepath }) => {
      const data = readFileSync(filepath, "utf8");
      return data;
    },
  });
}

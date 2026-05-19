// BORDERLINE: a LangChain `new DynamicStructuredTool({...})` constructed
// WITH a Zod `schema`, so structural validation runs before `func`. The
// constructor is a NewExpression (not a CallExpression) — a detector that
// only handles call-form registration would miss the schema guard and
// false-positive on the exec. agentguard must be SILENT (guard G1).
import { z } from "zod";
import { execFileSync } from "node:child_process";

export function makeBuildTool(DynamicStructuredTool) {
  return new DynamicStructuredTool({
    name: "build",
    description: "Run a build target",
    schema: z.object({ target: z.enum(["dev", "prod"]) }),
    func: async ({ target }) => {
      return execFileSync("make", [target]).toString();
    },
  });
}

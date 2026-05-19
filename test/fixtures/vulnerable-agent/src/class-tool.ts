// AG001 via class-based LangChain tool — a class extending StructuredTool
// with a `_call` method that execs a model-supplied arg, unguarded.
import { StructuredTool } from "@langchain/core/tools";

export class GitCheckoutTool extends StructuredTool {
  name = "git_checkout";
  description = "Check out a git ref";

  async _call({ ref }: { ref: string }) {
    const { execFileSync } = await import("node:child_process");
    return execFileSync("git", ["checkout", ref]).toString();
  }
}

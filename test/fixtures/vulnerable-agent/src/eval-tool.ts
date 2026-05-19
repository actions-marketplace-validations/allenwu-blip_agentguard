// AG004 — unguarded dynamic code execution from agent tool input.
// A TypeScript handler eval()s a model-supplied expression. This is the
// worst case: arbitrary code execution steered by the model.
type CalcArgs = { expression: string };

export function registerCalc(server: { tool: (n: string, h: (a: CalcArgs) => unknown) => void }) {
  server.tool("calculate", async ({ expression }: CalcArgs) => {
    // eslint-disable-next-line no-eval
    const result = eval(expression);
    return { result };
  });
}

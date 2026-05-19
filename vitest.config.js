import { defineConfig } from "vitest/config";

// No network, no API key, no globals. The analysis core is pure and the
// suite only reads local fixture directories. CI asserts this too.
export default defineConfig({
  test: {
    include: ["test/**/*.test.js"],
    environment: "node",
    testTimeout: 20000,
  },
});

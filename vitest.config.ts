import { defineConfig } from "vitest/config";

/**
 * Minimal vitest setup: Node environment (Electron main process APIs
 * are mocked in tests, not invoked), explicit imports (no globals),
 * scoped to `.test.ts` files under `src/`. Vitest handles TS natively.
 */
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    globals: false,
    reporters: "default",
  },
});

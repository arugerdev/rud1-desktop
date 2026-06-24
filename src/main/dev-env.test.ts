import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadDevEnvFile } from "./dev-env";

describe("loadDevEnvFile", () => {
  let dir: string;
  const KEYS = ["DEV_ENV_A", "DEV_ENV_B", "DEV_ENV_Q", "DEV_ENV_EXISTING"];

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "rud1-devenv-"));
    for (const k of KEYS) delete process.env[k];
  });
  afterEach(() => {
    for (const k of KEYS) delete process.env[k];
    rmSync(dir, { recursive: true, force: true });
  });

  it("loads KEY=VALUE pairs, skipping comments/blank lines and stripping quotes", () => {
    writeFileSync(
      join(dir, ".env"),
      ['# a comment', '', 'DEV_ENV_A=1', 'DEV_ENV_B = plain ', 'DEV_ENV_Q="quoted"'].join(
        "\n",
      ),
    );
    loadDevEnvFile(dir);
    expect(process.env.DEV_ENV_A).toBe("1");
    expect(process.env.DEV_ENV_B).toBe("plain");
    expect(process.env.DEV_ENV_Q).toBe("quoted");
  });

  it("never overrides a var already present in the environment", () => {
    process.env.DEV_ENV_EXISTING = "from-shell";
    writeFileSync(join(dir, ".env"), "DEV_ENV_EXISTING=from-file");
    loadDevEnvFile(dir);
    expect(process.env.DEV_ENV_EXISTING).toBe("from-shell");
  });

  it("is a silent no-op when no .env file exists", () => {
    expect(() => loadDevEnvFile(dir)).not.toThrow();
  });
});

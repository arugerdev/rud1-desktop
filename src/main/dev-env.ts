import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Minimal, dependency-free .env loader for DEV builds only.
 *
 * Electron's main process does not read a .env file on its own. To keep the
 * test-mode workflow ergonomic (set RUD1_TEST_MODE in a file instead of the
 * shell), this parses KEY=VALUE lines from <root>/.env and sets process.env for
 * keys NOT already present (a real shell var always wins). It is called only
 * when `!app.isPackaged`, so packaged/production builds never touch it. Silent
 * no-op when the file is missing.
 */
export function loadDevEnvFile(root: string): void {
  let raw: string;
  try {
    raw = readFileSync(join(root, ".env"), "utf8");
  } catch {
    return; // no .env — nothing to do
  }
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    if (key.length === 0 || key in process.env) continue;
    let val = trimmed.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    process.env[key] = val;
  }
}

/**
 * Detects installed CLI flasher binaries across the IDEs/toolchains a user may
 * have (Arduino IDE, PlatformIO, standalone installs, PATH). These are the
 * binaries the shim-lifecycle manager wraps so uploads to a rud1 device run
 * locally on the device (latency-immune). Detection is best-effort and
 * intentionally broad — adding a device family = adding its flasher name here.
 *
 * We only *detect* here; wrapping/restoring is done by shim-lifecycle-manager.
 */

import fs from "fs";
import os from "os";
import path from "path";

/** Flasher binary basenames we know how to reroute (no extension). */
export const KNOWN_FLASHERS = [
  "avrdude",
  "esptool",
  "stm32flash",
  "dfu-util",
  "bossac",
  "teensy_loader_cli",
  "rp2040load",
  "st-flash",
] as const;

export interface DetectedFlasher {
  tool: string; // basename without extension, e.g. "avrdude"
  path: string; // absolute path to the real flasher binary
  source: string; // which IDE/toolchain it belongs to (for logging/UX)
}

function exeName(tool: string): string {
  return process.platform === "win32" ? `${tool}.exe` : tool;
}

/** Roots under which IDEs keep their bundled flasher `bin/` directories. */
function searchRoots(): { root: string; source: string }[] {
  const home = os.homedir();
  const roots: { root: string; source: string }[] = [];
  const add = (root: string | undefined, source: string) => {
    if (root && fs.existsSync(root)) roots.push({ root, source });
  };

  if (process.platform === "win32") {
    const localApp = process.env["LOCALAPPDATA"];
    const programFiles = process.env["ProgramFiles"];
    const programFilesX86 = process.env["ProgramFiles(x86)"];
    // Arduino IDE 2.x / CLI package tools
    if (localApp) add(path.join(localApp, "Arduino15", "packages"), "Arduino IDE");
    // Arduino IDE 1.x legacy bundle
    add(programFiles && path.join(programFiles, "Arduino", "hardware", "tools"), "Arduino IDE (legacy)");
    add(programFilesX86 && path.join(programFilesX86, "Arduino", "hardware", "tools"), "Arduino IDE (legacy)");
    // PlatformIO
    add(path.join(home, ".platformio", "packages"), "PlatformIO");
  } else if (process.platform === "darwin") {
    add(path.join(home, "Library", "Arduino15", "packages"), "Arduino IDE");
    add("/Applications/Arduino.app/Contents/Java/hardware/tools", "Arduino IDE (legacy)");
    add(path.join(home, ".platformio", "packages"), "PlatformIO");
  } else {
    add(path.join(home, ".arduino15", "packages"), "Arduino IDE");
    add(path.join(home, ".platformio", "packages"), "PlatformIO");
  }
  return roots;
}

/** Bounded recursive search for the given exe names under `dir`. */
function findUnder(dir: string, wanted: Set<string>, depth: number, out: Map<string, string>): void {
  if (depth < 0) return;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      findUnder(full, wanted, depth - 1, out);
    } else if (wanted.has(e.name.toLowerCase())) {
      const tool = e.name.replace(/\.exe$/i, "").toLowerCase();
      // keep the first (shallowest) hit per tool per root
      if (!out.has(full)) out.set(full, tool);
    }
  }
}

/**
 * Detect all real flasher binaries. A flasher already wrapped by us
 * (a `<tool>-real` sibling exists) is reported at its `<tool>` path so the
 * caller can keep it wrapped / refresh config.
 */
export function detectFlashers(): DetectedFlasher[] {
  const wanted = new Set(KNOWN_FLASHERS.map((t) => exeName(t).toLowerCase()));
  const results: DetectedFlasher[] = [];
  const seen = new Set<string>();

  for (const { root, source } of searchRoots()) {
    const hits = new Map<string, string>();
    findUnder(root, wanted, 6, hits);
    for (const [full, tool] of hits) {
      if (seen.has(full)) continue;
      seen.add(full);
      results.push({ tool, path: full, source });
    }
  }
  return results;
}

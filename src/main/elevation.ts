/**
 * Running a command as root on Linux / macOS.
 *
 * Windows solves this once, at install time: the NSIS manifest is
 * `requireAdministrator`, so everything rud1 spawns is already elevated.
 * There is no equivalent on Linux — a desktop app runs as the user, and
 * both OpenVPN (creates the virtual adapter, sets routes) and usbip
 * (talks to the kernel's vhci driver) refuse to work without root.
 *
 * The desktop way to ask is polkit: `pkexec <program>` shows the system's
 * own password dialog and, on approval, runs the program as root. That is
 * what this module plans. Two consequences the callers must respect:
 *
 *   • The child is root and we are not, so `kill()` on it fails with
 *     EPERM. Anything spawned this way needs a shutdown path that does
 *     not depend on signals — for OpenVPN that is its management socket.
 *   • pkexec drops the environment. Pass absolute paths, never rely on
 *     inherited env vars.
 */

import { pkexecPath } from "./binary-helper";
import { pkexecMissingMessage } from "./install-hints";

export interface PrivilegedCommand {
  command: string;
  args: string[];
  /** True when the command runs through pkexec (root child, no signals). */
  elevated: boolean;
}

export type PrivilegedPlan =
  | ({ ok: true } & PrivilegedCommand)
  | { ok: false; reason: "no-pkexec" };

export class ElevationUnavailableError extends Error {
  constructor(message: string = pkexecMissingMessage()) {
    super(message);
    this.name = "ElevationUnavailableError";
  }
}

/** True when this process already runs as root (uid 0). */
export function isRootProcess(): boolean {
  return typeof process.getuid === "function" && process.getuid() === 0;
}

/**
 * Decide how to launch `exe` with root rights.
 *
 * Pure on purpose — every input is passed in, so the decision table is
 * unit-testable without a Linux box.
 */
export function planPrivilegedCommand(input: {
  platform: NodeJS.Platform;
  isRoot: boolean;
  pkexec: string | null;
  exe: string;
  args: readonly string[];
}): PrivilegedPlan {
  const { platform, isRoot, pkexec, exe, args } = input;
  // Windows: the app itself is elevated, spawn directly.
  if (platform === "win32" || isRoot) {
    return { ok: true, command: exe, args: [...args], elevated: false };
  }
  if (!pkexec) return { ok: false, reason: "no-pkexec" };
  return { ok: true, command: pkexec, args: [exe, ...args], elevated: true };
}

/** Same decision, reading the real process / filesystem. */
export function planPrivilegedSpawn(
  exe: string,
  args: readonly string[],
): PrivilegedPlan {
  return planPrivilegedCommand({
    platform: process.platform,
    isRoot: isRootProcess(),
    pkexec: pkexecPath(),
    exe,
    args,
  });
}

/**
 * Turn a pkexec failure into something a technician can act on.
 *
 * pkexec exits 126 when the authorisation was not obtained — the dialog
 * was dismissed, the password was wrong, or (the nasty one on a minimal
 * desktop) no polkit agent is running to show a dialog at all. 127 means
 * the program itself could not be run.
 *
 * Returns null when the exit was not pkexec's own, so the caller keeps
 * whatever OpenVPN said instead of overwriting it.
 */
export function describeElevationFailure(
  code: number | null,
  stderr: string,
): string | null {
  const text = (stderr || "").toLowerCase();
  if (text.includes("no authentication agent") || text.includes("polkit-agent-helper")) {
    return (
      "The desktop did not show the administrator password dialog " +
      "(no polkit authentication agent is running). Install one for your " +
      "desktop — for example polkit-gnome or lxqt-policykit — or start rud1 " +
      "from a terminal with sudo."
    );
  }
  if (code === 126) {
    return (
      "Administrator rights were not granted, so the VPN adapter could not " +
      "be created. Click Connect again and enter the password of an " +
      "administrator account."
    );
  }
  if (code === 127) {
    return (
      "The system could not run the command as administrator (pkexec " +
      "reported the program was not found)."
    );
  }
  return null;
}

/**
 * Unit tests for the elevation planner.
 *
 * The decision table is small but load-bearing: get it wrong and either
 * Windows starts asking for a password it already has, or Linux spawns an
 * OpenVPN that cannot create the adapter and dies with a cryptic
 * permission error.
 */

import { describe, expect, it, vi } from "vitest";
import * as os from "os";

// binary-helper pulls electron in at import time.
vi.mock("electron", () => ({
  app: {
    isPackaged: false,
    getAppPath: () => process.cwd(),
    getPath: (_n: string) => os.tmpdir(),
  },
}));

import { describeElevationFailure, planPrivilegedCommand } from "./elevation";

const base = {
  exe: "/usr/sbin/openvpn",
  args: ["--config", "/home/u/rud1.ovpn"],
};

describe("planPrivilegedCommand", () => {
  it("spawns directly on Windows — the app is already elevated", () => {
    const plan = planPrivilegedCommand({
      ...base,
      platform: "win32",
      isRoot: false,
      pkexec: "/usr/bin/pkexec",
    });
    expect(plan).toEqual({
      ok: true,
      command: base.exe,
      args: base.args,
      elevated: false,
    });
  });

  it("spawns directly when we already run as root", () => {
    const plan = planPrivilegedCommand({
      ...base,
      platform: "linux",
      isRoot: true,
      pkexec: "/usr/bin/pkexec",
    });
    expect(plan).toMatchObject({ ok: true, command: base.exe, elevated: false });
  });

  it("wraps the command in pkexec on a normal Linux session", () => {
    const plan = planPrivilegedCommand({
      ...base,
      platform: "linux",
      isRoot: false,
      pkexec: "/usr/bin/pkexec",
    });
    expect(plan).toEqual({
      ok: true,
      command: "/usr/bin/pkexec",
      args: ["/usr/sbin/openvpn", "--config", "/home/u/rud1.ovpn"],
      elevated: true,
    });
  });

  it("refuses instead of spawning a doomed process when polkit is missing", () => {
    const plan = planPrivilegedCommand({
      ...base,
      platform: "linux",
      isRoot: false,
      pkexec: null,
    });
    expect(plan).toEqual({ ok: false, reason: "no-pkexec" });
  });

  it("does not mutate the caller's argument array", () => {
    const args = ["--config", "x"];
    planPrivilegedCommand({
      platform: "linux",
      isRoot: false,
      pkexec: "/usr/bin/pkexec",
      exe: "/usr/sbin/openvpn",
      args,
    });
    expect(args).toEqual(["--config", "x"]);
  });
});

describe("describeElevationFailure", () => {
  it("explains a dismissed password dialog", () => {
    expect(describeElevationFailure(126, "")).toContain("Administrator rights were not granted");
  });

  it("calls out a desktop with no polkit agent", () => {
    const msg = describeElevationFailure(
      126,
      "[stderr] Error executing command as another user: No authentication agent found.",
    );
    expect(msg).toContain("polkit");
    expect(msg).toContain("agent");
  });

  it("says nothing for an ordinary OpenVPN failure", () => {
    expect(describeElevationFailure(1, "TLS Error: TLS handshake failed")).toBeNull();
    expect(describeElevationFailure(null, "")).toBeNull();
  });
});

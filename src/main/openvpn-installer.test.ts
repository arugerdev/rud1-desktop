/**
 * Unit tests for openvpn-installer.
 *
 * Scope: the pure decision helper `tapAdapterNeedsEnable`. The rest of the
 * module is shell-out orchestration (PowerShell / tapctl / UAC) that isn't
 * meaningfully unit-testable without a Windows host, so we cover the one
 * branch that decides whether a Connect must re-enable the TAP adapter.
 *
 * binary-helper imports electron at module-load time — stub it so vitest
 * can load openvpn-installer without an Electron runtime (mirror of the
 * vpn-manager.test.ts strategy).
 */

import { describe, expect, it, vi } from "vitest";
import * as os from "os";

vi.mock("electron", () => ({
  app: {
    isPackaged: false,
    getAppPath: () => process.cwd(),
    getPath: (_n: string) => os.tmpdir(),
  },
}));

import { tapAdapterNeedsEnable } from "./openvpn-installer";

describe("tapAdapterNeedsEnable", () => {
  it("returns false for usable statuses (openvpn can open these)", () => {
    expect(tapAdapterNeedsEnable("Up")).toBe(false);
    expect(tapAdapterNeedsEnable("Disconnected")).toBe(false);
    // Case / whitespace insensitive — PowerShell's Status can vary in case.
    expect(tapAdapterNeedsEnable("up")).toBe(false);
    expect(tapAdapterNeedsEnable("DISCONNECTED")).toBe(false);
    expect(tapAdapterNeedsEnable("  Disconnected  ")).toBe(false);
  });

  it("returns true for an administratively disabled adapter", () => {
    // The state that broke the tunnel: present under -IncludeHidden but
    // CreateFile fails errno=2. Windows reports either 'Disabled' or, for a
    // root-enumerated TAP, 'Not Present' while CM_PROB_DISABLED.
    expect(tapAdapterNeedsEnable("Disabled")).toBe(true);
    expect(tapAdapterNeedsEnable("Not Present")).toBe(true);
  });

  it("returns false when the adapter is absent (no status string)", () => {
    // Absent → the create path (ensureTapDriverInstalled), not the enable
    // path, is responsible. Don't claim work that isn't ours.
    expect(tapAdapterNeedsEnable(null)).toBe(false);
    expect(tapAdapterNeedsEnable(undefined)).toBe(false);
    expect(tapAdapterNeedsEnable("")).toBe(false);
    expect(tapAdapterNeedsEnable("   ")).toBe(false);
  });

  it("rejects non-string input without throwing", () => {
    // @ts-expect-error — exercising the runtime guard
    expect(tapAdapterNeedsEnable(42)).toBe(false);
    // @ts-expect-error
    expect(tapAdapterNeedsEnable({})).toBe(false);
  });
});

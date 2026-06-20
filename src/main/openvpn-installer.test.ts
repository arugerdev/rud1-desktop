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

import {
  createTapAdapterWithFallback,
  tapAdapterNeedsEnable,
} from "./openvpn-installer";

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

describe("createTapAdapterWithFallback", () => {
  it("creates on the first try and never touches the installer", async () => {
    const createAdapter = vi.fn().mockResolvedValue(undefined);
    const forceInstallDriver = vi.fn().mockResolvedValue(undefined);

    const res = await createTapAdapterWithFallback({
      allowInstallerFallback: true,
      forceInstallDriver,
      createAdapter,
    });

    expect(res).toEqual({ forcedInstaller: false });
    expect(createAdapter).toHaveBeenCalledTimes(1);
    expect(forceInstallDriver).not.toHaveBeenCalled();
  });

  it("forces the installer and retries once when a false-positive probe let the create fail (eCatcher case)", async () => {
    // The bug: eCatcher's "OpenVPN Technologies, Inc."-signed driver
    // satisfied the store probe, so the bundled installer was skipped — but
    // root\tap0901 isn't actually registered, so the first create fails.
    // The fallback must force the installer in and retry, then succeed.
    const createAdapter = vi
      .fn()
      .mockRejectedValueOnce(
        new Error("tapctl: failed to create adapter (root\\tap0901 not found)"),
      )
      .mockResolvedValueOnce(undefined);
    const forceInstallDriver = vi.fn().mockResolvedValue(undefined);

    const res = await createTapAdapterWithFallback({
      allowInstallerFallback: true,
      forceInstallDriver,
      createAdapter,
    });

    expect(res).toEqual({ forcedInstaller: true });
    expect(forceInstallDriver).toHaveBeenCalledTimes(1);
    expect(createAdapter).toHaveBeenCalledTimes(2);
  });

  it("does NOT retry when the installer already ran this pass (real failure surfaces)", async () => {
    // allowInstallerFallback=false means Step 1 already ran the installer,
    // so a create failure is genuine — don't loop, surface it verbatim.
    const err = new Error("tapctl: device busy");
    const createAdapter = vi.fn().mockRejectedValue(err);
    const forceInstallDriver = vi.fn().mockResolvedValue(undefined);

    await expect(
      createTapAdapterWithFallback({
        allowInstallerFallback: false,
        forceInstallDriver,
        createAdapter,
      }),
    ).rejects.toThrow("device busy");
    expect(forceInstallDriver).not.toHaveBeenCalled();
    expect(createAdapter).toHaveBeenCalledTimes(1);
  });

  it("surfaces the retry's error when the create still fails after forcing the installer", async () => {
    const finalErr = new Error("tapctl: create failed again");
    const createAdapter = vi
      .fn()
      .mockRejectedValueOnce(new Error("first create fail"))
      .mockRejectedValueOnce(finalErr);
    const forceInstallDriver = vi.fn().mockResolvedValue(undefined);

    await expect(
      createTapAdapterWithFallback({
        allowInstallerFallback: true,
        forceInstallDriver,
        createAdapter,
      }),
    ).rejects.toThrow("create failed again");
    expect(forceInstallDriver).toHaveBeenCalledTimes(1);
    expect(createAdapter).toHaveBeenCalledTimes(2);
  });
});

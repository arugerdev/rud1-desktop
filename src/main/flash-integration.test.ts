import { describe, expect, it, vi } from "vitest";

// flash-integration pulls in the shim lifecycle manager → binary-helper, which
// reads `app.isPackaged` at module load. electron is a native module absent in
// a plain Node vitest run, so stub the one field the import chain touches.
vi.mock("electron", () => ({ app: { isPackaged: true } }));

import { projectSessions } from "./flash-integration";

/**
 * The flasher shim's COM→device map is a pure projection of the live USB
 * session set (single source of truth). These tests lock that contract so the
 * map can never drift from what is actually attached.
 */
describe("projectSessions", () => {
  it("maps only sessions with a captured COM, carrying host+busId", () => {
    const m = projectSessions([
      { com: "COM3", host: "10.8.0.2", busId: "2-1.4" },
      { host: "10.8.0.3", busId: "2-1.5" }, // no COM yet → not routable
    ]);
    expect([...m]).toEqual([["COM3", { host: "10.8.0.2", busId: "2-1.4" }]]);
  });

  it("is a full rebuild: a detached device drops out of the map", () => {
    const both = projectSessions([
      { com: "COM3", host: "10.8.0.2", busId: "2-1.4" },
      { com: "COM7", host: "10.8.0.2", busId: "2-1.5" },
    ]);
    expect(both.size).toBe(2);
    // COM7 detached → only the still-attached device survives.
    const one = projectSessions([{ com: "COM3", host: "10.8.0.2", busId: "2-1.4" }]);
    expect([...one.keys()]).toEqual(["COM3"]);
    // All detached → empty map makes every wrapped flasher a passthrough.
    expect(projectSessions([]).size).toBe(0);
  });

  it("reflects a busId remap on the same COM (device swapped ports)", () => {
    const m = projectSessions([{ com: "COM3", host: "10.8.0.2", busId: "1-1.2" }]);
    expect(m.get("COM3")).toEqual({ host: "10.8.0.2", busId: "1-1.2" });
  });
});

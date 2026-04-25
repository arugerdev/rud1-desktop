/**
 * Unit tests for firmware-discovery — boots a real http server on an
 * ephemeral port (NOT the production 7070) so the suite can run
 * back-to-back without TIME_WAIT collisions on Windows. The probe is
 * pointed at the chosen port via its test-only `port` parameter.
 */
import { describe, expect, it, afterEach } from "vitest";
import http from "http";
import { AddressInfo } from "net";

import {
  isFirstBoot,
  probeFirmware,
  shouldNotifyFirstBoot,
  type FirmwareProbeResult,
} from "./firmware-discovery";

let activeServer: http.Server | null = null;

afterEach(async () => {
  if (activeServer) {
    await new Promise<void>((resolve) => activeServer!.close(() => resolve()));
    activeServer = null;
  }
});

function startProbeTarget(handler: http.RequestListener): Promise<{ host: string; port: number }> {
  const server = http.createServer(handler);
  activeServer = server;
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    // Port 0 = ephemeral; the OS assigns a free one and we read it back.
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo | null;
      if (!addr) {
        reject(new Error("server failed to listen"));
        return;
      }
      resolve({ host: "127.0.0.1", port: addr.port });
    });
  });
}

describe("probeFirmware", () => {
  it("returns reachable=true with parsed setup state on a 200 JSON response", async () => {
    const { port } = await startProbeTarget((req, res) => {
      expect(req.url).toBe("/api/setup/state");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          complete: false,
          deviceName: "Taller-A",
          deviceLocation: "Madrid",
          notes: "first boot",
          completedAt: null,
          deviceSerial: "RUD1-TEST",
          firmwareVersion: "0.5.0",
        }),
      );
    });

    const probe = await probeFirmware(["127.0.0.1"], port);
    expect(probe.reachable).toBe(true);
    expect(probe.host).toBe("127.0.0.1");
    expect(probe.panelUrl).toBe(`http://127.0.0.1:${port}`);
    expect(probe.setupUrl).toBe(`http://127.0.0.1:${port}/setup`);
    expect(probe.setup).not.toBeNull();
    expect(probe.setup!.complete).toBe(false);
    expect(probe.setup!.deviceName).toBe("Taller-A");
    expect(probe.setup!.deviceSerial).toBe("RUD1-TEST");
  });

  it("treats a 401 as reachable + complete=true (paired device, gated endpoint)", async () => {
    const { port } = await startProbeTarget((_req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "unauthorized" }));
    });
    const probe = await probeFirmware(["127.0.0.1"], port);
    expect(probe.reachable).toBe(true);
    expect(probe.setup).not.toBeNull();
    expect(probe.setup!.complete).toBe(true);
  });

  it("returns reachable=false when no candidate hosts are valid", async () => {
    const probe = await probeFirmware([]);
    expect(probe.reachable).toBe(false);
    expect(probe.error).toBe("no candidate hosts");
  });

  it("rejects unsafe hostnames before issuing any request", async () => {
    const probe = await probeFirmware([
      "rud1.local\r\nHost: evil.com",
      "../../../etc/passwd",
      "with spaces",
    ]);
    expect(probe.reachable).toBe(false);
    expect(probe.error).toBe("no candidate hosts");
  });

  it("returns reachable=false when the body is oversized", async () => {
    const { port } = await startProbeTarget((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      // 32 KB > 16 KB cap.
      res.end("a".repeat(32 * 1024));
    });
    const probe = await probeFirmware(["127.0.0.1"], port);
    expect(probe.reachable).toBe(false);
    expect(probe.error).toBe("response too large");
  });

  it("returns reachable=false when JSON is malformed", async () => {
    const { port } = await startProbeTarget((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{not-json");
    });
    const probe = await probeFirmware(["127.0.0.1"], port);
    expect(probe.reachable).toBe(false);
    expect(probe.error).toBeDefined();
  });

  it("returns reachable=false when no candidate is reachable", async () => {
    // Use a port we know is closed (we're not starting a server, so any
    // ephemeral high port is safe).
    const probe = await probeFirmware(["127.0.0.1"], 1);
    expect(probe.reachable).toBe(false);
    expect(probe.error).toBeDefined();
    expect(probe.setupUrl).toBe("");
  });

  it("returns reachable=false on non-2xx status", async () => {
    const { port } = await startProbeTarget((_req, res) => {
      res.writeHead(503);
      res.end("down");
    });
    const probe = await probeFirmware(["127.0.0.1"], port);
    expect(probe.reachable).toBe(false);
    expect(probe.error).toBe("status 503");
  });
});

// ─── shouldNotifyFirstBoot ────────────────────────────────────────────────
//
// Helpers to keep the assertions terse — every probe used here is a fully-
// formed `FirmwareProbeResult`, so building them inline in each test
// becomes noisy.

function probeUnreachable(host = ""): FirmwareProbeResult {
  return {
    reachable: false,
    host,
    panelUrl: "",
    setupUrl: "",
    setup: null,
    probedAt: 0,
    error: "no firmware detected",
  };
}

function probeFirstBoot(host: string): FirmwareProbeResult {
  return {
    reachable: true,
    host,
    panelUrl: `http://${host}`,
    setupUrl: `http://${host}/setup`,
    setup: {
      complete: false,
      deviceName: "",
      deviceLocation: "",
      notes: "",
      completedAt: null,
      deviceSerial: "",
      firmwareVersion: "",
    },
    probedAt: 0,
  };
}

function probeAlreadyPaired(host: string): FirmwareProbeResult {
  return {
    reachable: true,
    host,
    panelUrl: `http://${host}`,
    setupUrl: `http://${host}/setup`,
    setup: {
      complete: true,
      deviceName: "",
      deviceLocation: "",
      notes: "",
      completedAt: null,
      deviceSerial: "",
      firmwareVersion: "",
    },
    probedAt: 0,
  };
}

describe("shouldNotifyFirstBoot", () => {
  it("notifies on cold start when a first-boot device is already on LAN", () => {
    expect(shouldNotifyFirstBoot(null, probeFirstBoot("rud1.local"))).toBe(true);
  });

  it("notifies on the rising edge from no-device → first-boot", () => {
    expect(
      shouldNotifyFirstBoot(probeUnreachable(), probeFirstBoot("rud1.local")),
    ).toBe(true);
  });

  it("notifies on the rising edge from already-paired → first-boot", () => {
    expect(
      shouldNotifyFirstBoot(
        probeAlreadyPaired("rud1.local"),
        probeFirstBoot("192.168.50.1"),
      ),
    ).toBe(true);
  });

  it("does NOT notify when the same first-boot device is still detected", () => {
    expect(
      shouldNotifyFirstBoot(
        probeFirstBoot("rud1.local"),
        probeFirstBoot("rud1.local"),
      ),
    ).toBe(false);
  });

  it("notifies again when first-boot host changes (different device)", () => {
    expect(
      shouldNotifyFirstBoot(
        probeFirstBoot("rud1.local"),
        probeFirstBoot("192.168.50.1"),
      ),
    ).toBe(true);
  });

  it("does NOT notify when the device disappears from the LAN", () => {
    expect(
      shouldNotifyFirstBoot(probeFirstBoot("rud1.local"), probeUnreachable()),
    ).toBe(false);
  });

  it("does NOT notify for an already-paired device on cold start", () => {
    expect(
      shouldNotifyFirstBoot(null, probeAlreadyPaired("rud1.local")),
    ).toBe(false);
  });

  it("does NOT notify when an already-paired device stays already-paired", () => {
    expect(
      shouldNotifyFirstBoot(
        probeAlreadyPaired("rud1.local"),
        probeAlreadyPaired("rud1.local"),
      ),
    ).toBe(false);
  });
});

describe("isFirstBoot", () => {
  it("returns true only when reachable AND complete=false", () => {
    const base = {
      reachable: true,
      host: "rud1.local",
      panelUrl: "http://rud1.local",
      setupUrl: "http://rud1.local/setup",
      probedAt: 0,
    };
    expect(
      isFirstBoot({
        ...base,
        setup: {
          complete: false,
          deviceName: "",
          deviceLocation: "",
          notes: "",
          completedAt: null,
          deviceSerial: "",
          firmwareVersion: "",
        },
      }),
    ).toBe(true);
    expect(
      isFirstBoot({
        ...base,
        setup: {
          complete: true,
          deviceName: "",
          deviceLocation: "",
          notes: "",
          completedAt: null,
          deviceSerial: "",
          firmwareVersion: "",
        },
      }),
    ).toBe(false);
    expect(isFirstBoot({ ...base, setup: null })).toBe(false);
    expect(
      isFirstBoot({
        reachable: false,
        host: "",
        panelUrl: "",
        setupUrl: "",
        setup: null,
        probedAt: 0,
      }),
    ).toBe(false);
  });
});

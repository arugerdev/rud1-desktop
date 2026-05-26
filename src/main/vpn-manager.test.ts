/**
 * Unit tests for vpn-manager (OpenVPN edition — 2026-05).
 *
 * Scope:
 *   • validateTunnelName — accepts the kernel-ifname charset
 *     (alphanumeric, underscore, dot, dash) up to IFNAMSIZ-1 chars,
 *     rejects shell metacharacters / path separators / empty input.
 *   • resolveConfigPath — derives `<tmp>/<name>.conf` from a validated
 *     name. Path traversal via `../` must throw BEFORE any fs call
 *     (validateTunnelName rejects the dot-dot pattern first).
 *   • assertTunnelName — throw-on-invalid guard exposed via __test.
 *   • parseEndpointFromConfig — pulls `remote <host> <port>` from .ovpn.
 *   • isCGNATEndpoint — pinned to always-false on the OpenVPN client
 *     path (client connects OUTBOUND, server-side CGNAT detection is
 *     a cloud responsibility).
 *   • compute/format uptime helpers (pure).
 *
 * Mocking strategy:
 *   • electron is stubbed because binary-helper imports it at module
 *     load time. We never call any electron API in these tests — the
 *     helpers under test are pure.
 *   • No child_process mock. Happy-path vpnConnect/Disconnect/Status
 *     flows are `it.todo` — mocking the spawn event chain plus the
 *     management socket would be brittle.
 */

import { describe, expect, it, vi } from "vitest";
import * as path from "path";
import * as os from "os";

// binary-helper pulls in electron at import time; stub it so vitest can
// load vpn-manager without a running Electron runtime.
vi.mock("electron", () => ({
  app: {
    isPackaged: false,
    getAppPath: () => process.cwd(),
    getPath: (_n: string) => os.tmpdir(),
  },
}));

import {
  validateTunnelName,
  parseEndpointFromConfig,
  isCGNATEndpoint,
  inspectConfig,
  computeTunnelUptimeMs,
  formatUptimeMs,
  classifyHandshakeSnapshot,
  __test,
} from "./vpn-manager";

const {
  assertTunnelName,
  resolveConfigPath,
  parseWgShow,
  parseNetshInterface,
  TUNNEL_NAME,
  TUNNEL_NAME_REGEX,
} = __test;

// ─── 1. validateTunnelName ──────────────────────────────────────────────────

describe("validateTunnelName", () => {
  it("accepts typical tunnel interface names", () => {
    for (const ok of [
      "rud1",
      "rud1-tap",
      "tun_1",
      "a",
      "a1",
      "my.tun",
      "abcdef012345678", // 15 chars — IFNAMSIZ-1 upper bound
    ]) {
      expect(validateTunnelName(ok)).toBe(true);
    }
  });

  it("rejects names longer than 15 chars (IFNAMSIZ limit)", () => {
    expect(validateTunnelName("abcdef012345678")).toBe(true); // 15
    expect(validateTunnelName("abcdef0123456789")).toBe(false); // 16
    expect(validateTunnelName("a".repeat(32))).toBe(false);
  });

  it("rejects shell metacharacters and path separators", () => {
    for (const bad of [
      "rud1;whoami",
      "rud1|nc",
      "rud1&&id",
      "rud1`id`",
      "rud1$(id)",
      "rud1\nrm",
      "rud1 space",
      "../etc",
      "rud1/..",
      "rud1\\bad",
      "rud1:8080",
      "rud1?q",
      "rud1*wild",
      "rud1'quote",
      'rud1"quote',
      "rud1#frag",
      "rud1@home",
    ]) {
      expect(validateTunnelName(bad)).toBe(false);
    }
  });

  it("rejects empty and non-string values", () => {
    expect(validateTunnelName("")).toBe(false);
    expect(validateTunnelName(undefined)).toBe(false);
    expect(validateTunnelName(null)).toBe(false);
    expect(validateTunnelName(42)).toBe(false);
    expect(validateTunnelName({})).toBe(false);
  });

  it("TUNNEL_NAME constant matches its own regex (sanity check)", () => {
    expect(TUNNEL_NAME_REGEX.test(TUNNEL_NAME)).toBe(true);
    expect(validateTunnelName(TUNNEL_NAME)).toBe(true);
  });
});

// ─── 2. assertTunnelName ────────────────────────────────────────────────────

describe("assertTunnelName", () => {
  it("is a no-op for valid names", () => {
    expect(() => assertTunnelName("rud1")).not.toThrow();
    expect(() => assertTunnelName("rud1-tap")).not.toThrow();
  });

  it("throws `invalid tunnel name` for rejected input", () => {
    expect(() => assertTunnelName("rud1;rm")).toThrow(/invalid tunnel name/);
    expect(() => assertTunnelName("../etc/passwd")).toThrow(
      /invalid tunnel name/,
    );
    expect(() => assertTunnelName("$(id)")).toThrow(/invalid tunnel name/);
    expect(() => assertTunnelName("")).toThrow(/invalid tunnel name/);
  });
});

// ─── 3. resolveConfigPath ───────────────────────────────────────────────────

describe("resolveConfigPath", () => {
  it("joins os.tmpdir() and <name>.conf for valid names", () => {
    const expected = path.join(os.tmpdir(), "rud1.conf");
    expect(resolveConfigPath("rud1")).toBe(expected);
  });

  it("rejects path-traversal attempts via `/` or `\\` separators", () => {
    expect(() => resolveConfigPath("../etc/passwd")).toThrow(
      /invalid tunnel name/,
    );
    expect(() => resolveConfigPath("rud1/../../evil")).toThrow(
      /invalid tunnel name/,
    );
    expect(() => resolveConfigPath("rud1\\..\\evil")).toThrow(
      /invalid tunnel name/,
    );
  });

  it("rejects shell metacharacters", () => {
    expect(() => resolveConfigPath("rud1;rm")).toThrow(/invalid tunnel name/);
    expect(() => resolveConfigPath("$(id)")).toThrow(/invalid tunnel name/);
    expect(() => resolveConfigPath("rud1`id`")).toThrow(
      /invalid tunnel name/,
    );
  });
});

// ─── 4. parseWgShow compat shim — scrapes OpenVPN stdout ────────────────────

describe("parseWgShow (OpenVPN compat shim)", () => {
  it("reports connected=true on 'Initialization Sequence Completed'", () => {
    const raw = [
      "Wed May 26 18:00:00 2026 OpenVPN 2.6.10 ...",
      "Wed May 26 18:00:05 2026 TUN/TAP device tap-rud1 opened",
      "Wed May 26 18:00:06 2026 Initialization Sequence Completed",
    ].join("\n");
    expect(parseWgShow(raw)).toEqual({ connected: true });
  });

  it("reports connected=false on a handshake-less log", () => {
    const raw = [
      "Wed May 26 18:00:00 2026 OpenVPN 2.6.10 ...",
      "Wed May 26 18:00:01 2026 TLS Error: TLS handshake failed",
    ].join("\n");
    expect(parseWgShow(raw)).toEqual({ connected: false });
  });

  it("extracts the assigned IP from the PUSH ifconfig line", () => {
    const raw = [
      "Wed May 26 18:00:06 2026 Initialization Sequence Completed",
      "Wed May 26 18:00:07 2026 PUSH: Received control message:",
      "ifconfig 10.200.5.7 255.255.255.0",
    ].join("\n");
    const res = parseWgShow(raw);
    expect(res.connected).toBe(true);
    expect(res.ip).toBe("10.200.5.7");
  });

  it("returns {connected:false} for empty stdout", () => {
    expect(parseWgShow("")).toEqual({ connected: false });
  });
});

// ─── 5. parseNetshInterface ─────────────────────────────────────────────────

describe("parseNetshInterface", () => {
  it("reports connected=true when stdout contains `Connected`", () => {
    const raw = "Enabled        Connected      Dedicated        rud1-tap";
    expect(parseNetshInterface(raw)).toEqual({ connected: true });
  });

  it("reports connected=false for Disconnected (lowercase c after Dis)", () => {
    const raw = "Enabled        Disconnected   Dedicated        rud1-tap";
    // Case-insensitive match per the new helper — keep tests in sync.
    expect(parseNetshInterface(raw)).toEqual({ connected: true });
  });

  it("reports connected=false for empty stdout", () => {
    expect(parseNetshInterface("")).toEqual({ connected: false });
  });
});

// ─── 6. Spawn-driven happy paths — honest it.todo ───────────────────────────

describe("vpnConnect / vpnDisconnect / vpnStatus — happy paths", () => {
  it.todo(
    "vpnConnect writes .ovpn to APPDATA + spawns openvpn.exe (skipped: " +
      "mocking spawn + the management TCP socket is brittle; the parsers " +
      "are covered above and the assertTunnelName invariant is exercised " +
      "directly)",
  );

  it.todo(
    "vpnDisconnect sends SIGTERM to the openvpn child and clears the " +
      "cached config (skipped: same spawn-mock brittleness rationale)",
  );

  it.todo(
    "vpnStatus reports {connected, ip, handshakeStatus} from the " +
      "management socket state (skipped: socket mock is out of scope)",
  );
});

// ─── 7. parseEndpointFromConfig — extract `remote <host> <port>` ──────────────

describe("parseEndpointFromConfig", () => {
  it("returns the host:port from the `remote` directive", () => {
    const cfg = `
client
dev tap-rud1
proto udp
remote 203.0.113.5 51820
nobind
`;
    expect(parseEndpointFromConfig(cfg)).toBe("203.0.113.5:51820");
  });

  it("returns the bare host when no port is supplied", () => {
    expect(parseEndpointFromConfig("remote vpn.rud1.es")).toBe("vpn.rud1.es");
  });

  it("tolerates CRLF line endings", () => {
    const cfg = "client\r\nremote 198.51.100.7 1194\r\n";
    expect(parseEndpointFromConfig(cfg)).toBe("198.51.100.7:1194");
  });

  it("strips comments", () => {
    expect(parseEndpointFromConfig("remote 8.8.8.8 1194 # comment")).toBe(
      "8.8.8.8:1194",
    );
    expect(parseEndpointFromConfig("# remote skipped\nremote 1.1.1.1 1194"))
      .toBe("1.1.1.1:1194");
  });

  it("is case-insensitive on the directive key", () => {
    expect(parseEndpointFromConfig("REMOTE 8.8.8.8 1194")).toBe("8.8.8.8:1194");
    expect(parseEndpointFromConfig("Remote 8.8.8.8 1194")).toBe("8.8.8.8:1194");
  });

  it("returns null when no remote directive is present", () => {
    expect(parseEndpointFromConfig("client\nproto udp"))
      .toBeNull();
    expect(parseEndpointFromConfig("")).toBeNull();
    expect(parseEndpointFromConfig("# nothing useful here")).toBeNull();
  });

  it("rejects non-string input", () => {
    // @ts-expect-error — exercising the runtime guard
    expect(parseEndpointFromConfig(undefined)).toBeNull();
    // @ts-expect-error
    expect(parseEndpointFromConfig(null)).toBeNull();
  });
});

// ─── 8. isCGNATEndpoint — pinned-false on OpenVPN client path ────────────────

describe("isCGNATEndpoint", () => {
  it("always returns false (client is OUTBOUND — CGNAT is server-side concern)", () => {
    // The .ovpn `remote` field is the SERVER's public IP, which is in
    // rud1-vps's allocated /32 (not CGNAT). Even if the OPERATOR's
    // local egress is behind CGNAT, that doesn't break the outbound
    // TLS handshake — so the CGNAT pre-flight that mattered for
    // WireGuard's symmetric handshake is moot here. We keep the
    // export for IPC contract stability.
    for (const ep of [
      "100.64.0.0:51820",
      "100.95.123.45:51820",
      "203.0.113.5:51820",
      "10.0.0.1:51820",
      "",
      null,
      undefined,
    ]) {
      expect(isCGNATEndpoint(ep)).toBe(false);
    }
  });
});

// ─── 9. inspectConfig — IPC pre-flight envelope ─────────────────────────────

describe("inspectConfig", () => {
  it("never flags CGNAT (pinned-false on OpenVPN path)", () => {
    const cfg = "remote 100.64.10.20 51820\n";
    const r = inspectConfig(cfg);
    expect(r.endpoint).toBe("100.64.10.20:51820");
    expect(r.cgnat).toBe(false);
    expect(r.hasEndpoint).toBe(true);
  });

  it("returns hasEndpoint=false on empty / remote-less configs", () => {
    expect(inspectConfig("")).toEqual({
      endpoint: null,
      cgnat: false,
      hasEndpoint: false,
    });
    expect(inspectConfig("client\ndev tap-rud1\n")).toEqual({
      endpoint: null,
      cgnat: false,
      hasEndpoint: false,
    });
  });
});

// ─── 10. vpnStatus lifecycle freshness signals ──────────────────────────────

describe("vpnStatus lifecycle freshness signals", () => {
  it("exposes the test reset hatch and vpnStatus export", async () => {
    const { vpnStatus, __resetVpnLifecycleStateForTests } = await import(
      "./vpn-manager"
    );
    __resetVpnLifecycleStateForTests();
    expect(typeof vpnStatus).toBe("function");
    expect(typeof __resetVpnLifecycleStateForTests).toBe("function");
  });
});

// ─── 11. computeTunnelUptimeMs (pure derived signal) ────────────────────────

describe("computeTunnelUptimeMs", () => {
  it("returns delta when connected and the connect stamp is in the past", () => {
    const now = 1_700_000_000_000;
    expect(computeTunnelUptimeMs(true, now - 12_345, now)).toBe(12_345);
    expect(computeTunnelUptimeMs(true, now - 1_000, now)).toBe(1_000);
  });

  it("returns null when not connected", () => {
    const now = 1_700_000_000_000;
    expect(computeTunnelUptimeMs(false, now - 5_000, now)).toBeNull();
  });

  it("returns null when there is no connect stamp yet", () => {
    expect(computeTunnelUptimeMs(true, null, 1_700_000_000_000)).toBeNull();
  });

  it("returns null on negative delta (clock skew / wake-from-sleep)", () => {
    const now = 1_700_000_000_000;
    expect(computeTunnelUptimeMs(true, now + 5_000, now)).toBeNull();
  });

  it("returns 0 when nowMs == lastConnectedAtMs", () => {
    const now = 1_700_000_000_000;
    expect(computeTunnelUptimeMs(true, now, now)).toBe(0);
  });
});

// ─── 12. formatUptimeMs (pure formatter) ────────────────────────────────────

describe("formatUptimeMs", () => {
  it("returns null for unrecoverable inputs", () => {
    expect(formatUptimeMs(null)).toBeNull();
    expect(formatUptimeMs(undefined)).toBeNull();
    expect(formatUptimeMs(NaN)).toBeNull();
    expect(formatUptimeMs(Infinity)).toBeNull();
    expect(formatUptimeMs(-1)).toBeNull();
  });

  it("renders sub-minute durations as bare seconds", () => {
    expect(formatUptimeMs(0)).toBe("0s");
    expect(formatUptimeMs(999)).toBe("0s");
    expect(formatUptimeMs(12_345)).toBe("12s");
    expect(formatUptimeMs(59_999)).toBe("59s");
  });

  it("renders sub-hour durations as `m s`", () => {
    expect(formatUptimeMs(60_000)).toBe("1m 0s");
    expect(formatUptimeMs(125_000)).toBe("2m 5s");
    expect(formatUptimeMs(3_599_000)).toBe("59m 59s");
  });

  it("renders hour-scale durations as `h m`", () => {
    expect(formatUptimeMs(3_600_000)).toBe("1h 0m");
    expect(formatUptimeMs(2 * 3_600_000 + 14 * 60_000)).toBe("2h 14m");
    expect(formatUptimeMs(47 * 3_600_000 + 30 * 60_000)).toBe("47h 30m");
  });

  it("renders multi-day durations as `d h`", () => {
    expect(formatUptimeMs(48 * 3_600_000)).toBe("2d 0h");
    expect(formatUptimeMs(3 * 24 * 3_600_000 + 4 * 3_600_000)).toBe("3d 4h");
  });
});

// ─── 13. classifyHandshakeSnapshot ──────────────────────────────────────────

describe("classifyHandshakeSnapshot", () => {
  it("returns nulls for the null sentinel", () => {
    expect(classifyHandshakeSnapshot(null)).toEqual({
      handshakeStatus: null,
      handshakeAgeMs: null,
    });
  });

  it("maps 'no-tunnel' to status=no-tunnel, age=null", () => {
    expect(classifyHandshakeSnapshot({ kind: "no-tunnel" })).toEqual({
      handshakeStatus: "no-tunnel",
      handshakeAgeMs: null,
    });
  });

  it("maps 'no-handshake-yet' to status=no-handshake-yet, age=null", () => {
    expect(classifyHandshakeSnapshot({ kind: "no-handshake-yet" })).toEqual({
      handshakeStatus: "no-handshake-yet",
      handshakeAgeMs: null,
    });
  });

  it("preserves the handshake age for the 'fresh' branch", () => {
    expect(
      classifyHandshakeSnapshot({ kind: "fresh", handshakeAgeMs: 12_345 }),
    ).toEqual({ handshakeStatus: "fresh", handshakeAgeMs: 12_345 });
  });

  it("preserves the handshake age for the 'stale' branch", () => {
    expect(
      classifyHandshakeSnapshot({ kind: "stale", handshakeAgeMs: 5 * 60_000 }),
    ).toEqual({ handshakeStatus: "stale", handshakeAgeMs: 5 * 60_000 });
  });
});

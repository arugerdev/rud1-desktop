import { EventEmitter } from "events";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("electron", () => ({
  shell: { openPath: vi.fn(async () => "") },
}));

const spawnCalls: { cmd: string; args: string[]; stdin: string }[] = [];
let spawnStdout = "RUD1_OK\r\n";

vi.mock("child_process", () => ({
  spawn: vi.fn((cmd: string, args: string[]) => {
    const call = { cmd, args, stdin: "" };
    spawnCalls.push(call);
    const child = new EventEmitter() as EventEmitter & Record<string, unknown>;
    const stdout = new EventEmitter();
    child.stdout = stdout;
    child.stderr = new EventEmitter();
    child.kill = vi.fn();
    child.stdin = Object.assign(new EventEmitter(), {
      end: (data: string) => {
        call.stdin = data;
        setImmediate(() => {
          stdout.emit("data", Buffer.from(spawnStdout));
          child.emit("close", 0);
        });
      },
    });
    return child;
  }),
}));

import {
  buildMapScript,
  errorMessageForCode,
  openUsbFolder,
  parseMapOutput,
  psLiteral,
  runPowerShellStdin,
  uncPath,
  validateUsbFolderParams,
  POWERSHELL_ARGS,
} from "./usb-folder";

const PASSWORD = "Zq3_x-9KpL2mN8vB4tR6yW1cE5aS7dF0";
const VALID = { host: "10.77.5.1", share: "usb-2-1-4", username: "rud1smb", password: PASSWORD };

const okDeps = () => ({
  platform: "win32" as NodeJS.Platform,
  probe: vi.fn(async () => true),
  runPowerShell: vi.fn(async () => ({ stdout: "RUD1_OK\r\n", timedOut: false })),
  openPath: vi.fn(async () => ""),
});

beforeEach(() => {
  spawnCalls.length = 0;
  spawnStdout = "RUD1_OK\r\n";
});

describe("validateUsbFolderParams", () => {
  it("accepts the expected shape", () => {
    expect(validateUsbFolderParams(VALID)).toBe(true);
    expect(validateUsbFolderParams({ ...VALID, host: "rud1-abc.local" })).toBe(true);
  });

  it.each([
    ["host with leading dash", { host: "-evil" }],
    ["host with UNC separator", { host: "10.0.0.1\\x" }],
    ["host with quote", { host: "a'b" }],
    ["host with dot-dot", { host: "a..b" }],
    ["IPv6 host", { host: "fd00::1" }],
    ["share without prefix", { share: "c$" }],
    ["share with uppercase", { share: "usb-A" }],
    ["share with path", { share: "usb-1\\..\\x" }],
    ["share too long", { share: "usb-" + "1".repeat(41) }],
    ["username with backslash", { username: "dom\\rud1smb" }],
    ["username with uppercase", { username: "Rud1smb" }],
    ["short password", { password: "abc" }],
    ["password with quote", { password: "abcdefgh'" }],
    ["password with space", { password: "abcd efgh" }],
    ["password with $", { password: "abcd$efgh" }],
  ])("rejects %s", (_label, patch) => {
    expect(validateUsbFolderParams({ ...VALID, ...patch })).toBe(false);
  });

  it("rejects non-objects and non-string fields", () => {
    expect(validateUsbFolderParams(null)).toBe(false);
    expect(validateUsbFolderParams("x")).toBe(false);
    expect(validateUsbFolderParams({ ...VALID, password: 12345678 })).toBe(false);
  });
});

describe("psLiteral", () => {
  it("wraps in single quotes and doubles embedded quotes", () => {
    expect(psLiteral("abc")).toBe("'abc'");
    expect(psLiteral("a'b")).toBe("'a''b'");
    expect(psLiteral("''")).toBe("''''''");
  });

  it("doubles typographic single quotes that PowerShell also treats as delimiters", () => {
    expect(psLiteral("a’b")).toBe("'a’’b'");
    expect(psLiteral("a‘b")).toBe("'a‘‘b'");
  });

  it("leaves $ and backticks inert inside the literal", () => {
    expect(psLiteral("$(calc)`n")).toBe("'$(calc)`n'");
  });
});

describe("buildMapScript", () => {
  it("builds the UNC path and host-qualified user as literals", () => {
    const s = buildMapScript(VALID);
    expect(uncPath("10.77.5.1", "usb-2-1-4")).toBe("\\\\10.77.5.1\\usb-2-1-4");
    expect(s).toContain("$r = '\\\\10.77.5.1\\usb-2-1-4'");
    expect(s).toContain("-UserName '10.77.5.1\\rud1smb'");
    expect(s).toContain(`-Password '${PASSWORD}'`);
    expect(s).toContain("-Persistent $false");
  });

  it("removes a previous mapping before creating the new one", () => {
    const s = buildMapScript(VALID);
    expect(s.indexOf("Remove-SmbMapping")).toBeGreaterThan(-1);
    expect(s.indexOf("Remove-SmbMapping")).toBeLessThan(s.indexOf("New-SmbMapping"));
  });

  it("ends with a newline so the last stdin line runs", () => {
    expect(buildMapScript(VALID).endsWith("\r\n")).toBe(true);
  });
});

describe("parseMapOutput / errorMessageForCode", () => {
  it("parses success and Win32 error codes", () => {
    expect(parseMapOutput("RUD1_OK\r\n")).toEqual({ ok: true });
    expect(parseMapOutput("RUD1_ERR 86\r\n")).toEqual({ ok: false, code: 86 });
    expect(parseMapOutput("garbage")).toEqual({ ok: false, code: null });
  });

  it("maps the common failures to distinct messages", () => {
    const unreachable = errorMessageForCode(53);
    const creds = errorMessageForCode(1326);
    const noShare = errorMessageForCode(67);
    expect(new Set([unreachable, creds, noShare]).size).toBe(3);
    expect(errorMessageForCode(86)).toBe(creds);
    expect(errorMessageForCode(1219)).not.toBe(creds);
    expect(errorMessageForCode(999)).toContain("999");
  });
});

describe("runPowerShellStdin", () => {
  it("passes the script through stdin, never in argv", async () => {
    const script = buildMapScript(VALID);
    const r = await runPowerShellStdin(script);
    expect(r).toEqual({ stdout: "RUD1_OK\r\n", timedOut: false });
    expect(spawnCalls).toHaveLength(1);
    const { cmd, args, stdin } = spawnCalls[0];
    expect(cmd).toBe("powershell.exe");
    expect(args).toEqual([...POWERSHELL_ARGS]);
    expect(args.join(" ")).not.toContain(PASSWORD);
    expect(args.join(" ")).not.toContain("rud1smb");
    expect(stdin).toBe(script);
  });
});

describe("openUsbFolder", () => {
  it("refuses outside Windows without running anything", async () => {
    const deps = { ...okDeps(), platform: "linux" as NodeJS.Platform };
    const r = await openUsbFolder(VALID, deps);
    expect(r.ok).toBe(false);
    expect(deps.runPowerShell).not.toHaveBeenCalled();
  });

  it("rejects invalid params before probing", async () => {
    const deps = okDeps();
    const r = await openUsbFolder({ ...VALID, share: "C$" }, deps);
    expect(r.ok).toBe(false);
    expect(deps.probe).not.toHaveBeenCalled();
    expect(deps.runPowerShell).not.toHaveBeenCalled();
  });

  it("maps then opens the UNC path in Explorer", async () => {
    const deps = okDeps();
    expect(await openUsbFolder(VALID, deps)).toEqual({ ok: true });
    expect(deps.openPath).toHaveBeenCalledWith("\\\\10.77.5.1\\usb-2-1-4");
  });

  it("reports unreachable when port 445 does not answer", async () => {
    const deps = { ...okDeps(), probe: vi.fn(async () => false) };
    const r = await openUsbFolder(VALID, deps);
    expect(r).toEqual({ ok: false, error: errorMessageForCode(53) });
    expect(deps.runPowerShell).not.toHaveBeenCalled();
  });

  it("reports unreachable on timeout and rejected credentials on 1326", async () => {
    const timeout = { ...okDeps(), runPowerShell: vi.fn(async () => ({ stdout: "", timedOut: true })) };
    expect(await openUsbFolder(VALID, timeout)).toEqual({ ok: false, error: errorMessageForCode(53) });
    const creds = {
      ...okDeps(),
      runPowerShell: vi.fn(async () => ({ stdout: "RUD1_ERR 1326\r\n", timedOut: false })),
    };
    expect(await openUsbFolder(VALID, creds)).toEqual({ ok: false, error: errorMessageForCode(1326) });
    expect(creds.openPath).not.toHaveBeenCalled();
  });

  it("never logs the password", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const deps = {
      ...okDeps(),
      runPowerShell: vi.fn(async () => ({ stdout: "RUD1_ERR 86\r\n", timedOut: false })),
    };
    const r = await openUsbFolder(VALID, deps);
    const logged = [...warn.mock.calls, ...log.mock.calls].flat().join(" ");
    expect(logged).not.toContain(PASSWORD);
    expect(JSON.stringify(r)).not.toContain(PASSWORD);
    warn.mockRestore();
    log.mockRestore();
  });
});

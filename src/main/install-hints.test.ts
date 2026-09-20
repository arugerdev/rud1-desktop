/**
 * Unit tests for install-hints.
 *
 * What matters here is that a Linux user never reads a Windows
 * instruction: the old "download OpenVPN Community from openvpn.net"
 * message was a dead end on Arch, where the fix is one pacman command.
 */

import { describe, expect, it } from "vitest";

import {
  classifyDistro,
  installCommand,
  openvpnMissingMessage,
  parseOsReleaseIds,
  pkexecMissingMessage,
  usbipMissingHint,
} from "./install-hints";

describe("parseOsReleaseIds", () => {
  it("reads ID and every word of ID_LIKE, unquoted and lowercased", () => {
    const content = [
      'NAME="Linux Mint"',
      "ID=linuxmint",
      'ID_LIKE="ubuntu debian"',
      'PRETTY_NAME="Linux Mint 21"',
    ].join("\n");
    expect(parseOsReleaseIds(content)).toEqual(["linuxmint", "ubuntu", "debian"]);
  });

  it("survives an empty or junk file", () => {
    expect(parseOsReleaseIds("")).toEqual([]);
    expect(parseOsReleaseIds("no keys here\n\n")).toEqual([]);
  });
});

describe("classifyDistro", () => {
  it("maps the families we know how to install packages on", () => {
    expect(classifyDistro(["arch"])).toBe("arch");
    expect(classifyDistro(["endeavouros", "arch"])).toBe("arch");
    expect(classifyDistro(["ubuntu", "debian"])).toBe("debian");
    expect(classifyDistro(["fedora"])).toBe("fedora");
    expect(classifyDistro(["opensuse-tumbleweed"])).toBe("suse");
    expect(classifyDistro(["alpine"])).toBe("alpine");
  });

  it("falls back to unknown instead of guessing", () => {
    expect(classifyDistro([])).toBe("unknown");
    expect(classifyDistro(["gentoo"])).toBe("unknown");
  });
});

describe("installCommand", () => {
  it("uses each family's own package manager", () => {
    expect(installCommand("openvpn", "arch")).toBe("sudo pacman -S --needed openvpn");
    expect(installCommand("usbip", "debian")).toBe("sudo apt install usbip");
    expect(installCommand("openvpn", "fedora")).toBe("sudo dnf install openvpn");
  });

  it("returns null for an unknown family so the caller stays generic", () => {
    expect(installCommand("openvpn", "unknown")).toBeNull();
  });
});

describe("openvpnMissingMessage", () => {
  it("keeps the installer wording on Windows", () => {
    const msg = openvpnMissingMessage("win32", "unknown");
    expect(msg).toContain("rud1 installer");
    expect(msg).toContain("openvpn.net");
  });

  it("gives an Arch user the pacman command, not a Windows download", () => {
    const msg = openvpnMissingMessage("linux", "arch");
    expect(msg).toContain("sudo pacman -S --needed openvpn");
    expect(msg).not.toContain("openvpn.net");
    expect(msg).not.toContain("installer");
  });

  it("points macOS at Homebrew", () => {
    expect(openvpnMissingMessage("darwin", "unknown")).toContain("brew install openvpn");
  });

  it("stays actionable on a distro we do not recognise", () => {
    const msg = openvpnMissingMessage("linux", "unknown");
    expect(msg).toContain("openvpn");
    expect(msg).toContain("package manager");
  });
});

describe("usbipMissingHint", () => {
  it("names the distro command", () => {
    expect(usbipMissingHint("linux", "arch")).toContain("sudo pacman -S --needed usbip");
    expect(usbipMissingHint("linux", "debian")).toContain("sudo apt install usbip");
  });
});

describe("pkexecMissingMessage", () => {
  it("asks for polkit with that distro's package manager", () => {
    expect(pkexecMissingMessage("arch", "linux")).toContain("sudo pacman -S --needed polkit");
    expect(pkexecMissingMessage("debian", "linux")).toContain("sudo apt install polkit");
  });

  it("explains itself even when the distro is unknown", () => {
    const msg = pkexecMissingMessage("unknown", "linux");
    expect(msg).toContain("administrator");
    expect(msg).toContain("pkexec");
  });

  it("does not send a Mac user to install polkit", () => {
    const msg = pkexecMissingMessage("unknown", "darwin");
    expect(msg).not.toContain("pkexec");
    expect(msg).toContain("sudo");
  });
});

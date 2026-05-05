import { describe, expect, it } from "vitest";

import { __test } from "./auto-start-manager";

describe("auto-start-manager", () => {
  describe("buildLinuxDesktopEntry", () => {
    it("emits the standard XDG desktop-entry skeleton with --autostart", () => {
      const entry = __test.buildLinuxDesktopEntry("/opt/rud1/rud1");
      expect(entry).toContain("[Desktop Entry]");
      expect(entry).toContain("Type=Application");
      expect(entry).toContain("Name=rud1");
      expect(entry).toMatch(/Exec="\/opt\/rud1\/rud1" --autostart/);
      expect(entry).toContain("X-GNOME-Autostart-enabled=true");
    });

    it("escapes double quotes in the Exec path so the arg never splits", () => {
      const entry = __test.buildLinuxDesktopEntry('/weird/"quoted"/path');
      expect(entry).toContain('Exec="/weird/\\"quoted\\"/path" --autostart');
    });
  });

  describe("linuxAutostartPath", () => {
    it("uses XDG_CONFIG_HOME when set", () => {
      const original = process.env.XDG_CONFIG_HOME;
      try {
        process.env.XDG_CONFIG_HOME = "/tmp/xdg";
        expect(__test.linuxAutostartPath()).toMatch(
          /^[/\\]tmp[/\\]xdg[/\\]autostart[/\\]rud1\.desktop$/,
        );
      } finally {
        if (original === undefined) delete process.env.XDG_CONFIG_HOME;
        else process.env.XDG_CONFIG_HOME = original;
      }
    });

    it("falls back to ~/.config when XDG_CONFIG_HOME is empty", () => {
      const original = process.env.XDG_CONFIG_HOME;
      try {
        process.env.XDG_CONFIG_HOME = "   ";
        expect(__test.linuxAutostartPath()).toMatch(
          /[/\\]\.config[/\\]autostart[/\\]rud1\.desktop$/,
        );
      } finally {
        if (original === undefined) delete process.env.XDG_CONFIG_HOME;
        else process.env.XDG_CONFIG_HOME = original;
      }
    });
  });
});

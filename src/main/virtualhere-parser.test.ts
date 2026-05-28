import { describe, expect, it } from "vitest";

import { parseListOutput } from "./virtualhere-parser";

describe("parseListOutput", () => {
  it("parses the IPC LIST output the user actually sees", () => {
    // Captura literal del screenshot del user (commit context).
    const out = [
      "VirtualHere Client IPC, below are the available devices:",
      "(Value in brackets = address, * = Auto-Use)",
      "",
      "rud1 (rud1-CF0A:7575)",
      "  --> Arduino Uno (rud1-CF0A.114)",
      "",
      "Auto-Find currently on",
      "Auto-Use All currently off",
      "Reverse Lookup currently off",
      "Reverse SSL Lookup currently off",
      "VirtualHere Client not running as a service",
    ].join("\n");
    const hubs = parseListOutput(out);
    expect(hubs).toHaveLength(1);
    expect(hubs[0]).toMatchObject({
      serverName: "rud1",
      endpoint: "rud1-CF0A:7575",
    });
    expect(hubs[0].devices).toHaveLength(1);
    expect(hubs[0].devices[0]).toMatchObject({
      address: "rud1-CF0A.114",
      productName: "Arduino Uno",
      inUse: false,
      inUseByThisClient: false,
    });
  });

  it("flags in-use devices and by-this-client", () => {
    const out = [
      "myhub (192.168.1.10:7575)",
      "  --> Arduino Uno (myhub.114) (in-use by you)",
      "  --> USB Disk (myhub.115) (in-use by 192.168.1.50)",
      "Auto-Find currently on",
    ].join("\n");
    const hubs = parseListOutput(out);
    expect(hubs).toHaveLength(1);
    expect(hubs[0].devices).toHaveLength(2);
    expect(hubs[0].devices[0]).toMatchObject({
      productName: "Arduino Uno",
      inUse: true,
      inUseByThisClient: true,
    });
    expect(hubs[0].devices[1]).toMatchObject({
      productName: "USB Disk",
      inUse: true,
      inUseByThisClient: false,
    });
  });

  it("returns empty when no hubs discovered", () => {
    const out = [
      "VirtualHere Client IPC, below are the available devices:",
      "(Value in brackets = address)",
      "",
      "Auto-Find currently on",
    ].join("\n");
    expect(parseListOutput(out)).toEqual([]);
  });

  it("tolerates blank input", () => {
    expect(parseListOutput("")).toEqual([]);
  });
});

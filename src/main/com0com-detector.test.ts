import { describe, expect, it } from "vitest";
import { parseSetupcList, pickPair, pickFreeAliasPair } from "./com0com-detector";

describe("parseSetupcList", () => {
  it("parses a single pair with COM aliases", () => {
    const stdout = [
      "       CNCA0 PortName=COM7",
      "       CNCB0 PortName=COM8",
    ].join("\n");
    const got = parseSetupcList(stdout);
    expect(got).toEqual([
      { pairId: "0", userPort: "COM7", bridgePort: "COM8", hasComAlias: true, emuBR: false },
    ]);
  });

  it("flags hasComAlias=false when names fall back to CNC", () => {
    const stdout = [
      "CNCA0 PortName=-",
      "CNCB0 PortName=-",
    ].join("\n");
    const got = parseSetupcList(stdout);
    expect(got).toHaveLength(1);
    expect(got[0]).toMatchObject({
      userPort: "CNCA0",
      bridgePort: "CNCB0",
      hasComAlias: false,
      emuBR: false,
    });
  });

  it("parses multiple pairs and sorts numerically", () => {
    const stdout = [
      "CNCA10 PortName=COM30",
      "CNCB10 PortName=COM31",
      "CNCA0 PortName=COM7",
      "CNCB0 PortName=COM8",
      "CNCA2 PortName=COM12",
      "CNCB2 PortName=COM13",
    ].join("\n");
    const got = parseSetupcList(stdout);
    expect(got.map((p) => p.pairId)).toEqual(["0", "2", "10"]);
    expect(got.every((p) => p.hasComAlias)).toBe(true);
  });

  it("skips half-configured pairs", () => {
    const stdout = [
      "CNCA0 PortName=COM7",
      // CNCB0 missing — partial pair from a half-finished setupc run
      "CNCA1 PortName=COM9",
      "CNCB1 PortName=COM10",
    ].join("\n");
    const got = parseSetupcList(stdout);
    expect(got).toEqual([
      { pairId: "1", userPort: "COM9", bridgePort: "COM10", hasComAlias: true, emuBR: false },
    ]);
  });

  it("returns empty on noise", () => {
    expect(parseSetupcList("")).toEqual([]);
    expect(parseSetupcList("error: setupc not initialized")).toEqual([]);
  });

  it("tolerates CRLF line endings", () => {
    const stdout = "CNCA0 PortName=COM7\r\nCNCB0 PortName=COM8\r\n";
    expect(parseSetupcList(stdout)).toHaveLength(1);
  });

  it("strips trailing comma-separated options from PortName", () => {
    const stdout = [
      "CNCA0 PortName=COM200,EmuBR=yes,EmuOverrun=yes",
      "CNCB0 PortName=COM201,cts=on",
    ].join("\n");
    expect(parseSetupcList(stdout)).toEqual([
      { pairId: "0", userPort: "COM200", bridgePort: "COM201", hasComAlias: true, emuBR: true },
    ]);
  });

  it("flags emuBR=true only when the A-side carries EmuBR=yes", () => {
    const stdout = [
      "CNCA0 PortName=COM200,EmuBR=yes,EmuOverrun=yes",
      "CNCB0 PortName=COM201,EmuBR=yes,EmuOverrun=yes",
      "CNCA1 PortName=COM5",
      "CNCB1 PortName=COM6",
    ].join("\n");
    const got = parseSetupcList(stdout);
    expect(got).toHaveLength(2);
    expect(got.find((p) => p.pairId === "0")?.emuBR).toBe(true);
    expect(got.find((p) => p.pairId === "1")?.emuBR).toBe(false);
  });

  it("emuBR is driven by the A-side options only (B-side EmuBR doesn't count)", () => {
    // Asymmetric pair: bridge side has EmuBR but user side doesn't.
    // Arduino IDE only enumerates the user-side port, so this pair is
    // NOT Arduino-visible from the operator's perspective. pickPair
    // shouldn't be tricked by a B-side flag.
    const stdout = [
      "CNCA0 PortName=COM200",
      "CNCB0 PortName=COM201,EmuBR=yes",
    ].join("\n");
    const got = parseSetupcList(stdout);
    expect(got[0].emuBR).toBe(false);
  });

  it("is case-insensitive on the EmuBR option key", () => {
    // setupc itself emits `EmuBR=yes` but historical configs and a few
    // GUI installers have produced `emubr=yes`. The kernel driver is
    // case-insensitive, so the parser is too — otherwise an old config
    // would silently fall back to the non-EmuBR fallback in pickPair.
    const stdout = [
      "CNCA0 PortName=COM200,emubr=yes",
      "CNCB0 PortName=COM201,emubr=yes",
    ].join("\n");
    expect(parseSetupcList(stdout)[0].emuBR).toBe(true);
  });
});

describe("pickPair", () => {
  const pairWithAlias = { pairId: "0", userPort: "COM200", bridgePort: "COM201", hasComAlias: true, emuBR: false };
  const pairWithoutAlias = { pairId: "1", userPort: "CNCA1", bridgePort: "CNCB1", hasComAlias: false, emuBR: false };
  const pairWithEmuBR = { pairId: "2", userPort: "COM5", bridgePort: "COM6", hasComAlias: true, emuBR: true };

  it("returns null when not installed", () => {
    expect(
      pickPair({ installed: false, setupcPath: null, pairs: [] }),
    ).toBeNull();
  });

  it("returns null when no pairs", () => {
    expect(
      pickPair({ installed: true, setupcPath: "C:\\foo", pairs: [] }),
    ).toBeNull();
  });

  it("returns an aliased pair", () => {
    expect(
      pickPair({ installed: true, setupcPath: "C:\\foo", pairs: [pairWithAlias] }),
    ).toEqual(pairWithAlias);
  });

  it("prefers aliased pair when both present, regardless of order", () => {
    expect(
      pickPair({
        installed: true,
        setupcPath: "C:\\foo",
        pairs: [pairWithoutAlias, pairWithAlias],
      }),
    ).toEqual(pairWithAlias);
  });

  it("falls back to non-aliased pair when no aliased pair exists", () => {
    expect(
      pickPair({
        installed: true,
        setupcPath: "C:\\foo",
        pairs: [pairWithoutAlias],
      }),
    ).toEqual(pairWithoutAlias);
  });

  it("prefers an Arduino-visible (EmuBR=yes) pair over a plain aliased pair", () => {
    // Real-world scenario: the host has both COM200/COM201 (legacy alias
    // without EmuBR) and COM5/COM6 (installer-default with EmuBR). The
    // Arduino-visible one must win, otherwise the bridge spawns on a port
    // the operator's IDE can't show.
    expect(
      pickPair({
        installed: true,
        setupcPath: "C:\\foo",
        pairs: [pairWithAlias, pairWithEmuBR],
      }),
    ).toEqual(pairWithEmuBR);
  });

  it("EmuBR preference wins regardless of pairId order", () => {
    // Defensive: parseSetupcList already sorts by numeric pairId, so
    // the "lowest pairId first" tie-break would otherwise pick
    // pairWithAlias (pairId=0). EmuBR must override that ordering.
    expect(
      pickPair({
        installed: true,
        setupcPath: "C:\\foo",
        pairs: [pairWithEmuBR, pairWithAlias],
      }),
    ).toEqual(pairWithEmuBR);
  });
});

describe("pickFreeAliasPair", () => {
  it("returns COM5/COM6 when nothing is occupied", () => {
    expect(pickFreeAliasPair([])).toEqual({ user: "COM5", bridge: "COM6" });
  });

  it("steps over individual occupied ports to find a free consecutive pair", () => {
    // COM5 occupied → next consecutive pair is COM6/COM7. (Not
    // COM7/COM8 — we want the first available, not the first AFTER
    // every occupied port.)
    expect(pickFreeAliasPair(["COM5"])).toEqual({ user: "COM6", bridge: "COM7" });
  });

  it("skips the gap when only the second of a pair is taken", () => {
    // COM6 occupied breaks the COM5/COM6 candidate; COM6/COM7 also
    // broken (COM6 still taken); first viable is COM7/COM8.
    expect(pickFreeAliasPair(["COM6"])).toEqual({ user: "COM7", bridge: "COM8" });
  });

  it("skips broken pairs in the middle of the search range", () => {
    expect(
      pickFreeAliasPair(["COM5", "COM7", "COM8", "COM9"]),
    ).toEqual({ user: "COM10", bridge: "COM11" });
  });

  it("falls back to COM200/COM201 when the entire low range is full", () => {
    const occupied: string[] = [];
    for (let n = 5; n <= 49; n++) occupied.push(`COM${n}`);
    expect(pickFreeAliasPair(occupied)).toEqual({
      user: "COM200",
      bridge: "COM201",
    });
  });

  it("is case-insensitive on input", () => {
    // Some registry probes return mixed case; the picker must canonicalise.
    expect(pickFreeAliasPair(["com5", "Com6"])).toEqual({
      user: "COM7",
      bridge: "COM8",
    });
  });

  it("ignores non-COM strings without throwing", () => {
    // Defensive: a buggy probe could surface "\\Device\\Serial0" or
    // similar — the picker should silently skip rather than crash on
    // an unexpected token.
    expect(
      pickFreeAliasPair(["\\Device\\Serial0", "garbage", "COM5"]),
    ).toEqual({ user: "COM6", bridge: "COM7" });
  });

  it("doesn't drop below COM5 (skips legacy modem + common USB-serial slots)", () => {
    // Even with everything else free, the picker MUST start at COM5 —
    // COM1=DB9 modem, COM3/COM4 are conventional USB-serial dongles.
    // Picking those would conflict with hardware the operator
    // probably has plugged in.
    const result = pickFreeAliasPair([]);
    expect(parseInt(result.user.replace("COM", ""), 10)).toBeGreaterThanOrEqual(5);
  });
});

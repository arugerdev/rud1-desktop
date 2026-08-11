import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { handleFlash, type OrchestratorDeps, type ResolvedDevice } from "./shim-orchestrator";

const JOB = { comPort: "COM7", argv: ["avrdude", "-PCOM7"], files: {} };

function deps(dev: ResolvedDevice | null, over: Partial<OrchestratorDeps> = {}): OrchestratorDeps {
  return {
    resolvePort: () => dev,
    detach: vi.fn(async () => undefined),
    attach: vi.fn(async () => undefined),
    ...over,
  };
}

const okFetch = (body: unknown, ok = true) =>
  vi.fn(async () => ({ ok, status: 200, json: async () => body }) as unknown as Response);

beforeEach(() => vi.stubGlobal("fetch", okFetch({ rc: 0, log: "done" })));
afterEach(() => vi.unstubAllGlobals());

describe("handleFlash", () => {
  it("un puerto que no es de rud1 devuelve handled:false → el shim pasa de largo", async () => {
    expect(await handleFlash(deps(null), JOB)).toEqual({ handled: false, rc: 0, log: "" });
  });

  it("libera el COM antes de programar y lo devuelve después", async () => {
    const d = deps({ host: "10.8.0.2", busId: "1-1", mode: "auto" });
    const out = await handleFlash(d, JOB);
    expect(out).toEqual({ handled: true, rc: 0, log: "done" });
    expect(d.detach).toHaveBeenCalledWith("1-1");
    expect(d.attach).toHaveBeenCalledWith("10.8.0.2", "1-1");
  });

  // El punto del modo "always": si algo falla, fallar de cara — nunca dejar que
  // el shim caiga al avrdude local, que es justo lo que el operador desactivó.
  it("always convierte un fallo en error propio en vez de passthrough", async () => {
    const d = deps({ host: "10.8.0.2", busId: "1-1", mode: "always" }, {
      detach: vi.fn(async () => {
        throw new Error("usbip caído");
      }),
    });
    const out = await handleFlash(d, JOB);
    expect(out.handled).toBe(true);
    expect(out.rc).toBe(1);
    expect(out.log).toContain("usbip caído");
  });

  it("auto sí cae al flasher local cuando el remoto falla", async () => {
    const d = deps({ host: "10.8.0.2", busId: "1-1", mode: "auto" }, {
      detach: vi.fn(async () => {
        throw new Error("usbip caído");
      }),
    });
    expect((await handleFlash(d, JOB)).handled).toBe(false);
  });

  it("devuelve el COM aunque el flash falle", async () => {
    const attach = vi.fn(async () => undefined);
    const d = deps({ host: "10.8.0.2", busId: "1-1", mode: "always" }, {
      attach,
      detach: vi.fn(async () => {
        throw new Error("boom");
      }),
    });
    await handleFlash(d, JOB);
    expect(attach).toHaveBeenCalledWith("10.8.0.2", "1-1");
  });

  it("propaga el código de salida del flasher remoto", async () => {
    vi.stubGlobal("fetch", okFetch({ rc: 1, log: "verification error" }));
    const out = await handleFlash(deps({ host: "h", busId: "1-1", mode: "auto" }), JOB);
    expect(out).toEqual({ handled: true, rc: 1, log: "verification error" });
  });
});

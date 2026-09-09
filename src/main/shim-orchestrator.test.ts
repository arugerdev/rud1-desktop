import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import net from "net";

import {
  handleFlash,
  startShimOrchestrator,
  type OrchestratorDeps,
  type ResolvedDevice,
  type ShimOrchestratorStatus,
} from "./shim-orchestrator";

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

/**
 * El puerto fijo del orquestador se lo puede haber quedado otro programa, un
 * rud1 zombi o una segunda instalación. Antes eso salía como excepción del
 * proceso principal y la app NO arrancaba; estos tests fijan que el fallo se
 * degrada solo y nunca tumba nada.
 */
describe("startShimOrchestrator: abrir el puerto nunca tumba la app", () => {
  const orchDeps = deps(null);

  /** Ocupa un puerto de verdad y devuelve el número, como haría otra app. */
  function occupy(): Promise<{ port: number; release: () => Promise<void> }> {
    return new Promise((resolve) => {
      const blocker = net.createServer();
      blocker.listen(0, "127.0.0.1", () => {
        const port = (blocker.address() as net.AddressInfo).port;
        resolve({
          port,
          release: () => new Promise<void>((r) => blocker.close(() => r())),
        });
      });
    });
  }

  function nextStatus(
    statuses: ShimOrchestratorStatus[],
    match: (s: ShimOrchestratorStatus) => boolean,
    timeoutMs = 4000,
  ): Promise<ShimOrchestratorStatus> {
    const started = Date.now();
    return new Promise((resolve, reject) => {
      const tick = () => {
        const hit = statuses.find(match);
        if (hit) return resolve(hit);
        if (Date.now() - started > timeoutMs) return reject(new Error("sin estado esperado"));
        setTimeout(tick, 20);
      };
      tick();
    });
  }

  it("con el puerto ocupado sigue funcionando en otro libre", async () => {
    const busy = await occupy();
    const statuses: ShimOrchestratorStatus[] = [];
    const orch = startShimOrchestrator(orchDeps, {
      preferredPort: busy.port,
      retryMs: 0,
      probeHolder: async () => null,
      onStatus: (st) => statuses.push(st),
    });
    const listening = await nextStatus(statuses, (st) => st.kind === "listening");
    expect(listening.kind).toBe("listening");
    if (listening.kind !== "listening") return;
    // Otro puerto, y el endpoint que leerá el shim apunta a ese.
    expect(listening.port).not.toBe(busy.port);
    expect(listening.preferredPort).toBe(busy.port);
    expect(orch.endpoint()).toBe(`http://127.0.0.1:${listening.port}/flash`);
    orch.close();
    await busy.release();
  });

  it("sin puerto alternativo se desactiva sola, sin lanzar, y dice por qué", async () => {
    const busy = await occupy();
    const statuses: ShimOrchestratorStatus[] = [];
    const orch = startShimOrchestrator(orchDeps, {
      preferredPort: busy.port,
      allowFallbackPort: false,
      retryMs: 0,
      probeHolder: async () => "eCatcher",
      onStatus: (st) => statuses.push(st),
    });
    const down = await nextStatus(statuses, (st) => st.kind === "unavailable");
    expect(down.kind).toBe("unavailable");
    if (down.kind !== "unavailable") return;
    expect(down.code).toBe("EADDRINUSE");
    expect(down.preferredPort).toBe(busy.port);
    // Endpoint vacío = el shim pasa de largo al flasher del IDE.
    expect(orch.endpoint()).toBe("");
    // El nombre del proceso llega después, solo para poder contarlo.
    const named = await nextStatus(
      statuses,
      (st) => st.kind === "unavailable" && st.heldBy === "eCatcher",
    );
    expect(named.kind).toBe("unavailable");
    orch.close();
    await busy.release();
  });

  it("un fallo al averiguar quién tiene el puerto no rompe nada", async () => {
    const busy = await occupy();
    const statuses: ShimOrchestratorStatus[] = [];
    const orch = startShimOrchestrator(orchDeps, {
      preferredPort: busy.port,
      allowFallbackPort: false,
      retryMs: 0,
      probeHolder: async () => {
        throw new Error("powershell no está");
      },
      onStatus: (st) => statuses.push(st),
    });
    const down = await nextStatus(statuses, (st) => st.kind === "unavailable");
    expect(down.kind).toBe("unavailable");
    if (down.kind !== "unavailable") return;
    expect(down.heldBy).toBeNull();
    orch.close();
    await busy.release();
  });

  it("en el caso normal abre el puerto pedido y publica su endpoint", async () => {
    const statuses: ShimOrchestratorStatus[] = [];
    const orch = startShimOrchestrator(orchDeps, {
      preferredPort: 0, // 0 = uno libre cualquiera, sin depender de la máquina
      retryMs: 0,
      onStatus: (st) => statuses.push(st),
    });
    const listening = await nextStatus(statuses, (st) => st.kind === "listening");
    if (listening.kind !== "listening") return;
    expect(orch.endpoint()).toContain("127.0.0.1");
    orch.close();
    expect(orch.status()).toEqual({ kind: "stopped" });
    expect(orch.endpoint()).toBe("");
  });

  it("cerrar dos veces no lanza", async () => {
    const orch = startShimOrchestrator(orchDeps, { preferredPort: 0, retryMs: 0 });
    orch.close();
    expect(() => orch.close()).not.toThrow();
  });
});

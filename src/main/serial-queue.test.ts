import { describe, expect, it } from "vitest";

import { createSerialQueue } from "./serial-queue";

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("createSerialQueue", () => {
  it("nunca solapa dos operaciones", async () => {
    // El bug original: dos vpnConnect a la vez, el segundo pisaba al primero
    // y dejaba un openvpn huérfano aferrado al TAP.
    const run = createSerialQueue();
    let active = 0;
    let maxActive = 0;

    const task = async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      await wait(10);
      active--;
    };

    await Promise.all([run(task), run(task), run(task)]);
    expect(maxActive).toBe(1);
  });

  it("respeta el orden de llegada", async () => {
    const run = createSerialQueue();
    const order: number[] = [];
    await Promise.all(
      [1, 2, 3].map((n) =>
        run(async () => {
          await wait(n === 1 ? 20 : 1);
          order.push(n);
        }),
      ),
    );
    expect(order).toEqual([1, 2, 3]);
  });

  it("un fallo no bloquea la cola", async () => {
    // Si un error dejara la cadena rota, la VPN quedaría imposible de
    // conectar hasta reiniciar la app.
    const run = createSerialQueue();
    await expect(run(async () => { throw new Error("boom"); })).rejects.toThrow("boom");
    await expect(run(async () => "ok")).resolves.toBe("ok");
  });

  it("propaga el valor devuelto", async () => {
    const run = createSerialQueue();
    await expect(run(async () => 42)).resolves.toBe(42);
  });

  it("una operación lenta que falla no adelanta a la siguiente", async () => {
    const run = createSerialQueue();
    const order: string[] = [];
    const slow = run(async () => {
      await wait(20);
      order.push("slow");
      throw new Error("late failure");
    });
    const next = run(async () => {
      order.push("next");
    });
    await slow.catch(() => undefined);
    await next;
    expect(order).toEqual(["slow", "next"]);
  });
});

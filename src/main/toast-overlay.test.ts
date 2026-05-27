import { describe, it, expect, beforeEach, vi } from "vitest";

vi.mock("electron", () => ({
  app: {},
  BrowserWindow: class {},
  ipcMain: { on: vi.fn() },
  nativeTheme: { on: vi.fn(), shouldUseDarkColors: false },
  screen: { getPrimaryDisplay: () => ({ workArea: { x: 0, y: 0, width: 1, height: 1 } }) },
}));

vi.mock("./preferences-manager", () => ({
  getPreferences: () => ({ theme: "light" as const }),
}));

vi.mock("./ipc-handlers", () => ({
  markWebContentsTrusted: vi.fn(),
  unmarkWebContentsTrusted: vi.fn(),
}));

import { onToastAction, __test } from "./toast-overlay";

beforeEach(() => {
  __test.clearActionHandlers();
});

describe("onToastAction", () => {
  it("registers a handler that the returned unsubscribe can remove", () => {
    const handler = vi.fn();
    const off = onToastAction("test:channel", handler);
    expect(__test.hasActionHandler("test:channel")).toBe(true);
    off();
    expect(__test.hasActionHandler("test:channel")).toBe(false);
  });

  it("without ttlMs, the handler stays registered until the user clicks", () => {
    vi.useFakeTimers();
    const handler = vi.fn();
    onToastAction("test:no-ttl", handler);
    vi.advanceTimersByTime(60_000);
    expect(__test.hasActionHandler("test:no-ttl")).toBe(true);
    vi.useRealTimers();
  });

  it("with ttlMs, the handler auto-cleans when the dwell window passes", () => {
    vi.useFakeTimers();
    const handler = vi.fn();
    onToastAction("test:ttl", handler, { ttlMs: 100 });
    expect(__test.hasActionHandler("test:ttl")).toBe(true);
    vi.advanceTimersByTime(99);
    expect(__test.hasActionHandler("test:ttl")).toBe(true);
    vi.advanceTimersByTime(2);
    expect(__test.hasActionHandler("test:ttl")).toBe(false);
    vi.useRealTimers();
  });

  it("re-registering on the same channel replaces the prior handler", () => {
    const first = vi.fn();
    const second = vi.fn();
    const offFirst = onToastAction("test:replace", first);
    onToastAction("test:replace", second);
    expect(__test.actionHandlerCount()).toBe(1);
    // offFirst is now stale (handler is `second`); it MUST NOT delete the
    // replacement registration.
    offFirst();
    expect(__test.hasActionHandler("test:replace")).toBe(true);
  });

  it("ttl cleanup is idempotent — manual off after ttl is a no-op", () => {
    vi.useFakeTimers();
    const handler = vi.fn();
    const off = onToastAction("test:both", handler, { ttlMs: 50 });
    vi.advanceTimersByTime(60);
    expect(__test.hasActionHandler("test:both")).toBe(false);
    expect(() => off()).not.toThrow();
    vi.useRealTimers();
  });
});

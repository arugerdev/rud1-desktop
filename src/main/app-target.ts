// Resolves the dashboard URL/origin the app loads, in priority order:
//   1. RUD1_APP_URL / RUD1_APP_ORIGIN env (dev `electron .` runs)
//   2. baked build metadata rud1AppUrl / rud1AppOrigin (electron-builder
//      --config.extraMetadata.* — used ONLY by manual test builds, never prod)
//   3. production default https://www.rud1.es
//
// Side effects at import time (must run before ipc-handlers reads
// RUD1_APP_ORIGIN and before app is ready):
//   • pins RUD1_APP_ORIGIN so the IPC sender allowlist accepts the target
//   • marks an http:// origin as a secure context so WebCrypto (crypto.subtle)
//     works when loading a local develop server over plain HTTP.
import { app } from "electron";
import path from "path";

const PROD_URL = "https://www.rud1.es/dashboard";

function bakedMetadata(): { url?: string; origin?: string } {
  try {
    const pkg = require(path.join(app.getAppPath(), "package.json"));
    return {
      url: typeof pkg.rud1AppUrl === "string" ? pkg.rud1AppUrl : undefined,
      origin: typeof pkg.rud1AppOrigin === "string" ? pkg.rud1AppOrigin : undefined,
    };
  } catch {
    return {};
  }
}

const baked = bakedMetadata();
export const APP_URL = process.env.RUD1_APP_URL ?? baked.url ?? PROD_URL;

const resolvedOrigin =
  process.env.RUD1_APP_ORIGIN ??
  baked.origin ??
  (() => {
    try {
      return new URL(APP_URL).origin;
    } catch {
      return undefined;
    }
  })();

if (resolvedOrigin && !process.env.RUD1_APP_ORIGIN) {
  process.env.RUD1_APP_ORIGIN = resolvedOrigin;
}

// http:// LAN origins are not secure contexts, so crypto.subtle is undefined.
// Explicitly trust the resolved origin so WebCrypto-backed features work.
try {
  if (resolvedOrigin && resolvedOrigin.startsWith("http://")) {
    app.commandLine.appendSwitch(
      "unsafely-treat-insecure-origin-as-secure",
      resolvedOrigin,
    );
  }
} catch {
  /* commandLine unavailable — ignore */
}

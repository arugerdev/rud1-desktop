// Traduce un deep link `rud1://` a la URL del dashboard que la ventana debe
// cargar. El caso principal —conectar un dispositivo de un clic desde fuera de
// la app— resuelve a la página del dispositivo con `?autoconnect=1`, que hace
// que el panel cloud dispare el flujo VPN + bind automático.
//
// Formatos soportados:
//   rud1://connect?device=<id>        → /dashboard/devices/<id>/connect?autoconnect=1
//   rud1://connect/<id>               → idem
// Cualquier otro deep link cae al comportamiento antiguo: cargar la app con el
// deeplink crudo como query para que el cliente lo interprete.

function originOf(appUrl: string): string | null {
  try {
    return new URL(appUrl).origin;
  } catch {
    return null;
  }
}

function fallback(appUrl: string, deeplink: string): string {
  return `${appUrl}?deeplink=${encodeURIComponent(deeplink)}`;
}

export function resolveDeepLinkTarget(deeplink: string, appUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(deeplink);
  } catch {
    return fallback(appUrl, deeplink);
  }

  if (parsed.protocol !== "rud1:") return fallback(appUrl, deeplink);

  // host puede ser "connect" (rud1://connect?...) o el primer segmento del path.
  const action = parsed.host || parsed.pathname.replace(/^\/+/, "").split("/")[0];
  if (action !== "connect") return fallback(appUrl, deeplink);

  // device viene por query (?device=<id>) o como segmento (rud1://connect/<id>).
  const fromQuery = parsed.searchParams.get("device");
  const fromPath = parsed.host
    ? parsed.pathname.replace(/^\/+/, "")
    : parsed.pathname.replace(/^\/+/, "").split("/").slice(1).join("/");
  const deviceId = (fromQuery ?? fromPath ?? "").trim();
  if (!deviceId) return fallback(appUrl, deeplink);

  const origin = originOf(appUrl);
  if (!origin) return fallback(appUrl, deeplink);

  return `${origin}/dashboard/devices/${encodeURIComponent(deviceId)}/connect?autoconnect=1`;
}

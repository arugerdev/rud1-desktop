/**
 * Cached `.ovpn` configuration store.
 *
 * The rud1-es backend issues per-user .ovpn bundles signed by the rud1
 * CA (cert + private key + ca-bundle inlined). The desktop fetches the
 * latest blob via `GET /api/users/me/ovpn-config` (cookie auth) and
 * caches it under `%APPDATA%/rud1-desktop/ovpn/rud1-client.ovpn` so the
 * tunnel can be re-armed without a round-trip on app restart.
 *
 * Security:
 *   • The cached file embeds the user's private key in PEM form. We
 *     write with mode 0o600 on Unix; on Windows we rely on the per-user
 *     APPDATA ACL (the OS's default user-data ACL grants only the user
 *     and SYSTEM read access — same model the WG manager used).
 *   • Atomic writes (tmp file + rename) so a crash mid-write never
 *     leaves a partial PEM that the openvpn child would treat as
 *     corrupt and refuse to connect with.
 *
 * Cert rotation:
 *   • The blob carries an expiry hint as a PEM `notAfter` field; we
 *     don't parse it here (keeps the store dependency-free). The
 *     renderer is responsible for asking the backend "is my cert still
 *     fresh?" on every connect attempt and overwriting the cache when
 *     a rotation lands.
 */

import fs from "fs/promises";
import path from "path";
import { app } from "electron";

const CACHE_FILENAME = "rud1-client.ovpn";
const CACHE_SUBDIR = "ovpn";

/** Resolves the absolute on-disk path for the cached config. */
export function defaultOvpnConfigPath(): string {
  return path.join(app.getPath("userData"), CACHE_SUBDIR, CACHE_FILENAME);
}

/**
 * Persist the supplied `.ovpn` blob to the cache path, creating the
 * directory if needed and using a tmp+rename write for atomicity.
 * Returns the absolute path the openvpn child should load.
 */
export async function writeOvpnConfig(content: string): Promise<string> {
  if (typeof content !== "string" || content.length === 0) {
    throw new Error("invalid .ovpn content");
  }
  const target = defaultOvpnConfigPath();
  await fs.mkdir(path.dirname(target), { recursive: true });
  const tmp = target + ".tmp";
  // 0o600 is honoured on Unix; on Windows the umask doesn't apply but
  // the APPDATA ACL already keeps other users out.
  await fs.writeFile(tmp, content, { encoding: "utf8", mode: 0o600 });
  await fs.rename(tmp, target);
  return target;
}

/**
 * Read the cached `.ovpn` content if one was previously written.
 * Returns null on missing / unreadable file so the caller can fall
 * back to re-fetching from the cloud.
 */
export async function readOvpnConfig(): Promise<string | null> {
  try {
    const buf = await fs.readFile(defaultOvpnConfigPath(), "utf8");
    return buf.length > 0 ? buf : null;
  } catch {
    return null;
  }
}

/**
 * Drop the cached config. Used by the explicit "Sign out" flow so a
 * stolen laptop can't keep the prior user's VPN cert sitting on disk.
 * Best-effort: missing file is a silent success.
 */
export async function deleteOvpnConfig(): Promise<void> {
  try {
    await fs.unlink(defaultOvpnConfigPath());
  } catch {
    /* missing → nothing to do */
  }
}

// 30d TTL + 50-entry FIFO cap; falling-edge drops para que reflash re-notifique.
import { promises as fsp } from "fs";
import * as path from "path";

export interface NotifiedHost {
  host: string;
  notifiedAt: string; // ISO 8601
}

export interface PersistedDedupeFile {
  version: 1;
  notifiedHosts: NotifiedHost[];
}

export const DEDUPE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const DEDUPE_CAP = 50;
export const DEDUPE_FILENAME = "first-boot-notifications.json";

export function pruneExpiredHosts(
  hosts: readonly NotifiedHost[],
  now: Date,
  ttlMs: number = DEDUPE_TTL_MS,
): NotifiedHost[] {
  const cutoff = now.getTime() - ttlMs;
  return hosts.filter((h) => {
    const t = Date.parse(h.notifiedAt);
    if (Number.isNaN(t)) return false;
    return t >= cutoff;
  });
}

export function enforceCap(
  hosts: readonly NotifiedHost[],
  cap: number = DEDUPE_CAP,
): NotifiedHost[] {
  if (hosts.length <= cap) return [...hosts];
  // Asc por notifiedAt; NaN sorts oldest → evicted first.
  const sorted = [...hosts].sort((a, b) => {
    const ta = Date.parse(a.notifiedAt);
    const tb = Date.parse(b.notifiedAt);
    const av = Number.isNaN(ta) ? -Infinity : ta;
    const bv = Number.isNaN(tb) ? -Infinity : tb;
    return av - bv;
  });
  return sorted.slice(sorted.length - cap);
}

export function addHost(
  hosts: readonly NotifiedHost[],
  host: string,
  now: Date,
): NotifiedHost[] {
  const without = hosts.filter((h) => h.host !== host);
  without.push({ host, notifiedAt: now.toISOString() });
  return enforceCap(without);
}

export function removeHost(
  hosts: readonly NotifiedHost[],
  host: string,
): NotifiedHost[] {
  return hosts.filter((h) => h.host !== host);
}

function sanitize(parsed: unknown): NotifiedHost[] {
  if (!parsed || typeof parsed !== "object") return [];
  const obj = parsed as Record<string, unknown>;
  if (obj.version !== 1) return [];
  if (!Array.isArray(obj.notifiedHosts)) return [];
  const out: NotifiedHost[] = [];
  for (const item of obj.notifiedHosts) {
    if (!item || typeof item !== "object") continue;
    const e = item as Record<string, unknown>;
    if (typeof e.host !== "string" || typeof e.notifiedAt !== "string") continue;
    if (e.host.length === 0) continue;
    out.push({ host: e.host, notifiedAt: e.notifiedAt });
  }
  return out;
}

export async function loadNotifiedHosts(
  filepath: string,
  now: Date,
  ttlMs: number = DEDUPE_TTL_MS,
): Promise<NotifiedHost[]> {
  let raw: string;
  try {
    raw = await fsp.readFile(filepath, "utf8");
  } catch (err: unknown) {
    const e = err as NodeJS.ErrnoException;
    if (e?.code !== "ENOENT") {
      console.warn(
        `[first-boot-dedupe] read failed (${e?.code ?? "unknown"}): ${e?.message ?? err}`,
      );
    }
    return [];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    console.warn(
      `[first-boot-dedupe] parse failed: ${err instanceof Error ? err.message : err}`,
    );
    return [];
  }
  return pruneExpiredHosts(sanitize(parsed), now, ttlMs);
}

// Atomic write via tmp+rename evita ficheros truncados en process kill.
export async function saveNotifiedHosts(
  filepath: string,
  hosts: readonly NotifiedHost[],
): Promise<void> {
  const payload: PersistedDedupeFile = {
    version: 1,
    notifiedHosts: enforceCap([...hosts]),
  };
  const body = JSON.stringify(payload, null, 2) + "\n";
  const tmp = `${filepath}.tmp`;
  try {
    await fsp.mkdir(path.dirname(filepath), { recursive: true });
    await fsp.writeFile(tmp, body, "utf8");
    await fsp.rename(tmp, filepath);
  } catch (err) {
    console.warn(
      `[first-boot-dedupe] write failed: ${err instanceof Error ? err.message : err}`,
    );
    try {
      await fsp.unlink(tmp);
    } catch {
      /* ignore */
    }
  }
}

export function isHostNotified(
  hosts: readonly NotifiedHost[],
  host: string,
  now: Date,
  ttlMs: number = DEDUPE_TTL_MS,
): boolean {
  const cutoff = now.getTime() - ttlMs;
  for (const h of hosts) {
    if (h.host !== host) continue;
    const t = Date.parse(h.notifiedAt);
    if (Number.isNaN(t)) continue;
    if (t >= cutoff) return true;
  }
  return false;
}

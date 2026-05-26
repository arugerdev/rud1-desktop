/**
 * Preload script for the Liquid Glass toast overlay window.
 *
 * The overlay's HTML data: URL runs in an isolated renderer with
 * sandbox + contextIsolation, so it can't reach `ipcRenderer` directly.
 * This bridge exposes the narrow surface the overlay actually needs:
 *
 *   inbound (main → renderer):
 *     onPush(cb)     — new toast to add to the stack
 *     onDismiss(cb)  — request a specific toast be removed
 *     onTheme(cb)    — theme changed; re-skin the document
 *
 *   outbound (renderer → main):
 *     setHovering(b)        — gate the main process's click-through
 *     userDismiss(id)       — operator clicked the X
 *     fireAction(id, ch)    — operator clicked a CTA button
 *     notifyEmpty()         — stack drained; main can hide the window
 *
 * Channel names are mirrored on the main process side in
 * `src/main/toast-overlay.ts`. Keep them in sync.
 */

import { contextBridge, ipcRenderer } from "electron";

type ToastDescriptor = {
  id: string;
  kind: "info" | "success" | "warning" | "error";
  title: string;
  body: string;
  autoDismissMs?: number;
  action?: { label: string; channel: string };
};

contextBridge.exposeInMainWorld("rud1Bridge", {
  onPush: (cb: (t: ToastDescriptor) => void) =>
    ipcRenderer.on("toast:push", (_e, t: ToastDescriptor) => cb(t)),
  onDismiss: (cb: (id: string) => void) =>
    ipcRenderer.on("toast:dismiss", (_e, payload: { id: string }) => cb(payload?.id)),
  onTheme: (cb: (theme: "light" | "dark") => void) =>
    ipcRenderer.on("toast:theme", (_e, theme: "light" | "dark") => cb(theme)),

  setHovering: (hovering: boolean) =>
    ipcRenderer.send("toast:hover", { hovering: !!hovering }),
  userDismiss: (id: string) =>
    ipcRenderer.send("toast:user-dismiss", { id }),
  fireAction: (id: string, channel: string) =>
    ipcRenderer.send("toast:action", { id, channel }),
  notifyEmpty: () => ipcRenderer.send("toast:empty"),
});

/**
 * Wake word de RIA: sirve al renderer el modelo Vosk español empaquetado
 * (resources/models/vosk-es-small.tar.gz, ver scripts/fetch-vosk-model.mjs).
 * El reconocimiento corre entero en el renderer (vosk-browser, WASM): aquí
 * solo se leen los bytes. Sin modelo, el panel degrada solo (sin wake word).
 */

import path from "path";
import fs from "fs";
import { app, ipcMain } from "electron";

const MODEL_FILE = "vosk-es-small.tar.gz";

export function wakeModelPath(): string {
  const base = app.isPackaged
    ? path.join(process.resourcesPath, "models")
    : path.join(app.getAppPath(), "resources", "models");
  return path.join(base, MODEL_FILE);
}

export function registerWakeModelHandlers(): void {
  ipcMain.handle("wake:available", () => {
    try {
      return fs.existsSync(wakeModelPath());
    } catch {
      return false;
    }
  });

  // ~40 MB una única vez por sesión de renderer; el panel lo cachea.
  ipcMain.handle("wake:get-model", async () => {
    try {
      return await fs.promises.readFile(wakeModelPath());
    } catch {
      return null;
    }
  });
}

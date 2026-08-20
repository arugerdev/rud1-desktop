// Descarga el modelo Vosk español pequeño (wake word de RIA) y lo deja como
// resources/models/vosk-es-small.tar.gz (formato que exige vosk-browser).
// Idempotente; corre en Windows/Linux/macOS (CI incluido). Node >= 18.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODEL_URL = "https://alphacephei.com/vosk/models/vosk-model-small-es-0.42.zip";
const MODEL_DIR_NAME = "vosk-model-small-es-0.42";
// SHA-256 del zip oficial; si upstream lo rebasea, el build lo canta aquí.
const EXPECTED_SHA256 = "09b239888f633ef2f0b4e09736e3d9936acfd810bc65d53fad45261762c6511f";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(repoRoot, "resources", "models");
const outFile = path.join(outDir, "vosk-es-small.tar.gz");

if (fs.existsSync(outFile) && fs.statSync(outFile).size > 20_000_000) {
  console.log(`OK  modelo ya presente: ${outFile}`);
  process.exit(0);
}

fs.mkdirSync(outDir, { recursive: true });
const work = fs.mkdtempSync(path.join(os.tmpdir(), "vosk-model-"));
const zipPath = path.join(work, "model.zip");

console.log(`==> Descargando ${MODEL_URL}`);
const res = await fetch(MODEL_URL);
if (!res.ok) throw new Error(`descarga fallida: HTTP ${res.status}`);
const bytes = Buffer.from(await res.arrayBuffer());
fs.writeFileSync(zipPath, bytes);
console.log(`OK  ${(bytes.length / 1e6).toFixed(1)} MB`);

const sha = createHash("sha256").update(bytes).digest("hex");
if (EXPECTED_SHA256 && sha !== EXPECTED_SHA256) {
  throw new Error(`SHA-256 inesperado del zip del modelo:\n  esperado ${EXPECTED_SHA256}\n  obtenido ${sha}`);
}
console.log(`OK  sha256 ${sha}`);

// Extraer: bsdtar (Windows/macOS) abre zips; en Linux, unzip.
console.log("==> Extrayendo");
if (process.platform === "linux") {
  execFileSync("unzip", ["-q", zipPath, "-d", work], { stdio: "inherit" });
} else {
  execFileSync("tar", ["-xf", zipPath, "-C", work], { stdio: "inherit" });
}
const modelDir = path.join(work, MODEL_DIR_NAME);
if (!fs.existsSync(modelDir)) throw new Error(`el zip no contiene ${MODEL_DIR_NAME}`);

// Reempaquetar como .tar.gz (lo que vosk-browser sabe cargar).
console.log("==> Empaquetando tar.gz");
execFileSync("tar", ["-czf", outFile, "-C", work, MODEL_DIR_NAME], { stdio: "inherit" });
console.log(`OK  ${outFile} (${(fs.statSync(outFile).size / 1e6).toFixed(1)} MB)`);

fs.rmSync(work, { recursive: true, force: true });

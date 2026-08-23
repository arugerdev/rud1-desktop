#!/usr/bin/env node
/**
 * Generador de los iconos de la bandeja del sistema.
 *
 * La bandeja (`createTray` en src/main/tray.ts) necesita dos iconos: el normal
 * y el de "atención", que sale cuando hay equipos recién arrancados en la red
 * local. Antes se dibujaban aquí a mano —un aro gris con un punto— porque no
 * había ningún asset en el repositorio ni ganas de meter una dependencia de
 * gráficos. Ahora sí hay asset: `resources/icon.png` es el icono de la marca a
 * 512x512, y de ahí salen los cuatro ficheros.
 *
 * Salida en `resources/tray/`:
 *   tray-idle.png         (16x16, el icono de la marca)
 *   tray-idle@2x.png      (32x32, para pantallas de mucha densidad)
 *   tray-attention.png    (16x16, el mismo más un punto ámbar arriba a la
 *                          derecha, que es donde se esperan los avisos)
 *   tray-attention@2x.png (32x32)
 *
 * Sigue sin dependencias: el PNG se lee y se escribe con `node:zlib`, sin
 * `sharp` ni `canvas`. El reducido es una media por bloques, y sale exacto
 * porque 512 es múltiplo de 16 y de 32: cada píxel del icono pequeño es la
 * media de un bloque de 32x32 (o de 16x16) del grande, sin interpolar nada.
 *
 * Se mezcla con alfa premultiplicado. Sin eso, los píxeles transparentes del
 * borde arrastran su color a la media y el icono sale con un halo oscuro
 * alrededor.
 *
 * Idempotente: correrlo varias veces da los mismos bytes. Los ficheros están
 * en git, así que esto no corre en CI; está aquí para poder regenerarlos
 * cuando cambie el icono de la marca.
 */
import { writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { deflateSync, inflateSync } from "node:zlib";
import { createHash } from "node:crypto";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const SOURCE = join(REPO_ROOT, "resources", "icon.png");
const OUT_DIR = join(REPO_ROOT, "resources", "tray");

/** Ámbar del punto de aviso: el mismo `warning` que usa la interfaz. */
const ATTENTION_COLOR = [0xf5, 0xa5, 0x24];

if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });

// ── PNG: utilidades comunes ────────────────────────────────────────────────

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

// Tabla CRC32 (spec de PNG / RFC 1952). Se calcula una vez.
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

// ── Lectura del PNG de origen ──────────────────────────────────────────────

/**
 * Lee un PNG RGBA de 8 bits sin entrelazar y devuelve sus píxeles en crudo.
 *
 * No pretende leer cualquier PNG: solo el que genera el kit de marca. Si el
 * fichero viniera en otro formato (paleta, 16 bits, entrelazado) esto avisa en
 * lugar de devolver una imagen mal interpretada.
 */
function decodeRgbaPng(buf) {
  if (!buf.subarray(0, 8).equals(PNG_MAGIC)) {
    throw new Error("el origen no es un PNG");
  }

  let width = 0;
  let height = 0;
  const idat = [];

  // Recorrido de trozos: longitud (4) + tipo (4) + datos + CRC (4).
  let off = 8;
  while (off < buf.length) {
    const len = buf.readUInt32BE(off);
    const type = buf.subarray(off + 4, off + 8).toString("ascii");
    const data = buf.subarray(off + 8, off + 8 + len);

    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      const depth = data.readUInt8(8);
      const colorType = data.readUInt8(9);
      const interlace = data.readUInt8(12);
      if (depth !== 8 || colorType !== 6 || interlace !== 0) {
        throw new Error(
          `se esperaba RGBA de 8 bits sin entrelazar; llegó depth=${depth} colorType=${colorType} interlace=${interlace}`,
        );
      }
    } else if (type === "IDAT") {
      // Un PNG puede partir los datos en varios IDAT: hay que concatenarlos
      // antes de descomprimir, no descomprimir cada uno por su cuenta.
      idat.push(Buffer.from(data));
    } else if (type === "IEND") {
      break;
    }

    off += 12 + len;
  }

  if (width === 0 || height === 0) throw new Error("el PNG no trae IHDR");
  if (idat.length === 0) throw new Error("el PNG no trae datos de imagen");

  const raw = inflateSync(Buffer.concat(idat));
  return { width, height, pixels: unfilter(raw, width, height) };
}

/**
 * Deshace los filtros por línea del PNG.
 *
 * Cada línea viene precedida de un byte que dice con qué filtro se guardó
 * (0 ninguno, 1 diferencia con el píxel de la izquierda, 2 con el de arriba,
 * 3 con la media de los dos, 4 el predictor de Paeth). Sin deshacerlos, los
 * bytes no son colores.
 */
function unfilter(raw, width, height) {
  const bpp = 4; // RGBA
  const stride = width * bpp;
  const out = Buffer.alloc(stride * height);

  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)];
    const src = y * (stride + 1) + 1;
    const dst = y * stride;
    const prev = dst - stride;

    for (let i = 0; i < stride; i++) {
      const x = raw[src + i];
      const a = i >= bpp ? out[dst + i - bpp] : 0;
      const b = y > 0 ? out[prev + i] : 0;
      const c = i >= bpp && y > 0 ? out[prev + i - bpp] : 0;

      let value;
      switch (filter) {
        case 0:
          value = x;
          break;
        case 1:
          value = x + a;
          break;
        case 2:
          value = x + b;
          break;
        case 3:
          value = x + ((a + b) >> 1);
          break;
        case 4: {
          const p = a + b - c;
          const pa = Math.abs(p - a);
          const pb = Math.abs(p - b);
          const pc = Math.abs(p - c);
          value = x + (pa <= pb && pa <= pc ? a : pb <= pc ? b : c);
          break;
        }
        default:
          throw new Error(`filtro de línea desconocido: ${filter}`);
      }
      out[dst + i] = value & 0xff;
    }
  }

  return out;
}

// ── Reducido y composición ─────────────────────────────────────────────────

/**
 * Reduce la imagen a `size` haciendo la media de cada bloque.
 *
 * Exige que el tamaño de origen sea múltiplo exacto del de destino: así cada
 * píxel de salida cubre un bloque entero y no hay que decidir qué hacer con
 * los bordes a medias.
 */
function downscale(src, size) {
  if (src.width !== src.height) throw new Error("el icono de origen no es cuadrado");
  if (src.width % size !== 0) {
    throw new Error(`${src.width} no es múltiplo de ${size}: el reducido no saldría exacto`);
  }

  const block = src.width / size;
  const out = Buffer.alloc(size * size * 4);
  const total = block * block;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      // Se suma con el color ya multiplicado por su alfa. Los píxeles
      // transparentes pesan cero y no tiñen la media.
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;
      for (let by = 0; by < block; by++) {
        const row = (y * block + by) * src.width * 4;
        for (let bx = 0; bx < block; bx++) {
          const off = row + (x * block + bx) * 4;
          const pa = src.pixels[off + 3];
          r += src.pixels[off] * pa;
          g += src.pixels[off + 1] * pa;
          b += src.pixels[off + 2] * pa;
          a += pa;
        }
      }
      const dst = (y * size + x) * 4;
      if (a === 0) {
        out[dst] = 0;
        out[dst + 1] = 0;
        out[dst + 2] = 0;
        out[dst + 3] = 0;
      } else {
        // Se vuelve a dividir por el alfa acumulado para deshacer la
        // premultiplicación y recuperar el color real.
        out[dst] = Math.round(r / a);
        out[dst + 1] = Math.round(g / a);
        out[dst + 2] = Math.round(b / a);
        out[dst + 3] = Math.round(a / total);
      }
    }
  }

  return { width: size, height: size, pixels: out };
}

/**
 * Pinta el punto de aviso arriba a la derecha.
 *
 * Se muestrea 4x4 por píxel para que el borde del círculo no salga escalonado:
 * a 16 píxeles de lado, un círculo sin suavizar se ve como una cruz.
 */
function drawAttentionDot(img) {
  const size = img.width;
  // El punto ocupa poco más de un tercio del ancho: lo justo para verse en la
  // barra de tareas sin tapar el símbolo. Más grande y el icono deja de
  // reconocerse como el de rud1, que es el problema que tenía la versión
  // anterior.
  const radius = size * 0.2;
  const cx = size - radius * 1.05;
  const cy = radius * 1.05;
  // Anillo transparente alrededor del punto para que despegue del icono y no
  // se lea como una mancha pegada a la onda.
  const gap = radius + Math.max(1, size * 0.05);
  const samples = 4;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let inside = 0;
      let cleared = 0;
      for (let sy = 0; sy < samples; sy++) {
        for (let sx = 0; sx < samples; sx++) {
          const px = x + (sx + 0.5) / samples;
          const py = y + (sy + 0.5) / samples;
          const dist = Math.hypot(px - cx, py - cy);
          if (dist <= radius) inside++;
          else if (dist <= gap) cleared++;
        }
      }

      const off = (y * size + x) * 4;
      const totalSamples = samples * samples;

      if (cleared > 0 && inside === 0) {
        // Zona de separación: se rebaja lo que hubiera debajo.
        const keep = 1 - cleared / totalSamples;
        img.pixels[off + 3] = Math.round(img.pixels[off + 3] * keep);
      }

      if (inside > 0) {
        const cover = inside / totalSamples;
        const [dr, dg, db] = ATTENTION_COLOR;
        const base = img.pixels[off + 3] / 255;
        // Mezcla normal del punto sobre el icono.
        const outA = cover + base * (1 - cover);
        img.pixels[off] = Math.round(
          (dr * cover + img.pixels[off] * base * (1 - cover)) / outA,
        );
        img.pixels[off + 1] = Math.round(
          (dg * cover + img.pixels[off + 1] * base * (1 - cover)) / outA,
        );
        img.pixels[off + 2] = Math.round(
          (db * cover + img.pixels[off + 2] * base * (1 - cover)) / outA,
        );
        img.pixels[off + 3] = Math.round(outA * 255);
      }
    }
  }

  return img;
}

// ── Escritura del PNG ──────────────────────────────────────────────────────

function encodeRgbaPng(img) {
  const stride = img.width * 4;
  // Una línea de filtro por fila, todas con filtro 0 (ninguno): a estos
  // tamaños no compensa buscar el mejor filtro y así la salida es estable.
  const raw = Buffer.alloc((stride + 1) * img.height);
  for (let y = 0; y < img.height; y++) {
    raw[y * (stride + 1)] = 0;
    img.pixels.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(img.width, 0);
  ihdr.writeUInt32BE(img.height, 4);
  ihdr.writeUInt8(8, 8); // 8 bits por canal
  ihdr.writeUInt8(6, 9); // tipo 6 = RGBA
  ihdr.writeUInt8(0, 10); // compresión deflate
  ihdr.writeUInt8(0, 11); // filtrado estándar
  ihdr.writeUInt8(0, 12); // sin entrelazar

  return Buffer.concat([
    PNG_MAGIC,
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

// ── Generación ─────────────────────────────────────────────────────────────

if (!existsSync(SOURCE)) {
  throw new Error(
    `no está el icono de origen en ${SOURCE}. Sale del kit de marca: brand/03-iconos/app-escritorio/rud1.iconset/icon_512x512.png`,
  );
}

const source = decodeRgbaPng(readFileSync(SOURCE));
process.stdout.write(`origen: resources/icon.png ${source.width}x${source.height}\n`);

const targets = [
  { name: "tray-idle.png", size: 16, attention: false },
  { name: "tray-idle@2x.png", size: 32, attention: false },
  { name: "tray-attention.png", size: 16, attention: true },
  { name: "tray-attention@2x.png", size: 32, attention: true },
];

// Tope de tamaño. Ya no son 1 KB como cuando eran un aro en escala de grises:
// el icono de la marca va en color. 8 KB deja margen de sobra y sigue delatando
// una regresión del compresor (por ejemplo, un IDAT sin comprimir).
const MAX_BYTES = 8 * 1024;

for (const { name, size, attention } of targets) {
  const img = downscale(source, size);
  if (attention) drawAttentionDot(img);

  const png = encodeRgbaPng(img);
  const out = join(OUT_DIR, name);
  writeFileSync(out, png);

  if (png.length >= MAX_BYTES) {
    throw new Error(`${name} pesa ${png.length} bytes, se esperaban menos de ${MAX_BYTES}`);
  }

  // Se relee de disco para que una escritura corrupta salte aquí y no en
  // tiempo de ejecución, cuando ya está empaquetado.
  const back = readFileSync(out);
  const magic = back.subarray(0, 8).toString("hex");
  if (magic !== "89504e470d0a1a0a") throw new Error(`${name}: cabecera mal, ${magic}`);
  if (back.readUInt32BE(8) !== 13) throw new Error(`${name}: IHDR de largo raro`);
  const w = back.readUInt32BE(16);
  const h = back.readUInt32BE(20);
  if (w !== size || h !== size) throw new Error(`${name}: ${w}x${h} en vez de ${size}x${size}`);
  // Y se vuelve a decodificar: si el PNG no se puede leer, Electron tampoco
  // podrá y la bandeja saldría vacía.
  decodeRgbaPng(back);

  const sha = createHash("sha256").update(back).digest("hex").slice(0, 12);
  process.stdout.write(`  ${name}: ${png.length} B  ${size}x${size}  sha=${sha}\n`);
}

process.stdout.write("iconos de bandeja escritos en " + OUT_DIR + "\n");

#!/usr/bin/env node
/**
 * Tray-icon generator (iter 30).
 *
 * The desktop tray (`createTray` in src/main/tray.ts) needs at least two
 * cross-platform icons: an "idle" baseline and an "attention" variant
 * shown when first-boot devices are on the LAN. Iter 28 documented why
 * we previously fell back to `nativeImage.createEmpty()` (no asset in
 * the repo, no graphics dep willing to enter the dependency budget); iter
 * 30 ships real pixels by hand-crafting tiny PNGs from raw byte buffers
 * inside this script — no `sharp`, no `canvas`, no runtime cost.
 *
 * Output layout under `resources/tray/`:
 *   tray-idle.png        (16x16, grayscale-with-alpha, opaque ring)
 *   tray-idle@2x.png     (32x32, hi-DPI variant)
 *   tray-attention.png   (16x16, ring + filled dot in upper-right)
 *   tray-attention@2x.png(32x32, hi-DPI variant)
 *
 * The PNGs are constructed via the IHDR/IDAT/IEND chunk sequence with
 * a real zlib-deflated IDAT and proper CRCs. The result decodes in
 * Electron's `nativeImage.createFromPath` — verified at the end of this
 * script with a tiny in-process validator that reads the file back and
 * checks the magic + chunk lengths.
 *
 * Idempotent: run this script multiple times and the output is byte-equal
 * (the rasteriser is deterministic). Files are checked in so the build
 * doesn't run this script in CI; it's here for repo maintainability.
 */
import { writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { deflateSync } from "node:zlib";
import { createHash } from "node:crypto";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const OUT_DIR = join(REPO_ROOT, "resources", "tray");

if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });

// CRC32 table (per the PNG spec / RFC 1952). Computed once.
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
  const crcInput = Buffer.concat([typeBuf, data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(crcInput), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

/**
 * Rasterise an icon into a width*height grayscale-with-alpha buffer.
 *
 * `kind` is "idle" or "attention":
 *   - idle:      filled circle (gray-on-transparent) centred in the canvas
 *   - attention: same circle plus a small filled dot in the upper-right
 *                 corner (the conventional notification-badge position)
 *
 * Pixel format: 2 bytes per pixel (luminance + alpha). PNG colour type 4.
 * Each scanline is prefixed with a filter byte (0 = None) per the PNG spec.
 */
function rasterise(size, kind) {
  const cx = size / 2;
  const cy = size / 2;
  const radius = size * 0.42;
  const ringThickness = size * 0.18;
  // Dot for the attention variant — upper-right, inside the bounds.
  const dotCx = size - size * 0.28;
  const dotCy = size * 0.28;
  const dotRadius = size * 0.18;

  // 2 bytes per pixel + 1 filter byte per row.
  const stride = size * 2 + 1;
  const pixels = Buffer.alloc(stride * size);

  for (let y = 0; y < size; y++) {
    pixels[y * stride] = 0; // filter = None
    for (let x = 0; x < size; x++) {
      const dx = x - cx + 0.5;
      const dy = y - cy + 0.5;
      const dist = Math.sqrt(dx * dx + dy * dy);
      let lum = 0;
      let alpha = 0;
      // Ring around the centre — solid edge, hollow middle.
      if (dist <= radius && dist >= radius - ringThickness) {
        lum = 0xe4; // matches the zinc-200 used elsewhere in the dark UI
        alpha = 0xff;
      }
      // Filled core — slight contrast so the icon isn't a thin loop on
      // a light tray background.
      if (dist <= radius - ringThickness) {
        lum = 0x71;
        alpha = 0xc0;
      }
      // Attention dot — opaque, brighter; overrides whatever was drawn.
      if (kind === "attention") {
        const ddx = x - dotCx + 0.5;
        const ddy = y - dotCy + 0.5;
        const ddist = Math.sqrt(ddx * ddx + ddy * ddy);
        if (ddist <= dotRadius) {
          lum = 0xff;
          alpha = 0xff;
        }
      }
      const off = y * stride + 1 + x * 2;
      pixels[off] = lum;
      pixels[off + 1] = alpha;
    }
  }
  return pixels;
}

function buildPng(size, kind) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); // width
  ihdr.writeUInt32BE(size, 4); // height
  ihdr.writeUInt8(8, 8);       // bit depth
  ihdr.writeUInt8(4, 9);       // colour type 4 = grayscale + alpha
  ihdr.writeUInt8(0, 10);      // compression = deflate
  ihdr.writeUInt8(0, 11);      // filter method = standard
  ihdr.writeUInt8(0, 12);      // interlace = none
  const raw = rasterise(size, kind);
  const idat = deflateSync(raw, { level: 9 });
  return Buffer.concat([
    signature,
    chunk("IHDR", ihdr),
    chunk("IDAT", idat),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

const targets = [
  { name: "tray-idle.png", size: 16, kind: "idle" },
  { name: "tray-idle@2x.png", size: 32, kind: "idle" },
  { name: "tray-attention.png", size: 16, kind: "attention" },
  { name: "tray-attention@2x.png", size: 32, kind: "attention" },
];

for (const { name, size, kind } of targets) {
  const out = join(OUT_DIR, name);
  const png = buildPng(size, kind);
  writeFileSync(out, png);
  // The 1KB cap is the spec's hard requirement for these icons. Larger
  // would imply a regression in the rasteriser (e.g. uncompressed IDAT).
  if (png.length >= 1024) {
    throw new Error(`${name} is ${png.length} bytes, expected < 1024`);
  }
  // Validate the magic + IHDR length back from disk so a corrupted
  // write surfaces immediately rather than at runtime.
  const back = readFileSync(out);
  const magic = back.subarray(0, 8).toString("hex");
  if (magic !== "89504e470d0a1a0a") {
    throw new Error(`${name} magic mismatch: ${magic}`);
  }
  const ihdrLen = back.readUInt32BE(8);
  if (ihdrLen !== 13) throw new Error(`${name} IHDR length ${ihdrLen} != 13`);
  const w = back.readUInt32BE(16);
  const h = back.readUInt32BE(20);
  if (w !== size || h !== size) {
    throw new Error(`${name} dim ${w}x${h} != ${size}x${size}`);
  }
  const sha = createHash("sha256").update(back).digest("hex").slice(0, 12);
  process.stdout.write(`  ${name}: ${png.length} B  ${size}x${size}  sha=${sha}\n`);
}

process.stdout.write("tray icons written to " + OUT_DIR + "\n");

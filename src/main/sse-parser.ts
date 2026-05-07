/**
 * Minimal Server-Sent Events parser.
 *
 * Why hand-rolled: Electron's main process doesn't ship `EventSource`
 * by default, and pulling in the `eventsource` npm package for a
 * single client is overkill. The format is small enough to parse in
 * ~50 lines:
 *
 *   - Lines are separated by "\n" (and the spec also accepts "\r\n"
 *     and "\r"; we normalise all three).
 *   - Events are separated by a blank line ("\n\n").
 *   - Each non-comment line is `field: value` (the leading space
 *     after the colon is optional).
 *   - Lines starting with ":" are comments — used by servers as
 *     keep-alive pings; we ignore them but never let them flush a
 *     pending event.
 *   - `data` lines accumulate, joined by "\n" if multiple appear in
 *     one event.
 *
 * Tested in `sse-parser.test.ts` with the canonical fixtures from
 * the WHATWG spec plus a couple of streaming edge cases.
 */

export interface SseEvent {
  event: string;
  data: string;
  id?: string;
}

export class SseParser {
  private buffer = "";
  private decoder = new TextDecoder();
  private readonly onEvent: (event: SseEvent) => void;

  constructor(onEvent: (event: SseEvent) => void) {
    this.onEvent = onEvent;
  }

  /** Push raw bytes from the network into the parser. Re-entrant safe. */
  push(chunk: Uint8Array): void {
    // `stream: true` tells the decoder to keep partial multi-byte
    // sequences across calls — a UTF-8 character split across chunk
    // boundaries doesn't get garbled.
    this.buffer += this.decoder.decode(chunk, { stream: true });
    this.drain();
  }

  /** Process any complete events sitting in the buffer. */
  private drain(): void {
    // Normalise "\r\n" and bare "\r" line endings to "\n" so the
    // boundary search below only has to handle one separator.
    this.buffer = this.buffer.replace(/\r\n?/g, "\n");
    while (true) {
      const idx = this.buffer.indexOf("\n\n");
      if (idx < 0) break;
      const block = this.buffer.slice(0, idx);
      this.buffer = this.buffer.slice(idx + 2);
      const event = parseEventBlock(block);
      if (event) this.onEvent(event);
    }
  }

  /**
   * Force-flush any buffered partial data. Called on `done` so a
   * server that closes mid-event surfaces what it sent rather than
   * losing the trailer.
   */
  flush(): void {
    if (this.buffer.length === 0) return;
    const event = parseEventBlock(this.buffer);
    this.buffer = "";
    if (event) this.onEvent(event);
  }
}

/**
 * Pure parser for a single event block (the text between two
 * "\n\n" separators). Returns `null` for blocks that produce no
 * `data` field — comment-only blocks and the empty seed are common.
 */
export function parseEventBlock(block: string): SseEvent | null {
  let event = "message";
  let dataParts: string[] = [];
  let id: string | undefined;
  for (const rawLine of block.split("\n")) {
    if (rawLine.length === 0) continue;
    if (rawLine.startsWith(":")) continue;
    const colonIdx = rawLine.indexOf(":");
    const field = colonIdx < 0 ? rawLine : rawLine.slice(0, colonIdx);
    let value = colonIdx < 0 ? "" : rawLine.slice(colonIdx + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    switch (field) {
      case "event":
        event = value;
        break;
      case "data":
        dataParts.push(value);
        break;
      case "id":
        id = value;
        break;
      // "retry" and unknown fields are ignored; spec says clients
      // should treat them as no-ops.
      default:
        break;
    }
  }
  if (dataParts.length === 0) return null;
  return { event, data: dataParts.join("\n"), id };
}

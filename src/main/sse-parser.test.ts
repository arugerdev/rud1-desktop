import { describe, expect, it } from "vitest";

import { SseParser, parseEventBlock } from "./sse-parser";

describe("parseEventBlock", () => {
  it("returns null for an empty block", () => {
    expect(parseEventBlock("")).toBeNull();
  });

  it("returns null for a comment-only block", () => {
    expect(parseEventBlock(": keep-alive")).toBeNull();
  });

  it("defaults event type to 'message' when omitted", () => {
    const ev = parseEventBlock("data: hello");
    expect(ev).not.toBeNull();
    expect(ev?.event).toBe("message");
    expect(ev?.data).toBe("hello");
  });

  it("strips one optional leading space after the colon", () => {
    const ev = parseEventBlock("data: hello");
    expect(ev?.data).toBe("hello");
    const noSpace = parseEventBlock("data:hello");
    expect(noSpace?.data).toBe("hello");
  });

  it("joins multiple data lines with a literal newline", () => {
    const ev = parseEventBlock("data: line1\ndata: line2");
    expect(ev?.data).toBe("line1\nline2");
  });

  it("captures custom event name and id", () => {
    const ev = parseEventBlock("event: notification\nid: 42\ndata: {\"x\":1}");
    expect(ev?.event).toBe("notification");
    expect(ev?.id).toBe("42");
    expect(ev?.data).toBe('{"x":1}');
  });

  it("ignores comment lines mixed with data", () => {
    const ev = parseEventBlock(": ping\nevent: foo\ndata: bar");
    expect(ev?.event).toBe("foo");
    expect(ev?.data).toBe("bar");
  });
});

describe("SseParser", () => {
  function feed(parser: SseParser, text: string): void {
    parser.push(new TextEncoder().encode(text));
  }

  it("emits one event per complete block", () => {
    const events: { event: string; data: string }[] = [];
    const parser = new SseParser((e) => events.push(e));
    feed(parser, "event: hello\ndata: hi\n\n");
    expect(events).toEqual([{ event: "hello", data: "hi", id: undefined }]);
  });

  it("buffers partial blocks across chunks", () => {
    const events: { event: string; data: string }[] = [];
    const parser = new SseParser((e) => events.push(e));
    feed(parser, "event: notification\ndata: par");
    expect(events).toHaveLength(0);
    feed(parser, "tial\n\n");
    expect(events).toEqual([
      { event: "notification", data: "partial", id: undefined },
    ]);
  });

  it("emits multiple events from one chunk", () => {
    const events: string[] = [];
    const parser = new SseParser((e) => events.push(e.data));
    feed(parser, "data: a\n\ndata: b\n\ndata: c\n\n");
    expect(events).toEqual(["a", "b", "c"]);
  });

  it("normalises CRLF / CR line endings", () => {
    const events: { event: string; data: string }[] = [];
    const parser = new SseParser((e) => events.push(e));
    feed(parser, "event: x\r\ndata: y\r\n\r\n");
    expect(events).toEqual([{ event: "x", data: "y", id: undefined }]);
  });

  it("skips comment-only blocks (keep-alive pings)", () => {
    const events: unknown[] = [];
    const parser = new SseParser((e) => events.push(e));
    feed(parser, ": keep-alive\n\n");
    expect(events).toHaveLength(0);
  });

  it("flush surfaces a trailing event when the server cuts mid-stream", () => {
    const events: { event: string; data: string }[] = [];
    const parser = new SseParser((e) => events.push(e));
    feed(parser, "event: bye\ndata: tail");
    expect(events).toHaveLength(0);
    parser.flush();
    expect(events).toEqual([{ event: "bye", data: "tail", id: undefined }]);
  });
});

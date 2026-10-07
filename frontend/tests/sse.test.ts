import { describe, expect, it } from "vitest";

import { SseParser } from "@/lib/sse";

describe("SseParser", () => {
  it("parses a complete frame", () => {
    const frames = new SseParser().push('id: 1\nevent: security_event\ndata: {"a":1}\n\n');
    expect(frames).toEqual([{ id: "1", event: "security_event", data: '{"a":1}' }]);
  });

  it("buffers frames split across chunks", () => {
    const p = new SseParser();
    expect(p.push("event: security_event\nda")).toEqual([]);
    const frames = p.push("ta: x\n\n");
    expect(frames).toHaveLength(1);
    expect(frames[0].data).toBe("x");
  });

  it("ignores comment/heartbeat lines and handles CRLF", () => {
    const frames = new SseParser().push(
      ": connected\n\n: ping\n\nevent: resync\r\ndata: {}\r\n\r\n",
    );
    expect(frames).toEqual([{ event: "resync", data: "{}", id: undefined }]);
  });

  it("joins multi-line data", () => {
    const frames = new SseParser().push("data: a\ndata: b\n\n");
    expect(frames[0].data).toBe("a\nb");
  });
});

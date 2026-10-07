export interface SseFrame {
  event: string;
  data: string;
  id?: string;
}

/** Incremental parser for text/event-stream. Comment lines (":") are ignored. */
export class SseParser {
  private buffer = "";

  push(chunk: string): SseFrame[] {
    this.buffer += chunk.replace(/\r\n?/g, "\n");
    const blocks = this.buffer.split("\n\n");
    this.buffer = blocks.pop() ?? "";
    const frames: SseFrame[] = [];
    for (const block of blocks) {
      let event = "message";
      let id: string | undefined;
      const data: string[] = [];
      let hasField = false;
      for (const line of block.split("\n")) {
        if (!line || line.startsWith(":")) continue;
        const idx = line.indexOf(":");
        const field = idx === -1 ? line : line.slice(0, idx);
        const value = idx === -1 ? "" : line.slice(idx + 1).replace(/^ /, "");
        if (field === "event") event = value;
        else if (field === "data") data.push(value);
        else if (field === "id") id = value;
        else continue;
        hasField = true;
      }
      if (hasField) frames.push({ event, data: data.join("\n"), id });
    }
    return frames;
  }
}

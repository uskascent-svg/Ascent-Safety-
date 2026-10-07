import { API_URL, getAccessToken, refreshAccessToken } from "@/lib/api";
import { SseParser, type SseFrame } from "@/lib/sse";

interface Handlers {
  onOpen: () => void;
  onFrame: (frame: SseFrame) => void;
}

/**
 * Reads the authenticated SSE stream with fetch (EventSource cannot send an Authorization
 * header, and tokens must not go in URLs). Resolves when the server ends the stream.
 */
export async function streamEvents(signal: AbortSignal, handlers: Handlers): Promise<void> {
  const open = () =>
    fetch(`${API_URL}/api/security-events/stream`, {
      headers: {
        Accept: "text/event-stream",
        Authorization: `Bearer ${getAccessToken() ?? ""}`,
      },
      credentials: "include",
      signal,
    });

  if (!getAccessToken()) await refreshAccessToken();
  let res = await open();
  if (res.status === 401 && (await refreshAccessToken())) res = await open();
  if (!res.ok || !res.body) throw new Error(`Stream unavailable (${res.status})`);

  handlers.onOpen();
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const parser = new SseParser();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return;
    for (const frame of parser.push(decoder.decode(value, { stream: true }))) {
      handlers.onFrame(frame);
    }
  }
}

"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { streamEvents } from "@/lib/stream";

export type LiveStatus = "connecting" | "live" | "reconnecting";

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    const t = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => (clearTimeout(t), resolve()), { once: true });
  });

/**
 * Subscribes to the backend event stream. The stream carries only events the backend has already
 * validated and stored, so on each one we refetch (debounced) and let the API recompute the
 * map, feed and statistics. Nothing is generated on the client.
 */
export function useLiveUpdates(enabled: boolean): LiveStatus {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<LiveStatus>("connecting");

  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    let debounce: ReturnType<typeof setTimeout> | undefined;
    const refetch = () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => queryClient.invalidateQueries({ queryKey: ["security"] }), 400);
    };

    (async () => {
      let delay = 1000;
      while (!controller.signal.aborted) {
        try {
          await streamEvents(controller.signal, {
            onOpen: () => {
              setStatus("live");
              delay = 1000;
              refetch(); // catch up on anything missed while disconnected
            },
            onFrame: (frame) => {
              if (frame.event === "security_event" || frame.event === "resync") refetch();
            },
          });
        } catch {
          if (controller.signal.aborted) return;
          setStatus("reconnecting");
          await sleep(delay, controller.signal);
          delay = Math.min(delay * 2, 30_000);
          continue;
        }
        await sleep(1000, controller.signal); // server ended the stream (max lifetime): reconnect
      }
    })();

    return () => {
      controller.abort();
      clearTimeout(debounce);
    };
  }, [enabled, queryClient]);

  return status;
}

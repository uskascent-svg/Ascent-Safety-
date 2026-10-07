"""In-process fan-out of newly stored security events to connected SSE clients.

Single-process only. For multiple API workers, replace with a Redis pub/sub implementation
behind the same publish/subscribe interface.
"""

import asyncio
import threading

RESYNC = {"__resync__": True}  # sent to a slow consumer: "you missed events, refetch"


class EventBroker:
    def __init__(self) -> None:
        self._subs: dict[asyncio.Queue, asyncio.AbstractEventLoop] = {}
        self._lock = threading.Lock()

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        with self._lock:
            self._subs[queue] = asyncio.get_running_loop()
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        with self._lock:
            self._subs.pop(queue, None)

    def publish(self, payload: dict) -> None:
        """Thread-safe; called from sync request handlers after the event is committed."""
        with self._lock:
            targets = list(self._subs.items())
        for queue, loop in targets:
            try:
                loop.call_soon_threadsafe(self._deliver, queue, payload)
            except RuntimeError:  # loop closed
                self.unsubscribe(queue)

    @staticmethod
    def _deliver(queue: asyncio.Queue, payload: dict) -> None:
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            while not queue.empty():
                queue.get_nowait()
            queue.put_nowait(RESYNC)


broker = EventBroker()

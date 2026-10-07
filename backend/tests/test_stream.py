import asyncio
import threading
import time

from app.core.config import get_settings
from app.services.broker import RESYNC, EventBroker
from tests.test_events import KEY, analyst, event  # noqa: F401


def test_stream_requires_analyst(client, make_user):
    assert client.get("/api/security-events/stream").status_code == 401
    make_user("plain@example.com")
    from tests.conftest import PASSWORD

    tok = client.post(
        "/api/auth/login", json={"email": "plain@example.com", "password": PASSWORD}
    ).json()["access_token"]
    r = client.get("/api/security-events/stream", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_stream_delivers_stored_events_then_ends(client, analyst):  # noqa: F811
    settings = get_settings()
    original = settings.sse_max_seconds
    settings.sse_max_seconds = 3
    created = {}

    def ingest_later():
        time.sleep(0.7)
        r = client.post("/api/security-events", json=event(title="streamed"), headers=KEY)
        created.update(r.json())

    try:
        t = threading.Thread(target=ingest_later)
        t.start()
        lines = []
        with client.stream("GET", "/api/security-events/stream", headers=analyst) as r:
            assert r.status_code == 200
            assert r.headers["content-type"].startswith("text/event-stream")
            lines = list(r.iter_lines())
        t.join()
    finally:
        settings.sse_max_seconds = original
    assert "event: security_event" in lines
    assert f"id: {created['id']}" in lines
    assert any(line.startswith("data: ") and '"streamed"' in line for line in lines)


def test_broker_marks_slow_consumers_for_resync():
    async def run():
        broker = EventBroker()
        q = broker.subscribe()
        for i in range(150):
            broker.publish({"id": str(i)})
        await asyncio.sleep(0.1)
        items = []
        while not q.empty():
            items.append(q.get_nowait())
        return items

    items = asyncio.run(run())
    assert RESYNC in items and len(items) <= 100

"""Rate-limit and body-size middleware (`app/core/limits.py`)."""

from fastapi.testclient import TestClient

from app.core.app_factory import create_app
from app.core.config import Settings
from app.core.limits import RateLimitMiddleware


def _client(**overrides):
    return TestClient(create_app(Settings(**overrides)))


def test_limits_are_off_by_default():
    client = _client()
    assert all(client.get("/devices").status_code == 200 for _ in range(30))
    assert client.post("/detections/score-flows", json={"device_id": "d", "flows": []}).status_code == 422


def test_rate_limit_returns_429_with_retry_after_and_exempts_health():
    client = _client(rate_limit_per_minute=3)
    codes = [client.get("/devices").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    blocked = client.get("/devices")
    assert blocked.status_code == 429 and int(blocked.headers["retry-after"]) >= 1
    assert "Rate limit" in blocked.json()["detail"]
    assert all(client.get("/health").status_code == 200 for _ in range(10))


def test_rate_limit_is_per_client_key():
    client = _client(rate_limit_per_minute=1)
    assert client.get("/devices", headers={"X-API-Key": "a"}).status_code == 200
    assert client.get("/devices", headers={"X-API-Key": "a"}).status_code == 429
    assert client.get("/devices", headers={"X-API-Key": "b"}).status_code == 200


def test_rate_limit_window_resets_with_the_clock():
    now = [1000.0]
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = RateLimitMiddleware(app, per_minute=2, clock=lambda: now[0])
    sent = []

    async def send(message):
        sent.append(message)

    import asyncio

    scope = {"type": "http", "path": "/x", "headers": [], "client": ("1.2.3.4", 1)}

    async def call():
        await mw(scope, None, send)

    for _ in range(3):
        asyncio.run(call())
    statuses = [m["status"] for m in sent if m["type"] == "http.response.start"]
    assert statuses == [200, 200, 429]
    now[0] += 61
    sent.clear()
    asyncio.run(call())
    assert [m["status"] for m in sent if m["type"] == "http.response.start"] == [200]


def test_body_over_the_limit_is_rejected_with_413_but_small_bodies_pass():
    client = _client(max_request_body_bytes=2000)
    big = {"device_id": "d", "flows": [{"x": 1.0}] * 400}
    r = client.post("/detections/score-flows", json=big)
    assert r.status_code == 413 and "exceeds" in r.json()["detail"]
    small = client.post("/detections/score-flows", json={"device_id": "d", "flows": []})
    assert small.status_code == 422  # reached the app; rejected by validation, not by the limit

"""Request-size and rate limits (closes the Phase 12 "rate limiting and
request-size limits" known gap).

Two pure-ASGI middlewares (no `BaseHTTPMiddleware`, so request bodies are not
buffered by the middleware itself):

* `BodySizeLimitMiddleware` -- 413 for a body over `max_bytes`, checked from
  `Content-Length` up front and by counting streamed bytes for chunked bodies.
* `RateLimitMiddleware` -- fixed-window per-client counter, 429 with
  `Retry-After`. The client key is the API key when one is sent (hashed, never
  stored or logged in clear), else the peer IP. `/health` is exempt so a
  liveness probe cannot be starved.

Both are off by default (`Settings.rate_limit_per_minute = 0`,
`max_request_body_bytes = 0`), so existing behaviour and tests are unchanged
until an operator opts in. Honest limits: state is in-process, so with several
worker processes each enforces its own window (an edge proxy or shared store is
the right place for a global limit), and the peer IP behind a reverse proxy is
the proxy's -- put the real client-IP handling in that proxy.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_EXEMPT_PATHS = frozenset({"/health"})


async def _send_json(send: Send, status: int, detail: str, extra_headers: list[tuple[bytes, bytes]]) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), *extra_headers],
        }
    )
    await send({"type": "http.response.body", "body": body})


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.max_bytes <= 0:
            await self.app(scope, receive, send)
            return

        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            await _send_json(send, 413, f"Request body exceeds {self.max_bytes} bytes", [])
            return

        received = 0
        too_big = False
        response_started = False

        async def counting_receive() -> Message:
            nonlocal received, too_big
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    too_big = True
                    # Stop the app reading further: pretend the client went away.
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal response_started
            if too_big:
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        await self.app(scope, counting_receive, guarded_send)
        if too_big and not response_started:
            await _send_json(send, 413, f"Request body exceeds {self.max_bytes} bytes", [])


class RateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        per_minute: int,
        clock: Callable[[], float] = time.monotonic,
        window_seconds: float = 60.0,
    ) -> None:
        self.app = app
        self.per_minute = per_minute
        self._clock = clock
        self._window = window_seconds
        self._windows: dict[str, tuple[float, int]] = {}

    def _client_key(self, scope: Scope) -> str:
        headers = dict(scope["headers"])
        api_key = headers.get(b"x-api-key")
        if api_key:
            return "key:" + hashlib.sha256(api_key).hexdigest()[:16]
        client = scope.get("client")
        return "ip:" + (client[0] if client else "unknown")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.per_minute <= 0 or scope["path"] in _EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        now = self._clock()
        key = self._client_key(scope)
        start, count = self._windows.get(key, (now, 0))
        if now - start >= self._window:
            start, count = now, 0
        if count >= self.per_minute:
            retry_after = max(1, int(self._window - (now - start)) + 1)
            await _send_json(
                send,
                429,
                f"Rate limit of {self.per_minute} requests per minute exceeded",
                [(b"retry-after", str(retry_after).encode())],
            )
            return
        self._windows[key] = (start, count + 1)
        # Bound memory: drop windows that have already expired.
        if len(self._windows) > 10_000:
            self._windows = {k: v for k, v in self._windows.items() if now - v[0] < self._window}
        await self.app(scope, receive, send)

import logging
import uuid


class RequestContextMiddleware:
    """ASGI middleware: bounds JSON bodies, adds correlation and browser security headers."""

    def __init__(self, app, max_upload_bytes: int, on_limit):
        self.app, self.max_upload_bytes, self.on_limit = app, max_upload_bytes, on_limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id = str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id
        headers = dict(scope.get("headers", []))
        upload = scope["path"].endswith("/upload")
        limit = self.max_upload_bytes + 16 if upload else 65536
        try:
            content_length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            content_length = limit + 1

        async def wrapped_send(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).extend(
                    [
                        (b"x-request-id", request_id.encode()),
                        (b"x-content-type-options", b"nosniff"),
                        (b"cache-control", b"no-store"),
                        (b"referrer-policy", b"no-referrer"),
                    ]
                )
                logging.getLogger("secureshare").info(
                    "HTTP request completed",
                    extra={
                        "event_type": "HTTP_REQUEST",
                        "request_id": request_id,
                        "source_ip": scope.get("client", (None,))[0],
                        "status": message["status"],
                    },
                )
            await send(message)

        async def too_large():
            from starlette.responses import JSONResponse

            response = JSONResponse(
                {
                    "error": "REQUEST_TOO_LARGE",
                    "message": "Request exceeds the configured size limit.",
                    "request_id": request_id,
                },
                status_code=413,
            )
            self.on_limit(scope, request_id)
            await response(scope, receive, wrapped_send)

        if content_length > limit or content_length < 0:
            return await too_large()
        if not upload:
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > limit:
                    return await too_large()
                if not message.get("more_body", False):
                    break
            delivered = False
            original_receive = receive

            async def replay_receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await original_receive()

            receive = replay_receive
        await self.app(scope, receive, wrapped_send)

from __future__ import annotations

import asyncio
import contextlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

TOKEN_RE = re.compile(r"/ssrf/([A-Za-z0-9_-]{8,})")


@dataclass
class CallbackHit:
    token: str
    path: str
    method: str
    client: str
    headers: dict[str, str] = field(default_factory=dict)
    received_at: str = ""


class CallbackServer:
    """Small HTTP listener used only to verify out-of-band SSRF callbacks.

    The listener answers every request with a fixed 200 response and records
    requests whose path contains one of the tokens created by url_for().
    It never serves files or exposes scanner internals.
    """

    def __init__(self, base_url: str | None = None) -> None:
        self.requested_url = base_url.strip().rstrip("/") if base_url else None
        parsed = urlsplit(self.requested_url) if self.requested_url else None
        self._path_prefix = parsed.path.rstrip("/") if parsed else ""
        host = parsed.hostname if parsed else "127.0.0.1"
        if ":" in (host or ""):
            self._bind_host = "::1" if host == "::1" else "::"
        else:
            self._bind_host = "127.0.0.1" if host in ("127.0.0.1", "localhost") else "0.0.0.0"
        self._bind_port = parsed.port if parsed and parsed.port else 0
        self._server: asyncio.AbstractServer | None = None
        self._hits: dict[str, list[CallbackHit]] = {}
        self._waiters: dict[str, asyncio.Event] = {}
        self.base_url = ""

    async def start(self) -> str:
        self._server = await asyncio.start_server(
            self._handle,
            self._bind_host,
            self._bind_port,
            limit=64 * 1024,
        )
        socket = self._server.sockets[0]
        port = socket.getsockname()[1]
        if self.requested_url:
            parsed = urlsplit(self.requested_url)
            host = parsed.hostname or "127.0.0.1"
            if host == "localhost":
                host = "127.0.0.1"
            netloc = f"[{host}]" if ":" in host else host
            netloc = f"{netloc}:{port}"
            self.base_url = f"http://{netloc}{self._path_prefix}"
        else:
            self.base_url = f"http://127.0.0.1:{port}"
        return self.base_url

    async def stop(self) -> None:
        if not self._server:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    def url_for(self, token: str) -> str:
        self._waiters.setdefault(token, asyncio.Event())
        return f"{self.base_url}/ssrf/{token}"

    async def wait(self, token: str, timeout: float = 3.0) -> list[CallbackHit]:
        event = self._waiters.setdefault(token, asyncio.Event())
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except TimeoutError:
            return []
        return list(self._hits.get(token, []))

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await asyncio.wait_for(reader.read(64 * 1024), timeout=3.0)
            text = raw.decode("latin-1", errors="replace")
            lines = text.split("\r\n")
            request_line = lines[0].split() if lines else []
            method = request_line[0] if request_line else "?"
            target = request_line[1] if len(request_line) > 1 else "/"
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if not line:
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()[:500]
            path = urlsplit(target).path
            match = TOKEN_RE.search(path)
            if match:
                token = match.group(1)
                if token in self._waiters:
                    peer = writer.get_extra_info("peername")
                    client = peer[0] if isinstance(peer, tuple) and peer else "unknown"
                    self._hits.setdefault(token, []).append(
                        CallbackHit(
                            token=token,
                            path=target[:500],
                            method=method,
                            client=str(client),
                            headers={
                                key: headers[key]
                                for key in ("host", "user-agent", "x-forwarded-for")
                                if key in headers
                            },
                            received_at=datetime.now(UTC).isoformat(),
                        )
                    )
                    if len(self._hits[token]) > 20:
                        self._hits[token] = self._hits[token][-20:]
                    self._waiters[token].set()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: close\r\n\r\nok"
                )
                await writer.drain()
                writer.close()
                await writer.wait_closed()

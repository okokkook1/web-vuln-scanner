from __future__ import annotations

import json
import threading
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "DemoServer/1.0"
    sys_version = ""

    def log_message(self, _format, *args):
        pass

    def _common_headers(self) -> None:
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("X-Demo", "vulnscan-fixture")

    def _send(
        self,
        status: int,
        body: str,
        content_type: str = "text/html; charset=utf-8",
        extra: dict[str, str] | None = None,
    ) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self._common_headers()
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        if self.path == "/":
            self.send_header("Set-Cookie", "sessionid=demo-session; Path=/")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def do_OPTIONS(self):
        self._send(
            200,
            "",
            extra={"Allow": "GET, HEAD, POST, OPTIONS, PUT, DELETE"},
        )

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        path = urlsplit(self.path).path
        if path == "/login":
            data = parse_qs(body)
            if (
                (data.get("username") or [""])[0] == "demo"
                and (data.get("password") or [""])[0] == "demo123"
                and (data.get("csrf_token") or [""])[0] == "demo-csrf"
            ):
                self._send(
                    302,
                    "",
                    extra={
                        "Location": "/dashboard",
                        "Set-Cookie": "auth=ok; Path=/; HttpOnly; SameSite=Lax",
                    },
                )
            else:
                self._send(
                    401,
                    "<html><body><h1>Login failed</h1>"
                    '<form method="post" action="/login">'
                    '<input type="password" name="password"></form></body></html>',
                )
            return
        if path == "/profile":
            self._send(200, "<html><body><h1>Profile saved</h1></body></html>")
            return
        if path == "/api/refresh":
            data = parse_qs(body)
            if (data.get("refresh_token") or [""])[0] != "refresh-demo":
                self._send(401, '{"error":"invalid refresh token"}', "application/json")
                return
            self._send(
                200,
                json.dumps({"access_token": "refreshed-token"}),
                "application/json",
                extra={"Set-Cookie": "auth=ok; Path=/; HttpOnly; SameSite=Lax"},
            )
            return
        if path == "/api/echo":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                data = {}
            q = str(data.get("q") or "")
            url = str(data.get("url") or "")
            user = data.get("user") if isinstance(data.get("user"), dict) else {}
            name = str(user.get("name") or "")
            if "'" in q:
                self._send(
                    200,
                    '{"error":"You have an error in your SQL syntax; check the manual"}',
                    "application/json",
                )
                return
            status = 0
            if url.startswith(("http://", "https://")):
                try:
                    with urllib.request.urlopen(url, timeout=2) as response:
                        status = response.status
                except Exception:
                    status = 0
            self._send(
                200,
                json.dumps({"q": q, "url": url, "status": status, "name": name}),
                "application/json",
            )
            return
        if path == "/api/boolean":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                data = {}
            q = str(data.get("q") or "")
            if "'1'='2" in q:
                payload = {"exists": False, "message": "no record", "items": []}
            else:
                payload = {
                    "exists": True,
                    "message": "record found",
                    "items": [1, 2, 3, 4, 5],
                }
            self._send(200, json.dumps(payload), "application/json")
            return
        self._send(404, "<html><body>not found</body></html>")

    def _is_authenticated(self) -> bool:
        return "auth=ok" in (self.headers.get("Cookie") or "")

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/":
            body = """<!doctype html>
<html><head><title>VulnScan Demo</title>
<script src="/app.js"></script></head>
<body>
<h1>Demo shop</h1>
<a href="/page?x=1">page</a>
<a href="/search?q=hello">search</a>
<a href="/redirect?next=/home">redirect</a>
<a href="/boolean?id=1">boolean</a>
<a href="/download?file=readme.txt">download</a>
<a href="/fetch?url=/home">fetch</a>
<a href="/private">private</a>
<a href="/moved">moved</a>
<a href="/error">error</a>
<a href="/logout">logout</a>
<form method="get" action="/search"><input name="q" value="hello"></form>
<form method="post" action="/profile"><input name="email" value="a@example.com"></form>
<img src="http://insecure.example/banner.png" alt="banner">
</body></html>"""
            self._send(200, body)
            return
        if path == "/api/admin/settings":
            cookie = self.headers.get("Cookie") or ""
            if "auth=alice" not in cookie and "auth=bob" not in cookie:
                self._send(401, '{"error":"authentication required"}', "application/json")
                return
            self._send(
                200,
                json.dumps({"admin": True, "setting": "demo"}),
                "application/json",
            )
            return
        if path in ("/api/object/1", "/api/object/2"):
            cookie = self.headers.get("Cookie") or ""
            if "auth=alice" not in cookie and "auth=bob" not in cookie:
                self._send(401, '{"error":"authentication required"}', "application/json")
                return
            object_id = path.rsplit("/", 1)[-1]
            if object_id == "2" and "auth=bob" in cookie:
                self._send(403, '{"error":"forbidden"}', "application/json")
                return
            self._send(
                200,
                json.dumps(
                    {
                        "id": int(object_id),
                        "owner": "alice",
                        "label": f"object-{object_id}",
                    }
                ),
                "application/json",
            )
            return
        if path == "/page":
            x = (query.get("x") or [""])[0]
            self._send(200, f"<html><body><p>Value: {x}</p></body></html>")
            return
        if path == "/search":
            q = (query.get("q") or [""])[0]
            if "'" in q:
                self._send(
                    200,
                    "<html><body>You have an error in your SQL syntax; check the manual</body></html>",
                )
                return
            self._send(200, f"<html><body><h1>Search</h1><p>You searched: {q}</p></body></html>")
            return
        if path == "/redirect":
            target = (query.get("next") or ["/home"])[0]
            if target.startswith(("http://", "https://")):
                self._send(302, "", extra={"Location": target})
            else:
                self._send(200, "<html><body>redirect target ignored</body></html>")
            return
        if path == "/boolean":
            value = (query.get("id") or [""])[0]
            if "'1'='2" in value:
                body = "<html><body><h1>Item missing</h1><p>No item found for this id.</p></body></html>"
            else:
                body = "<html><body><h1>Item exists</h1><p>Item exists: demo product A.</p></body></html>"
            self._send(200, body)
            return
        if path == "/download":
            filename = (query.get("file") or ["readme.txt"])[0]
            if ".." in filename:
                self._send(
                    400,
                    "<html><body>Warning: No such file or directory: "
                    f"/srv/app/{filename}</body></html>",
                )
            else:
                self._send(200, "<html><body>Download: readme.txt</body></html>")
            return
        if path == "/fetch":
            target = (query.get("url") or [""])[0]
            status = 0
            try:
                if target.startswith(("http://", "https://")):
                    with urllib.request.urlopen(target, timeout=2) as response:
                        status = response.status
            except Exception:
                status = 0
            self._send(200, f"<html><body>Fetched status {status}</body></html>")
            return
        if path == "/login":
            self._send(
                200,
                """<html><body><h1>Login</h1>
<form method="post" action="/login">
<input type="hidden" name="csrf_token" value="demo-csrf">
<input type="text" name="username">
<input type="password" name="password">
<button type="submit">Sign in</button>
</form></body></html>""",
            )
            return
        if path == "/dashboard":
            if not self._is_authenticated():
                self._send(302, "", extra={"Location": "/login"})
                return
            self._send(200, "<html><body><h1>Welcome, demo</h1></body></html>")
            return
        if path == "/private":
            if not self._is_authenticated():
                self._send(302, "", extra={"Location": "/login"})
                return
            self._send(200, "<html><body><h1>Private area</h1><p>members only</p></body></html>")
            return
        if path == "/auto-login":
            self._send(
                200,
                """<html><body><h1>Auto login</h1>
<script>
document.cookie = "auth=ok; path=/; SameSite=Lax";
localStorage.setItem("access_token", "token-123");
</script></body></html>""",
            )
            return
        if path == "/moved":
            self._send(302, "", extra={"Location": "/hidden"})
            return
        if path == "/hidden":
            self._send(200, "<html><body><h1>Hidden page</h1></body></html>")
            return
        if path == "/error":
            self._send(
                500,
                "<html><body><h1>Server error</h1><pre>Traceback (most recent call last):\n"
                '  File "app.py", line 12, in handler\nValueError: demo error</pre></body></html>',
            )
            return
        if path == "/.env":
            self._send(
                200,
                "APP_KEY=base64:demo-secret\nDB_PASSWORD=demo-password\nMAIL_FROM=a@example.com\n",
                "text/plain; charset=utf-8",
            )
            return
        if path == "/openapi.json":
            self._send(
                200,
                '{"openapi":"3.0.0","info":{"title":"Demo API"},"paths":{"/search":{}}}',
                "application/json",
            )
            return
        if path == "/api/ref-schema.json":
            self._send(
                200,
                json.dumps(
                    {
                        "schemas": {
                            "EchoBody": {
                                "type": "object",
                                "properties": {
                                    "q": {"type": "string"},
                                    "user": {"$ref": "#/schemas/User"},
                                },
                            },
                            "User": {
                                "type": "object",
                                "properties": {"name": {"type": "string"}},
                            },
                        }
                    }
                ),
                "application/json",
            )
            return
        if path == "/api/openapi-external.json":
            base = f"http://127.0.0.1:{self.server.server_port}"
            spec = {
                "openapi": "3.1.0",
                "servers": [{"url": base}],
                "paths": {
                    "/api/echo": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "$ref": "/api/ref-schema.json#/schemas/EchoBody"
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            }
            self._send(200, json.dumps(spec), "application/json")
            return
        if path == "/api/openapi-protected":
            cookie = self.headers.get("Cookie") or ""
            authorization = self.headers.get("Authorization") or ""
            if (
                "demo-session=" not in cookie
                and "auth=ok" not in cookie
                and not authorization
            ):
                self._send(
                    401,
                    '{"error":"authentication required"}',
                    "application/json",
                )
                return
            base = f"http://127.0.0.1:{self.server.server_port}"
            spec = {
                "openapi": "3.1.0",
                "servers": [{"url": base}],
                "paths": {
                    "/api/echo": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {"q": {"type": "string"}},
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            }
            self._send(200, json.dumps(spec), "application/json")
            return
        if path == "/api/openapi-redirect":
            self._send(302, "", extra={"Location": "/api/openapi.json"})
            return
        if path == "/api/openapi-outside":
            self._send(
                302,
                "",
                extra={"Location": "http://198.51.100.10/openapi.json"},
            )
            return
        if path == "/api/openapi-loop":
            self._send(302, "", extra={"Location": "/api/openapi-loop"})
            return
        if path == "/api/openapi.json":
            base = f"http://127.0.0.1:{self.server.server_port}"
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "Fixture API"},
                "servers": [{"url": base}],
                "paths": {
                    "/api/echo": {
                        "post": {
                            "requestBody": {
                                "required": True,
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "q": {"type": "string"},
                                                "url": {"type": "string"},
                                                "user": {
                                                    "type": "object",
                                                    "properties": {
                                                        "name": {"type": "string"}
                                                    },
                                                },
                                            },
                                        }
                                    }
                                },
                            }
                        }
                    },
                    "/api/boolean": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {"q": {"type": "string"}},
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "/search": {
                        "get": {
                            "parameters": [
                                {
                                    "name": "q",
                                    "in": "query",
                                    "schema": {"type": "string"},
                                }
                            ]
                        }
                    },
                },
            }
            self._send(200, json.dumps(spec), "application/json")
            return
        if path == "/app.js":
            self._send(
                200,
                'const API_KEY = "AKIAABCDEFGHIJKLMNOP";\n'
                'const endpoint = "/api/v1/items";\n'
                "//# sourceMappingURL=app.js.map\n",
                "application/javascript",
            )
            return
        if path == "/logout":
            self._send(200, "<html><body>logged out</body></html>")
            return
        self._send(404, "<html><body>not found</body></html>")


@contextmanager
def fixture_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8899), DemoHandler)
    server.daemon_threads = True
    print("Fixture server: http://127.0.0.1:8899")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

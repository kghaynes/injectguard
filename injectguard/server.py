"""Local HTTP API the Chrome extension (and scripts) talk to.

Locked down three ways:
  1. Binds to 127.0.0.1 only.
  2. Every call except /health needs the X-InjectGuard-Token header (pairing token).
  3. Requests from web pages are refused: Origin must be absent or chrome-extension://, and Host must be loopback
     (stops a malicious site from driving the API through the browser or by DNS rebinding).
"""
from __future__ import annotations

import hmac
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional
from urllib.parse import parse_qs, urlparse

from . import __version__, engine, store
from .config import Settings, api_token
from .models import Segment, ScanResult

MAX_BODY = 12 * 1024 * 1024
# chrome-extension://<32 letters a-p>, moz-extension://<uuid>, extension://<id>; nothing else is echoed back
EXT_ORIGIN = re.compile(r"(?:chrome-extension|moz-extension|extension)://[A-Za-z0-9-]{1,64}/?")
VALID_VIS = {"visible", "hidden", "comment", "metadata"}


class _Handler(BaseHTTPRequestHandler):
    server_version = "InjectGuard/" + __version__
    app: "ApiServer" = None  # set by ApiServer

    def log_message(self, fmt, *args):  # quiet
        if self.app.log:
            self.app.log("api: " + fmt % args)

    # ---------------------------------------------------------- helpers
    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if origin and not EXT_ORIGIN.fullmatch(origin):
            return False
        allowed = self.app.settings.get("allowed_extension_ids") or []
        if origin and allowed and origin.split("://", 1)[1].strip("/") not in allowed:
            return False
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost", "[::1]")

    def _cors(self):
        # Only browser extensions get past _origin_ok, so a fixed "*" is safe here and nothing from the request is
        # copied into a response header. Auth is the X-InjectGuard-Token header, never cookies.
        if EXT_ORIGIN.fullmatch(self.headers.get("Origin") or ""):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-InjectGuard-Token")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _send(self, code: int, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _auth(self) -> bool:
        tok = self.headers.get("X-InjectGuard-Token", "")
        return hmac.compare_digest(tok, self.app.token)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(n) or b"{}")

    # ---------------------------------------------------------- verbs
    def do_OPTIONS(self):
        if not self._origin_ok():
            return self._send(403, {"error": "origin not allowed"})
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if not self._origin_ok():
            return self._send(403, {"error": "origin not allowed"})
        u = urlparse(self.path)
        if u.path == "/health":
            return self._send(200, {"ok": True, "app": "InjectGuard", "version": __version__})
        if not self._auth():
            return self._send(401, {"error": "bad or missing token"})
        if u.path == "/status":
            s = self.app.settings
            return self._send(200, {"version": __version__, "llm_enabled": s.get("llm_enabled"),
                                    "realtime": self.app.status().get("realtime"),
                                    "watch_folders": s.get("watch_folders")})
        if u.path == "/history":
            q = parse_qs(u.query)
            return self._send(200, store.history(int(q.get("limit", ["100"])[0])))
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._origin_ok():
            return self._send(403, {"error": "origin not allowed"})
        if not self._auth():
            return self._send(401, {"error": "bad or missing token"})
        try:
            body = self._body()
        except Exception as e:  # noqa: BLE001
            return self._send(400, {"error": str(e)})
        path = urlparse(self.path).path
        s = self.app.settings
        try:
            if path == "/scan/page":
                segs = []
                for x in body.get("segments", [])[:5000]:
                    vis = x.get("visibility", "visible")
                    segs.append(Segment(str(x.get("text", ""))[:200000], str(x.get("location", ""))[:300],
                                        vis if vis in VALID_VIS else "visible", x.get("hidden_reason")))
                res = engine.scan_segments_result(str(body.get("url", "page"))[:2000], "page", segs, s)
                src = "browser"
            elif path == "/scan/text":
                res = engine.scan_text(str(body.get("text", "")), str(body.get("label", "Text"))[:200], s)
                src = "browser"
            elif path == "/scan/url":
                url = str(body.get("url", ""))
                if not url.startswith(("http://", "https://")):
                    return self._send(400, {"error": "http(s) URL required"})
                res = engine.scan_url(url, s, allow_private=False)
                src = "browser"
            else:
                return self._send(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            return self._send(500, {"error": str(e)})
        if body.get("record", True):
            store.record(res, src)
        self.app.on_result(res, src)
        self._send(200, res.to_dict())


class ApiServer:
    def __init__(self, settings: Settings, on_result: Optional[Callable[[ScanResult, str], None]] = None,
                 log: Optional[Callable[[str], None]] = None, status: Optional[Callable[[], dict]] = None):
        self.settings = settings
        self.token = api_token()
        self.on_result = on_result or (lambda r, s: None)
        self.log = log
        self.status = status or (lambda: {})
        self.httpd: Optional[ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self) -> int:
        handler = type("H", (_Handler,), {"app": self})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", int(self.settings.get("api_port", 47321))), handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="ig-api", daemon=True)
        self.thread.start()
        return self.httpd.server_address[1]

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None

    @property
    def running(self) -> bool:
        return self.httpd is not None

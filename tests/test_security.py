"""Hardening checks for the CodeQL findings: SSRF, file-path access through the API, header echo."""
import json
import os
import tempfile
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

os.environ.setdefault("INJECTGUARD_HOME", tempfile.mkdtemp())

from injectguard import engine  # noqa: E402
from injectguard.config import Settings, api_token  # noqa: E402
from injectguard.server import ApiServer  # noqa: E402

EXT = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"


@pytest.mark.parametrize("url", ["http://127.0.0.1:8080/", "http://localhost/", "http://10.0.0.1/", "http://192.168.1.1/",
                                 "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://0.0.0.0/",
                                 "file:///etc/passwd", "ftp://example.com/x"])
def test_browser_scans_cannot_reach_local_network(url):
    r = engine.scan_url(url, allow_private=False)
    assert r.verdict == "error" and ("local or private" in r.errors[0] or "only http(s)" in r.errors[0]), r.errors


def test_redirect_to_private_address_is_blocked():
    h = engine._opener(False).handlers
    redirect = next(x for x in h if isinstance(x, urllib.request.HTTPRedirectHandler))
    req = urllib.request.Request("https://example.com/")
    with pytest.raises(engine.BlockedAddress):
        redirect.redirect_request(req, None, 302, "Found", {}, "http://169.254.169.254/")


def test_cli_and_app_may_scan_local_addresses():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            b = b"<html><body><p>hello</p></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = engine.scan_url(f"http://127.0.0.1:{srv.server_address[1]}/", allow_private=True)
    finally:
        srv.shutdown()
    assert r.verdict == "clean", r.errors


def _post(port, path, body, origin=EXT):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-InjectGuard-Token": api_token(),
                                          "Origin": origin})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e), dict(e.headers)


@pytest.fixture()
def api():
    s = Settings.load()
    s["api_port"] = 0
    a = ApiServer(s)
    port = a.start()
    yield port
    a.stop()


def test_api_has_no_file_path_endpoint(api):
    code, _, _ = _post(api, "/scan/path", {"path": "/etc/passwd"})
    assert code == 404


def test_api_url_scan_refuses_local_network(api):
    code, res, _ = _post(api, "/scan/url", {"url": "http://169.254.169.254/latest/meta-data/"})
    assert code == 200 and res["verdict"] == "error" and "local or private" in res["errors"][0]


@pytest.mark.parametrize("origin", ["chrome-extension://abc/extra/path", "chrome-extension://a b", "https://evil.example",
                                    "chrome-extension://evil.example.com"])
def test_odd_origins_rejected(api, origin):
    code, _, _ = _post(api, "/scan/text", {"text": "hi"}, origin=origin)
    assert code == 403


def test_cors_echoes_only_valid_extension_origin(api):
    code, _, headers = _post(api, "/scan/text", {"text": "hi"})
    assert code == 200 and headers.get("Access-Control-Allow-Origin") == EXT

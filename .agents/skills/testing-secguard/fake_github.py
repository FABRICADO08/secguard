"""Minimal fake GitHub (OAuth + REST) for testing SecGuard's GitHub sign-in locally.

Run: python fake_github.py [port]   (default 9100). Dispatches are appended to /tmp/fakegh.log.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9100
LOG = "/tmp/fakegh.log"
TOKEN = "gho_fake_token"


def repo(full, push, desc="", private=False, pull=True):
    return {"full_name": full, "private": private, "default_branch": "trunk" if push else "main",
            "html_url": f"http://127.0.0.1:{PORT}/{full}", "description": desc,
            "permissions": {"pull": pull, "push": push, "admin": False}}


REPOS = [
    repo("alice/secguard-demo", True, "Demo <img src=x onerror=window.__xss=1>"),
    repo("alice/readonly-lib", False, "Read-only library", private=True),
    repo("alice/never-scanned", True, "No scan yet"),
    repo("alice/<svg onload=window.__xss=2>", False, "<script>window.__xss=3</script>"),
    repo("alice/no-pull", False, "pull permission false", pull=False),
]


def log(entry):
    with open(LOG, "a") as handle:
        handle.write(json.dumps(entry) + "\n")


class Handler(BaseHTTPRequestHandler):
    def _json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authed(self):
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if url.path == "/login/oauth/authorize":
            log({"authorize": {k: v[0] for k, v in query.items()}})
            # Touch /tmp/fakegh_tamper to simulate an attacker-altered state on the way back.
            state = "TAMPERED" if os.path.exists("/tmp/fakegh_tamper") else query["state"][0]
            target = query["redirect_uri"][0] + "?" + urlencode({"code": "fake-code", "state": state})
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return
        if not self._authed():
            return self._json(401, {"message": "Bad credentials"})
        if url.path == "/user":
            return self._json(200, {"login": "alice", "name": "Alice Example", "avatar_url": ""})
        if url.path == "/user/repos":
            page = int(query.get("page", ["1"])[0])
            return self._json(200, REPOS if page == 1 else [])
        self._json(404, {"message": "Not Found"})

    def do_POST(self):
        url = urlparse(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        if url.path == "/login/oauth/access_token":
            form = parse_qs(body)
            log({"token_exchange": {k: v[0] for k, v in form.items() if k != "client_secret"}})
            if form.get("code", [""])[0] != "fake-code":
                return self._json(200, {"error": "bad_verification_code"})
            return self._json(200, {"access_token": TOKEN, "token_type": "bearer", "scope": "repo"})
        if url.path.endswith("/actions/workflows/secguard.yml/dispatches"):
            log({"dispatch": url.path, "auth_ok": self._authed(), "body": json.loads(body or "{}")})
            if not self._authed():
                return self._json(401, {"message": "Bad credentials"})
            self.send_response(204)
            self.end_headers()
            return
        self._json(404, {"message": "Not Found"})

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

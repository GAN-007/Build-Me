#!/usr/bin/env python3
"""Hardened Auto Company dashboard server.

This module preserves the existing dashboard runtime and action logic while adding
production-safe transport controls around it. The legacy ``dashboard.server``
module remains importable for compatibility and parser tests.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from dashboard import server as runtime

MAX_REQUEST_BYTES = 16 * 1024
MAX_LOG_LINES = 2_000
DEFAULT_PORT = 8787
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _is_loopback(host: str) -> bool:
    return host.strip().lower() in LOOPBACK_HOSTS


def _token_from_environment() -> str:
    return os.environ.get("AUTO_COMPANY_DASHBOARD_TOKEN", "").strip()


def _allowed_origins(host: str, port: int) -> set[str]:
    configured = {
        value.strip().rstrip("/")
        for value in os.environ.get("AUTO_COMPANY_DASHBOARD_ALLOWED_ORIGINS", "").split(",")
        if value.strip()
    }
    configured.update(
        {
            f"http://{host}:{port}",
            f"https://{host}:{port}",
        }
    )
    if _is_loopback(host):
        configured.update(
            {
                f"http://127.0.0.1:{port}",
                f"http://localhost:{port}",
                f"http://[::1]:{port}",
            }
        )
    return configured


def _secure_compare(candidate: str, expected: str) -> bool:
    if not candidate or not expected:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


class HardenedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], token: str, allowed_origins: set[str]):
        super().__init__(server_address, HardenedDashboardHandler)
        self.dashboard_token = token
        self.allowed_origins = allowed_origins
        self.server_version = "AutoCompanyDashboard/2"


class HardenedDashboardHandler(runtime.DashboardHandler):
    server: HardenedThreadingHTTPServer

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    def end_headers(self) -> None:
        self._security_headers()
        super().end_headers()

    def _json(self, payload: dict[str, Any], code: int = 200) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _text(
        self,
        text: str,
        code: int = 200,
        content_type: str = "text/plain; charset=utf-8",
    ) -> None:
        raw = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _bearer_token(self) -> str:
        authorization = self.headers.get("Authorization", "")
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer":
            return value.strip()
        return self.headers.get("X-Auto-Company-Token", "").strip()

    def _authorized(self) -> bool:
        expected = self.server.dashboard_token
        return bool(expected) and _secure_compare(self._bearer_token(), expected)

    def _origin_allowed(self) -> bool:
        origin = self.headers.get("Origin", "").strip().rstrip("/")
        if not origin:
            return True
        return origin in self.server.allowed_origins

    def _require_control_access(self) -> bool:
        if not self._origin_allowed():
            self._json(
                {"ok": False, "error": "origin_not_allowed"},
                code=HTTPStatus.FORBIDDEN,
            )
            return False
        if not self._authorized():
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("WWW-Authenticate", 'Bearer realm="auto-company-dashboard"')
            self.send_header("Content-Type", "application/json; charset=utf-8")
            raw = b'{"ok":false,"error":"authentication_required"}'
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return False
        return True

    def _discard_bounded_body(self) -> bool:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            content_length = int(raw_length)
        except ValueError:
            self._json({"ok": False, "error": "invalid_content_length"}, HTTPStatus.BAD_REQUEST)
            return False
        if content_length < 0 or content_length > MAX_REQUEST_BYTES:
            self._json({"ok": False, "error": "request_too_large"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return False
        if content_length:
            self.rfile.read(content_length)
        return True

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._json(
                {
                    "ok": True,
                    "service": "auto-company-dashboard",
                    "version": "2",
                }
            )
            return
        if parsed.path == "/api/log-tail":
            query = parse_qs(parsed.query)
            requested = runtime.parse_positive_int(query.get("lines", ["180"])[0], 180)
            lines = min(requested, MAX_LOG_LINES)
            self._json(
                {
                    "timestamp": runtime.datetime.now(runtime.timezone.utc).isoformat(),
                    "lines": lines,
                    "logTail": runtime.read_tail(runtime.LOG_FILE, lines=lines),
                }
            )
            return
        super().do_GET()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path not in {
            "/api/action/start",
            "/api/action/stop",
            "/api/action/refresh",
        }:
            self._text("Not found", code=HTTPStatus.NOT_FOUND)
            return
        if not self._discard_bounded_body() or not self._require_control_access():
            return
        super().do_POST()


def build_server(host: str, port: int, token: str) -> HardenedThreadingHTTPServer:
    normalized_host = host.strip()
    if not normalized_host:
        raise ValueError("host must not be empty")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not _is_loopback(normalized_host) and not token:
        raise ValueError(
            "AUTO_COMPANY_DASHBOARD_TOKEN is required when binding beyond loopback"
        )
    effective_token = token or secrets.token_urlsafe(32)
    return HardenedThreadingHTTPServer(
        (normalized_host, port),
        token=effective_token,
        allowed_origins=_allowed_origins(normalized_host, port),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Hardened Auto Company dashboard server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    try:
        host_kind = runtime.detect_host_kind()
        server = build_server(args.host, args.port, _token_from_environment())
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"[dashboard] {exc}")
        raise SystemExit(1) from exc

    print(f"[dashboard] serving on http://{args.host}:{args.port}")
    print(f"[dashboard] repo: {runtime.REPO_ROOT}")
    print(f"[dashboard] host: {host_kind}")
    print("[dashboard] control endpoints require a bearer token")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("[dashboard] stopped")


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    main()

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from collections import defaultdict, deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .control_plane import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    ControlPlane,
    ValidationError,
)

MAX_BODY_BYTES = 256 * 1024
DEFAULT_PORT = 8790


class SlidingWindowLimiter:
    def __init__(self, limit: int = 120, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        bucket = self.events[key]
        cutoff = now - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True


class EnterpriseHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], control_plane: ControlPlane) -> None:
        super().__init__(address, EnterpriseAPIHandler)
        self.control_plane = control_plane
        self.rate_limiter = SlidingWindowLimiter(
            int(os.environ.get("BUILD_ME_API_RATE_LIMIT", "120")), 60
        )


class EnterpriseAPIHandler(BaseHTTPRequestHandler):
    server: EnterpriseHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        request_id = getattr(self, "request_id", "-")
        print(f"[enterprise-api] request_id={request_id} client={self.client_address[0]} {format % args}")

    def _headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.send_header("X-Request-ID", self.request_id)

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self._headers()
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict[str, Any]:
        value = self.headers.get("Content-Length")
        if value is None:
            return {}
        try:
            length = int(value)
        except ValueError as exc:
            raise ValidationError("invalid Content-Length") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValidationError("request body exceeds 256 KiB")
        if length == 0:
            return {}
        if "application/json" not in self.headers.get("Content-Type", ""):
            raise ValidationError("Content-Type must be application/json")
        try:
            payload = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ValidationError("invalid JSON body") from exc
        if not isinstance(payload, dict):
            raise ValidationError("JSON body must be an object")
        return payload

    def _bearer(self) -> str:
        scheme, _, token = self.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise AuthenticationError("bearer token required")
        return token.strip()

    def _principal(self, scope: str) -> dict[str, Any]:
        principal = self.server.control_plane.authenticate(self._bearer(), scope)
        limiter_key = principal["credential_id"]
        if not self.server.rate_limiter.allow(limiter_key):
            raise ConflictError("rate limit exceeded")
        return principal

    def _dispatch(self) -> None:
        self.request_id = self.headers.get("X-Request-ID", str(uuid.uuid4()))[:128]
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if self.command == "GET" and path == "/healthz":
            self._send(HTTPStatus.OK, {"ok": True, "service": "build-me-enterprise-api", "api_version": "v1"})
            return
        if not path.startswith("/api/v1/"):
            self._send(HTTPStatus.NOT_FOUND, {"error": "not_found", "request_id": self.request_id})
            return

        if self.command == "GET" and path == "/api/v1/me":
            principal = self._principal("identity:read")
            self._send(HTTPStatus.OK, {"principal": principal})
            return

        if self.command == "POST" and path == "/api/v1/workflow-runs":
            principal = self._principal("workflow:write")
            body = self._body()
            idempotency_key = self.headers.get("Idempotency-Key", "").strip()
            if not idempotency_key:
                raise ValidationError("Idempotency-Key header is required")
            run = self.server.control_plane.start_workflow(
                principal["organization_id"],
                principal["user_id"],
                str(body.get("definition_id", "")),
                idempotency_key,
                dict(body.get("input", {})),
            )
            self._send(HTTPStatus.ACCEPTED, {"run": run})
            return

        if self.command == "POST" and path.endswith("/approve") and path.startswith("/api/v1/workflow-runs/"):
            principal = self._principal("workflow:approve")
            run_id = path.split("/")[-2]
            self.server.control_plane.approve_workflow(
                principal["organization_id"], run_id, principal["user_id"]
            )
            self._send(HTTPStatus.OK, {"ok": True, "run_id": run_id})
            return

        if self.command == "GET" and path.startswith("/api/v1/workflow-runs/"):
            principal = self._principal("workflow:read")
            run_id = path.rsplit("/", 1)[-1]
            run = self.server.control_plane.get_workflow_run(
                principal["organization_id"], principal["user_id"], run_id
            )
            self._send(HTTPStatus.OK, run)
            return

        if self.command == "POST" and path == "/api/v1/worker/leases":
            principal = self._principal("worker:lease")
            body = self._body()
            lease = self.server.control_plane.lease_next_step(
                principal["organization_id"],
                str(body.get("worker_id") or principal["user_id"]),
                int(body.get("lease_seconds", 120)),
            )
            self._send(HTTPStatus.OK, {"lease": lease})
            return

        if self.command == "POST" and path.endswith("/begin") and path.startswith("/api/v1/worker/steps/"):
            principal = self._principal("worker:execute")
            body = self._body()
            step_id = path.split("/")[-2]
            self.server.control_plane.begin_step(
                step_id,
                str(body.get("worker_id") or principal["user_id"]),
                str(body.get("lease_token", "")),
            )
            self._send(HTTPStatus.OK, {"ok": True, "step_id": step_id})
            return

        if self.command == "POST" and path.endswith("/complete") and path.startswith("/api/v1/worker/steps/"):
            principal = self._principal("worker:execute")
            body = self._body()
            step_id = path.split("/")[-2]
            self.server.control_plane.complete_step(
                step_id,
                str(body.get("worker_id") or principal["user_id"]),
                str(body.get("lease_token", "")),
                dict(body.get("output", {})),
            )
            self._send(HTTPStatus.OK, {"ok": True, "step_id": step_id})
            return

        if self.command == "POST" and path.endswith("/fail") and path.startswith("/api/v1/worker/steps/"):
            principal = self._principal("worker:execute")
            body = self._body()
            step_id = path.split("/")[-2]
            state = self.server.control_plane.fail_step(
                step_id,
                str(body.get("worker_id") or principal["user_id"]),
                str(body.get("lease_token", "")),
                dict(body.get("error", {})),
                bool(body.get("retryable", True)),
            )
            self._send(HTTPStatus.OK, {"ok": True, "step_id": step_id, "state": state})
            return

        self._send(HTTPStatus.NOT_FOUND, {"error": "not_found", "request_id": self.request_id})

    def do_GET(self) -> None:
        self._safe_dispatch()

    def do_POST(self) -> None:
        self._safe_dispatch()

    def _safe_dispatch(self) -> None:
        try:
            self._dispatch()
        except AuthenticationError as exc:
            self._send(HTTPStatus.UNAUTHORIZED, {"error": "authentication_failed", "message": str(exc), "request_id": self.request_id})
        except AuthorizationError as exc:
            self._send(HTTPStatus.FORBIDDEN, {"error": "authorization_denied", "message": str(exc), "request_id": self.request_id})
        except ValidationError as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"error": "invalid_request", "message": str(exc), "request_id": self.request_id})
        except ConflictError as exc:
            status = HTTPStatus.TOO_MANY_REQUESTS if "rate limit" in str(exc) else HTTPStatus.CONFLICT
            self._send(status, {"error": "conflict", "message": str(exc), "request_id": self.request_id})
        except Exception:
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error", "request_id": self.request_id})


def main() -> None:
    parser = argparse.ArgumentParser(description="Build-Me Enterprise API")
    parser.add_argument("--host", default=os.environ.get("BUILD_ME_API_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("BUILD_ME_API_PORT", DEFAULT_PORT)))
    parser.add_argument("--database", default=os.environ.get("BUILD_ME_DATABASE", "data/organization.db"))
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        raise SystemExit("port must be between 1 and 65535")
    server = EnterpriseHTTPServer((args.host, args.port), ControlPlane(args.database))
    print(f"[enterprise-api] serving http://{args.host}:{args.port}/api/v1")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

from __future__ import annotations

import hmac
import ipaddress
import os
import secrets
from dataclasses import dataclass
from typing import Mapping


DEFAULT_MAX_BODY_BYTES = 16_384
DEFAULT_RATE_LIMIT_REQUESTS = 120
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60


@dataclass(frozen=True)
class DashboardSecurityConfig:
    auth_token: str
    allow_remote: bool
    trusted_proxy: bool
    max_body_bytes: int
    rate_limit_requests: int
    rate_limit_window_seconds: int

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "DashboardSecurityConfig":
        env = os.environ if environ is None else environ
        token = env.get("AUTO_COMPANY_DASHBOARD_TOKEN", "").strip()
        allow_remote = _env_bool(env.get("AUTO_COMPANY_DASHBOARD_ALLOW_REMOTE"), False)
        trusted_proxy = _env_bool(env.get("AUTO_COMPANY_DASHBOARD_TRUST_PROXY"), False)
        max_body_bytes = _positive_int(
            env.get("AUTO_COMPANY_DASHBOARD_MAX_BODY_BYTES"), DEFAULT_MAX_BODY_BYTES
        )
        rate_limit_requests = _positive_int(
            env.get("AUTO_COMPANY_DASHBOARD_RATE_LIMIT_REQUESTS"),
            DEFAULT_RATE_LIMIT_REQUESTS,
        )
        rate_limit_window_seconds = _positive_int(
            env.get("AUTO_COMPANY_DASHBOARD_RATE_LIMIT_WINDOW_SECONDS"),
            DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
        )
        return cls(
            auth_token=token,
            allow_remote=allow_remote,
            trusted_proxy=trusted_proxy,
            max_body_bytes=max_body_bytes,
            rate_limit_requests=rate_limit_requests,
            rate_limit_window_seconds=rate_limit_window_seconds,
        )

    def validate_bind_host(self, host: str) -> None:
        if self.allow_remote:
            if not self.auth_token:
                raise ValueError(
                    "AUTO_COMPANY_DASHBOARD_TOKEN is required when remote access is enabled"
                )
            return

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if host.lower() == "localhost":
                return
            raise ValueError(
                "dashboard binds to loopback by default; set "
                "AUTO_COMPANY_DASHBOARD_ALLOW_REMOTE=1 and a strong token for remote access"
            ) from None

        if not address.is_loopback:
            raise ValueError(
                "dashboard binds to loopback by default; set "
                "AUTO_COMPANY_DASHBOARD_ALLOW_REMOTE=1 and a strong token for remote access"
            )

    def is_authorized(self, headers: Mapping[str, str]) -> bool:
        if not self.auth_token:
            return True
        supplied = extract_bearer_token(headers)
        return bool(supplied) and hmac.compare_digest(supplied, self.auth_token)


def extract_bearer_token(headers: Mapping[str, str]) -> str:
    authorization = headers.get("Authorization", "").strip()
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return headers.get("X-Auto-Company-Token", "").strip()


def client_ip(
    peer_host: str, headers: Mapping[str, str], *, trusted_proxy: bool = False
) -> str:
    if trusted_proxy:
        forwarded = headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
        if forwarded:
            try:
                return str(ipaddress.ip_address(forwarded))
            except ValueError:
                pass
    try:
        return str(ipaddress.ip_address(peer_host))
    except ValueError:
        return peer_host


def generate_token() -> str:
    return secrets.token_urlsafe(48)


def _env_bool(value: str | None, default: bool) -> bool:
    if value is None or not value.strip():
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean value: {value!r}")


def _positive_int(value: str | None, default: int) -> int:
    if value is None or not value.strip():
        return default
    parsed = int(value)
    if parsed <= 0:
        raise ValueError("value must be greater than zero")
    return parsed

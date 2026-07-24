import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECURITY_PATH = ROOT / "dashboard" / "security.py"
RATE_LIMIT_PATH = ROOT / "dashboard" / "rate_limit.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


security = load_module("dashboard_security", SECURITY_PATH)
rate_limit = load_module("dashboard_rate_limit", RATE_LIMIT_PATH)


class DashboardSecurityTests(unittest.TestCase):
    def test_loopback_bind_allowed_without_token(self) -> None:
        config = security.DashboardSecurityConfig.from_env({})
        config.validate_bind_host("127.0.0.1")
        config.validate_bind_host("::1")
        config.validate_bind_host("localhost")

    def test_remote_bind_requires_explicit_enablement(self) -> None:
        config = security.DashboardSecurityConfig.from_env({})
        with self.assertRaisesRegex(ValueError, "loopback"):
            config.validate_bind_host("0.0.0.0")

    def test_remote_bind_requires_token(self) -> None:
        config = security.DashboardSecurityConfig.from_env(
            {"AUTO_COMPANY_DASHBOARD_ALLOW_REMOTE": "1"}
        )
        with self.assertRaisesRegex(ValueError, "TOKEN"):
            config.validate_bind_host("0.0.0.0")

    def test_remote_bind_with_token_is_allowed(self) -> None:
        config = security.DashboardSecurityConfig.from_env(
            {
                "AUTO_COMPANY_DASHBOARD_ALLOW_REMOTE": "true",
                "AUTO_COMPANY_DASHBOARD_TOKEN": "strong-secret",
            }
        )
        config.validate_bind_host("0.0.0.0")

    def test_bearer_and_custom_header_authentication(self) -> None:
        config = security.DashboardSecurityConfig.from_env(
            {"AUTO_COMPANY_DASHBOARD_TOKEN": "secret"}
        )
        self.assertTrue(config.is_authorized({"Authorization": "Bearer secret"}))
        self.assertTrue(config.is_authorized({"X-Auto-Company-Token": "secret"}))
        self.assertFalse(config.is_authorized({"Authorization": "Bearer wrong"}))

    def test_invalid_boolean_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid boolean"):
            security.DashboardSecurityConfig.from_env(
                {"AUTO_COMPANY_DASHBOARD_ALLOW_REMOTE": "perhaps"}
            )

    def test_trusted_proxy_uses_valid_forwarded_ip(self) -> None:
        self.assertEqual(
            security.client_ip(
                "127.0.0.1",
                {"X-Forwarded-For": "203.0.113.10, 10.0.0.1"},
                trusted_proxy=True,
            ),
            "203.0.113.10",
        )


class RateLimiterTests(unittest.TestCase):
    def test_sliding_window_enforces_limit_and_recovers(self) -> None:
        now = [100.0]
        limiter = rate_limit.SlidingWindowRateLimiter(
            limit=2, window_seconds=10, clock=lambda: now[0]
        )
        self.assertTrue(limiter.allow("client"))
        self.assertTrue(limiter.allow("client"))
        self.assertFalse(limiter.allow("client"))
        now[0] = 111.0
        self.assertTrue(limiter.allow("client"))

    def test_clients_are_isolated(self) -> None:
        limiter = rate_limit.SlidingWindowRateLimiter(
            limit=1, window_seconds=60, clock=lambda: 1.0
        )
        self.assertTrue(limiter.allow("a"))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))


if __name__ == "__main__":
    unittest.main()

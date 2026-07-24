from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from dashboard import secure_server


class SecureDashboardConfigurationTests(unittest.TestCase):
    def test_loopback_is_recognized(self) -> None:
        self.assertTrue(secure_server._is_loopback("127.0.0.1"))
        self.assertTrue(secure_server._is_loopback("localhost"))
        self.assertTrue(secure_server._is_loopback("::1"))
        self.assertFalse(secure_server._is_loopback("0.0.0.0"))

    def test_token_comparison_rejects_empty_values(self) -> None:
        self.assertFalse(secure_server._secure_compare("", "secret"))
        self.assertFalse(secure_server._secure_compare("secret", ""))
        self.assertTrue(secure_server._secure_compare("secret", "secret"))
        self.assertFalse(secure_server._secure_compare("secret", "different"))

    def test_non_loopback_binding_requires_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "TOKEN is required"):
            secure_server.build_server("0.0.0.0", 8787, "")

    def test_invalid_port_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "port must be"):
            secure_server.build_server("127.0.0.1", 70000, "token")

    def test_configured_origins_are_normalized(self) -> None:
        with patch.dict(
            os.environ,
            {"AUTO_COMPANY_DASHBOARD_ALLOWED_ORIGINS": "https://ops.example.com/, https://admin.example.com"},
            clear=False,
        ):
            origins = secure_server._allowed_origins("127.0.0.1", 8787)
        self.assertIn("https://ops.example.com", origins)
        self.assertIn("https://admin.example.com", origins)
        self.assertIn("http://localhost:8787", origins)

    @patch("dashboard.secure_server.HardenedThreadingHTTPServer")
    def test_loopback_build_uses_generated_token_when_unconfigured(self, server_cls) -> None:
        secure_server.build_server("127.0.0.1", 8787, "")
        _, kwargs = server_cls.call_args
        self.assertGreaterEqual(len(kwargs["token"]), 32)
        self.assertIn("http://127.0.0.1:8787", kwargs["allowed_origins"])

    @patch("dashboard.secure_server.HardenedThreadingHTTPServer")
    def test_non_loopback_build_preserves_explicit_token(self, server_cls) -> None:
        secure_server.build_server("0.0.0.0", 8787, "production-secret")
        _, kwargs = server_cls.call_args
        self.assertEqual(kwargs["token"], "production-secret")


if __name__ == "__main__":
    unittest.main()

"""Website rules. Uses Flask's test client, so no port is opened."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app as webapp  # noqa: E402


class Clock:
    def __init__(self) -> None:
        self.value = 1_800_000_000.0

    def __call__(self) -> float:
        return self.value


class WebTest(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {
            name: os.environ.get(name)
            for name in ("OTP_VALIDITY_SECONDS", "OTP_LOCKOUT_SECONDS", "OTP_DEMO_SECRET")
        }
        for name in self._saved:
            os.environ.pop(name, None)
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def test_home_page_shows_the_assignment_window(self) -> None:
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        self.assertIn("OTP Generator and Verifier", html)
        self.assertIn("30", html)
        self.assertIn("60", html)
        self.assertNotIn("REHEARSAL MODE", html)
        script = self.client.get("/static/app.js")
        style = self.client.get("/static/styles.css")
        self.assertEqual(script.status_code, 200)
        self.assertEqual(style.status_code, 200)
        script.close()
        style.close()

    def test_health_and_parameters(self) -> None:
        health = self.client.get("/api/health").get_json()
        self.assertTrue(health["ok"])
        demo = self.client.get("/api/parameters").get_json()["demo"]
        self.assertEqual(demo["validity_seconds"], 30)
        self.assertEqual(demo["lockout_seconds"], 60)

    def test_wrong_then_right_then_replay(self) -> None:
        issued = self.client.post("/api/challenge").get_json()
        self.assertEqual(len(issued["otp"]), 6)
        wrong = "000000" if issued["otp"] != "000000" else "111111"
        mismatch = self.client.post(
            "/api/verify",
            json={"otp": wrong, "token": issued["token"]},
        ).get_json()
        self.assertEqual(mismatch["status"], "mismatch")
        invalid = self.client.post(
            "/api/verify",
            json={"otp": "12ab", "token": issued["token"]},
        ).get_json()
        self.assertEqual(invalid["status"], "invalid")
        success = self.client.post(
            "/api/verify",
            json={"otp": issued["otp"], "token": issued["token"]},
        )
        self.assertEqual(success.get_json()["status"], "success")
        self.assertIn("otp_used", success.headers.get("Set-Cookie", ""))
        replay = self.client.post(
            "/api/verify",
            json={"otp": issued["otp"], "token": issued["token"]},
        ).get_json()
        self.assertEqual(replay["status"], "used")

    def test_late_otp_locks_the_browser_cookie(self) -> None:
        clock = Clock()
        with patch("otp.core.now", clock):
            issued = self.client.post("/api/challenge")
            self.assertEqual(issued.status_code, 200)
            body = issued.get_json()
            clock.value = body["expires_at"] + 1
            late = self.client.post(
                "/api/verify",
                json={"otp": body["otp"], "token": body["token"]},
            )
            payload = late.get_json()
            self.assertEqual(payload["status"], "expired")
            self.assertIn("second 31", payload["message"])
            self.assertEqual(payload["retry_after"], 60)
            self.assertIn("otp_lock", late.headers.get("Set-Cookie", ""))
            blocked = self.client.post("/api/challenge")
            self.assertEqual(blocked.status_code, 423)
            self.assertEqual(blocked.get_json()["status"], "locked")
            status = self.client.get("/api/lock-status").get_json()
            self.assertTrue(status["locked"])

    def test_forged_token_does_not_lock(self) -> None:
        forged = "v1~1030.000~30~" + ("ab" * 8) + "~" + ("a" * 64) + "~" + ("b" * 64)
        result = self.client.post("/api/verify", json={"otp": "123456", "token": forged})
        self.assertEqual(result.get_json()["status"], "invalid")
        self.assertNotIn("otp_lock", result.headers.get("Set-Cookie", ""))
        self.assertEqual(self.client.post("/api/challenge").status_code, 200)

    def test_vectors_totp_and_hotp(self) -> None:
        report = self.client.get("/api/vectors").get_json()
        self.assertTrue(report["passed"])
        self.assertGreaterEqual(report["count"], 30)
        self.assertEqual(report["rows"][0]["expected"], "755224")

        current = self.client.get("/api/totp").get_json()
        self.assertEqual(len(current["otp"]), 6)
        self.assertEqual(
            self.client.post("/api/verify-totp", json={"otp": current["otp"]}).get_json()["status"],
            "success",
        )
        wrong = "000000" if current["otp"] != "000000" else "111111"
        self.assertEqual(
            self.client.post("/api/verify-totp", json={"otp": wrong}).get_json()["status"],
            "mismatch",
        )

        shown = self.client.post("/api/hotp", json={"counter": 0}).get_json()
        self.assertEqual(shown["otp"], "755224")
        self.assertEqual(
            self.client.post(
                "/api/verify-hotp",
                json={"otp": "755224", "counter": 0},
            ).get_json()["status"],
            "success",
        )
        self.assertEqual(
            self.client.post(
                "/api/verify-hotp",
                json={"otp": "000000", "counter": 0},
            ).get_json()["status"],
            "mismatch",
        )
        self.assertEqual(
            self.client.post("/api/hotp", json={"counter": -1}).status_code,
            400,
        )

    def test_bad_requests_are_json(self) -> None:
        self.assertEqual(self.client.post("/api/verify", json={}).get_json()["status"], "invalid")
        self.assertEqual(self.client.get("/api/verify").status_code, 405)
        self.assertEqual(self.client.get("/api/does-not-exist").status_code, 404)
        self.assertIn("Unknown API", self.client.get("/api/does-not-exist").get_json()["message"])
        missing = self.client.get("/no-such-page")
        self.assertEqual(missing.status_code, 404)
        self.assertIn("Page not found", missing.get_data(as_text=True))

    def test_rehearsal_banner_uses_the_environment_window(self) -> None:
        os.environ["OTP_VALIDITY_SECONDS"] = "8"
        os.environ["OTP_LOCKOUT_SECONDS"] = "10"
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("REHEARSAL MODE", html)
        issued = self.client.post("/api/challenge").get_json()
        self.assertAlmostEqual(issued["expires_at"] - issued["issued_at"], 8, places=2)


if __name__ == "__main__":
    unittest.main()

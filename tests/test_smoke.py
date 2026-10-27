"""Smoke checks for the console program and the website.

These are short "does the product still start" checks on top of the
unit tests. They do not wait out the 60-second lock.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app as webapp  # noqa: E402
from otp.console import main as console_main  # noqa: E402
from otp.core import (  # noqa: E402
    issue_demo_challenge,
    public_parameters,
    vectors_passed,
    verify_demo_challenge,
)


class ConsoleSmokeTest(unittest.TestCase):
    def test_sample_and_vectors_exit_zero(self) -> None:
        sample = io.StringIO()
        with redirect_stdout(sample):
            self.assertEqual(console_main(["--sample"]), 0)
        text = sample.getvalue()
        self.assertIn("SUCCESS", text)
        self.assertIn("EXPIRED", text)
        self.assertIn("LOCKED", text)

        vectors = io.StringIO()
        with redirect_stdout(vectors):
            self.assertEqual(console_main(["--vectors"]), 0)
        self.assertIn("All 34 sample test vectors passed.", vectors.getvalue())

    def test_main_py_subprocess(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "main.py"), "--vectors"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("755224", result.stdout)
        self.assertIn("All 34 sample test vectors passed.", result.stdout)

    def test_assignment_parameters_are_public(self) -> None:
        demo = public_parameters()["demo"]
        self.assertEqual(demo["assignment_validity_seconds"], 30)
        self.assertEqual(demo["assignment_lockout_seconds"], 60)
        self.assertTrue(vectors_passed())


class FrontendSmokeTest(unittest.TestCase):
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

    def test_home_and_static_assets(self) -> None:
        home = self.client.get("/")
        self.assertEqual(home.status_code, 200)
        html = home.get_data(as_text=True)
        self.assertIn("OTP Generator and Verifier", html)
        self.assertIn("30s", html)
        self.assertIn("60s", html)
        self.assertIn("Generate new OTP", html)
        script = self.client.get("/static/app.js")
        style = self.client.get("/static/styles.css")
        self.assertEqual(script.status_code, 200)
        self.assertEqual(style.status_code, 200)
        self.assertIn("startLock", script.get_data(as_text=True))
        script.close()
        style.close()

    def test_api_health_parameters_and_vectors(self) -> None:
        self.assertTrue(self.client.get("/api/health").get_json()["ok"])
        demo = self.client.get("/api/parameters").get_json()["demo"]
        self.assertEqual(demo["validity_seconds"], 30)
        self.assertEqual(demo["lockout_seconds"], 60)
        report = self.client.get("/api/vectors").get_json()
        self.assertTrue(report["passed"])
        self.assertEqual(report["count"], 34)

    def test_generate_verify_success_path(self) -> None:
        issued = self.client.post("/api/challenge").get_json()
        self.assertEqual(len(issued["otp"]), 6)
        self.assertIn("token", issued)
        result = self.client.post(
            "/api/verify",
            json={"otp": issued["otp"], "token": issued["token"]},
        ).get_json()
        self.assertEqual(result["status"], "success")

    def test_generate_verify_failure_path(self) -> None:
        issued = self.client.post("/api/challenge").get_json()
        wrong = "000000" if issued["otp"] != "000000" else "111111"
        result = self.client.post(
            "/api/verify",
            json={"otp": wrong, "token": issued["token"]},
        ).get_json()
        self.assertEqual(result["status"], "mismatch")

    def test_core_and_website_share_expiry_rule(self) -> None:
        challenge = issue_demo_challenge(when=1_000.0, validity=30, otp="123456")
        late = verify_demo_challenge("123456", challenge.token, when=1_030.0)
        self.assertEqual(late["status"], "expired")
        self.assertEqual(late["lockout_seconds"], 60)


if __name__ == "__main__":
    unittest.main()

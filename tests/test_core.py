"""Rules for the demo OTP, HOTP, TOTP, and the sample vectors.

Run from the project folder:

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from otp.core import (  # noqa: E402
    HOTP_VECTORS,
    LOCKOUT_SECONDS,
    OTP_DIGITS,
    RFC_SHA1_SECRET,
    RFC_SHA256_SECRET,
    RFC_SHA512_SECRET,
    TOTP_RFC_VECTORS,
    TOTP_SHA1_6_VECTORS,
    VALIDITY_SECONDS,
    displayed_seconds,
    generate_numeric_otp,
    hotp,
    issue_demo_challenge,
    public_parameters,
    read_lock,
    read_used_nonce,
    run_test_vectors,
    sign_lock,
    sign_used_nonce,
    totp,
    using_assignment_defaults,
    validity_seconds,
    verify_demo_challenge,
    verify_hotp,
    verify_totp,
    vectors_passed,
)


class DefaultsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {
            name: os.environ.get(name)
            for name in ("OTP_VALIDITY_SECONDS", "OTP_LOCKOUT_SECONDS", "OTP_DEMO_SECRET")
        }
        os.environ.pop("OTP_VALIDITY_SECONDS", None)
        os.environ.pop("OTP_LOCKOUT_SECONDS", None)
        os.environ.pop("OTP_DEMO_SECRET", None)

    def tearDown(self) -> None:
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def test_assignment_window_and_lockout(self) -> None:
        self.assertEqual(OTP_DIGITS, 6)
        self.assertEqual(VALIDITY_SECONDS, 30)
        self.assertEqual(LOCKOUT_SECONDS, 60)
        self.assertEqual(validity_seconds(), 30)
        self.assertTrue(using_assignment_defaults())
        demo = public_parameters()["demo"]
        self.assertEqual(demo["validity_seconds"], 30)
        self.assertEqual(demo["lockout_seconds"], 60)

    def test_secret_lengths_match_the_rfcs(self) -> None:
        self.assertEqual(len(RFC_SHA1_SECRET), 20)
        self.assertEqual(len(RFC_SHA256_SECRET), 32)
        self.assertEqual(len(RFC_SHA512_SECRET), 64)


class DemoOtpTest(unittest.TestCase):
    def setUp(self) -> None:
        os.environ.pop("OTP_LOCKOUT_SECONDS", None)

    def test_generator_keeps_leading_zeros(self) -> None:
        for _ in range(30):
            code = generate_numeric_otp()
            self.assertEqual(len(code), 6)
            self.assertTrue(code.isdigit())

    def test_success_inside_the_window(self) -> None:
        challenge = issue_demo_challenge(when=1_000.0, validity=30, otp="482913")
        result = verify_demo_challenge("482913", challenge.token, when=1_005.0)
        self.assertEqual(result["status"], "success")
        self.assertIn("30-second", result["message"])

    def test_wrong_code_is_a_failure_and_can_be_retried(self) -> None:
        challenge = issue_demo_challenge(when=1_000.0, validity=30, otp="482913")
        wrong = verify_demo_challenge("000000", challenge.token, when=1_010.0)
        self.assertEqual(wrong["status"], "mismatch")
        again = verify_demo_challenge("482913", challenge.token, when=1_012.0)
        self.assertEqual(again["status"], "success")

    def test_invalid_shapes_do_not_match(self) -> None:
        challenge = issue_demo_challenge(when=1_000.0, validity=30, otp="482913")
        for guess in ("", "12345", "1234567", "12ab34", "123 456", "١٢٣٤٥٦", None, 3.14):
            result = verify_demo_challenge(guess, challenge.token, when=1_005.0)
            self.assertEqual(result["status"], "invalid", guess)

    def test_surrounding_spaces_are_ignored(self) -> None:
        challenge = issue_demo_challenge(when=1_000.0, validity=30, otp="012345")
        result = verify_demo_challenge("  012345  ", challenge.token, when=1_001.0)
        self.assertEqual(result["status"], "success")

    def test_exact_deadline_is_second_31_and_expires(self) -> None:
        challenge = issue_demo_challenge(when=1_000.0, validity=30, otp="550019")
        just_inside = verify_demo_challenge("550019", challenge.token, when=1_029.999)
        self.assertEqual(just_inside["status"], "success")
        at_deadline = verify_demo_challenge("550019", challenge.token, when=1_030.0)
        self.assertEqual(at_deadline["status"], "expired")
        self.assertIn("second 31", at_deadline["message"])
        self.assertEqual(at_deadline["lockout_seconds"], 60)
        # A wrong late code is still the time-bomb, not a normal failure.
        late_wrong = verify_demo_challenge("000000", challenge.token, when=1_031.0)
        self.assertEqual(late_wrong["status"], "expired")
        late_junk = verify_demo_challenge("abcdef", challenge.token, when=1_040.0)
        self.assertEqual(late_junk["status"], "expired")

    def test_edited_token_is_rejected_without_looking_like_a_late_otp(self) -> None:
        forged = "v1~1030.000~30~" + ("ab" * 8) + "~" + ("a" * 64) + "~" + ("b" * 64)
        result = verify_demo_challenge("123456", forged, when=2_000.0)
        self.assertEqual(result["status"], "invalid")

    def test_used_nonce_cannot_be_replayed_early(self) -> None:
        challenge = issue_demo_challenge(when=1_000.0, validity=30, otp="109284")
        result = verify_demo_challenge(
            "109284",
            challenge.token,
            when=1_010.0,
            used_nonce=challenge.nonce,
        )
        self.assertEqual(result["status"], "used")

    def test_lock_cookie_round_trip(self) -> None:
        cookie = sign_lock(2_000.0)
        self.assertEqual(read_lock(cookie, when=1_999.0), 2_000.0)
        self.assertEqual(read_lock(cookie, when=2_000.0), 0.0)
        self.assertEqual(read_lock("2000.000~" + ("0" * 64), when=1_000.0), 0.0)
        used = sign_used_nonce("ab" * 8)
        self.assertEqual(read_used_nonce(used), "ab" * 8)
        self.assertIsNone(read_used_nonce("nope"))

    def test_countdown_label(self) -> None:
        self.assertEqual(displayed_seconds(30), 30)
        self.assertEqual(displayed_seconds(29.2), 30)
        self.assertEqual(displayed_seconds(29), 29)
        self.assertEqual(displayed_seconds(0.1), 1)
        self.assertEqual(displayed_seconds(0), 0)


class StandardsTest(unittest.TestCase):
    def test_official_hotp_vectors(self) -> None:
        for counter, expected in HOTP_VECTORS:
            self.assertEqual(hotp(RFC_SHA1_SECRET, counter), expected)

    def test_official_totp_vectors(self) -> None:
        secrets = {
            "sha1": RFC_SHA1_SECRET,
            "sha256": RFC_SHA256_SECRET,
            "sha512": RFC_SHA512_SECRET,
        }
        for timestamp, algorithm, expected in TOTP_RFC_VECTORS:
            actual = totp(secrets[algorithm], timestamp, digits=8, algorithm=algorithm)
            self.assertEqual(actual, expected, (timestamp, algorithm))

    def test_six_digit_totp_matches_last_digits_of_the_rfc_table(self) -> None:
        for timestamp, expected in TOTP_SHA1_6_VECTORS:
            eight = totp(RFC_SHA1_SECRET, timestamp, digits=8, algorithm="sha1")
            six = totp(RFC_SHA1_SECRET, timestamp, digits=6, algorithm="sha1")
            self.assertEqual(six, eight[-6:])
            self.assertEqual(six, expected)

    def test_totp_skew_accepts_one_neighbouring_step_only(self) -> None:
        # t=59 is step counter 1. The next step starts at t=60.
        current = totp(RFC_SHA1_SECRET, 59, digits=6)
        upcoming = totp(RFC_SHA1_SECRET, 60, digits=6)
        self.assertEqual(verify_totp(current, when=59)["status"], "success")
        self.assertEqual(verify_totp(upcoming, when=59)["status"], "success")
        # Two steps away (counter at t=0 is 0; t=59 is counter 1; t=90 is counter 3).
        two_steps_later = totp(RFC_SHA1_SECRET, 90, digits=6)
        self.assertEqual(verify_totp(two_steps_later, when=59)["status"], "mismatch")

    def test_hotp_failure_does_not_claim_the_counter_moved(self) -> None:
        self.assertEqual(verify_hotp("755224", 0)["status"], "success")
        wrong = verify_hotp("000000", 0)
        self.assertEqual(wrong["status"], "mismatch")
        self.assertIn("not changed", wrong["message"])
        self.assertEqual(verify_hotp("12345", 0)["status"], "invalid")

    def test_bundled_report_passes(self) -> None:
        rows = run_test_vectors()
        self.assertGreaterEqual(len(rows), 30)
        self.assertTrue(vectors_passed(rows))
        self.assertTrue(all(row["actual"] == row["expected"] for row in rows))


if __name__ == "__main__":
    unittest.main()

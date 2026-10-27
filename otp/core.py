"""Shared OTP rules for the console program and the Vercel website.

Three kinds of one-time password live here:

1. Demo OTP
   A random 6-digit code from ``secrets.randbelow``.
   It is valid for 30 seconds after it is issued.
   A submission at that deadline or later is expired. The apps then
   lock input for 60 seconds. This is the "time-bomb".

2. HOTP (RFC 4226), event-based
   The code is HMAC-SHA1 of a counter. It changes only when the
   counter changes. A wrong guess does not move the counter.

3. TOTP (RFC 6238), time-based
   The same HMAC construction as HOTP, but the counter is the number
   of 30-second steps since the Unix epoch. This app accepts the
   previous, current, and next step (skew of +/- 1).

The demo code is shown on screen on purpose so the flow can be graded.
A production system would send the code on another channel and store
only a hash. Do not reuse the sample secrets for a real account.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
from dataclasses import dataclass


# Assignment defaults. Tests lock these numbers so they cannot drift.
OTP_DIGITS = 6
VALIDITY_SECONDS = 30
LOCKOUT_SECONDS = 60
TOTP_STEP_SECONDS = 30
TOTP_SKEW_STEPS = 1
TOTP_T0 = 0
HOTP_LOOKAHEAD = 0

# Public sample secret printed in RFC 4226 and RFC 6238.
# 20 bytes for SHA-1, 32 for SHA-256, 64 for SHA-512.
RFC_SHA1_SECRET = b"12345678901234567890"
RFC_SHA256_SECRET = b"12345678901234567890123456789012"
RFC_SHA512_SECRET = b"1234567890123456789012345678901234567890123456789012345678901234"

_RFC_SECRETS = {
    "sha1": RFC_SHA1_SECRET,
    "sha256": RFC_SHA256_SECRET,
    "sha512": RFC_SHA512_SECRET,
}

# Official HOTP values from RFC 4226 Appendix D (6 digits, SHA-1).
HOTP_VECTORS: tuple[tuple[int, str], ...] = (
    (0, "755224"),
    (1, "287082"),
    (2, "359152"),
    (3, "969429"),
    (4, "338314"),
    (5, "254676"),
    (6, "287922"),
    (7, "162583"),
    (8, "399871"),
    (9, "520489"),
)

# Official TOTP values from RFC 6238 Appendix B (8 digits).
# timestamp, algorithm, otp
TOTP_RFC_VECTORS: tuple[tuple[int, str, str], ...] = (
    (59, "sha1", "94287082"),
    (59, "sha256", "46119246"),
    (59, "sha512", "90693936"),
    (1111111109, "sha1", "07081804"),
    (1111111109, "sha256", "68084774"),
    (1111111109, "sha512", "25091201"),
    (1111111111, "sha1", "14050471"),
    (1111111111, "sha256", "67062674"),
    (1111111111, "sha512", "99943326"),
    (1234567890, "sha1", "89005924"),
    (1234567890, "sha256", "91819424"),
    (1234567890, "sha512", "93441116"),
    (2000000000, "sha1", "69279037"),
    (2000000000, "sha256", "90698825"),
    (2000000000, "sha512", "38618901"),
    (20000000000, "sha1", "65353130"),
    (20000000000, "sha256", "77737706"),
    (20000000000, "sha512", "47863826"),
)

# Same timestamps and SHA-1 secret as the RFC, kept to 6 digits.
# The 6-digit code is the same truncated integer modulo 1_000_000, so it
# matches the last six digits of the official 8-digit code. test_core.py
# locks these strings. The 8-digit rows remain the RFC's own published checks.
TOTP_SHA1_6_VECTORS: tuple[tuple[int, str], ...] = (
    (59, "287082"),
    (1111111109, "081804"),
    (1111111111, "050471"),
    (1234567890, "005924"),
    (2000000000, "279037"),
    (20000000000, "353130"),
)

_DEFAULT_DEMO_SECRET = "classroom-demo-only-not-for-real-accounts"
_TOKEN_PART = re.compile(r"^[0-9a-f]{64}$")
_NONCE_PART = re.compile(r"^[0-9a-f]{16}$")
_EXPIRES_PART = re.compile(r"^\d+\.\d{3}$")


def now() -> float:
    """Current time in seconds. Tests replace this function."""

    return time.time()


def validity_seconds() -> int:
    """Demo window. Defaults to 30. ``OTP_VALIDITY_SECONDS`` can rehearse a shorter bar."""

    return _bounded_env_int("OTP_VALIDITY_SECONDS", VALIDITY_SECONDS, low=5, high=120)


def lockout_seconds() -> int:
    """How long input stays locked after a late OTP. Defaults to 60."""

    return _bounded_env_int("OTP_LOCKOUT_SECONDS", LOCKOUT_SECONDS, low=5, high=300)


def using_assignment_defaults() -> bool:
    """True when the graded 30-second window and 60-second lockout are active."""

    return validity_seconds() == VALIDITY_SECONDS and lockout_seconds() == LOCKOUT_SECONDS


def _bounded_env_int(name: str, default: int, *, low: int, high: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value < low:
        return low
    if value > high:
        return high
    return value


def _demo_secret() -> bytes:
    """Key used only to sign demo tokens. It is not the OTP itself."""

    value = os.environ.get("OTP_DEMO_SECRET", _DEFAULT_DEMO_SECRET).strip()
    if len(value) < 16:
        raise RuntimeError("OTP_DEMO_SECRET must be at least 16 characters.")
    return value.encode("utf-8")


def _sign(message: str) -> str:
    """Hex HMAC-SHA256. Used for tokens and cookies, not for HOTP/TOTP."""

    return hmac.new(_demo_secret(), message.encode("utf-8"), hashlib.sha256).hexdigest()


def _result(status: str, title: str, message: str, **extra: object) -> dict:
    body = {"status": status, "title": title, "message": message}
    body.update(extra)
    return body


def is_decimal_otp(value: object, digits: int = OTP_DIGITS) -> bool:
    """True only for an ASCII code of exactly ``digits`` characters.

    ``str.isdigit()`` is not enough: it accepts digits from other
    scripts. Those must not count as a 6-digit OTP.
    """

    if not isinstance(value, str):
        return False
    if len(value) != digits:
        return False
    return all(character in "0123456789" for character in value)


def generate_numeric_otp(digits: int = OTP_DIGITS) -> str:
    """Return a zero-padded numeric OTP.

    ``secrets.randbelow`` is the cryptographic generator. The ``random``
    module is not used, because it is not meant for security codes.
    Leading zeros are kept: 000042 is a real code, not the number 42.
    """

    if digits not in (6, 7, 8):
        raise ValueError("digits must be 6, 7, or 8")
    return f"{secrets.randbelow(10 ** digits):0{digits}d}"


def displayed_seconds(remaining: float) -> int:
    """Whole seconds still left, for the countdown label.

    30.0 displays as 30. 29.2 displays as 30 for that first fraction,
    then 29 once a full second has passed. 0 means the window is shut.
    """

    if remaining <= 0:
        return 0
    seconds = int(remaining)
    if remaining > seconds:
        seconds += 1
    return seconds


@dataclass(frozen=True)
class DemoChallenge:
    """A demo OTP plus the signed token that can check it later.

    ``otp`` is returned so a classroom screen can show it. The token does
    not contain the OTP in clear text. The website can check a guess
    without storing the code, which is what a serverless host needs.
    """

    otp: str
    issued_at: float
    expires_at: float
    validity_seconds: int
    nonce: str
    token: str

    def public_dict(self) -> dict:
        return {
            "otp": self.otp,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "validity_seconds": self.validity_seconds,
            "lockout_seconds": lockout_seconds(),
            "digits": OTP_DIGITS,
            "token": self.token,
            "demo_only": True,
            "message": (
                "Shown for the classroom demo. A production system would not "
                "return the OTP on the same channel that verifies it."
            ),
        }


def issue_demo_challenge(
    when: float | None = None,
    validity: int | None = None,
    digits: int = OTP_DIGITS,
    otp: str | None = None,
) -> DemoChallenge:
    """Create a demo OTP that expires after ``validity`` seconds.

    ``otp`` is optional so tests and the printed sample can use a fixed
    code. The website never passes that argument; live codes come from
    ``generate_numeric_otp``.
    """

    if validity is None:
        validity = validity_seconds()
    if not isinstance(validity, int) or isinstance(validity, bool):
        raise ValueError("validity must be a whole number of seconds")
    if validity < 1:
        raise ValueError("validity must be at least 1 second")

    issued_at = now() if when is None else float(when)
    if otp is None:
        code = generate_numeric_otp(digits)
    else:
        if not is_decimal_otp(otp, digits):
            raise ValueError("otp override must be an ASCII numeric code of the right length")
        code = otp

    expires_at = issued_at + validity
    expires_s = f"{expires_at:.3f}"
    nonce = secrets.token_hex(8)
    # Two different HMACs so a signature for the envelope cannot be
    # pasted into the OTP slot. The prefixes stop that swap.
    envelope_mac = _sign(f"env|{expires_s}|{validity}|{nonce}")
    otp_mac = _sign(f"otp|{code}|{nonce}")
    token = "~".join(("v1", expires_s, str(validity), nonce, envelope_mac, otp_mac))
    return DemoChallenge(
        otp=code,
        issued_at=issued_at,
        expires_at=expires_at,
        validity_seconds=validity,
        nonce=nonce,
        token=token,
    )


@dataclass(frozen=True)
class _ParsedToken:
    expires_at: float
    expires_s: str
    validity: int
    nonce: str
    otp_mac: str


def _parse_token(token: object) -> _ParsedToken | None:
    if not isinstance(token, str):
        return None
    parts = token.split("~")
    if len(parts) != 6 or parts[0] != "v1":
        return None
    _version, expires_s, validity_s, nonce, envelope_mac, otp_mac = parts
    if not _EXPIRES_PART.fullmatch(expires_s):
        return None
    if not validity_s.isdigit():
        return None
    if not _NONCE_PART.fullmatch(nonce):
        return None
    if not _TOKEN_PART.fullmatch(envelope_mac) or not _TOKEN_PART.fullmatch(otp_mac):
        return None
    expected_envelope = _sign(f"env|{expires_s}|{validity_s}|{nonce}")
    if not hmac.compare_digest(expected_envelope, envelope_mac):
        return None
    return _ParsedToken(
        expires_at=float(expires_s),
        expires_s=expires_s,
        validity=int(validity_s),
        nonce=nonce,
        otp_mac=otp_mac,
    )


def _prepare_submission(submitted: object, digits: int = OTP_DIGITS) -> str | None:
    """Return a 6-digit string, or None if the input cannot be an OTP.

    A JSON number is accepted only as a convenience for hand-written
    requests. Leading zeros cannot survive that path, so the website
    always sends the OTP as text.
    """

    if isinstance(submitted, str):
        text = submitted.strip()
    elif isinstance(submitted, int) and not isinstance(submitted, bool):
        if submitted < 0 or submitted >= 10 ** digits:
            return None
        text = f"{submitted:0{digits}d}"
    else:
        return None
    if not is_decimal_otp(text, digits):
        return None
    return text


def verify_demo_challenge(
    submitted: object,
    token: object,
    when: float | None = None,
    used_nonce: str | None = None,
    lockout_for_message: int | None = None,
) -> dict:
    """Check a demo guess against a signed challenge.

    Status values the apps understand:

    - success: right code, inside the window
    - mismatch: wrong code, window still open
    - invalid: not 6 digits, or the token was edited
    - used: this code was already accepted
    - expired: the submission is at the deadline or later

    Expiry is decided before right-versus-wrong. A correct code entered
    late is still expired. That is the time-bomb rule.
    """

    current = now() if when is None else float(when)
    parsed = _parse_token(token)
    if parsed is None:
        return _result(
            "invalid",
            "INVALID",
            "This challenge is not valid or was edited. Generate a new OTP.",
        )

    if current >= parsed.expires_at:
        if parsed.validity == VALIDITY_SECONDS:
            when_text = "second 31 or later"
        else:
            when_text = f"after the {parsed.validity}-second window"
        # The console can pass its own lockout (the --lockout flag).
        # The website leaves this empty and uses the shared default.
        duration = lockout_seconds() if lockout_for_message is None else lockout_for_message
        return _result(
            "expired",
            "EXPIRED",
            (
                f"The submission is outside the {parsed.validity}-second window "
                f"({when_text}). Input will lock for {duration} seconds."
            ),
            lockout_seconds=duration,
            validity_seconds=parsed.validity,
        )

    if used_nonce and hmac.compare_digest(used_nonce, parsed.nonce):
        return _result(
            "used",
            "ALREADY USED",
            "That OTP was already accepted. Generate a new one.",
        )

    code = _prepare_submission(submitted, OTP_DIGITS)
    if code is None:
        return _result(
            "invalid",
            "INVALID",
            "Enter exactly 6 digits (000000 to 999999). This was not counted as an attempt.",
        )

    expected_mac = _sign(f"otp|{code}|{parsed.nonce}")
    if hmac.compare_digest(expected_mac, parsed.otp_mac):
        return _result(
            "success",
            "SUCCESS",
            (
                f"The OTP matches and was entered inside the "
                f"{parsed.validity}-second window."
            ),
            nonce=parsed.nonce,
            validity_seconds=parsed.validity,
        )

    return _result(
        "mismatch",
        "FAILURE",
        "That OTP does not match. You can try again while the window is still open.",
        validity_seconds=parsed.validity,
    )


def sign_lock(until: float) -> str:
    """Signed cookie value meaning 'input is locked until this timestamp'."""

    until_s = f"{until:.3f}"
    return f"{until_s}~{_sign('lock|' + until_s)}"


def read_lock(cookie: object, when: float | None = None) -> float:
    """Return the lock timestamp if the cookie is real and still active, else 0."""

    if not isinstance(cookie, str) or "~" not in cookie:
        return 0.0
    until_s, mac = cookie.split("~", 1)
    if not _EXPIRES_PART.fullmatch(until_s):
        return 0.0
    if not _TOKEN_PART.fullmatch(mac):
        return 0.0
    if not hmac.compare_digest(_sign("lock|" + until_s), mac):
        return 0.0
    until = float(until_s)
    current = now() if when is None else float(when)
    if until <= current:
        return 0.0
    return until


def arm_lock(seconds: int | None = None, when: float | None = None) -> tuple[str, float]:
    """Start a lockout. Returns the cookie value and the absolute end time."""

    current = now() if when is None else float(when)
    duration = lockout_seconds() if seconds is None else seconds
    until = current + duration
    return sign_lock(until), until


def sign_used_nonce(nonce: str) -> str:
    return f"{nonce}~{_sign('used|' + nonce)}"


def read_used_nonce(cookie: object) -> str | None:
    if not isinstance(cookie, str) or "~" not in cookie:
        return None
    nonce, mac = cookie.split("~", 1)
    if not _NONCE_PART.fullmatch(nonce) or not _TOKEN_PART.fullmatch(mac):
        return None
    if not hmac.compare_digest(_sign("used|" + nonce), mac):
        return None
    return nonce


def retry_after(until: float, when: float | None = None) -> int:
    current = now() if when is None else float(when)
    remaining = until - current
    if remaining <= 0:
        return 0
    return displayed_seconds(remaining)


# ---------------------------------------------------------------------------
# HOTP (RFC 4226) and TOTP (RFC 6238)
# ---------------------------------------------------------------------------


def hotp(key: bytes, counter: int, digits: int = OTP_DIGITS, algorithm: str = "sha1") -> str:
    """Event-based one-time password.

    Steps from RFC 4226:
    1. Write the counter as 8 bytes, big-endian.
    2. HMAC it with the shared secret.
    3. Dynamic truncation: the low 4 bits of the last byte pick a
       starting offset. Take 4 bytes from there and clear the top bit
       so the result is a positive 31-bit integer.
    4. Keep the last ``digits`` decimal digits (modulo 10**digits).
    """

    if digits not in (6, 7, 8):
        raise ValueError("digits must be 6, 7, or 8")
    if isinstance(counter, bool) or not isinstance(counter, int):
        raise ValueError("counter must be an integer")
    if counter < 0 or counter > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("counter must fit in an unsigned 64-bit integer")
    if algorithm not in _RFC_SECRETS:
        raise ValueError("algorithm must be sha1, sha256, or sha512")
    if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
        raise ValueError("key must be non-empty bytes")

    digest = hmac.new(bytes(key), counter.to_bytes(8, "big"), algorithm).digest()
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24)
        | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8)
        | digest[offset + 3]
    )
    return f"{binary % (10 ** digits):0{digits}d}"


def totp_counter(timestamp: float, step: int = TOTP_STEP_SECONDS, t0: int = TOTP_T0) -> int:
    """How many whole time steps have finished since T0."""

    if step <= 0:
        raise ValueError("step must be positive")
    # int() truncates toward zero. The sample times are all positive.
    return (int(timestamp) - t0) // step


def totp_seconds_remaining(timestamp: float | None = None, step: int = TOTP_STEP_SECONDS) -> int:
    current = now() if timestamp is None else float(timestamp)
    elapsed = int(current) % step
    remaining = step - elapsed
    if remaining == step and (current % step) == 0:
        return step
    # At the exact boundary the new step has a full window left.
    if int(current) % step == 0 and float(current).is_integer():
        return step
    return remaining


def totp(
    key: bytes,
    timestamp: float | None = None,
    *,
    step: int = TOTP_STEP_SECONDS,
    t0: int = TOTP_T0,
    digits: int = OTP_DIGITS,
    algorithm: str = "sha1",
) -> str:
    """Time-based OTP. The counter is floor((time - T0) / step)."""

    current = now() if timestamp is None else float(timestamp)
    return hotp(key, totp_counter(current, step, t0), digits=digits, algorithm=algorithm)


def verify_totp(
    submitted: object,
    key: bytes = RFC_SHA1_SECRET,
    when: float | None = None,
    *,
    step: int = TOTP_STEP_SECONDS,
    skew: int = TOTP_SKEW_STEPS,
    t0: int = TOTP_T0,
    digits: int = OTP_DIGITS,
    algorithm: str = "sha1",
) -> dict:
    """Accept the current step, plus ``skew`` steps on either side.

    Skew of 1 means a code can match for up to 90 seconds: the previous
    30, the current 30, and the next 30. This is separate from the demo
    time-bomb, which has no skew and locks the terminal when it expires.
    """

    current = now() if when is None else float(when)
    code = _prepare_submission(submitted, digits)
    if code is None:
        return _result(
            "invalid",
            "INVALID",
            f"Enter exactly {digits} digits. Letters and short codes are not a TOTP.",
        )

    counter = totp_counter(current, step, t0)
    for delta in range(-skew, skew + 1):
        candidate = counter + delta
        if candidate < 0:
            continue
        expected = hotp(key, candidate, digits=digits, algorithm=algorithm)
        if hmac.compare_digest(expected, code):
            return _result(
                "success",
                "SUCCESS",
                (
                    f"The OTP matches a time step inside the +/- {skew} step skew "
                    f"({step}-second steps)."
                ),
            )

    return _result(
        "mismatch",
        "FAILURE",
        (
            f"That OTP does not match the previous, current, or next "
            f"{step}-second step."
        ),
    )


def verify_hotp(
    submitted: object,
    counter: int,
    key: bytes = RFC_SHA1_SECRET,
    *,
    digits: int = OTP_DIGITS,
    algorithm: str = "sha1",
) -> dict:
    """Check HOTP for exactly this counter.

    Look-ahead is 0 in this project: only the current counter matches.
    The caller advances the counter after success, and leaves it alone
    after a failure, so one typo cannot skip a code.
    """

    code = _prepare_submission(submitted, digits)
    if code is None:
        return _result(
            "invalid",
            "INVALID",
            f"Enter exactly {digits} digits. The counter was not changed.",
        )
    expected = hotp(key, counter, digits=digits, algorithm=algorithm)
    if hmac.compare_digest(expected, code):
        return _result(
            "success",
            "SUCCESS",
            "The OTP matches the current counter.",
        )
    return _result(
        "mismatch",
        "FAILURE",
        "That OTP does not match this counter. The counter was not changed.",
    )


def run_test_vectors() -> list[dict]:
    """Run the bundled sample vectors and report expected versus actual."""

    rows: list[dict] = []
    for counter, expected in HOTP_VECTORS:
        actual = hotp(RFC_SHA1_SECRET, counter, digits=6, algorithm="sha1")
        rows.append(
            {
                "kind": "HOTP",
                "algorithm": "sha1",
                "digits": 6,
                "detail": f"counter {counter}",
                "expected": expected,
                "actual": actual,
                "passed": actual == expected,
            }
        )
    for timestamp, algorithm, expected in TOTP_RFC_VECTORS:
        actual = totp(
            _RFC_SECRETS[algorithm],
            timestamp,
            digits=8,
            algorithm=algorithm,
        )
        rows.append(
            {
                "kind": "TOTP",
                "algorithm": algorithm,
                "digits": 8,
                "detail": f"t={timestamp} digits=8",
                "expected": expected,
                "actual": actual,
                "passed": actual == expected,
            }
        )
    for timestamp, expected in TOTP_SHA1_6_VECTORS:
        actual = totp(RFC_SHA1_SECRET, timestamp, digits=6, algorithm="sha1")
        rows.append(
            {
                "kind": "TOTP",
                "algorithm": "sha1",
                "digits": 6,
                "detail": f"t={timestamp} digits=6",
                "expected": expected,
                "actual": actual,
                "passed": actual == expected,
            }
        )
    return rows


def vectors_passed(rows: list[dict] | None = None) -> bool:
    report = run_test_vectors() if rows is None else rows
    return all(row["passed"] for row in report)


def public_parameters() -> dict:
    """The numbers a README, a screenshot, and the website should agree on."""

    return {
        "demo": {
            "digits": OTP_DIGITS,
            "validity_seconds": validity_seconds(),
            "lockout_seconds": lockout_seconds(),
            "assignment_validity_seconds": VALIDITY_SECONDS,
            "assignment_lockout_seconds": LOCKOUT_SECONDS,
            "using_assignment_defaults": using_assignment_defaults(),
            "generator": "secrets.randbelow",
            "comparison": "hmac.compare_digest",
            "late_rule": (
                "A submission at issued_at + validity, or later, is expired "
                "and locks input. Commands n and q are not OTP attempts."
            ),
        },
        "totp": {
            "rfc": "6238",
            "algorithm": "HMAC-SHA1",
            "digits": OTP_DIGITS,
            "step_seconds": TOTP_STEP_SECONDS,
            "t0": TOTP_T0,
            "skew_steps": TOTP_SKEW_STEPS,
            "secret_note": "RFC 6238 sample secret, ASCII 12345678901234567890",
        },
        "hotp": {
            "rfc": "4226",
            "algorithm": "HMAC-SHA1",
            "digits": OTP_DIGITS,
            "lookahead": HOTP_LOOKAHEAD,
            "secret_note": "RFC 4226 sample secret, ASCII 12345678901234567890",
        },
    }

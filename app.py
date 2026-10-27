"""Website for the OTP demo. Vercel loads the Flask object named ``app``.

Local run (does not replace the console program):

    pip install -r requirements.txt
    python app.py

Then open http://127.0.0.1:5000

The console time-bomb (``python main.py``) and this site share ``otp.core``.
Vercel cannot attach to a keyboard, so the moving bar and the red lock
are drawn in the browser. Expiry is still decided here, on the server.
A late OTP also sets an HttpOnly cookie, so refreshing the page does not
wipe the 60-second lock.

This file binds to localhost only when you run it yourself. The demo
prints live OTPs, and it should not listen on the whole network by accident.
Vercel does not use the ``app.run`` block.
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from otp.core import (
    OTP_DIGITS,
    RFC_SHA1_SECRET,
    TOTP_SKEW_STEPS,
    TOTP_STEP_SECONDS,
    arm_lock,
    hotp,
    issue_demo_challenge,
    lockout_seconds,
    public_parameters,
    read_lock,
    read_used_nonce,
    retry_after,
    run_test_vectors,
    sign_used_nonce,
    totp,
    totp_seconds_remaining,
    using_assignment_defaults,
    validity_seconds,
    vectors_passed,
    verify_demo_challenge,
    verify_hotp,
    verify_totp,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "web", "templates"),
    static_folder=os.path.join(BASE_DIR, "web", "static"),
)
# Trust Vercel's proxy headers so HTTPS cookies are marked Secure in production.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024

LOCK_COOKIE = "otp_lock"
USED_COOKIE = "otp_used"


def _cookie_secure() -> bool:
    return request.is_secure


def _json(payload: dict, status: int = 200, *, lock: str | None = None, used: str | None = None):
    response = jsonify(payload)
    response.headers["Cache-Control"] = "no-store"
    if lock:
        response.set_cookie(
            LOCK_COOKIE,
            lock,
            max_age=lockout_seconds() + 15,
            httponly=True,
            samesite="Lax",
            secure=_cookie_secure(),
            path="/",
        )
    if used:
        response.set_cookie(
            USED_COOKIE,
            used,
            max_age=120,
            httponly=True,
            samesite="Lax",
            secure=_cookie_secure(),
            path="/",
        )
    return response, status


def _locked_payload() -> dict | None:
    until = read_lock(request.cookies.get(LOCK_COOKIE))
    if until <= 0:
        return None
    wait = retry_after(until)
    return {
        "status": "locked",
        "title": "LOCKED",
        "message": "Input is locked. Wait for the timer to finish, then generate a new OTP.",
        "retry_after": wait,
        "locked_until": until,
        "lockout_seconds": lockout_seconds(),
    }


def _body() -> tuple[dict | None, dict | None]:
    """Read a small JSON object. The second item is an error payload, if any."""

    if request.content_length in (None, 0) and not request.data:
        return {}, None
    data = request.get_json(force=False, silent=True)
    if not isinstance(data, dict):
        return None, {
            "status": "invalid",
            "title": "INVALID",
            "message": 'Send a JSON object, for example {"otp": "123456", "token": "..."}.',
        }
    return data, None


def _normalize_otp(value: object, digits: int = OTP_DIGITS) -> object:
    """Keep string OTPs as typed. A JSON number is zero-padded when it fits.

    ``012345`` cannot arrive as a JSON number; the leading zero is already
    gone. The web page always sends text. The number path is only for a
    hand-written request that forgot the quotes.
    """

    if isinstance(value, str) or value is None:
        return "" if value is None else value
    if isinstance(value, bool) or not isinstance(value, int):
        return value
    if value < 0 or value >= 10 ** digits:
        return str(value)
    return f"{value:0{digits}d}"


def _parse_counter(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        counter = value
    elif isinstance(value, str) and value.strip().isdigit():
        counter = int(value.strip())
    else:
        return None
    if counter < 0 or counter > 0xFFFFFFFFFFFFFFFF:
        return None
    return counter


@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.get("/")
def index():
    return render_template(
        "index.html",
        validity=validity_seconds(),
        lockout=lockout_seconds(),
        digits=OTP_DIGITS,
        totp_step=TOTP_STEP_SECONDS,
        totp_skew=TOTP_SKEW_STEPS,
        rehearsal=not using_assignment_defaults(),
    )


@app.get("/api/health")
def health():
    return _json({"ok": True, "service": "otp-generator-verifier"})


@app.get("/api/parameters")
def parameters():
    return _json(public_parameters())


@app.get("/api/lock-status")
def lock_status():
    locked = _locked_payload()
    if locked is None:
        return _json({"locked": False, "retry_after": 0, "status": "open", "title": "OPEN", "message": ""})
    locked["locked"] = True
    return _json(locked)


@app.post("/api/challenge")
def challenge():
    locked = _locked_payload()
    if locked is not None:
        return _json(locked, 423)
    issued = issue_demo_challenge(validity=validity_seconds())
    return _json(issued.public_dict())


@app.post("/api/verify")
def verify():
    locked = _locked_payload()
    if locked is not None:
        return _json(locked, 423)
    data, error = _body()
    if error is not None or data is None:
        return _json(error or {}, 400)
    result = verify_demo_challenge(
        _normalize_otp(data.get("otp", "")),
        data.get("token", ""),
        used_nonce=read_used_nonce(request.cookies.get(USED_COOKIE)),
    )
    nonce = result.pop("nonce", None)
    if result["status"] == "expired":
        cookie, until = arm_lock()
        result["locked_until"] = until
        result["retry_after"] = retry_after(until)
        return _json(result, 200, lock=cookie)
    if result["status"] == "success" and isinstance(nonce, str):
        return _json(result, 200, used=sign_used_nonce(nonce))
    return _json(result)


@app.get("/api/vectors")
def vectors():
    rows = run_test_vectors()
    return _json({"passed": vectors_passed(rows), "count": len(rows), "rows": rows})


@app.get("/api/totp")
def current_totp():
    return _json(
        {
            "otp": totp(RFC_SHA1_SECRET, digits=OTP_DIGITS),
            "seconds_remaining": totp_seconds_remaining(),
            "step_seconds": TOTP_STEP_SECONDS,
            "skew_steps": TOTP_SKEW_STEPS,
            "digits": OTP_DIGITS,
            "secret_note": "RFC 6238 sample secret, shown because this is a classroom lab.",
        }
    )


@app.post("/api/verify-totp")
def check_totp():
    data, error = _body()
    if error is not None or data is None:
        return _json(error or {}, 400)
    result = verify_totp(_normalize_otp(data.get("otp", "")))
    return _json(result)


@app.post("/api/hotp")
def current_hotp():
    data, error = _body()
    if error is not None or data is None:
        return _json(error or {}, 400)
    counter = _parse_counter(data.get("counter", 0))
    if counter is None:
        return _json(
            {
                "status": "invalid",
                "title": "INVALID",
                "message": "Counter must be a whole number from 0 upward.",
            },
            400,
        )
    return _json(
        {
            "counter": counter,
            "otp": hotp(RFC_SHA1_SECRET, counter, digits=OTP_DIGITS),
            "digits": OTP_DIGITS,
            "lookahead": 0,
            "secret_note": "RFC 4226 sample secret, shown because this is a classroom lab.",
        }
    )


@app.post("/api/verify-hotp")
def check_hotp():
    data, error = _body()
    if error is not None or data is None:
        return _json(error or {}, 400)
    counter = _parse_counter(data.get("counter", None))
    if counter is None:
        return _json(
            {
                "status": "invalid",
                "title": "INVALID",
                "message": "Counter must be a whole number from 0 upward.",
            },
            400,
        )
    result = verify_hotp(_normalize_otp(data.get("otp", "")), counter)
    return _json(result)


@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    return _json(
        {
            "status": "invalid",
            "title": "INVALID",
            "message": "That request is too large.",
        },
        413,
    )


@app.errorhandler(404)
def missing(error):
    if request.path.startswith("/api/"):
        return _json(
            {"status": "invalid", "title": "INVALID", "message": "Unknown API route."},
            404,
        )
    return render_template("404.html"), 404


@app.errorhandler(HTTPException)
def http_error(error: HTTPException):
    if request.path.startswith("/api/"):
        return _json(
            {
                "status": "invalid",
                "title": "INVALID",
                "message": error.description or "Request rejected.",
            },
            error.code or 400,
        )
    return error


@app.errorhandler(Exception)
def unexpected(_error):
    # Do not include the request body in the response. It may contain an OTP.
    app.logger.exception("request failed")
    if request.path.startswith("/api/"):
        return _json(
            {
                "status": "invalid",
                "title": "INVALID",
                "message": "Something went wrong. Please try again.",
            },
            500,
        )
    return "Something went wrong. Please try again.", 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f"OTP website at http://127.0.0.1:{port}")
    print("Console time-bomb is a different program: python main.py")
    app.run(host="127.0.0.1", port=port, debug=False)

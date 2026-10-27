"""Console entry point for the OTP Generator and Verifier.

Run this file for the terminal time-bomb. It does not start the website
and it does not need Flask.

    python main.py
    python main.py --sample
    python main.py --vectors

Vercel loads ``app.py`` (the Flask object named ``app``), not this file.
The split is deliberate: a serverless host has no keyboard attached, so
the 30-second bar and the 60-second lock live in the terminal here and
in the browser on the website. Both call ``otp.core``.
"""

from otp.console import main

if __name__ == "__main__":
    raise SystemExit(main())

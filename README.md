# OTP Generator and Verifier

A classroom one-time-password lab. The console program is the time-bomb: it shows a 6-digit code, draws a bar that counts down from 30 seconds, and locks the keyboard for 60 seconds if the code is entered late. The website uses the same rules and is what Vercel hosts, because a serverless platform has no terminal attached to your keyboard.

Both programs import `otp/core.py`. A pass or a fail means the same thing in the terminal and in the browser.

This is a demonstration. The sample secrets are the public strings from RFC 4226 and RFC 6238. Do not protect a real account with them, and do not treat a deployed copy of this site as a login system.

## What it does

- Generates a random 6-digit OTP with `secrets.randbelow` (a cryptographic generator, not the `random` module).
- Prints the code so the flow can be marked. Production systems send the code on another channel and store only a hash.
- Asks for the code, more than once, until it is accepted or the window shuts.
- Accepts `n` to throw the code away and issue another one, and `q` to leave.
- Rejects letters, the wrong length, and blank input without counting them as an attempt.
- Treats a submission at 30.000 seconds, or later, as expired. That is second 31. Right and wrong codes both expire. The terminal then flashes red and ignores OTP keys for 60 seconds.
- Also speaks HOTP (event-based, RFC 4226) and TOTP (time-based, RFC 6238), and prints the sample test vectors.

Ctrl+C still stops the program. The lock swallows OTP keystrokes. It does not disable the operating system.

## Validity parameters

| Rule | Value |
| --- | --- |
| Demo digits | 6, from `000000` to `999999`. Leading zeros count. |
| Demo generator | `secrets.randbelow` |
| Demo window | 30 seconds from the moment the code is issued |
| Late rule | `submitted_at >= issued_at + 30` is expired, even if the digits are correct |
| Lockout | 60 seconds. OTP input is ignored. `n` and `q` are not attempts, so they do not trip the lock by themselves. A blank line does not trip it either. |
| Comparison | `hmac.compare_digest` (timing-safe) |
| HOTP | RFC 4226, HMAC-SHA1, 6 digits, look-ahead 0. The counter moves only after a correct code. |
| TOTP | RFC 6238, HMAC-SHA1, 6 digits, 30-second steps, T0 = Unix epoch, skew +/- 1 step |
| Sample secret | ASCII `12345678901234567890` (public RFC sample) |

TOTP skew of +/- 1 means a code can match for up to 90 seconds (previous step, current step, next step). That is a different rule from the demo time-bomb, which has no skew and locks the terminal when the 30 seconds are gone.

Rehearsal only, not for submission screenshots:

```powershell
python main.py --window 8 --lockout 10
```

If the screen says `REHEARSAL MODE`, those shots are not the graded ones. Quit and run `python main.py` with no flags.

## Algorithms

**Demo OTP.** The program draws a number in `0 .. 999999` and keeps it as six characters. It signs an expiry time and a nonce with HMAC-SHA256. The browser can send a guess back without the server storing the code, which is what Vercel needs. The OTP itself is not written inside the token.

**HOTP.** The counter is written as 8 bytes. HMAC-SHA1 produces a digest. The low 4 bits of the last byte pick a starting point. Four bytes from there, with the top bit cleared, become a 31-bit integer. The code is that integer modulo `10^digits`.

**TOTP.** The counter is `floor((unix_time - 0) / 30)`. Everything else is HOTP. The published RFC 6238 table uses 8 digits. This app's live codes use 6. The 6-digit value is the same integer modulo 1,000,000, which is the last six digits of the 8-digit code.

## Run the console

Python 3.12 or newer. Flask is not required for this part.

```powershell
cd "C:\Users\faiza\Downloads\OTP Generator and Verifier Task 3"
python main.py
```

Use Windows Terminal or PowerShell, at least 80 columns wide and about 30 rows tall. IDLE cannot redraw the bar. In that case you still get a prompt, and the 30-second rule still applies when you press Enter.

Other commands:

```powershell
python main.py --sample
python main.py --vectors
python main.py --preview 5
python -m unittest discover -s tests -v
```

`--sample` prints `examples/sample_session.txt`. `--vectors` must end with `All 34 sample test vectors passed.` `--preview` only checks that the bar moves.

## Example session

The judgements below are computed by `otp.core`. The full transcript, including every test vector, is `examples/sample_session.txt`. In the live program the bar redraws about ten times a second, and the lock really waits 60 seconds.

Menu choice that is not 1–5:

```text
Choose an option (1-5): hello
Invalid choice. Enter a number from 1 to 5.
```

Correct code inside the window:

```text
    OTP: 482913
[##########################------]  25s remaining
OTP> 482913

SUCCESS
The OTP matches and was entered inside the 30-second window.
```

Wrong code, then an invalid code (not counted), then the right code:

```text
OTP> 000000
FAILURE
That OTP does not match. You can try again while the window is still open.
Attempt 1. 18s left in this window.

OTP> 12ab
INVALID
Enter exactly 6 digits (000000 to 999999). This was not counted as an attempt.

OTP> 109284
SUCCESS
The OTP matches and was entered inside the 30-second window.
```

New code with `n`, then a submit after the bar says `EXPIRED`:

```text
OTP> n
Previous code discarded. Generating a new OTP.
    OTP: 771204

Window closed. Submitting an OTP now locks input.
[--------------------------------]  EXPIRED
OTP> 771204

EXPIRED
The submission is outside the 30-second window (second 31 or later). Input will lock for 60 seconds.
```

The terminal then flashes a red `LOCKED` box and counts down from 60. Typed digits are discarded. Ctrl+C still exits.

TOTP at the RFC timestamp `t=59` (6 digits): wrong `000000` is `FAILURE`, `287082` is `SUCCESS`.

HOTP at counter 0: wrong `000000` is `FAILURE` and the counter stays 0. `755224` is `SUCCESS` and the counter becomes 1.

## Sample test vectors

Secret for every row: `12345678901234567890`, extended to 32 bytes for SHA-256 and 64 bytes for SHA-512 exactly as RFC 6238 specifies. Run `python main.py --vectors` to reproduce the table. The website shows the same rows at `/`.

HOTP, 6 digits, SHA-1 (RFC 4226 Appendix D):

| Counter | Code |
| --- | --- |
| 0 | 755224 |
| 1 | 287082 |
| 2 | 359152 |
| 3 | 969429 |
| 4 | 338314 |
| 5 | 254676 |
| 6 | 287922 |
| 7 | 162583 |
| 8 | 399871 |
| 9 | 520489 |

TOTP, 8 digits (RFC 6238 Appendix B). The timestamp is Unix time.

| Unix time | SHA-1 | SHA-256 | SHA-512 |
| --- | --- | --- | --- |
| 59 | 94287082 | 46119246 | 90693936 |
| 1111111109 | 07081804 | 68084774 | 25091201 |
| 1111111111 | 14050471 | 67062674 | 99943326 |
| 1234567890 | 89005924 | 91819424 | 93441116 |
| 2000000000 | 69279037 | 90698825 | 38618901 |
| 20000000000 | 65353130 | 77737706 | 47863826 |

TOTP, same SHA-1 secret and timestamps, 6 digits (what the live TOTP screen uses):

| Unix time | Code |
| --- | --- |
| 59 | 287082 |
| 1111111109 | 081804 |
| 1111111111 | 050471 |
| 1234567890 | 005924 |
| 2000000000 | 279037 |
| 20000000000 | 353130 |

## Run the website locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

The page binds to localhost only, so the demo OTP is not offered to the rest of your network. Vercel does not use that `app.run` block.

On the page: generate, enter a wrong code, enter letters, enter the right code, generate again, wait until the bar says `EXPIRED`, then submit. The card flashes red and the box stays disabled for 60 seconds. Refreshing does not clear the lock. An HttpOnly cookie holds the deadline.

## Deploy on Vercel

Take this in order. Nothing here changes the 30-second or 60-second rules.

1. Install [Git](https://git-scm.com/) and create a GitHub repository. A good name is `otp-generator-verifier`.
2. From this folder, commit the project and push it. Do not commit a real `.env`. `.env.example` is the template. This workspace was not committed for you.
3. Sign in at [vercel.com](https://vercel.com) and choose **Add New… → Project**.
4. Import the GitHub repository. Leave the root directory as the repository root.
5. Vercel should detect **Flask** from `requirements.txt` and `pyproject.toml`. If it does not, set the framework to Flask. The entrypoint is already `app:app` under `[tool.vercel]` in `pyproject.toml`. Python 3.12 comes from `.python-version`.
6. Open **Environment Variables** and add `OTP_DEMO_SECRET` with a long random string (16 characters at minimum). This signs demo tokens. It is not the OTP.
7. Do **not** set `OTP_VALIDITY_SECONDS` or `OTP_LOCKOUT_SECONDS`. If either is set, the site shows a rehearsal banner and the screenshots are no longer the 30/60 assignment.
8. Click **Deploy**. The first build installs Flask 3.1.2 and publishes `app.py`.
9. Open the `*.vercel.app` URL. You should see the OTP card, a 30-second bar, and the vector table.
10. Visit `https://<your-project>.vercel.app/api/health`. The body contains `"ok": true`.
11. Walk the same success, failure, invalid, and late-lock flow as on localhost.
12. Take the Vercel screenshot in `docs/SCREENSHOTS.md` with the address bar in frame.

There is no `api/` directory on purpose. Vercel would turn each file in that folder into its own function and could ignore the Flask app. The `/api/...` routes live inside `app.py`.

Optional CLI, after `npm i -g vercel` and `vercel login`:

```powershell
vercel
vercel --prod
```

A console countdown cannot be the Vercel process. The function would have nobody's keyboard to lock, and a 60-second sleep is the wrong shape for a request. The browser draws the bar and the red state. The server still rejects a late code and sets the lock cookie.

## Layout

See `docs/FOLDER_STRUCTURE.md` for what each file is for. Short form:

```text
main.py            console program (python main.py)
app.py             Flask app Vercel loads
otp/core.py        demo OTP, HOTP, TOTP, vectors
otp/console.py     bar, red flash, 60-second lock
web/               page, styles, browser countdown
tests/             30 unittest checks
examples/          sample session
docs/              structure, screenshots, checklist
```

## Screenshots and checklist

The shot list is `docs/SCREENSHOTS.md`. The boxes to tick before you hand the work in are `docs/SUBMISSION_CHECKLIST.md`.

Save images in `docs/screenshots/`. Submission shots must come from `python main.py` with no flags, and from a website that is not in rehearsal mode.

## Security notes

- Demo codes are printed and returned by `/api/challenge` so a marker can see them. That is unsafe for a real login. Say so if you are asked.
- Guessing is compared with `hmac.compare_digest`.
- A forged token does not start the lock. Only a real challenge that has expired does.
- The last accepted demo code is remembered with an HttpOnly cookie so the same browser cannot replay it. Without a database, another client that captured the token can still use it until the 30 seconds end. A production server would store a one-time hash.
- The lock cookie is HttpOnly and, on HTTPS, Secure. Refreshing the page does not clear it.
- API responses are sent with `Cache-Control: no-store`.
- The page sends `noindex` so a homework URL is less likely to be treated as a public login.

## License

MIT. See `LICENSE`.

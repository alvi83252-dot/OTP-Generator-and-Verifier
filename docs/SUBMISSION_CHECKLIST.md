# Submission checklist

Tick these in order. The details for the pictures are in `docs/SCREENSHOTS.md`.

## Program

- [ ] `python main.py` opens the menu with a 30-second window and a 60-second lock.
- [ ] Option 1 prints a 6-digit OTP, including a code that can start with 0.
- [ ] The bar counts down. A correct code before it expires prints `SUCCESS`.
- [ ] A wrong 6-digit code prints `FAILURE` and lets you try again.
- [ ] `abc`, a 5-digit code, and a 7-digit code print `INVALID` and are not counted as attempts.
- [ ] `n` discards the code and shows a new one. `q` leaves the prompt.
- [ ] After the bar says `EXPIRED`, submitting the OTP flashes red and ignores input for 60 seconds.
- [ ] Ctrl+C still quits during the lock.
- [ ] Option 2 verifies a TOTP. Option 3 verifies an HOTP and only then advances the counter.
- [ ] `python main.py --vectors` ends with `All 34 sample test vectors passed.`
- [ ] `python -m unittest discover -s tests -v` passes.

## Website and Vercel

- [ ] `pip install -r requirements.txt` then `python app.py` opens http://127.0.0.1:5000
- [ ] The page shows the same 30-second window and 60-second lock, with no rehearsal banner.
- [ ] Wrong, invalid, and correct codes match the console words (`FAILURE`, `INVALID`, `SUCCESS`).
- [ ] A submit after `EXPIRED` turns the card red and disables the box for 60 seconds.
- [ ] Refreshing during the lock does not re-enable the box.
- [ ] The vector table on the page says all 34 passed.
- [ ] The GitHub repo is pushed. `.env` is not in the repo.
- [ ] Vercel project uses this folder as the root, Flask is detected, entrypoint is `app:app`.
- [ ] `OTP_DEMO_SECRET` is set on Vercel. `OTP_VALIDITY_SECONDS` and `OTP_LOCKOUT_SECONDS` are not.
- [ ] The deployed URL loads, and `/api/health` returns `"ok": true`.

## Write-up and evidence

- [ ] `README.md` is in the repo and states the 30-second window, the 60-second lock, and the HOTP/TOTP parameters.
- [ ] `examples/sample_session.txt` is in the repo.
- [ ] Screenshots `01` through `19` are in `docs/screenshots/`, or a recording covers the same moments.
- [ ] Success shots show the same OTP that was generated in that shot.
- [ ] The lock shots are red and show a countdown, not only the word expired.
- [ ] `19-vercel.png` shows the `vercel.app` address bar.
- [ ] No rehearsal-mode screenshots are included.

## Hand-in

- [ ] Repository link.
- [ ] Vercel URL.
- [ ] README, sample session, and screenshots or recording.

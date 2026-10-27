# Screenshot requirements

Take these yourself, from a real run. Save them in `docs/screenshots/` with the file names below. A marker should be able to read the OTP, the bar, and the result word without opening the image and zooming.

Use **Windows Terminal** or **PowerShell**, not IDLE. Make the window at least 80 columns wide and about 30 rows tall. Font size around 16. Capture with Win+Shift+S or the Snipping Tool, and grab the whole window.

For the website, include the **address bar** so it is obvious whether the shot is localhost or the Vercel URL.

## Before you start

1. Close any rehearsal run.
2. For the console shots, start with:

```powershell
python main.py
```

No `--window` and no `--lockout`. The menu must say `30 seconds` and `60 seconds`. If you see `REHEARSAL MODE`, stop and start again with no flags.

3. For local website shots:

```powershell
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. The yellow rehearsal banner must be absent. The fact chips must say 30s and 60s.

4. Optional practice, not for submission:

```powershell
python main.py --window 8 --lockout 10
```

That only lets you learn the keys. Delete those images.

## Console shots

| File | When | What must be readable |
| --- | --- | --- |
| `01-menu.png` | Main menu, before you choose | Title, options 1–5, "30 seconds", "60 seconds" |
| `02-otp-and-bar.png` | Option 1, while time remains | The 6-digit OTP, a partly filled `[####----]` bar, a seconds label, the `OTP>` prompt |
| `03-failure.png` | After a wrong 6-digit code such as `000000` | `FAILURE`, the attempt number, seconds still left |
| `04-invalid.png` | After `12ab` or `abc` | `INVALID`, and the line that says it was not counted as an attempt |
| `05-success.png` | After the code that is on screen | `SUCCESS` and the sentence about the 30-second window |
| `06-new-otp.png` | After `n`, or after choosing option 1 again | A different 6-digit OTP from the previous shot |
| `07-expired-lock.png` | After the bar says `EXPIRED`, type that OTP and press Enter | `EXPIRED`, the words "second 31", and the red `LOCKED` box. You have the whole minute. The box stays on screen. |
| `08-lockout-countdown.png` | A second or two later, same lock | "input disabled" and a remaining-seconds count. There must be no `OTP>` prompt waiting for a code. |
| `09-totp.png` | Option 2 | "RFC 6238", the 30-second step, skew +/- 1, a 6-digit code, and either `SUCCESS` or `FAILURE` |
| `10-hotp.png` | Option 3, counter 0 | Counter 0, code `755224`, and a `SUCCESS` or `FAILURE` line |
| `11-vectors.png` | Option 4 | The table and the last line `All 34 sample test vectors passed.` Widen the window if a column is cut off. |

How to get shot 07 without missing it:

1. Choose option 1 and read the OTP.
2. Wait until the label changes to `EXPIRED`. Do not press `n`.
3. Type that same OTP and press Enter.
4. The banner flashes red, then stays red for 60 seconds. Capture `07` and `08` during that minute.
5. Digits you type during the minute must not appear as a new prompt. That is the lock.

Ctrl+C is the emergency exit if you need to leave early. Prefer to let the countdown finish once so you have seen it.

## Website shots

| File | When | What must be readable |
| --- | --- | --- |
| `12-web-home.png` | Just after load | Address bar, the 6-digit OTP, the bar, the chips "30s" and "60s" |
| `13-web-failure.png` | Wrong 6-digit code, Verify | `FAILURE` and "Attempts this window: 1" |
| `14-web-invalid.png` | `abc`, Verify | `INVALID` |
| `15-web-success.png` | The code on screen, Verify | `SUCCESS` |
| `16-web-new-otp.png` | Generate new OTP | A different code, bar back near full |
| `17-web-lockout.png` | Bar says `EXPIRED`, then Verify | Red card, `LOCKED`, input disabled, a seconds count. Address bar included. |
| `18-web-vectors.png` | Scroll to Sample test vectors | Header row and `All 34 sample test vectors passed.` |
| `19-vercel.png` | The deployed site | The `*.vercel.app` address bar, OTP, and the 30s chip. No rehearsal banner. |

Shot 17 is the same idea as shot 07. Wait for `EXPIRED`, then press Verify. Do not press Generate. The red state lasts 60 seconds, including after a refresh.

## Recorded flow (optional, accepted in place of a pile of stills)

A two-minute recording can replace the stills if the brief asks for a recorded flow. Name it `docs/screenshots/demo-flow.mp4`.

1. Start at the console menu.
2. Option 1. Show the OTP and the moving bar.
3. Enter a wrong code, then the right code.
4. Issue another OTP, wait for `EXPIRED`, submit, and show the red lock for a few seconds.
5. Option 4, scroll to `All 34 sample test vectors passed.`
6. Cut to the website, or to the Vercel URL, and show one success and the red lock.

Windows Game Bar: Win+Alt+R. Or Snipping Tool's video button.

## Check before you attach them

- No `REHEARSAL MODE` text in any submission image.
- The menu or the fact chips show 30 and 60, not 8 and 10.
- Shot 07 or 17 is actually red, not only a line that says expired.
- The OTP in a success shot is the OTP printed in that same shot.
- The Vercel shot shows a `vercel.app` host, not only localhost.

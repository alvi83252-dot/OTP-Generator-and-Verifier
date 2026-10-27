# Folder structure

Suggested GitHub repository name: `otp-generator-verifier`.

The console program and the Vercel site are one project. They share `otp/core.py` so a code is accepted or rejected for the same reason in both places. There is no top-level `api/` folder. Those routes are Flask routes inside `app.py`. A real `api/` directory would make Vercel build a separate function per file and could hide the Flask app.

```text
otp-generator-verifier/
├── README.md                 # parameters, vectors, how to run, how to deploy
├── LICENSE                   # MIT
├── requirements.txt          # Flask pin for pip and for Vercel
├── pyproject.toml            # Python version, Flask pin, Vercel entrypoint app:app
├── .python-version           # 3.12, read by Vercel
├── vercel.json               # function timeout; tests and docs stay out of the bundle
├── .gitignore
├── .env.example              # copy to .env only if you set OTP_DEMO_SECRET locally
├── main.py                   # console entry: python main.py
├── app.py                    # website entry: python app.py, and the Vercel app
├── otp/
│   ├── __init__.py           # package version
│   ├── core.py               # demo OTP, HOTP, TOTP, test vectors, lock cookies
│   └── console.py            # countdown bar, red flash, 60-second input lock
├── web/
│   ├── templates/
│   │   ├── index.html        # time-bomb card, TOTP, HOTP, vector table
│   │   └── 404.html
│   └── static/
│       ├── app.js            # bar, attempts, red lock in the browser
│       └── styles.css
├── tests/
│   ├── test_core.py          # RFC vectors, second-31 boundary, invalid input
│   ├── test_console.py       # bar text and the sample transcript
│   └── test_web.py           # Flask client: success, failure, lock cookie
├── examples/
│   └── sample_session.txt    # example input and output, generated from the checker
└── docs/
    ├── FOLDER_STRUCTURE.md   # this file
    ├── SCREENSHOTS.md        # what to capture, and in what order
    ├── SUBMISSION_CHECKLIST.md
    └── screenshots/          # put the PNG files here before you submit
```

## What not to add

- Do not add a second copy of the OTP algorithm in JavaScript. The page asks `app.py`, and `app.py` asks `otp/core.py`.
- Do not name another top-level file `index.py`, `server.py`, `wsgi.py`, or `asgi.py`. Vercel treats those names as possible entrypoints. `main.py` is the console program on purpose, and `pyproject.toml` tells Vercel to load `app:app` instead.
- Do not put the real `OTP_DEMO_SECRET` in git.

## Commands that match this tree

```powershell
python main.py
python app.py
python -m unittest discover -s tests -v
python main.py --sample
python main.py --vectors
```

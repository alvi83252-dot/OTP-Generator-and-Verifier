"""Terminal visualizer for the OTP time-bomb.

The bar counts down from 30 seconds. The OTP is printed because this is
a classroom demo. Type it and press Enter before the bar expires.

If the submission happens at second 31 (the deadline or later), the
terminal flashes red and ignores OTP input for 60 seconds. ``n`` and
``q`` are controls, not OTP attempts, so they do not trip the lock.
Ctrl+C still stops the program: a class demo must not trap the keyboard
at the operating-system level.

The live bar needs a real terminal at least 72 columns wide (Windows
Terminal or PowerShell). IDLE and some editor consoles fall back to a
one-shot prompt. Expiry is still enforced there.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time

from otp.core import (
    LOCKOUT_SECONDS,
    RFC_SHA1_SECRET,
    VALIDITY_SECONDS,
    displayed_seconds,
    hotp,
    issue_demo_challenge,
    lockout_seconds,
    run_test_vectors,
    totp,
    totp_seconds_remaining,
    validity_seconds,
    verify_demo_challenge,
    verify_hotp,
    verify_totp,
)


BAR_WIDTH = 32


def configure_stdio() -> None:
    """Ask the console for UTF-8 so a redirected transcript is stable."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


def enable_virtual_terminal() -> bool:
    """Turn on ANSI colors in the Windows console. Other systems already have them."""

    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING is the bit that understands
        # the red-background sequences used by the lockout flash.
        enabled = mode.value | 0x0004
        return kernel32.SetConsoleMode(handle, enabled) != 0
    except (AttributeError, OSError):
        return False


def color_enabled() -> bool:
    """Red flash is for a human at a terminal. ``NO_COLOR`` switches it off."""

    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("OTP_COLOR", "").strip().lower() in {"0", "false", "no"}:
        return False
    if not sys.stdout.isatty():
        return False
    return enable_virtual_terminal()


def live_ui_available() -> bool:
    """The redrawing bar needs a wide terminal that understands cursor moves."""

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    if shutil.get_terminal_size((80, 24)).columns < 72:
        return False
    return enable_virtual_terminal()


def paint(text: str, red: bool) -> str:
    """Wrap a line in a red background when color is available."""

    if not red or not color_enabled():
        return text
    return "\033[41m\033[97m" + text + "\033[0m"


def progress_bar(remaining: float, total: float, width: int = BAR_WIDTH) -> str:
    """ASCII loading bar. A full bar means the whole window is left."""

    if total <= 0:
        ratio = 0.0
    else:
        ratio = max(0.0, min(1.0, remaining / total))
    filled = int(width * ratio)
    return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"


def live_lines(buffer: str, remaining: float, total: float) -> list[str]:
    """Three short lines. They stay under 72 columns so the redraw does not wrap."""

    if remaining <= 0:
        hint = "Window closed. Submitting an OTP now locks input."
        label = "EXPIRED"
    else:
        hint = "Window open. n = new OTP, q = quit."
        label = f"{displayed_seconds(remaining)}s remaining"
    bar = f"{progress_bar(remaining, total)}  {label}"
    return [hint, bar, f"OTP> {buffer}"]


def lockout_lines(remaining: float, total: float) -> list[str]:
    return [
        "LOCKED - input disabled. Typed keys are ignored.",
        f"{progress_bar(remaining, total)}  {displayed_seconds(remaining)}s remaining",
    ]


def star_box(paragraphs: list[str], width: int = 64) -> list[str]:
    border = "*" * width
    inner = width - 4
    lines = [border]
    for paragraph in paragraphs:
        lines.append("* " + paragraph[:inner].ljust(inner) + " *")
    lines.append(border)
    return lines


def paint_lines(lines: list[str], already_drawn: bool) -> bool:
    """Redraw a block of lines in place.

    Cursor-up keeps the current column, so the carriage return is
    required or the next frame starts in the middle of the bar.
    """

    if already_drawn:
        sys.stdout.write(f"\033[{len(lines)}A\r")
    for line in lines:
        sys.stdout.write("\033[2K")
        sys.stdout.write(line)
        sys.stdout.write("\n")
    sys.stdout.flush()
    return True


class _Cbreak:
    """Deliver each key immediately on Unix. Windows ``msvcrt`` needs no change."""

    def __enter__(self) -> "_Cbreak":
        self._active = False
        if os.name == "nt" or not sys.stdin.isatty():
            return self
        import termios
        import tty

        self._termios = termios
        self._fd = sys.stdin.fileno()
        self._old = termios.tcgetattr(self._fd)
        tty.setcbreak(self._fd)
        self._active = True
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._active:
            self._termios.tcsetattr(self._fd, self._termios.TCSADRAIN, self._old)
        return False


def read_key(timeout: float) -> str | None:
    """One typed character, or None if the timeout expires first."""

    if os.name == "nt":
        import msvcrt

        deadline = time.time() + max(0.0, timeout)
        while True:
            if msvcrt.kbhit():
                character = msvcrt.getwch()
                # Arrow keys arrive as a prefix plus a second code.
                if character in ("\x00", "\xe0"):
                    if msvcrt.kbhit():
                        msvcrt.getwch()
                    return None
                return character
            if time.time() >= deadline:
                return None
            time.sleep(0.02)

    import select

    ready, _, _ = select.select([sys.stdin], [], [], max(0.0, timeout))
    if not ready:
        return None
    return sys.stdin.read(1)


def drain_pending_keys() -> None:
    """Throw away keys typed during the lock so they do not become the next OTP."""

    for _ in range(64):
        if read_key(0) is None:
            return


def read_line_live(total: float, expires_at: float) -> tuple[str, float]:
    """Read a line while the bar keeps moving. Does not stop when the bar hits 0.

    Stopping at 0 would hide the time-bomb. The late OTP has to be
    submitted, and that submission is what locks the terminal.
    """

    buffer = ""
    drawn = False
    with _Cbreak():
        while True:
            remaining = expires_at - time.time()
            drawn = paint_lines(live_lines(buffer, remaining, total), drawn)
            key = read_key(0.1)
            if key is None:
                continue
            if key in ("\r", "\n"):
                sys.stdout.write("\n")
                sys.stdout.flush()
                return buffer.strip(), time.time()
            if key in ("\b", "\x7f"):
                buffer = buffer[:-1]
                continue
            if key == "\x03":
                raise KeyboardInterrupt
            if key == "\x1b":
                read_key(0.02)
                read_key(0.02)
                continue
            if len(key) == 1 and key.isprintable() and len(buffer) < 24:
                buffer += key


def read_line_plain(total: float, expires_at: float) -> tuple[str, float]:
    """Fallback prompt when the terminal cannot redraw a bar."""

    remaining = expires_at - time.time()
    hint, bar, _prompt = live_lines("", remaining, total)
    print(hint)
    print(bar)
    print("Live redraw needs a terminal at least 72 columns wide.")
    print("The expiry time is still enforced when you press Enter.")
    try:
        line = input("OTP> ")
    except EOFError:
        return "q", time.time()
    return line.strip(), time.time()


def flash_box(box: list[str]) -> None:
    """Blink the lock banner red, then leave it red so a screenshot can catch it."""

    wide_enough = shutil.get_terminal_size((80, 24)).columns >= 72
    if not (color_enabled() and sys.stdout.isatty() and wide_enough):
        for line in box:
            print(paint(line, True))
        return
    drawn = False
    # Nine frames end on red (frames 0, 2, 4, 6, 8).
    for frame in range(9):
        colored = [paint(line, frame % 2 == 0) for line in box]
        drawn = paint_lines(colored, drawn)
        time.sleep(0.12)


def run_lockout(seconds: int) -> None:
    """Ignore OTP input for ``seconds``. Ctrl+C still raises KeyboardInterrupt."""

    box = star_box(
        [
            "LOCKED",
            "The OTP was entered outside the validity window.",
            f"Input is disabled for {seconds} seconds.",
            "Ctrl+C still stops the program. OTP keys are ignored.",
        ]
    )
    use_live = live_ui_available()
    with _Cbreak():
        flash_box(box)
        deadline = time.time() + seconds
        drawn = False
        while True:
            left = deadline - time.time()
            if left <= 0:
                break
            lines = [paint(line, True) for line in lockout_lines(left, seconds)]
            if use_live:
                drawn = paint_lines(lines, drawn)
                drain_pending_keys()
                time.sleep(0.1)
            else:
                # No cursor-addressing available. Reprint the countdown on one line.
                print("\r" + lockout_lines(left, seconds)[1], end="", flush=True)
                time.sleep(0.25)
        if use_live:
            sys.stdout.write("\n")
        else:
            print()
    print("Lockout finished. Input is enabled again.")
    print()


def run_preview(seconds: int) -> int:
    """Show the bar and exit. Useful for checking colors before a screenshot."""

    if not live_ui_available():
        print("A live bar needs a terminal at least 72 columns wide.")
        return 1
    print(f"Preview only. No OTP is issued. Counting down from {seconds}s.")
    print("Press Ctrl+C to stop.")
    end = time.time() + seconds
    drawn = False
    try:
        while True:
            left = end - time.time()
            drawn = paint_lines(live_lines("", left, seconds), drawn)
            if left <= 0:
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nPreview stopped.")
        return 0
    print("\nPreview finished. The real demo is: python main.py")
    return 0


def print_issued(challenge_otp: str, window: int) -> None:
    print()
    print("New demo OTP issued.")
    print("This code is shown only for the classroom demo.")
    print("In production it would travel on another channel.")
    print()
    print(f"    OTP: {challenge_otp}")
    print()
    print(f"Window: {window} seconds. A submission at the deadline locks input.")
    print("Commands: n = new OTP, q = quit. A blank line does nothing.")
    print()


def run_demo(window: int, lockout: int) -> None:
    """Random 6-digit OTP, many attempts, new-code option, late-entry lock."""

    while True:
        challenge = issue_demo_challenge(validity=window)
        print_issued(challenge.otp, window)
        attempt = 0
        while True:
            try:
                if live_ui_available():
                    line, submitted_at = read_line_live(window, challenge.expires_at)
                else:
                    line, submitted_at = read_line_plain(window, challenge.expires_at)
            except KeyboardInterrupt:
                print("\nStopped.")
                return

            command = line.strip().lower()
            if command in {"q", "quit"}:
                print("Returning to the menu.")
                return
            if command in {"n", "new"}:
                print()
                print("Previous code discarded. Generating a new OTP.")
                break
            if command == "":
                print()
                if time.time() >= challenge.expires_at:
                    print("Blank line ignored. The window is closed.")
                    print("Type the OTP and press Enter to trigger the lock, or q to quit.")
                else:
                    print("Enter the 6-digit OTP, or n for a new one, or q to quit.")
                continue

            result = verify_demo_challenge(
                line,
                challenge.token,
                when=submitted_at,
                lockout_for_message=lockout,
            )
            print()
            print(result["title"])
            print(result["message"])
            status = result["status"]
            if status == "success":
                print("That code is now used. Generate another from the menu if you want one.")
                print()
                return
            if status == "expired":
                print()
                try:
                    run_lockout(lockout)
                except KeyboardInterrupt:
                    print("\nLockout interrupted. Exiting.")
                return
            if status == "mismatch":
                attempt += 1
                left = displayed_seconds(challenge.expires_at - time.time())
                print(f"Attempt {attempt}. {left}s left in this window.")
                continue
            if status == "invalid":
                print("This was not counted as an attempt.")
                continue
            print("Generate a new OTP from the menu.")
            print()
            return


def run_totp() -> None:
    """Show the current RFC-sample TOTP and verify what the user types."""

    print()
    print("Time-based OTP (TOTP, RFC 6238)")
    print("Algorithm : HMAC-SHA1, 6 digits")
    print("Step      : 30 seconds, T0 = Unix epoch")
    print("Skew      : +/- 1 step (previous, current, and next)")
    print("Secret    : 12345678901234567890  (public sample from the RFC)")
    print("This mode does not use the 60-second lock. That belongs to the demo OTP.")
    print("Enter q to return to the menu.")
    print()
    while True:
        code = totp(RFC_SHA1_SECRET, digits=6)
        remaining = totp_seconds_remaining()
        print(f"    TOTP: {code}")
        print(f"    This step has about {remaining}s left.")
        try:
            line = input("Enter OTP (q = menu): ")
        except (EOFError, KeyboardInterrupt):
            print()
            return
        command = line.strip().lower()
        if command in {"q", "quit"}:
            return
        if command == "":
            print("Enter the 6-digit code shown above, or q to leave.")
            print()
            continue
        result = verify_totp(line.strip())
        print(result["title"])
        print(result["message"])
        print()


def run_hotp() -> None:
    """Event-based OTP. The counter moves only after a correct code."""

    print()
    print("Event-based OTP (HOTP, RFC 4226)")
    print("Algorithm  : HMAC-SHA1, 6 digits")
    print("Look-ahead : 0 (only the current counter is accepted)")
    print("Secret     : 12345678901234567890  (public sample from the RFC)")
    print("A wrong or invalid code does not move the counter.")
    print("Enter q to return to the menu. Enter n to show the same code again.")
    print()
    counter = 0
    while True:
        code = hotp(RFC_SHA1_SECRET, counter, digits=6)
        print(f"    Counter: {counter}")
        print(f"    HOTP:    {code}")
        try:
            line = input("Enter OTP (n = show again, q = menu): ")
        except (EOFError, KeyboardInterrupt):
            print()
            return
        command = line.strip().lower()
        if command in {"q", "quit"}:
            return
        if command in {"n", "new", ""}:
            print()
            continue
        result = verify_hotp(line.strip(), counter)
        print(result["title"])
        print(result["message"])
        if result["status"] == "success":
            counter += 1
            print(f"Counter advanced to {counter}.")
        print()


def format_vector_table(rows: list[dict] | None = None) -> str:
    report = run_test_vectors() if rows is None else rows
    header = f"{'Kind':<8} {'Hash':<8} {'Detail':<24} {'Expected':<10} {'Actual':<10} Result"
    lines = [header, "-" * len(header)]
    for row in report:
        mark = "PASS" if row["passed"] else "FAIL"
        lines.append(
            f"{row['kind']:<8} {row['algorithm']:<8} {row['detail']:<24} "
            f"{row['expected']:<10} {row['actual']:<10} {mark}"
        )
    failed = sum(1 for row in report if not row["passed"])
    if failed:
        lines.append(f"{failed} sample test vector(s) failed.")
    else:
        lines.append(f"All {len(report)} sample test vectors passed.")
    return "\n".join(lines)


def run_vectors_cli() -> int:
    print()
    print("Sample test vectors")
    print("HOTP rows are the published RFC 4226 appendix values.")
    print("TOTP 8-digit rows are the published RFC 6238 appendix values.")
    print("TOTP 6-digit rows are that same code kept to 6 digits.")
    print()
    report = run_test_vectors()
    print(format_vector_table(report))
    print()
    return 1 if any(not row["passed"] for row in report) else 0


def menu_text(window: int, lockout: int) -> str:
    rehearsal = ""
    if window != VALIDITY_SECONDS or lockout != LOCKOUT_SECONDS:
        rehearsal = (
            "\n*** REHEARSAL MODE ***\n"
            "Submission screenshots need the default 30-second window\n"
            "and the 60-second lockout. Start again with:  python main.py\n"
        )
    return (
        "============================================================\n"
        "  OTP GENERATOR AND VERIFIER\n"
        "  Time-Bomb Auth\n"
        "============================================================\n"
        f"Validity window : {window} seconds\n"
        f"Late OTP entry  : locks input for {lockout} seconds\n"
        "Digits          : 6\n"
        "Generator       : secrets.randbelow (cryptographic RNG)\n"
        "Comparison      : hmac.compare_digest (timing-safe)\n"
        "============================================================\n"
        "  1  Demo OTP (random 6-digit time-bomb)\n"
        "  2  Time-based OTP (TOTP, RFC 6238)\n"
        "  3  Event-based OTP (HOTP, RFC 4226)\n"
        "  4  Sample test vectors\n"
        "  5  Quit\n"
        "------------------------------------------------------------"
        f"{rehearsal}"
    )


def run_menu(window: int, lockout: int) -> int:
    while True:
        print()
        print(menu_text(window, lockout))
        try:
            choice = input("Choose an option (1-5): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            return 0
        if choice == "1":
            run_demo(window, lockout)
        elif choice == "2":
            run_totp()
        elif choice == "3":
            run_hotp()
        elif choice == "4":
            run_vectors_cli()
        elif choice in {"5", "q", "quit"}:
            print("Goodbye.")
            return 0
        else:
            print()
            print("Invalid choice. Enter a number from 1 to 5.")


def _expect(status: str, result: dict) -> dict:
    """The printed sample must come from the real checker."""

    if result["status"] != status:
        raise RuntimeError(
            f"Sample transcript expected {status} but the checker returned "
            f"{result['status']}: {result['message']}"
        )
    return result


def build_sample_transcript() -> str:
    """A full example session. Judgements are computed, not typed by hand.

    The countdown is shown as single frames. In a real terminal the same
    ``progress_bar`` redraws about ten times a second. This transcript does
    not wait out the 60-second lock; the program does.
    """

    lines: list[str] = []
    add = lines.append

    def bar_at(remaining: float, total: float = 30) -> str:
        return live_lines("", remaining, total)[1]

    add("OTP GENERATOR AND VERIFIER")
    add("Example session (judgements come from otp.core)")
    add("The live program redraws the bar; this file shows one frame at a time.")
    add("The 60-second lock is waited out in the real program. It is not skipped.")
    add("")
    add(menu_text(30, 60))
    add("Choose an option (1-5): hello")
    add("")
    add("Invalid choice. Enter a number from 1 to 5.")
    add("")
    add("Choose an option (1-5): 1")
    add("")
    add("New demo OTP issued.")
    add("This code is shown only for the classroom demo.")
    add("")
    add("    OTP: 482913")
    add("")
    add(bar_at(25))
    add("OTP> 482913")
    early = issue_demo_challenge(when=1_700_000_000.0, validity=30, otp="482913")
    success = _expect(
        "success",
        verify_demo_challenge("482913", early.token, when=1_700_000_005.0, lockout_for_message=60),
    )
    add("")
    add(success["title"])
    add(success["message"])
    add("")
    add("Choose an option (1-5): 1")
    add("")
    add("    OTP: 109284")
    add("")
    add(bar_at(18))
    add("OTP> 000000")
    retry = issue_demo_challenge(when=1_700_000_100.0, validity=30, otp="109284")
    mismatch = _expect(
        "mismatch",
        verify_demo_challenge("000000", retry.token, when=1_700_000_112.0, lockout_for_message=60),
    )
    add("")
    add(mismatch["title"])
    add(mismatch["message"])
    add("Attempt 1. 18s left in this window.")
    add("")
    add(bar_at(16))
    add("OTP> 12ab")
    invalid = _expect(
        "invalid",
        verify_demo_challenge("12ab", retry.token, when=1_700_000_114.0, lockout_for_message=60),
    )
    add("")
    add(invalid["title"])
    add(invalid["message"])
    add("This was not counted as an attempt.")
    add("")
    add(bar_at(14))
    add("OTP> 109284")
    retry_ok = _expect(
        "success",
        verify_demo_challenge("109284", retry.token, when=1_700_000_116.0, lockout_for_message=60),
    )
    add("")
    add(retry_ok["title"])
    add(retry_ok["message"])
    add("")
    add("Choose an option (1-5): 1")
    add("")
    add("    OTP: 550019")
    add("")
    add("OTP> n")
    add("")
    add("Previous code discarded. Generating a new OTP.")
    add("")
    add("    OTP: 771204")
    add("")
    add("(The bar runs down to 0. The late submit is the line below.)")
    add(live_lines("", 0, 30)[0])
    add(bar_at(0))
    add("OTP> 771204")
    late = issue_demo_challenge(when=1_700_000_200.0, validity=30, otp="771204")
    expired = _expect(
        "expired",
        verify_demo_challenge("771204", late.token, when=1_700_000_231.0, lockout_for_message=60),
    )
    add("")
    add(expired["title"])
    add(expired["message"])
    add("")
    for line in star_box(
        [
            "LOCKED",
            "The OTP was entered outside the validity window.",
            "Input is disabled for 60 seconds.",
            "Ctrl+C still stops the program. OTP keys are ignored.",
        ]
    ):
        add(line)
    add(lockout_lines(60, 60)[0])
    add(lockout_lines(60, 60)[1])
    add(lockout_lines(59, 60)[1])
    add("... the countdown continues once a second until it reaches 0 ...")
    add("Lockout finished. Input is enabled again.")
    add("")
    add("Choose an option (1-5): 2")
    add("")
    frozen = 59
    totp_code = totp(RFC_SHA1_SECRET, frozen, digits=6)
    add(f"Clock frozen at t={frozen} for this example.")
    add(f"    TOTP: {totp_code}")
    add("Enter OTP (q = menu): 000000")
    totp_bad = _expect("mismatch", verify_totp("000000", when=frozen))
    add(totp_bad["title"])
    add(totp_bad["message"])
    add(f"Enter OTP (q = menu): {totp_code}")
    totp_ok = _expect("success", verify_totp(totp_code, when=frozen))
    add(totp_ok["title"])
    add(totp_ok["message"])
    add("")
    add("Choose an option (1-5): 3")
    add("")
    hotp_code = hotp(RFC_SHA1_SECRET, 0, digits=6)
    add("    Counter: 0")
    add(f"    HOTP:    {hotp_code}")
    add("Enter OTP (n = show again, q = menu): 000000")
    hotp_bad = _expect("mismatch", verify_hotp("000000", 0))
    add(hotp_bad["title"])
    add(hotp_bad["message"])
    add(f"Enter OTP (n = show again, q = menu): {hotp_code}")
    hotp_ok = _expect("success", verify_hotp(hotp_code, 0))
    add(hotp_ok["title"])
    add(hotp_ok["message"])
    add("Counter advanced to 1.")
    add("")
    add("Choose an option (1-5): 4")
    add("")
    add(format_vector_table())
    add("")
    add("Choose an option (1-5): 5")
    add("Goodbye.")
    add("")
    return "\n".join(lines)


def _positive_range(name: str, value: int, low: int, high: int) -> str | None:
    if value < low or value > high:
        return f"{name} must be between {low} and {high} seconds."
    return None


def main(argv: list[str] | None = None) -> int:
    configure_stdio()
    parser = argparse.ArgumentParser(
        description="OTP Generator and Verifier. Console time-bomb demo."
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Print an example session (real judgements, no waiting) and exit.",
    )
    parser.add_argument(
        "--vectors",
        action="store_true",
        help="Run the sample HOTP and TOTP test vectors and exit.",
    )
    parser.add_argument(
        "--preview",
        type=int,
        metavar="SECONDS",
        help="Redraw the countdown bar, then exit. No OTP is issued.",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=None,
        help=f"Demo validity window in seconds (default {VALIDITY_SECONDS}).",
    )
    parser.add_argument(
        "--lockout",
        type=int,
        default=None,
        help=f"Lockout length in seconds after a late OTP (default {LOCKOUT_SECONDS}).",
    )
    args = parser.parse_args(argv)

    if args.sample:
        print(build_sample_transcript(), end="")
        return 0
    if args.vectors:
        return run_vectors_cli()
    if args.preview is not None:
        problem = _positive_range("Preview", args.preview, 1, 30)
        if problem:
            print(problem)
            return 2
        return run_preview(args.preview)

    window = validity_seconds() if args.window is None else args.window
    lockout = lockout_seconds() if args.lockout is None else args.lockout
    window_problem = _positive_range("Window", window, 5, 120)
    lock_problem = _positive_range("Lockout", lockout, 5, 300)
    if window_problem:
        print(window_problem)
        return 2
    if lock_problem:
        print(lock_problem)
        return 2
    return run_menu(window, lockout)


if __name__ == "__main__":
    raise SystemExit(main())

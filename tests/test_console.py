"""Console helpers and the printed example session.

The live keyboard loop needs a real terminal, so these tests cover the
bar text, the sample transcript, and the non-interactive commands.
"""

from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from otp.console import (  # noqa: E402
    build_sample_transcript,
    live_lines,
    main,
    progress_bar,
)


class BarTest(unittest.TestCase):
    def test_bar_endpoints(self) -> None:
        self.assertEqual(progress_bar(30, 30, width=10), "[##########]")
        self.assertEqual(progress_bar(15, 30, width=10), "[#####-----]")
        self.assertEqual(progress_bar(0, 30, width=10), "[----------]")

    def test_live_lines_switch_at_expiry(self) -> None:
        open_lines = live_lines("12", 12, 30)
        self.assertEqual(len(open_lines), 3)
        self.assertIn("Window open", open_lines[0])
        self.assertIn("12s remaining", open_lines[1])
        self.assertEqual(open_lines[2], "OTP> 12")
        closed = live_lines("550019", 0, 30)
        self.assertIn("locks input", closed[0])
        self.assertIn("EXPIRED", closed[1])
        self.assertTrue(all(len(line) < 72 for line in closed))


class SampleCommandTest(unittest.TestCase):
    def test_sample_transcript_matches_the_real_checker(self) -> None:
        text = build_sample_transcript()
        for phrase in (
            "SUCCESS",
            "FAILURE",
            "INVALID",
            "EXPIRED",
            "second 31",
            "LOCKED",
            "755224",
            "All ",
            "sample test vectors passed",
            "Invalid choice",
        ):
            self.assertIn(phrase, text)
        saved = (ROOT / "examples" / "sample_session.txt").read_text(encoding="utf-8")
        self.assertEqual(saved, text)

    def test_commands(self) -> None:
        sample = io.StringIO()
        with redirect_stdout(sample):
            self.assertEqual(main(["--sample"]), 0)
        self.assertIn("SUCCESS", sample.getvalue())

        vectors = io.StringIO()
        with redirect_stdout(vectors):
            self.assertEqual(main(["--vectors"]), 0)
        self.assertIn("755224", vectors.getvalue())

        rejected = io.StringIO()
        with redirect_stdout(rejected):
            self.assertEqual(main(["--window", "0"]), 2)
        self.assertIn("between", rejected.getvalue())


if __name__ == "__main__":
    unittest.main()

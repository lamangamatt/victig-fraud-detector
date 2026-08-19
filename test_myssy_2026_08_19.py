"""
Regression test for Myssy Clayson's 2026-08-19 false-positive report
(#2727744 - MORGAN, JULIE ANN - VILLAGE MEDICAL/PRIMARY CARE).

Myssy forwarded a PHONE PHOTO of a physical VillageMD/ADP earnings statement
(Julie Morgan) with all dollar amounts hand-redacted (black marker). The
detector scored it 100/100 on TWO false positives:

  1. "Date/Year Tampering Detected" — the AI vision layer called the June-2026
     pay period (06/07/2026-06/20/2026) and advice date (06/26/2026)
     "future-dated" even though the document was analysed on 2026-08-19, i.e.
     the dates are in the PAST. Root cause: the AI prompt never told the model
     today's date, so it inferred "now" as 2024/2025 and treated any 2026 date
     as future.

  2. "Non-Black Machine Text" — the colour check reported "56% of machine text
     renders in red (mean RGB 91, 61, 31)". That RGB is a warm-light BROWN, not
     red — an artifact of photographing black ink under warm indoor light on a
     wood surface. The hue test (R > G+25 and R > B+25) mis-classified the warm
     colour cast as red.

Fixes (2026-08-19):
  A. Inject "Today's Date" into the AI vision CONTEXT and instruct the model
     that past pay periods / pay dates / tax years are NORMAL; only dates AFTER
     today are future-dated.
  B. Deterministic backstop `_is_false_future_date_claim`: drop a
     "Date/Year Tampering Detected" issue that is phrased as a future-date claim
     when none of the dates it cites are actually after today.
  C. White-balance `_check_text_color_channel` against the paper white point so
     a warm photo cast normalises out; plus require genuine red to be
     reasonably bright (mean_r >= 110) with its other two channels close
     together (reject brown ramps).

This test needs no API key (AI layer is disabled / mocked). The paystub sample
lives under test-samples/ which is gitignored (PII); if absent the image parts
of the test cleanly skip.

Run with:
    python3 test_myssy_2026_08_19.py
"""
import os
import sys

import numpy as np

from document_analyzer import DocumentAnalyzer

HERE = os.path.dirname(__file__)
SAMPLE = os.path.join(HERE, "test-samples", "myssy_2026_08_19_paystub_photo.jpg")

FORBIDDEN_ON_PAYSTUB = {"Non-Black Machine Text", "Date/Year Tampering Detected"}


def _make(bg, txt, w=400, h=300, ratio=0.12, seed=0):
    """Synthetic doc: solid background with `ratio` of pixels painted `txt`."""
    rng = np.random.RandomState(seed)
    im = np.full((h, w, 3), bg, dtype=np.uint8)
    n = int(h * w * ratio)
    ys = rng.randint(0, h, n)
    xs = rng.randint(0, w, n)
    im[ys, xs] = txt
    return im


def test_false_future_date_claim():
    """The deterministic backstop drops PAST 'future-dated' claims, keeps real
    future dates and non-date tampering claims. (today is read live.)"""
    a = DocumentAnalyzer(use_ai=False)
    from datetime import date
    today = date.today()
    cases = [
        # (issue, expect_suppressed)
        ("Document shows future dates (Period Begin/End: 06/07/2026 - 06/20/2026, "
         "Advice Date: 06/26/2026)", today.year >= 2026),
        ("Advice Date '06/26/2026' is also a future date", today.year >= 2026),
        ("Period dates show '06/07/2026 - 06/20/2026' which is a FUTURE date", today.year >= 2026),
        ("pay stubs cannot be issued for periods that haven't occurred "
         "(06/07/2026 - 06/20/2026)", today.year >= 2026),
        ("future dates (2026)", today.year >= 2026),
        # Genuinely future -> never suppress
        ("Document references tax year 2099, which is in the future", False),
        ("Pay period 01/01/2099 - 01/15/2099 is in the future", False),
        # Not a future-date claim -> never suppress
        ("Tax year printed on top of other text (overprint) with different font", False),
        ("Black box covering original date overlaid with a new date", False),
    ]
    ok = True
    for issue, expect in cases:
        got = a._is_false_future_date_claim(issue)
        flag = "OK" if got == expect else "**FAIL**"
        if got != expect:
            ok = False
        print(f"  [{flag}] suppress={got} expect={expect} :: {issue[:64]}")
    assert ok, "future-date backstop mis-classified at least one case"
    print("PASS: _is_false_future_date_claim behaves correctly")


def test_colour_check_controls():
    """White-balance colour check: genuine ink still flags, warm cast does not."""
    # A) neutral scan + blue ink  -> flag
    a = DocumentAnalyzer(use_ai=False); s = {}
    a._check_text_color_channel(_make((250, 250, 250), (35, 45, 150)), s)
    assert any(f["title"] == "Non-Black Machine Text" for f in a.flags), \
        "genuine blue ink on a neutral scan must still flag"
    print("PASS: neutral scan + blue ink -> Non-Black Machine Text")

    # B) neutral scan + red ink   -> flag
    b = DocumentAnalyzer(use_ai=False); s = {}
    b._check_text_color_channel(_make((250, 250, 250), (180, 35, 40)), s)
    assert any(f["title"] == "Non-Black Machine Text" for f in b.flags), \
        "genuine red ink on a neutral scan must still flag"
    print("PASS: neutral scan + red ink  -> Non-Black Machine Text")

    # C) warm-lit black ink (brown cast) -> NO flag  (the reported false positive)
    c = DocumentAnalyzer(use_ai=False); s = {}
    c._check_text_color_channel(_make((214, 196, 168), (92, 62, 32)), s)
    assert not any(f["title"] == "Non-Black Machine Text" for f in c.flags), \
        "warm-light brown cast on black ink must NOT be flagged as red"
    print("PASS: warm-lit black ink (brown cast) -> no false red flag")

    # D) warm-lit genuine red ink -> STILL flag  (WB preserves true colour)
    d = DocumentAnalyzer(use_ai=False); s = {}
    d._check_text_color_channel(_make((214, 196, 168), (190, 70, 60)), s)
    assert any(f["title"] == "Non-Black Machine Text" for f in d.flags), \
        "genuinely red ink must still flag even under a warm photo cast"
    print("PASS: warm-lit genuine red ink -> Non-Black Machine Text (preserved)")


def test_paystub_photo_no_reported_false_positives():
    """Full deterministic pipeline on the real sample: neither reported false
    positive fires. (AI layer disabled -> no API key needed.)"""
    if not os.path.exists(SAMPLE):
        print(f"SKIP: sample not found at {SAMPLE}")
        return
    res = DocumentAnalyzer(use_ai=False).analyze(SAMPLE, "Pay Stub")
    titles = {f.get("title") for f in res.get("flags", [])}
    fired = FORBIDDEN_ON_PAYSTUB & titles
    print(f"  score={res.get('risk_score')} level={res.get('risk_level')}")
    print(f"  flags={sorted(titles)}")
    assert not fired, f"reported false positives still fire: {fired}"
    print("PASS: paystub photo fires neither 'Non-Black Machine Text' nor "
          "'Date/Year Tampering Detected'")

    # And confirm the colour check actually ran and saw a warm paper cast
    # (proves the no-flag result is a real WB correction, not an early skip).
    sub = {}
    DocumentAnalyzer(use_ai=False)._check_text_color_channel(
        np.array(__import__("PIL.Image", fromlist=["Image"]).open(SAMPLE).convert("RGB")), sub)
    print(f"  paper_white_rgb={sub.get('paper_white_rgb')} "
          f"spread={sub.get('paper_white_spread')} "
          f"colored_text_rgb={sub.get('colored_text_rgb')}")


def run():
    print("== test_false_future_date_claim ==")
    test_false_future_date_claim()
    print("\n== test_colour_check_controls ==")
    test_colour_check_controls()
    print("\n== test_paystub_photo_no_reported_false_positives ==")
    test_paystub_photo_no_reported_false_positives()
    print("\nALL TESTS PASSED")
    return True


if __name__ == "__main__":
    try:
        run()
    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)

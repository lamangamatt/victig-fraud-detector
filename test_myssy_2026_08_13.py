"""
Positive detection test for Myssy Clayson's 2026-08-13 blue-ink 1099-NEC
sample.

Sample: `myssy_2026_08_13_blue_ink_1099.png` — a 1099-NEC where all
payer/recipient fields (name, TIN, address) render in blue-colored
machine typeset instead of the standard black. Image is also heavily
cropped (aspect ratio 2.71, resolution 743×274).

Before the 2026-08-13 fixes (issue #1), this document scored LOW risk
(25/100) despite three obvious tampering signals — the detector did not
check text color, weighted cropped images the same as ordinary low-res
scans, and never aggregated multiple minor anomalies.

The 2026-08-13 fixes:
  1. New `_check_text_color_channel`: flags non-black machine text
     as warning +25.
  2. New `Cropped or Truncated Image` check in `_analyze_visual_forensics`:
     aspect ratio outside 0.4–2.0 fires as warning +20.
  3. New `_compound_info_flags` post-processing pass: 3+ info-level
     flags produce a `Multiple Anomalies Detected` warning +15.

This regression test asserts the detector now returns at least MEDIUM
risk (≥35) and fires the two new warning-level flags relevant to this
sample.

Run with:
    python3 test_myssy_2026_08_13.py

The sample image lives under test-samples/ which is gitignored (contains
PII); if not present locally the test cleanly skips.
"""
import os
import sys
import json


REQUIRED_FLAGS = {
    "Cropped or Truncated Image",
    "Non-Black Machine Text",
}


def run() -> bool:
    from document_analyzer import DocumentAnalyzer

    here = os.path.dirname(__file__)
    path = os.path.join(here, "test-samples", "myssy_2026_08_13_blue_ink_1099.png")

    if not os.path.exists(path):
        print(f"SKIP: sample not found at {path}")
        return True

    result = DocumentAnalyzer(use_ai=False).analyze(path, "1099")
    score = result.get("risk_score", 0)
    level = result.get("risk_level", "")
    flags = [(f.get("severity"), f.get("title")) for f in result.get("flags", [])]
    titles = {t for _, t in flags}

    print(json.dumps({
        "file": os.path.basename(path),
        "score": score,
        "level": level,
        "flags": flags,
    }, indent=2))

    ok = True

    # Assertion 1: risk level should be at least MEDIUM (was LOW = 25 before fix)
    if level not in ("MEDIUM", "HIGH"):
        print(f"FAIL: expected MEDIUM or HIGH, got {level} ({score})")
        ok = False
    else:
        print(f"PASS: risk level {level} ({score}/100)")

    # Assertion 2: score should be well above the old 25
    if score < 35:
        print(f"FAIL: score {score} is still under the MEDIUM threshold (35)")
        ok = False
    else:
        print(f"PASS: score {score} >= 35")

    # Assertion 3: both new warning flags must fire
    missing = REQUIRED_FLAGS - titles
    if missing:
        print(f"FAIL: required flags did not fire: {sorted(missing)}")
        ok = False
    else:
        print(f"PASS: all required flags fired: {sorted(REQUIRED_FLAGS)}")

    # Assertion 4: the new flags must be at warning severity (not info)
    for sev, title in flags:
        if title in REQUIRED_FLAGS and sev != "warning":
            print(f"FAIL: '{title}' fired at severity '{sev}', expected 'warning'")
            ok = False

    return ok


if __name__ == "__main__":
    sys.exit(0 if run() else 1)

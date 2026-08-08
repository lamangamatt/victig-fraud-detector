"""
Regression test for Myssy Clayson's 2026-07-03 W-2 forgery sample.

This document (two W-2s on one page for Aretha L Hall, 2020) was scoring only
10/100 LOW RISK before the 2026-07-03 detection improvements.  It should now
score > 50/100 HIGH.

2026-08-07 update: the OCR of this JPEG extracts NO visible dollar amounts,
so the old "Missing Decimal Formatting" hit was actually firing on spurious
noise (address numbers, EIN prefixes, SSN fragments) rather than on real
missing-decimal wages.  The actual fraud signal on this document is that it
contains TWO DISTINCT EINs (47-3880436 and 46-4997666) on a single page —
a composite forgery.  This test now asserts the accurate signal.

Run with:
    python3 test_myssy_2026_07_03.py
"""
import os
import sys
import json


def run():
    # Locate the sample relative to this script
    sample = os.path.join(
        os.path.dirname(__file__),
        "..", "tmp", "w2-review", "w2.jpeg"
    )
    if not os.path.exists(sample):
        print(f"SKIP: sample not found at {sample}")
        return 0

    from document_analyzer import DocumentAnalyzer

    result = DocumentAnalyzer(use_ai=False).analyze(sample, "W-2")
    score = result.get("risk_score", 0)
    level = result.get("risk_level", "")
    flag_titles = [f.get("title") for f in result.get("flags", [])]
    flag_severities = {f.get("title"): f.get("severity") for f in result.get("flags", [])}

    print(json.dumps({
        "score": score,
        "level": level,
        "flags": [(flag_severities[t], t) for t in flag_titles],
    }, indent=2))

    ok = True

    # Requirement 1: score must be > 50
    if score <= 50:
        print(f"FAIL: score {score} is not > 50")
        ok = False
    else:
        print(f"PASS: score {score} > 50")

    # Requirement 2: level must be HIGH
    if level != "HIGH":
        print(f"FAIL: level is {level}, expected HIGH")
        ok = False
    else:
        print(f"PASS: level is HIGH")

    # Requirement 3: composite forgery must be caught by the multi-W-2 or
    # missing-tax-year signal.  Either firing is enough (they represent the
    # two real signals on this sample).
    composite_signals = [
        ("Multiple W-2 Forms on Single Page", "warning"),
        ("Missing Tax Year", "critical"),
    ]
    fired = [t for t, sev in composite_signals
             if t in flag_titles and flag_severities.get(t) == sev]
    if not fired:
        print(f"FAIL: none of the composite-forgery signals fired: {composite_signals}")
        ok = False
    else:
        print(f"PASS: composite-forgery signals fired: {fired}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run())

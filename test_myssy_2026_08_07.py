"""
Positive regression tests for Myssy Clayson's 2026-08-07 false-positive samples.

Both documents are LEGITIMATE:
  1. W2_2025.pdf                 — Intuit Payroll W-2 for David N Pruitt
  2. AutoPay_output_documents.pdf — ADP paystub

Before the 2026-08-07 fixes:
  W-2 scored 85/100 HIGH on four false positives:
    - Missing Decimal Formatting (fired on box numbers, IRC codes, form refs)
    - Multiple W-2 Forms on Single Page (fired on standard 3-copy layout)
    - Bimodal Text Darkness Pattern (fired on pre-printed IRS form + overprint)
    - Inconsistent Text Darkness (same underlying cause)
  Paystub scored 15/100 LOW but still flagged "Inconsistent Text Darkness" and
  the visual redaction detector fired on totals bars.

After fixes both documents must score LOW with no critical/warning flags.

Run with:
    python3 test_myssy_2026_08_07.py
"""
import os
import sys
import json


def run():
    from document_analyzer import DocumentAnalyzer

    here = os.path.dirname(__file__)
    cases = [
        ("W-2",     os.path.join(here, "samples", "2026-08-07-myssy", "W2_2025.pdf")),
        ("Pay Stub", os.path.join(here, "samples", "2026-08-07-myssy", "AutoPay_output_documents.pdf")),
    ]

    ok = True
    for doc_type, path in cases:
        if not os.path.exists(path):
            print(f"SKIP: sample not found at {path}")
            continue

        result = DocumentAnalyzer(use_ai=False).analyze(path, doc_type)
        score  = result.get("risk_score", 0)
        level  = result.get("risk_level", "")
        flags  = [(f.get("severity"), f.get("title")) for f in result.get("flags", [])]

        print(json.dumps({
            "file": os.path.basename(path),
            "doc_type": doc_type,
            "score": score,
            "level": level,
            "flags": flags,
        }, indent=2))

        # Must be LOW risk
        if level != "LOW":
            print(f"FAIL: {os.path.basename(path)} expected LOW, got {level} ({score})")
            ok = False
        else:
            print(f"PASS: {os.path.basename(path)} is LOW ({score})")

        # No critical or warning flags allowed
        bad = [t for sev, t in flags if sev in ("critical", "warning")]
        if bad:
            print(f"FAIL: {os.path.basename(path)} has critical/warning flags: {bad}")
            ok = False
        else:
            print(f"PASS: {os.path.basename(path)} has no critical/warning flags")

        # Specific false positives that must NOT fire
        forbidden = {
            "Missing Decimal Formatting on Monetary Fields",
            "Multiple W-2 Forms on Single Page",
            "Bimodal Text Darkness Pattern",
            "Inconsistent Text Darkness",
        }
        titles = {t for _, t in flags}
        overlap = forbidden & titles
        if overlap:
            print(f"FAIL: {os.path.basename(path)} triggered forbidden flags: {sorted(overlap)}")
            ok = False
        else:
            print(f"PASS: {os.path.basename(path)} did not trigger any forbidden false positives")

        # W-2 specifically should be recognized as Intuit Payroll
        if doc_type == "W-2":
            legit = "Legitimate Source: Intuit Payroll"
            if legit in titles:
                print(f"PASS: {os.path.basename(path)} identified Intuit Payroll source")
            else:
                print(f"FAIL: {os.path.basename(path)} did not identify Intuit Payroll source")
                ok = False

        # Paystub specifically should be recognized as ADP Payroll
        if doc_type == "Pay Stub":
            legit = "Legitimate Source: ADP Payroll"
            if legit in titles:
                print(f"PASS: {os.path.basename(path)} identified ADP Payroll source")
            else:
                print(f"FAIL: {os.path.basename(path)} did not identify ADP Payroll source")
                ok = False

        print()

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run())

"""
Regression test for Myssy Clayson's 2026-07-03 W-2 forgery sample.

This document (two W-2s on one page for Aretha L Hall, 2020) was scoring only
10/100 LOW RISK before the 2026-07-03 detection improvements.  It should now
score > 50/100 HIGH with the "Missing Decimal Formatting on Monetary Fields"
flag firing at critical severity.

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

    # Requirement 3: decimal formatting flag must fire at critical
    decimal_flag = "Missing Decimal Formatting on Monetary Fields"
    if decimal_flag not in flag_titles:
        print(f"FAIL: '{decimal_flag}' flag not fired")
        ok = False
    elif flag_severities.get(decimal_flag) != "critical":
        print(f"FAIL: '{decimal_flag}' severity is {flag_severities.get(decimal_flag)}, expected critical")
        ok = False
    else:
        print(f"PASS: '{decimal_flag}' fired at critical")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run())

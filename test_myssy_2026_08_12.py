"""
Positive regression test for Myssy Clayson's 2026-08-12 false-positive sample.

Sample: RG_Sage_W2.pdf — a legitimate multi-copy ADP W-2 with a top-right
"Earnings Summary" reconciliation grid.

The Earnings Summary block renders currency as space-separated triplets:

    $496,702.91  →  "496 702 91"

Before the 2026-08-07 cleanup (commit 370f15d) each row of the summary
exploded into 2–3 phantom integer tokens, so the "Missing Decimal
Formatting on Monetary Fields" heuristic fired with the signature message:

    "Only 46 of 227 detected monetary values include required cent formatting"

The verifier team flagged this on 2026-08-11 — even though the underlying
regex/scope fix had already shipped on 2026-08-07, Streamlit Cloud had not
picked up a fresh deploy, so the pre-fix code was still live.

This regression test asserts the current code returns LOW risk and does
NOT emit the decimal-formatting flag on the ADP Earnings Summary layout.

Run with:
    python3 test_myssy_2026_08_12.py

The sample PDF lives under samples/ which is gitignored (contains PII);
if not present locally the test cleanly skips.
"""
import os
import sys
import json


FORBIDDEN_FLAGS = {
    "Missing Decimal Formatting on Monetary Fields",
    "Multiple W-2 Forms on Single Page",
    "Bimodal Text Darkness Pattern",
    "Inconsistent Text Darkness",
}


def run() -> bool:
    from document_analyzer import DocumentAnalyzer

    here = os.path.dirname(__file__)
    path = os.path.join(here, "samples", "2026-08-12-myssy", "RG_Sage_W2.pdf")

    if not os.path.exists(path):
        print(f"SKIP: sample not found at {path}")
        return True

    result = DocumentAnalyzer(use_ai=False).analyze(path, "W-2")
    score = result.get("risk_score", 0)
    level = result.get("risk_level", "")
    flags = [(f.get("severity"), f.get("title")) for f in result.get("flags", [])]

    print(json.dumps({
        "file": os.path.basename(path),
        "score": score,
        "level": level,
        "flags": flags,
    }, indent=2))

    ok = True

    if level != "LOW":
        print(f"FAIL: expected LOW, got {level} ({score})")
        ok = False
    else:
        print(f"PASS: is LOW ({score})")

    bad = [t for sev, t in flags if sev in ("critical", "warning")]
    if bad:
        print(f"FAIL: critical/warning flags fired: {bad}")
        ok = False
    else:
        print("PASS: no critical/warning flags")

    titles = {t for _, t in flags}
    overlap = FORBIDDEN_FLAGS & titles
    if overlap:
        print(f"FAIL: forbidden flags triggered: {sorted(overlap)}")
        ok = False
    else:
        print("PASS: no forbidden flags triggered")

    return ok


if __name__ == "__main__":
    sys.exit(0 if run() else 1)

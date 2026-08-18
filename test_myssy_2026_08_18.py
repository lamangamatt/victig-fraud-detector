"""
Regression test for Myssy Clayson's 2026-08-18 report: a fabricated W-2
(Kelly Vasquez, submitted as a "W-2 with a letter" PDF) where the detector
flagged the ink shades but never reported the THREE different font sizes used
in the values.

Root causes found + fixed (see improvements_from_myssy.md 2026-08-18):
  1. DEAD AI MODEL: the pinned claude-sonnet-4-20250514 now returns 404
     (retired), which silently disabled the entire AI vision layer -- every
     AI-only tell (font sizes, box structure, date tampering) went unchecked.
     Now uses a current, env-overridable model with fallback.
  2. PAGE SELECTION: _pdf_to_image only rasterized page 0. For a "W-2 + cover
     letter" PDF, page 0 is the letter, so the W-2 was never visually/AI
     analyzed. _select_form_page now picks the most form-like page.
  3. FONT-SIZE DETECTION: the AI prompt now analyzes font SIZE among the typed
     values (value_size_inconsistency) and _apply_employment_ai_flags fires an
     "Inconsistent Font Sizes" warning when detected + corroborated. A pure
     numpy CV backstop (_check_font_size_consistency) also fires on >=3 distinct
     text sizes when an overlay tell already fired.
  4. SCORE GUARDRAIL: the AI's "Appears Legitimate" -10 no longer applies when a
     CRITICAL structural flag is present, so a lenient AI read cannot drop a
     tampered form to LOW.

These assertions are deterministic (use_ai=False + a mocked AI result); the live
AI vision behavior is validated separately. The PII sample lives under
test-samples/ (gitignored); page-selection assertions skip cleanly if absent.

Run with:
    python3 test_myssy_2026_08_18.py
"""
import os
import sys


def _mock_ai_font_size_result():
    return {
        "overall_assessment": "SUSPICIOUS",
        "confidence": 72,
        "font_consistency": {
            "consistent": False,
            "issues": [],
            "corroborating_indicators": ["bimodal darkness", "non-black machine text"],
            "value_size_inconsistency": {
                "detected": True,
                "sizes_observed": 3,
                "fields": [
                    "Box 14 values smaller than Box 1-6 wage/tax values",
                    "EIN digits larger than Box 14 numeric values",
                ],
            },
        },
    }


def run() -> bool:
    from document_analyzer import DocumentAnalyzer

    ok = True
    here = os.path.dirname(__file__)

    # --- 1. AI plumbing: value_size_inconsistency -> Inconsistent Font Sizes ---
    a = DocumentAnalyzer(use_ai=False)
    a.flags = []
    a.risk_score = 0
    a._apply_employment_ai_flags(_mock_ai_font_size_result(), "W-2")
    titles = {f["title"] for f in a.flags}
    if "Inconsistent Font Sizes" in titles:
        print("PASS: AI value-size inconsistency -> 'Inconsistent Font Sizes' flag")
    else:
        print(f"FAIL: font-size flag did not fire from AI result; got {sorted(titles)}")
        ok = False

    # --- 2. Corroboration gate: no overlay + no AI indicators -> no false flag ---
    b = DocumentAnalyzer(use_ai=False)
    b.flags = []
    b.risk_score = 0
    weak = {
        "font_consistency": {
            "consistent": False,
            "issues": [],
            "corroborating_indicators": [],
            "value_size_inconsistency": {"detected": True, "sizes_observed": 2, "fields": []},
        }
    }
    b._apply_employment_ai_flags(weak, "W-2")
    if "Inconsistent Font Sizes" not in {f["title"] for f in b.flags}:
        print("PASS: font-size flag suppressed without corroboration")
    else:
        print("FAIL: font-size flag fired without corroboration (false positive)")
        ok = False

    # --- 3. Page selection + page-aware analysis (needs the gitignored sample) ---
    pdf = os.path.join(here, "test-samples", "2026-08-18-kelly-vasquez", "IRS letter Kelly Vasquez.pdf")
    if os.path.exists(pdf):
        try:
            import fitz

            idx = DocumentAnalyzer(use_ai=False)._select_form_page(fitz.open(pdf))
        except Exception as e:
            idx = None
            print(f"WARN: page-selection check errored: {e}")
        if idx == 1:
            print("PASS: _select_form_page picked the W-2 page (1), not the letter (0)")
        else:
            print(f"FAIL: expected form page 1, got {idx}")
            ok = False

        an = DocumentAnalyzer(use_ai=False)
        res = an.analyze(pdf, "W-2")
        if getattr(an, "_rasterized_page_index", None) == 1:
            print("PASS: analyze() rasterized the W-2 page for visual forensics")
        else:
            print(f"FAIL: rasterized page index = {getattr(an, '_rasterized_page_index', None)}")
            ok = False
        # A fabricated W-2 must never read as LOW without AI: the critical
        # bimodal-darkness flag floors it at MEDIUM+.
        if res.get("risk_level") in ("MEDIUM", "HIGH"):
            print(f"PASS: fraud W-2 scores {res['risk_level']} ({res['risk_score']}) even with AI off")
        else:
            print(f"FAIL: fraud W-2 scored {res.get('risk_level')} ({res.get('risk_score')})")
            ok = False
    else:
        print(f"SKIP: sample not present ({pdf}) -- page-selection checks skipped")

    return ok


if __name__ == "__main__":
    sys.exit(0 if run() else 1)

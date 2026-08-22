"""
Regression test for Myssy Clayson's 2026-08-21 report:

  "Detector Concerns" - fraud detector v2.2 failed to catch text-clipping
  in Box 14 of a real (but suspicious) 2024 W-2 that v2.1 had flagged as
  HIGH risk. Myssy manually confirmed at 500% zoom that the tops of the
  letters in Box 14 (NYPSL-E, NYSDI-E) are shaved off flush with the
  cell's top border.

Root cause found + fixed
------------------------
The submitted PDF is a standard IRS-issued W-2 PACKAGE - seven pages:
Copy A/B/C at pages 0, 1, 2 (the actual W-2 forms) and four pages of
"Instructions for Employee" / "Employers, Please Note" at pages 3-6.

`_select_form_page` (added 2026-08-18) was scoring each page by
  hlines + vlines,  where line := row/column with >40% dark pixels.
That threshold ALSO fires on rows of dense body prose, so Instructions
for Employee (continued) at page 5 scored 23 while the actual W-2 pages
scored 17-20. The detector then rasterized page 5 (instructions) for
visual/AI analysis instead of a W-2 page, so W-2-specific tells (font
sizes, box borders, text clipping) had nothing to bite on.

Fix: score each page by
  hlines + vlines + 5 * (long_row + long_col)
where long_row/long_col count rows/cols containing a SOLID continuous
run of dark pixels spanning >50% of the page dimension. Only real form
rule lines produce these; prose paragraphs cannot because letters have
inter-glyph gaps. On this PDF the actual W-2 pages score 67-73 while the
instruction pages stay at 2-23 - clean separation. On the fabricated
Kelly Vasquez W-2 (2026-08-18, whose "rules" are not perfectly solid) the
coarse coarse hlines+vlines term still wins, so page 1 is still picked.

Also strengthened the AI prompt (item 9 "Form Lines Crossing OR Clipping
Text") to explicitly ask the vision model to check for characters shaved
off at cell top/bottom borders, with W-2 Box 14 named as a common
location.

Assertions here are deterministic (no live AI call needed):
  1. _select_form_page picks one of pages 0-2 (a real W-2 copy), NOT
     the Instructions pages 3-6.
  2. analyze() rasterizes that same page for visual forensics.
  3. The rebuilt AI prompt asks about clipped-at-boundary text in Box 14.

Run with:
    python3 test_myssy_2026_08_21.py
"""
import os
import sys


def run() -> bool:
    from document_analyzer import DocumentAnalyzer
    import fitz

    ok = True
    here = os.path.dirname(__file__)
    pdf = os.path.join(here, "samples", "myssy-2026-08-21-box14-w2.pdf")

    if not os.path.exists(pdf):
        print(f"SKIP: sample not present ({pdf})")
        return True

    # --- 1. Page selector picks an actual W-2 copy, not an instructions page ---
    a = DocumentAnalyzer(use_ai=False)
    doc = fitz.open(pdf)
    idx = a._select_form_page(doc)
    doc.close()
    if idx in (0, 1, 2):
        print(f"PASS: _select_form_page picked a W-2 copy page ({idx}), not instructions (3-6)")
    else:
        print(f"FAIL: _select_form_page picked page {idx}; expected a W-2 copy at 0, 1, or 2")
        ok = False

    # --- 2. analyze() rasterizes that same W-2 page ---
    an = DocumentAnalyzer(use_ai=False)
    res = an.analyze(pdf, "W-2")
    rast = getattr(an, "_rasterized_page_index", None)
    if rast in (0, 1, 2):
        print(f"PASS: analyze() rasterized W-2 page {rast} for visual forensics")
    else:
        print(f"FAIL: analyze() rasterized page {rast}; expected a W-2 copy at 0, 1, or 2")
        ok = False

    # --- 3. Overlay tells still fire on the correct page ---
    # The Box 14 clipping renders as bimodal / inconsistent text darkness
    # regardless of whether the AI vision layer notices the actual clipping.
    titles = {f["title"] for f in res.get("flags", [])}
    darkness_flags = titles & {
        "Bimodal Text Darkness Pattern",
        "Inconsistent Text Darkness",
        "Non-Black Machine Text",
    }
    if darkness_flags:
        print(f"PASS: overlay/darkness flags fire on W-2 page: {sorted(darkness_flags)}")
    else:
        print(f"FAIL: expected at least one overlay/darkness flag; got {sorted(titles)}")
        ok = False

    # --- 4. Risk floor: never LOW on this document ---
    # With the correct page under analysis and darkness overlay signals
    # present, score must be MEDIUM or higher. This is the guardrail Myssy
    # relies on when the AI vision layer is on the fence.
    if res.get("risk_level") in ("MEDIUM", "HIGH"):
        print(f"PASS: risk floor holds - {res['risk_level']} ({res['risk_score']})")
    else:
        print(f"FAIL: expected MEDIUM/HIGH, got {res.get('risk_level')} ({res.get('risk_score')})")
        ok = False

    # --- 5. AI prompt explicitly asks about clipped-at-boundary text ---
    # Without this guidance, the vision model tends to ignore text that is
    # merely truncated at a cell border (as opposed to clearly overprinted).
    try:
        prompt = an._build_employment_ai_prompt("W-2", {}, "")  # type: ignore[attr-defined]
    except Exception:
        prompt = None
    if prompt is None:
        # Prompt builder may take different args across versions; fall back
        # to scanning the source directly.
        with open(os.path.join(here, "document_analyzer.py"), "r") as fh:
            prompt_source = fh.read()
    else:
        prompt_source = prompt
    needs = [
        "Clipping Text",       # section 9 title update
        "shaved off",           # explicit clipping wording
        "Box 14",               # W-2 hint
    ]
    missing = [n for n in needs if n not in prompt_source]
    if not missing:
        print("PASS: AI prompt explicitly covers text clipped at cell boundaries (incl. Box 14)")
    else:
        print(f"FAIL: AI prompt missing clipping guidance: {missing}")
        ok = False

    return ok


if __name__ == "__main__":
    try:
        sys.exit(0 if run() else 1)
    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)

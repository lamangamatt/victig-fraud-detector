"""
Regression test for Myssy Clayson's 2026-08-27 false-positive report
(Dion George - Experis / ManpowerGroup paystubs, Cisco Systems assignment).

Myssy forwarded two Experis paystubs where the applicant had redacted every
dollar amount (gross, net, all taxes, all YTD, all deductions) with solid
black bars. Employer, employee name, pay period dates, and assignment info
were all clearly visible. The detector scored the stubs 100/100 HIGH RISK
and Myssy pushed back with a very legitimate point:

  "We specifically ask for the documents to be redacted because salary
  history inquiry bans are currently active in 22 states and numerous city
  or county jurisdictions. In these areas, it is illegal for employers to
  request or verify an applicant's past income. Allowing these redactions
  directly protects the privacy of the applicant. Concurrently, it shields
  both our organization and our clients from being accused of performing
  an unlawful income verification."

Her ask: can the fraud detector be updated so wage/earnings redactions
don't trigger critical flags?

ROOT CAUSE:
The AI vision prompt (`_build_employment_ai_prompt`) treats "white or
colored rectangles covering original content" as a manipulation indicator
with no exception for compliance-redactable fields. `_apply_employment_ai_flags`
then turns each into an "AI Detected Manipulation" critical +15 flag. Two
of those (plus the AI's overall_assessment shifting to LIKELY_FRAUDULENT
which drags other subscores up) pushed the Dion George stubs to HIGH.

FIXES (2026-08-27):

  A. NEW `_is_wage_redaction_finding(indicator)` helper. Suppresses
     manipulation indicators that describe covering/redaction language
     combined with wage/tax/PII field names, unless the indicator also
     mentions an identity/date field (employer name, employee name, dates,
     tax year, pay period dates). Applied inside `_apply_employment_ai_flags`
     as a belt-and-suspenders backstop for the prompt update.

  B. AI PROMPT — added a CRITICAL POLICY block at the top of the employment
     prompt explaining VICTIG's redaction request and the salary-history-ban
     compliance basis. Instructs the model NOT to include compliance-related
     redactions (wages/taxes/YTD/PII) in `manipulation_indicators`,
     `visual_consistency.issues`, or `template_authenticity.concerns`.
     Instructs it to still flag redactions on identity/date fields.

  C. NEW `redaction_analysis` JSON field in the AI response schema. Reports
     whether redactions are compliance-related and lists suspicious
     redactions on identity/date fields.

  D. NEW handling in `_apply_employment_ai_flags`:
     - If AI reports `suspicious_redactions` (identity/date fields), add a
       critical "Suspicious Redaction on Identity/Date Field" flag (+30).
     - If AI reports `appears_compliance_related=True` on a paystub/W-2/1099,
       add an info-level "Wage/PII Redactions - Compliance Context" flag (+0)
       explaining why the redactions were expected.

SCOPE GUARDRAILS (what does NOT change):
  * IRS Wage & Income Transcripts still flag wage redaction bars (the IRS
    never redacts, that one's a real tell).
  * Bank/SSN redactions get their existing treatment.
  * W-2 math checks, box structure, font-size inconsistency, date tampering,
    line-clipping, box borders — all still fire normally.
  * Suspicious redactions on employer/employee/date fields still fire critical.

This test needs no API key (AI layer disabled). Sample stubs live under
test-samples/2026-08-27-dion-george/ which is gitignored (PII).

Run with:
    python3 test_myssy_2026_08_27.py
"""
import os
import sys

from document_analyzer import DocumentAnalyzer

HERE = os.path.dirname(__file__)
SAMPLE_DIR = os.path.join(HERE, "test-samples", "2026-08-27-dion-george")
SAMPLES = [
    os.path.join(SAMPLE_DIR, "Experis_20260827_074243.pdf"),
    os.path.join(SAMPLE_DIR, "Experis_20260827_074455.pdf"),
]


def test_wage_redaction_helper_suppresses_wage_bars():
    """`_is_wage_redaction_finding` correctly classifies AI indicators."""
    a = DocumentAnalyzer(use_ai=False)

    # SUPPRESS - covering language + wage/tax/PII field names
    suppress = [
        "Black bars cover all gross and net pay amounts",
        "Solid black rectangles obscure all wage figures",
        "Every dollar figure in the Taxes section is blacked out",
        "Deductions column is entirely redacted with black boxes",
        "YTD totals are covered by solid black rectangles",
        "Bank account number is redacted",
        "Routing number obscured by black bar",
        "SSN partially concealed with black box",
        "White boxes covering the withholding amounts",
        "Federal and state tax values are hidden behind black bars",
        "401(k) deduction covered",
        "Medicare wages blacked out",
    ]
    for indicator in suppress:
        assert a._is_wage_redaction_finding(indicator), \
            f"should suppress (compliance redaction): {indicator!r}"

    # KEEP - covering language + identity/date field
    keep = [
        "Black rectangle covering the employer name",
        "Employee name is redacted with a white box",
        "Pay period date obscured by black bar",
        "Tax year covered with a white rectangle",
        "First name is hidden with black box",
        # covering + wage + identity - identity wins, keep
        "Rectangle covers both employer name and gross pay",
    ]
    for indicator in keep:
        assert not a._is_wage_redaction_finding(indicator), \
            f"should NOT suppress (identity/date redaction): {indicator!r}"

    # KEEP - non-covering manipulation language (real fraud tells)
    keep_manip = [
        "Text appears to float above the background",
        "Blur artifacts around the wage numbers suggest editing",
        "Different resolution in the tax withholding area",
        "Cut-and-paste artifacts visible on the pay period line",
    ]
    for indicator in keep_manip:
        assert not a._is_wage_redaction_finding(indicator), \
            f"should NOT suppress (real manipulation, no covering language): {indicator!r}"

    print("PASS: _is_wage_redaction_finding classifies all 22 cases correctly")


def test_apply_ai_flags_filters_wage_redaction_manipulation():
    """`_apply_employment_ai_flags` drops wage-redaction manipulation flags
    but keeps real manipulation flags and adds the compliance-context note."""
    # Case 1: pure wage-redaction manipulation -> should be fully suppressed
    a = DocumentAnalyzer(use_ai=False)
    ai_result = {
        "overall_assessment": "SUSPICIOUS",
        "manipulation_indicators": {
            "detected": True,
            "indicators": [
                "Solid black bars cover all wage and tax amounts",
                "Every YTD total is blacked out with a rectangle",
            ],
        },
        "redaction_analysis": {
            "redactions_present": True,
            "appears_compliance_related": True,
            "fields_redacted": ["gross pay", "net pay", "all taxes", "YTD"],
            "suspicious_redactions": [],
        },
    }
    a._apply_employment_ai_flags(ai_result, "Pay Stub")
    titles = {f["title"] for f in a.flags}
    assert "AI Detected Manipulation" not in titles, \
        f"wage-redaction manipulation should be suppressed, got: {titles}"
    assert "Wage/PII Redactions - Compliance Context" in titles, \
        f"compliance context flag should fire, got: {titles}"
    context_flag = next(f for f in a.flags
                       if f["title"] == "Wage/PII Redactions - Compliance Context")
    assert context_flag["score_impact"] == 0, "context flag must not add score"
    assert context_flag["severity"] == "info", "context flag must be info level"
    print("PASS: pure wage-redaction manipulation suppressed + compliance context added")

    # Case 2: real manipulation (not redaction-related) -> still fires
    b = DocumentAnalyzer(use_ai=False)
    ai_result_real = {
        "overall_assessment": "LIKELY_FRAUDULENT",
        "manipulation_indicators": {
            "detected": True,
            "indicators": [
                "Blur artifacts around wage numbers indicate digital editing",
                "Cut-and-paste seams visible in employer address block",
            ],
        },
        "redaction_analysis": {"redactions_present": False},
    }
    b._apply_employment_ai_flags(ai_result_real, "Pay Stub")
    ai_flags = [f for f in b.flags if f["title"] == "AI Detected Manipulation"]
    assert len(ai_flags) == 2, f"real manipulation should fire, got: {b.flags}"
    print("PASS: real manipulation flags (blur / cut-paste) still fire")

    # Case 3: identity/date redaction -> critical suspicious-redaction flag
    c = DocumentAnalyzer(use_ai=False)
    ai_result_identity = {
        "overall_assessment": "SUSPICIOUS",
        "manipulation_indicators": {
            "detected": True,
            "indicators": [
                "Black rectangle covering the employer name",
                "White box over the pay period date",
            ],
        },
        "redaction_analysis": {
            "redactions_present": True,
            "appears_compliance_related": False,
            "fields_redacted": ["employer name", "pay period date"],
            "suspicious_redactions": [
                "Employer name is covered by a black rectangle",
                "Pay period date is obscured by a white box",
            ],
        },
    }
    c._apply_employment_ai_flags(ai_result_identity, "Pay Stub")
    sus_flags = [f for f in c.flags
                 if f["title"] == "Suspicious Redaction on Identity/Date Field"]
    assert len(sus_flags) == 2, \
        f"identity/date redactions should fire critical, got: {c.flags}"
    for f in sus_flags:
        assert f["severity"] == "critical"
        assert f["score_impact"] == 30
    # And identity-covering manipulation indicators still fire (not suppressed
    # by the wage-redaction filter because they mention identity fields)
    ai_flags = [f for f in c.flags if f["title"] == "AI Detected Manipulation"]
    assert len(ai_flags) == 2, \
        f"identity/date covering language should still fire manipulation, got: {c.flags}"
    print("PASS: identity/date redactions fire critical + AI manipulation retained")


def test_dion_george_paystubs_no_high_risk():
    """Dion George Experis paystubs: with AI DISABLED (baseline), should stay
    LOW or MEDIUM, not HIGH. The fixes above address the AI layer that was
    pushing this to 100/100 in production. This test proves the deterministic
    baseline is fine and the paystubs are structurally clean."""
    if not all(os.path.exists(s) for s in SAMPLES):
        print(f"SKIP: samples not found under {SAMPLE_DIR}")
        return

    for sample in SAMPLES:
        name = os.path.basename(sample)
        res = DocumentAnalyzer(use_ai=False).analyze(sample, "Pay Stub")
        risk = res.get("risk_level")
        score = res.get("risk_score")
        titles = [f["title"] for f in res.get("flags", [])]
        print(f"  {name}: {risk} / {score}/100  flags={titles}")
        assert risk != "HIGH", \
            f"{name}: should not be HIGH-risk on deterministic baseline"
    print("PASS: both Dion George stubs stay below HIGH on deterministic baseline")


def test_ai_prompt_has_redaction_policy():
    """The employment AI prompt must include the CRITICAL POLICY block that
    tells the model to treat compliance redactions as normal."""
    a = DocumentAnalyzer(use_ai=False)
    prompt = a._build_employment_ai_prompt("Pay Stub", "Today's Date: 2026-08-27")
    required_phrases = [
        "CRITICAL POLICY",
        "salary history inquiry ban",
        "22+ US states",
        "expected and normal",
        "manipulation_indicators",
        "redaction_analysis",
        "Employer name",
        "Employee name",
    ]
    missing = [p for p in required_phrases if p.lower() not in prompt.lower()]
    assert not missing, f"prompt missing required phrases: {missing}"
    print("PASS: AI prompt contains all required redaction-policy phrases")


def run():
    print("== test_wage_redaction_helper_suppresses_wage_bars ==")
    test_wage_redaction_helper_suppresses_wage_bars()

    print("\n== test_apply_ai_flags_filters_wage_redaction_manipulation ==")
    test_apply_ai_flags_filters_wage_redaction_manipulation()

    print("\n== test_ai_prompt_has_redaction_policy ==")
    test_ai_prompt_has_redaction_policy()

    print("\n== test_dion_george_paystubs_no_high_risk ==")
    test_dion_george_paystubs_no_high_risk()

    print("\nALL TESTS PASSED")
    return True


if __name__ == "__main__":
    try:
        run()
    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)

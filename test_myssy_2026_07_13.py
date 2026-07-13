"""
Regression test: Christopher Nicola IRS Wage & Income Transcript forgery.

Sample forwarded by Myssy Clayson on 2026-07-13 (VICTIG file #2684776).
Fabrication signals she called out (source: email 2026-07-13 12:07 CDT):
  1. Response Date blank in the transcript header block
  2. Employee first names removed (and partial last name on one W-2)
  3. Submission Type shows "Origin" instead of "Original" (right-justified)
  4. IRS footer replaced with "NON-EMPLOYMENT INFORMATION REDACTED" box
  5. Employer names not consistently truncated into 3-4 word groups
  6. Third Party Sick Pay Indicator values truncated
  7. PDF was converted to editable form (only IRS-issued PDFs should be
     uneditable) - /Subject metadata reads "Employment verification".

This test asserts the detector fires HIGH risk with at least these
critical/warning flags on the sample.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from irs_transcript import analyze_files

SAMPLE = os.path.join(
    os.path.dirname(__file__),
    "samples",
    "2026-07-13-myssy",
    "Christopher_Nicola_Employment_Verification_2018-2025_REDACTED.pdf",
)


def main():
    if not os.path.exists(SAMPLE):
        print(f"SKIP  sample not present: {SAMPLE}")
        return 0

    result = analyze_files([SAMPLE])

    errors = []

    # Overall risk should be HIGH
    if result["risk_level"] != "HIGH":
        errors.append(
            f"Expected overall HIGH risk, got {result['risk_level']} "
            f"({result['risk_score']}/100)"
        )
    if result["risk_score"] < 90:
        errors.append(
            f"Expected risk score >= 90, got {result['risk_score']}"
        )

    doc = result["documents"][0]
    titles = {f["title"] for f in doc["flags"]}

    required = {
        'Truncated "Submission Type" Values',
        '"Non-Employment Information Redacted" Replacement Box',
        "Missing Response Date on IRS Transcript",
    }
    missing = required - titles
    if missing:
        errors.append(f"Missing required flags: {sorted(missing)}")

    # Field-level parse assertions
    fields = doc["fields"]
    if fields["truncated_submission_types"] < 2:
        errors.append(
            f"Expected >=2 truncated submission types, got "
            f"{fields['truncated_submission_types']}"
        )
    if not fields["has_nonemp_redacted_box"]:
        errors.append('Expected "Non-Employment Information Redacted" box to be detected')
    if fields["response_date"]:
        errors.append(
            f"Expected blank response_date on the forgery, got "
            f"{fields['response_date']!r}"
        )
    if fields["request_date"] is None:
        errors.append("Expected request_date to still be parsed from the header")

    if errors:
        print("FAIL")
        for e in errors:
            print(f"  - {e}")
        print(f"  overall={result['risk_level']} score={result['risk_score']}")
        print(f"  flags: {sorted(titles)}")
        return 1

    print(f"PASS  overall={result['risk_level']} score={result['risk_score']}")
    print(f"      flags: {sorted(titles)}")
    print(
        f"      submission_type_truncated={fields['truncated_submission_types']}"
        f"  sick_pay_truncated={fields['truncated_sickpay_indicators']}"
        f"  nonemp_box={fields['has_nonemp_redacted_box']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
Regression test for Myssy Clayson's *clean* IRS transcript sample
(received 2026-07-08 as a follow-up to the KCC/Excalibur forgery batch).

Myssy sent Maryville22.pdf — a legitimate 3-page IRS Wage & Income
Transcript — after her forgery samples, so we'd have a known-good
baseline. When she first ran it through the tool it scored MEDIUM/25
because the wage-bar detector was falsely tripping on the thin
horizontal separator rules around the "Sensitive Taxpayer Data"
masthead.

The updated detector requires a *tall* contiguous dark band (>=30 rows
at 200 dpi), which the masthead rules never satisfy. This test locks
in that no false-positive flag fires on a clean, multi-page transcript.
"""

from __future__ import annotations
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "samples", "2026-07-08-myssy-clean", "Maryville22.pdf")

sys.path.insert(0, HERE)
from irs_transcript import analyze_files, detect_wage_redaction_bar  # noqa: E402


def main() -> int:
    if not os.path.exists(SAMPLE):
        print(f"SKIP: sample not found at {SAMPLE} (samples/ is gitignored)")
        return 0

    failures: list[str] = []

    # The wage-bar detector alone must not fire on a clean transcript.
    if detect_wage_redaction_bar(SAMPLE):
        failures.append("detect_wage_redaction_bar fired on clean IRS transcript")

    report = analyze_files([SAMPLE])

    if report["risk_level"] != "LOW":
        failures.append(
            f"Expected overall LOW risk, got {report['risk_level']} "
            f"(score {report['risk_score']})"
        )

    doc = report["documents"][0]
    if doc["score"] != 0:
        failures.append(
            f"Expected 0/100 score on clean transcript, got {doc['score']} "
            f"with flags: {[f['title'] for f in doc['flags']]}"
        )
    if doc["flags"]:
        failures.append(
            f"Expected no flags, got: {[f['title'] for f in doc['flags']]}"
        )

    # Field extraction sanity — these are the real IRS-issued values
    fields = doc["fields"]
    if fields["tracking_number"] != "110825154192":
        failures.append(f"Tracking# wrong: {fields['tracking_number']!r}")
    if fields["tax_period"] != "12-31-2022":
        failures.append(f"Tax period wrong: {fields['tax_period']!r}")
    if not fields["has_title"] or not fields["has_masthead"]:
        failures.append("Masthead / title should be detected on page 1")
    if fields["wage_bar_redaction"]:
        failures.append("wage_bar_redaction should be False on clean transcript")

    if failures:
        print("FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(f"PASS  overall={report['risk_level']} score={report['risk_score']}")
    print(
        f"      Maryville22.pdf: {doc['risk_level']} {doc['score']}/100  "
        f"tracking={fields['tracking_number']}  "
        f"w2_sections={fields['w2_section_count']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

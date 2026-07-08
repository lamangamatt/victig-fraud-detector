"""
Regression test for Myssy Clayson's IRS transcript forgery sample
(received 2026-07-07).

Two PDFs — KCC_W2_Redacted.pdf and Excalibur_W2_Redacted.pdf — each
present themselves as page 1 of an IRS Wage & Income Transcript and
share the same tracking number (110822371779). The existing single-doc
detector rated both LOW/25. The new IRS transcript module should catch
the duplicate-header pattern and rate the submission HIGH.
"""

from __future__ import annotations
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples", "2026-07-07-myssy")

sys.path.insert(0, HERE)
from irs_transcript import analyze_files  # noqa: E402


def _flag_titles(flags):
    return {f["title"] for f in flags}


def main() -> int:
    files = [
        os.path.join(SAMPLES, "KCC_W2_Redacted.pdf"),
        os.path.join(SAMPLES, "Excalibur_W2_Redacted.pdf"),
    ]
    for p in files:
        if not os.path.exists(p):
            print(f"SKIP: sample not found at {p} (samples/ is gitignored)")
            return 0

    report = analyze_files(files)

    failures: list[str] = []

    # Overall verdict
    if report["risk_level"] != "HIGH":
        failures.append(
            f"Expected overall HIGH risk, got {report['risk_level']} "
            f"(score {report['risk_score']})"
        )

    # Batch-level: duplicate tracking number MUST fire
    batch_titles = _flag_titles(report["batch_flags"])
    required_batch = {
        "Duplicate IRS Transcript Tracking Number",
        "Same Tracking Number, Different Creation Times",
    }
    missing_batch = required_batch - batch_titles
    if missing_batch:
        failures.append(f"Missing batch flags: {missing_batch}")

    # Per-document: each doc should carry its own duplicate-header flag
    # and truncated employer-name flag
    for doc in report["documents"]:
        titles = _flag_titles(doc["flags"])
        if "Duplicate IRS Transcript Header" not in titles:
            failures.append(
                f"{os.path.basename(doc['file'])}: missing "
                f"'Duplicate IRS Transcript Header'"
            )
        if "Truncated / Garbled Employer Name" not in titles:
            failures.append(
                f"{os.path.basename(doc['file'])}: missing "
                f"'Truncated / Garbled Employer Name'"
            )
        if doc["risk_level"] != "HIGH":
            failures.append(
                f"{os.path.basename(doc['file'])}: expected HIGH, "
                f"got {doc['risk_level']} ({doc['score']})"
            )

    # Field extraction sanity
    kcc = next(d for d in report["documents"] if "KCC" in d["file"])
    exc = next(d for d in report["documents"] if "Excalibur" in d["file"])
    if kcc["fields"]["tracking_number"] != "110822371779":
        failures.append(
            f"KCC tracking# wrong: {kcc['fields']['tracking_number']!r}"
        )
    if exc["fields"]["tracking_number"] != "110822371779":
        failures.append(
            f"Excalibur tracking# wrong: {exc['fields']['tracking_number']!r}"
        )
    if kcc["fields"]["employer_name"] != "KURT CARS CONS LL":
        failures.append(
            f"KCC employer wrong: {kcc['fields']['employer_name']!r}"
        )
    if exc["fields"]["employer_name"] != "EXCA SECU IN":
        failures.append(
            f"Excalibur employer wrong: {exc['fields']['employer_name']!r}"
        )

    if failures:
        print("FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(f"PASS  overall={report['risk_level']} score={report['risk_score']}")
    print(f"      batch flags: {sorted(batch_titles)}")
    for d in report["documents"]:
        print(
            f"      {os.path.basename(d['file'])}: "
            f"{d['risk_level']} {d['score']}/100  "
            f"tracking={d['fields']['tracking_number']}  "
            f"employer={d['fields']['employer_name']!r}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

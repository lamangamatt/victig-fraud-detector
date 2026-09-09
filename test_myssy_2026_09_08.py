"""Regression tests for Myssy Clayson's 2026-09-08 extraction-bug pair.

Two production false positives, same root class — numeric field
misattribution during data extraction on column-layout documents:

FILE 2727974 (ADP paystub): the Gross Pay line reads
    "Gross Pay    80.00    5752.11    134985.57"   (hours / current / YTD)
The extractor grabbed the FIRST number (80.00 hours) as gross pay, then
"Net pay ($4,483.31) exceeds gross pay ($80.00)" fired as a critical
fraud flag. Fix: money labels now capture the full line remainder and
_pick_money_from_line() drops a leading hours-like token (<= 500 with a
4x-larger second token) when 3+ numbers are present.

FILE 2747281 (Takeda/Randstad W-2 packet): 'box\\s*1' matched the phrase
"box 12" in the form's fine print ("See Instructions for box 12") and
captured the digit "2" as wages -> $2.00 wages with $7,376.75 withholding
-> "Impossible Federal Tax Rate 368837.5%" critical + low-wage warning.
(Myssy described it as the EIN being read as a dollar amount — same
mechanism: values associated with the wrong labels in OCR column
layouts.) Fixes:
  * box-number patterns carry a (?![0-9a-dA-D]) lookahead so box 1
    cannot match box 12/12a/14 etc.;
  * W-2 captures are same-line only — a MISSING value is safer than a
    WRONG one (math checks skip absent fields);
  * captures require a leading digit (no more bare-comma matches);
  * sanity gates: withholding > wages => "Extraction Uncertain" info
    (score 0) instead of impossible-rate critical; paystub net > gross
    with gross < $500 => same treatment;
  * low-wage check gains consistency guards: skip when sibling wage
    fields or the document's own largest $-amount contradict a tiny
    wages parse (protects RG_Sage-style ADP Earnings Summary layouts
    whose currency renders as space-separated triplets).

The real PDFs live in test-samples/myssy-2026-09-08/ (gitignored, PII).
File-based tests skip cleanly when absent; unit tests always run.

Author: Molesley | 2026-09-09
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from document_analyzer import DocumentAnalyzer

SAMPLES = os.path.join(HERE, 'test-samples', 'myssy-2026-09-08')
PAYSTUB = os.path.join(SAMPLES, 'paystub-2727974.pdf')
W2S = os.path.join(SAMPLES, 'w2s-takeda-2747281.pdf')


class PickMoneyFromLineTests(unittest.TestCase):
    """Unit tests for the multi-column token selector (no PII needed)."""

    def pick(self, line, field='gross_pay'):
        return DocumentAnalyzer._pick_money_from_line(line, field)

    def test_adp_hours_current_ytd_takes_current(self):
        # File 2727974's exact layout: hours 80.00, current 5752.11, YTD 134985.57
        self.assertEqual(self.pick('80.00      5752.11     134985.57'), 5752.11)

    def test_two_token_current_ytd_takes_first(self):
        # Net Pay line: current + YTD only — first token is correct
        self.assertEqual(self.pick('4483.31      98182.56', 'net_pay'), 4483.31)

    def test_federal_tax_two_tokens_keeps_first(self):
        # "Federal Withholding Tax 412.69 14387.20" — 412.69 is current
        self.assertEqual(self.pick('412.69       14387.20', 'federal_tax'), 412.69)

    def test_small_parttime_gross_two_tokens_untouched(self):
        # Legit tiny gross with YTD: 2 tokens -> hours rule requires 3+
        self.assertEqual(self.pick('320.00     4800.00'), 320.00)

    def test_parttime_with_hours_three_tokens(self):
        # 20 hrs, $320 current, $4800 YTD -> picks current
        self.assertEqual(self.pick('20.00   320.00   4800.00'), 320.00)

    def test_single_token(self):
        self.assertEqual(self.pick('5752.11'), 5752.11)

    def test_comma_amounts(self):
        self.assertEqual(self.pick('80.00   5,752.11   134,985.57'), 5752.11)

    def test_no_numbers_returns_none(self):
        self.assertIsNone(self.pick('see attached summary'))


class W2BoxBoundaryTests(unittest.TestCase):
    """The 'box 1' pattern must not match 'box 12' fine print (no PII)."""

    W2_FINEPRINT = (
        'Employer identification number\n38-3691673\n'
        '12a See instructions for box 12\n'
        '14 Other\n'
        'box 12b\n'
    )

    def extract(self, text):
        a = DocumentAnalyzer(use_ai=False)
        return a._extract_document_data(text, 'W-2')

    def test_box12_fineprint_yields_no_wages(self):
        data = self.extract(self.W2_FINEPRINT)
        self.assertNotIn('wages', data,
                         f"wages should not extract from box-12 fine print, got {data.get('wages')!r}")

    def test_clean_same_line_box1_still_extracts(self):
        data = self.extract('Box 1 Wages, tips, other compensation: 55,432.10\n')
        self.assertEqual(data.get('wages'), 55432.10)

    def test_wages_tips_same_line(self):
        data = self.extract('Wages, tips 43,210.99\nFederal income tax withheld 5,100.25\n')
        self.assertEqual(data.get('wages'), 43210.99)
        self.assertEqual(data.get('federal_withheld'), 5100.25)

    def test_cross_line_value_not_grabbed(self):
        # OCR column layout: labels then values on later lines.
        # Same-line-only capture must leave the field absent.
        data = self.extract('1 Wages, tips, other comp.\n2 Federal income tax withheld\n7376.75\n450.87\n')
        self.assertNotIn('wages', data)


class SanityGateTests(unittest.TestCase):
    """Misparse patterns degrade to info notes, never fraud criticals."""

    def test_w2_withholding_exceeds_wages_is_info_not_critical(self):
        a = DocumentAnalyzer(use_ai=False)
        a.flags = []; a.risk_score = 0
        result = a._validate_w2_math('', {'wages': 2.0, 'federal_withheld': 7376.75})
        titles = [f['title'] for f in a.flags]
        self.assertIn('Extraction Uncertain - Wage Fields', titles)
        self.assertNotIn('Impossible Federal Tax Rate', titles)
        crits = [f for f in a.flags if f['severity'] == 'critical']
        self.assertEqual(crits, [])
        self.assertEqual(a.risk_score, 0)

    def test_w2_genuinely_impossible_rate_still_fires(self):
        # 60% withholding (plausible-as-typed but impossible) stays critical
        a = DocumentAnalyzer(use_ai=False)
        a.flags = []; a.risk_score = 0
        a._validate_w2_math('', {'wages': 10000.0, 'federal_withheld': 6000.0})
        titles = [f['title'] for f in a.flags]
        self.assertIn('Impossible Federal Tax Rate', titles)

    def test_paystub_tiny_gross_is_info_not_critical(self):
        a = DocumentAnalyzer(use_ai=False)
        a.flags = []; a.risk_score = 0
        a._validate_pay_stub_math('', {'gross_pay': 80.0, 'net_pay': 4483.31})
        titles = [f['title'] for f in a.flags]
        self.assertIn('Extraction Uncertain - Gross Pay Field', titles)
        self.assertNotIn('Math Error: Net > Gross', titles)
        self.assertEqual(a.risk_score, 0)

    def test_paystub_real_net_gt_gross_still_fires(self):
        # Plausible-sized gross with net above it = the real fraud pattern
        a = DocumentAnalyzer(use_ai=False)
        a.flags = []; a.risk_score = 0
        a._validate_pay_stub_math('', {'gross_pay': 2500.0, 'net_pay': 3100.0})
        titles = [f['title'] for f in a.flags]
        self.assertIn('Math Error: Net > Gross', titles)

    def test_low_wage_guard_skips_on_contradicting_largest_amount(self):
        a = DocumentAnalyzer(use_ai=False)
        a.flags = []; a.risk_score = 0
        a._check_low_wages_with_withholding(
            'Wages, tips 496\nfederal tax withheld 120.00',
            {'wages': 496.0, 'federal_withheld': 120.0, 'largest_amount': 496702.91})
        titles = [f['title'] for f in a.flags]
        self.assertNotIn('Implausibly Low Wages With Tax Withholding', titles)

    def test_low_wage_still_fires_on_consistent_fraud_pattern(self):
        # The 2026-07-03 pattern: consistently tiny figures, no large amounts
        a = DocumentAnalyzer(use_ai=False)
        a.flags = []; a.risk_score = 0
        a._check_low_wages_with_withholding(
            'Wages, tips, other compensation 918\nSocial security tax withheld 56.92',
            {'wages': 918.0, 'social_security_tax': 56.92})
        titles = [f['title'] for f in a.flags]
        self.assertIn('Implausibly Low Wages With Tax Withholding', titles)


@unittest.skipUnless(os.path.exists(PAYSTUB), 'PII sample not present')
class Paystub2727974Tests(unittest.TestCase):
    """End-to-end on the real file (local only, gitignored)."""

    @classmethod
    def setUpClass(cls):
        a = DocumentAnalyzer(use_ai=False)
        cls.r = a.analyze(PAYSTUB, doc_type='Pay Stub')

    def test_gross_is_dollars_not_hours(self):
        self.assertEqual(self.r['extracted_data'].get('gross_pay'), 5752.11)

    def test_no_net_gt_gross_critical(self):
        titles = [f['title'] for f in self.r['flags']]
        self.assertNotIn('Math Error: Net > Gross', titles)

    def test_risk_low(self):
        self.assertEqual(self.r['risk_level'], 'LOW')


@unittest.skipUnless(os.path.exists(W2S), 'PII sample not present')
class W2Takeda2747281Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        a = DocumentAnalyzer(use_ai=False)
        cls.r = a.analyze(W2S, doc_type='W-2')

    def test_no_garbage_wages(self):
        w = self.r['extracted_data'].get('wages')
        # Either absent or a real dollar figure — never a stray fine-print digit
        if w not in (None, ''):
            self.assertGreaterEqual(float(w), 100.0)

    def test_no_impossible_rate_critical(self):
        titles = [f['title'] for f in self.r['flags']]
        self.assertNotIn('Impossible Federal Tax Rate', titles)

    def test_no_low_wage_warning(self):
        titles = [f['title'] for f in self.r['flags']]
        self.assertNotIn('Implausibly Low Wages With Tax Withholding', titles)


if __name__ == '__main__':
    unittest.main(verbosity=2)

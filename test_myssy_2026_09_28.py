"""Regression test for Myssy Clayson's 2026-09-28 error list, file 2767274
(CVS Caremark).

The future-dated-tax-year check did a blind `re.findall(r'\\b(20[2-9]\\d)\\b',
text)` over the ENTIRE document and reported the first hit >= current_year+1
as "the tax year." On the CVS Caremark document, a stray 4-digit number
elsewhere in the text (an OCR misread / ID number, not the tax year) matched
as "2044," and the tool flagged "Document references tax year 2044... current
year is 2026" as a critical Future-Dated Document finding. Myssy: "The tax
year is clearly 2025."

Fix: the check now takes the MOST-FREQUENT 20[2-9]X year in the document as
the tax year (a real tax year is printed repeatedly across box labels, copy
headers, and filing boilerplate; a stray misread number appears once), and
breaks ties toward the year closest to today.

Author: Molesley | 2026-09-28
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from document_analyzer import DocumentAnalyzer


class FutureTaxYearMisreadTests(unittest.TestCase):

    def check(self, text, doc_type='W-2'):
        a = DocumentAnalyzer(use_ai=False)
        a.flags = []
        a.risk_score = 0
        a._check_text_anomalies(text, doc_type)
        return a

    def test_stray_year_like_number_not_treated_as_tax_year(self):
        # Real tax year 2025 repeats (box labels / copy headers); "2044"
        # appears once, as an unrelated ID/control number.
        text = (
            'Form W-2 Wage and Tax Statement 2025\n'
            'Copy B - To Be Filed With Employee\'s FEDERAL Tax Return 2025\n'
            'Control No. 2044\n'
            'Copy C - For EMPLOYEE\'S RECORDS 2025\n'
        )
        a = self.check(text)
        titles = [f['title'] for f in a.flags]
        self.assertNotIn('Future-Dated Document', titles,
                          f'should not flag a stray non-tax-year 4-digit number; flags={titles}')

    def test_genuine_future_tax_year_still_fires(self):
        # The real, repeated tax year is actually in the future.
        text = (
            'Form W-2 Wage and Tax Statement 2044\n'
            'Copy B - To Be Filed With Employee\'s FEDERAL Tax Return 2044\n'
            'Copy C - For EMPLOYEE\'S RECORDS 2044\n'
        )
        a = self.check(text)
        titles = [f['title'] for f in a.flags]
        self.assertIn('Future-Dated Document', titles)

    def test_current_year_before_december_still_warns(self):
        year_now = __import__('datetime').datetime.now().year
        month_now = __import__('datetime').datetime.now().month
        if month_now == 12:
            self.skipTest('current month is December; premature-year case does not apply')
        text = f'Form W-2 Wage and Tax Statement {year_now}\nCopy B {year_now}\nCopy C {year_now}\n'
        a = self.check(text)
        titles = [f['title'] for f in a.flags]
        self.assertIn('Premature Tax Year', titles)


if __name__ == '__main__':
    unittest.main()

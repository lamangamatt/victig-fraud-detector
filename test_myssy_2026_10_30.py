"""Regression tests for Myssy Clayson's 2026-10-30 email: two Lincoln Property / Dayforce
W-2s (browser print of the payroll portal, three copies on one page) scored 100/100 HIGH
even though the detector itself said "Normal for documents downloaded from employer/bank
portals", and the old Box 12-17 errors were "back".

Root causes:
1. The PDF producer is just "Chrome/Skia"; the payroll system only appears in the PDF
   *title* ("Earnings - Dayforce"), so the two-level-darkness checks (pre-printed form +
   payroll data) were not suppressed.
2. Copy labels / perforation lines are vector art, so the multi-copy layout was not
   recognised (no "FOLD AND DETACH HERE" in the text layer).
3. Even when recognised, per-wording regex suppression of the vision model's box-geometry
   misreads is whack-a-mole. On multi-copy + recognised payroll system those observations
   are now kept visible but carry no score.
4. "Multiple Anomalies Detected" counted explanatory notes as anomalies.

Author: Molesley | 2026-10-30
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from document_analyzer import DocumentAnalyzer

DAYFORCE_TEXT = """
Federal Box 1 Soc. Sec. Box 3 & 7 Medicare Box 5
227-69-1734 75-1653011 000944276401
36187.91 3271.53 C 25.60 D 2666.68 DD 2257.50
2024
227-69-1734 75-1653011 000944276401
36187.91 3271.53
2024
227-69-1734 75-1653011 000944276401
2024
"""
SINGLE_COPY_TEXT = "227-69-1734 75-1653011 000944276401 36187.91 3271.53"

# What the vision model produced for the real files (paraphrased from the screenshots).
AI_MISREADS = {
    'font_consistency': {
        'consistent': False,
        'issues': ["Employee name appears in different font weight than other values"],
        'corroborating_indicators': ['Box 13 structure invalid'],
        'value_size_inconsistency': {'detected': True, 'sizes_observed': 2,
                                     'fields': ["Box 14 'Code C' smaller than wage boxes"]},
    },
    'invalid_field_values': {'detected': True, 'issues': [
        "Box 14 contains 'Code C', '12b', '13c' - not legitimate Box 14 codes"]},
    'manipulation_indicators': {'detected': True, 'indicators': [
        "Box 15 border appears lighter/incomplete compared to boxes 16 and 17"]},
    'box_numbering_structure': {'valid': False, 'issues': [
        "Box 13 shows three separate checkbox rows rather than one box with three checkboxes"]},
    'overlapping_text': {'detected': True, 'issues': ["'VA' in Box 15 collides with left border"]},
    'lines_crossing_text': {'detected': True, 'issues': [
        "Horizontal line crosses digits of Box 15 state ID"]},
    'box_border_anomalies': {'detected': True, 'issues': ["Box 15 top border lighter than Box 16"]},
}


def fresh(meta=None, multi=False):
    a = DocumentAnalyzer(use_ai=False)
    a.flags = []
    a.risk_score = 0
    a._metadata = meta or {}
    a._is_multi_copy_layout = multi
    return a


def titles(a):
    return [f['title'] for f in a.flags]


DAYFORCE_META = {'creator': 'Mozilla/5.0 (Windows NT 10.0) Chrome/156 Edg/156',
                 'producer': 'Skia/PDF m156', 'title': 'Earnings - Dayforce'}


class PortalTitleCountsAsPayrollProducer(unittest.TestCase):

    def test_dayforce_title_in_browser_print(self):
        self.assertTrue(fresh(DAYFORCE_META)._has_legitimate_producer())

    def test_other_portal_titles(self):
        for t in ('W-2 Statement - ADP Workforce Now', 'Paycom - Employee', 'My Pay | Paylocity'):
            m = dict(DAYFORCE_META, title=t)
            self.assertTrue(fresh(m)._has_legitimate_producer(), t)

    def test_plain_browser_print_is_not_legit(self):
        m = dict(DAYFORCE_META, title='W2 final.docx')
        self.assertFalse(fresh(m)._has_legitimate_producer())

    def test_substring_does_not_match(self):
        m = dict(DAYFORCE_META, title='Gadpet payroll sapphire')
        self.assertFalse(fresh(m)._has_legitimate_producer())

    def test_dayforce_creator_key(self):
        m = {'creator': 'Dayforce', 'producer': '', 'title': ''}
        self.assertTrue(fresh(m)._has_legitimate_producer())


class MultiCopyFromRepeatedIdentifiers(unittest.TestCase):

    def test_three_copies_repeating_ssn_and_ein(self):
        self.assertTrue(fresh()._is_adp_multi_copy_layout(DAYFORCE_TEXT))

    def test_single_copy_not_multi(self):
        self.assertFalse(fresh()._is_adp_multi_copy_layout(SINGLE_COPY_TEXT))

    def test_masked_ssn_repeated(self):
        t = "XXX-XX-1734 75-1653011\nXXX-XX-1734 75-1653011\n"
        self.assertTrue(fresh()._is_adp_multi_copy_layout(t))

    def test_repeated_ein_alone_is_not_enough(self):
        self.assertFalse(fresh()._is_adp_multi_copy_layout("75-1653011 and 75-1653011 again"))


class GeometryObservationsAreLowWeight(unittest.TestCase):

    def test_multicopy_payroll_print_scores_zero_and_lists_observations(self):
        a = fresh(DAYFORCE_META, multi=True)
        a._apply_employment_ai_flags(AI_MISREADS, 'W-2')
        self.assertEqual(a.risk_score, 0, [(f['title'], f['score_impact']) for f in a.flags])
        self.assertIn('AI Visual Observations (Low Weight)', titles(a))
        note = next(f for f in a.flags if f['title'] == 'AI Visual Observations (Low Weight)')
        self.assertIn('Box 13', note['description'])  # still visible to the reviewer

    def test_unrecognised_producer_still_scored(self):
        a = fresh({'creator': 'Microsoft Word', 'producer': '', 'title': 'W2 final'}, multi=True)
        a._apply_employment_ai_flags(AI_MISREADS, 'W-2')
        self.assertGreater(a.risk_score, 0)
        self.assertNotIn('AI Visual Observations (Low Weight)', titles(a))

    def test_single_copy_layout_still_scored(self):
        a = fresh(DAYFORCE_META, multi=False)
        a._apply_employment_ai_flags(AI_MISREADS, 'W-2')
        self.assertGreater(a.risk_score, 0)

    def test_content_findings_still_scored_on_lowweight_docs(self):
        a = fresh(DAYFORCE_META, multi=True)
        a._apply_employment_ai_flags({
            'date_year_tampering': {'detected': True, 'issues': ['Tax year 2024 has been painted over']},
        }, 'W-2')
        self.assertIn('Date/Year Tampering Detected', titles(a))
        self.assertGreater(a.risk_score, 0)

    def test_box_3_5_higher_than_box_1_claim_dropped_on_multicopy(self):
        a = fresh(DAYFORCE_META, multi=True)
        a._apply_employment_ai_flags({'invalid_field_values': {'detected': True, 'issues': [
            'Box 3 Social Security wages (116336.11) and Box 5 are HIGHER than Box 1 wages (104119.44)']}}, 'W-2')
        self.assertEqual(a.risk_score, 0)

    def test_parenthesised_deferred_comp_not_negative(self):
        a = fresh(DAYFORCE_META, multi=True)
        a._apply_employment_ai_flags({'invalid_field_values': {'detected': True, 'issues': [
            "Deferred Comp shows impossible negative value in parentheses (12216.67)"]}}, 'W-2')
        self.assertEqual(a.risk_score, 0)


class ExplanatoryNotesAreNotAnomalies(unittest.TestCase):

    def test_clean_portal_print_has_no_multiple_anomalies(self):
        a = fresh()
        a._add_flag('Recently Created', 'Document was created 1 days ago. Normal for documents downloaded from employer/bank portals.', 'info', 0)
        a._add_flag('Expected Text Darkness Variance', 'x', 'info', 0)
        a._add_flag('ADP Multi-Copy W-2 Layout Detected', 'x', 'info', 0)
        a._compound_info_flags()
        self.assertNotIn('Multiple Anomalies Detected', titles(a))

    def test_real_minor_anomalies_still_compound(self):
        a = fresh()
        for t in ('A odd thing', 'B odd thing', 'C odd thing'):
            a._add_flag(t, 'x', 'info', 0)
        a._compound_info_flags()
        self.assertIn('Multiple Anomalies Detected', titles(a))


class DarknessSuppressedForPortalPrint(unittest.TestCase):
    """End-to-end on the real sample when it is available locally (no AI, no network)."""

    SAMPLE = os.path.join(os.path.expanduser('~/clawd/tmp/myssy-1030'), 'w2_1.pdf')

    @unittest.skipUnless(os.path.exists(SAMPLE), 'sample PDF not present')
    def test_real_dayforce_pdf_is_low_without_ai(self):
        a = DocumentAnalyzer(use_ai=False)
        a.analyze(self.SAMPLE, 'W-2')
        self.assertLess(a.risk_score, 35, [(f['title'], f['score_impact']) for f in a.flags])
        self.assertNotIn('Bimodal Text Darkness Pattern', titles(a))


if __name__ == '__main__':
    unittest.main(verbosity=1)

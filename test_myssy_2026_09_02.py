"""Regression tests for the 2026-09-02 Myssy Clayson batch (file 2745525).

Context: after the 2026-08-31 detector redeploy, Myssy's team reported that
"nearly every ADP W-2 is being flagged as high risk". Sample file 2745525
(St. Johns Riverside Hospital, ADP multi-copy layout) scored 100/100 with:

    1. Invalid Box Numbering / Structure (Box 12 "four rows without a/b/c/d")
    2. Invalid Box Numbering / Structure (Box 13 "three separate rows")
    3. Invalid Box Numbering / Structure ("characteristic of fraudulent templates")
    4. AI Detected Manipulation ("text clipping at cell boundaries", "overlaid")
    5. AI Detected Manipulation ("box border inconsistencies suggest selective editing")
    6. Form Line Crosses Through Text ("Box 14 GOC top clipping")
    7. Form Line Crosses Through Text ("Box 12 code/amount bottom clipping")
    8. Form Line Crosses Through Text ("state code NY character clipping")
    9. Invalid Field Value (AI) ("Box 14 'G1-1 GOC' placeholder/template text")
   10. Invalid Field Value (AI) ("identical G1-1 GOC across all three copies")

Every one of these is a KNOWN false positive on ADP multi-copy layouts.
Root causes:

  A. Multi-copy ADP W-2s print Copy B / Copy 2 / Copy C side-by-side with
     FOLD AND DETACH HERE perforation lines. The AI vision model reads the
     dashed perforation lines as "form lines cutting through text".
  B. ADP compact multi-copy layouts stack 12a/12b/12c/12d with very small
     suffix letters and a single Box 13 with three checkboxes. The AI reads
     the compact stack as "four rows without letter suffixes" and "three
     rows labeled 13".
  C. Matching values across Copy B / Copy 2 / Copy C are REQUIRED by IRS
     (all copies of the same W-2 must show the same figures). The AI reads
     the required matching values as "identical placeholder / template reuse".
  D. The OCR misreads the small-font Box 14 code "51.11 QOC" as "G1-1 GOC"
     and the AI then flags it as placeholder text.

Fix (this test asserts the behaviour):

  * `_is_adp_multi_copy_layout()` detects the layout from OCR text using
    FOLD AND DETACH HERE (strong single signal) or 2+ corroborating
    signals (Copy markers, ADP branding, Reference Copy phrases, etc.).
  * `_looks_like_multi_copy_false_positive()` classifies each of the 10
    listed AI issue patterns as false-positive so `_apply_employment_ai_flags`
    drops them and adds a single "ADP Multi-Copy W-2 Layout Detected"
    info-level audit-trail flag.
  * Genuine tells (font-size inconsistency, ink-bimodal, missing decimal
    formatting, math errors, invalid EIN, wrong tax year styling) still
    fire independently and will catch actual forgery of a multi-copy
    layout.

Author: Molesley  |  2026-09-02
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from document_analyzer import DocumentAnalyzer


# ---------------------------------------------------------------------------
# Sample OCR text representing a genuine multi-copy ADP W-2 (file 2745525)
# ---------------------------------------------------------------------------

ADP_MULTI_COPY_TEXT = """
2025 W-2 and EARNINGS SUMMARY                     PAGE 1 OF 1
Employee Reference Copy - Copy C for employee's records.
© 2025 ADP, Inc.

Social Security Number: XXX-XX-5320

FOLD AND DETACH HERE

Copy B to be filed with employee's Federal Income Tax Return.
Copy 2 to be filed with employee's State Income Tax Return.
Copy 2 to be filed with employee's City or Local Income Tax Return.

ST JOHNS RIVERSIDE HOSPITAL
967 N BROADWAY, YONKERS, NY 10701
Employer FED ID: 13-1740126

BRITTANY B BENNETT
315 PALISADE AVE, 36
BRIDGEPORT, CT 06610

Box 1  Wages, tips, other comp  19595.29
Box 2  Federal income tax withheld  1490.40
Box 3  Social security wages  19595.29
Box 4  Social security tax withheld  1214.88
Box 5  Medicare wages and tips  19595.29
Box 6  Medicare tax withheld  284.13
Box 12a  D  2000.00
Box 12b
Box 12c
Box 12d
Box 13  Statutory employee  Retirement plan  Third-party sick pay
Box 14  Other  51.11 QOC
Box 15  NY  Employer's state ID  131740126 9
Box 16  State wages  19595.29
Box 17  State income tax  835.78
Box 18  Local wages  19595.29
Box 19  Local income tax  97.63
Box 20  Locality  YONKERS
"""

# Single-copy Intuit-style W-2 (should NOT trigger multi-copy detection)
SINGLE_COPY_INTUIT_TEXT = """
2024 Form W-2 Wage and Tax Statement
Intuit QuickBooks Payroll
Employer: Acme Widgets LLC
Employee: John Doe
Box 1  50000.00
Box 2  4500.00
Box 3  50000.00
Box 4  3100.00
Box 15  UT  Employer's state ID  12-3456789
"""


# ---------------------------------------------------------------------------
# Direct classifier tests (no AI, no image, deterministic)
# ---------------------------------------------------------------------------

class MultiCopyLayoutDetectionTests(unittest.TestCase):
    """Test `_is_adp_multi_copy_layout()` classifier."""

    def setUp(self):
        self.analyzer = DocumentAnalyzer(use_ai=False)

    def test_positive_full_adp_multi_copy(self):
        self.assertTrue(self.analyzer._is_adp_multi_copy_layout(ADP_MULTI_COPY_TEXT))

    def test_positive_fold_and_detach_alone(self):
        # FOLD AND DETACH HERE is a strong-enough single signal.
        text = "some payroll blurb\nFOLD AND DETACH HERE\nsome more text"
        self.assertTrue(self.analyzer._is_adp_multi_copy_layout(text))

    def test_positive_case_insensitive_fold_and_detach(self):
        text = "some payroll blurb\nfold and detach here\nsome more text"
        self.assertTrue(self.analyzer._is_adp_multi_copy_layout(text))

    def test_positive_multi_signal_without_fold_marker(self):
        # Two distinct Copy markers + ADP branding + earnings summary title
        text = (
            "2025 W-2 and Earnings Summary\n"
            "© 2025 ADP, Inc.\n"
            "Copy B  Copy 2  Copy C\n"
        )
        self.assertTrue(self.analyzer._is_adp_multi_copy_layout(text))

    def test_negative_empty_text(self):
        self.assertFalse(self.analyzer._is_adp_multi_copy_layout(""))

    def test_negative_single_copy_intuit(self):
        self.assertFalse(self.analyzer._is_adp_multi_copy_layout(SINGLE_COPY_INTUIT_TEXT))

    def test_negative_one_copy_marker_only(self):
        # A single "Copy B" reference is NOT enough — must corroborate.
        text = "Copy B for employee's records"
        self.assertFalse(self.analyzer._is_adp_multi_copy_layout(text))

    def test_negative_single_adp_mention_only(self):
        text = "processed by ADP payroll"
        self.assertFalse(self.analyzer._is_adp_multi_copy_layout(text))


# ---------------------------------------------------------------------------
# Direct false-positive-pattern classifier tests
# ---------------------------------------------------------------------------

class FalsePositivePatternClassifierTests(unittest.TestCase):
    """Test `_looks_like_multi_copy_false_positive()` for each flag kind."""

    def setUp(self):
        self.analyzer = DocumentAnalyzer(use_ai=False)

    # -- box_structure ------------------------------------------------------

    def test_box_structure_box_12_missing_suffixes(self):
        issue = (
            "CRITICAL: Box 12 shows four rows all labeled '12' without a/b/c/d "
            "letter suffixes - official W-2s must use 12a, 12b, 12c, 12d"
        )
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'box_structure'))

    def test_box_structure_box_13_three_rows(self):
        issue = (
            "CRITICAL: Box 13 shows three separate rows all labeled '13' "
            "(13a, 13b, 13c implied but not properly formatted)"
        )
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'box_structure'))

    def test_box_structure_characteristic_of_fraudulent_templates(self):
        issue = (
            "This exact error pattern is characteristic of fraudulent W-2 "
            "templates and would never occur on legitimate payroll system output"
        )
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'box_structure'))

    def test_box_structure_negative_real_issue(self):
        # A genuine structural anomaly (unrelated to compact multi-copy)
        issue = "Box 12 code D shows no amount value"
        self.assertFalse(self.analyzer._looks_like_multi_copy_false_positive(issue, 'box_structure'))

    # -- lines_crossing -----------------------------------------------------

    def test_lines_crossing_perforation_line(self):
        issue = "Dashed perforation line crosses through Employer state ID in Box 15"
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'lines_crossing'))

    def test_lines_crossing_fold_and_detach(self):
        issue = "FOLD AND DETACH HERE marking runs through the state code cell"
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'lines_crossing'))

    def test_lines_crossing_top_clipping_box_14(self):
        issue = (
            "Box 14 'Other' entries show top clipping: the tops of characters in "
            "'G1-1 GOC' are truncated/shaved off flush with the cell's top border"
        )
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'lines_crossing'))

    def test_lines_crossing_bottom_clipping_box_12(self):
        issue = (
            "Box 12 code/amount values show bottom clipping where descenders or "
            "lower portions of numbers appear cut off by cell bottom border"
        )
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'lines_crossing'))

    def test_lines_crossing_state_code_clipping(self):
        issue = "State code in Box 15 ('NY') shows character clipping at cell boundary"
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'lines_crossing'))

    def test_lines_crossing_negative_real_line_through(self):
        # A genuine line running through characters (not perforation/clipping)
        issue = "Horizontal red mark runs across the middle of the employer name"
        self.assertFalse(self.analyzer._looks_like_multi_copy_false_positive(issue, 'lines_crossing'))

    # -- manipulation -------------------------------------------------------

    def test_manipulation_text_clipping_at_cell(self):
        issue = "Text clipping at cell boundaries indicates values were overlaid on fixed template"
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'manipulation'))

    def test_manipulation_box_border_inconsistencies(self):
        issue = "Box border inconsistencies suggest selective editing of form fields"
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'manipulation'))

    def test_manipulation_multi_stage_assembly(self):
        issue = "Value size inconsistency across boxes suggests multi-stage document assembly"
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'manipulation'))

    def test_manipulation_negative_real_blur(self):
        # Genuine manipulation tell — should still fire
        issue = "Visible blur around Box 1 wages amount"
        self.assertFalse(self.analyzer._looks_like_multi_copy_false_positive(issue, 'manipulation'))

    # -- invalid_value ------------------------------------------------------

    def test_invalid_value_placeholder_text(self):
        issue = (
            "Box 14 contains 'G1-1 GOC' which appears to be placeholder/template "
            "text rather than legitimate 'Other' compensation codes"
        )
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'invalid_value'))

    def test_invalid_value_identical_across_copies(self):
        issue = "Multiple instances of identical 'G1-1 GOC' across all three copies suggests template reuse"
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'invalid_value'))

    def test_invalid_value_negative_real_na(self):
        # Genuine "N/A in numeric field" — should still fire
        issue = "Box 2 contains 'N/A' instead of a dollar amount"
        self.assertFalse(self.analyzer._looks_like_multi_copy_false_positive(issue, 'invalid_value'))

    def test_invalid_value_negative_wrong_kind(self):
        # placeholder pattern only counts for invalid_value, not box_structure
        issue = "Box 14 contains 'GOC' which appears to be placeholder text"
        self.assertTrue(self.analyzer._looks_like_multi_copy_false_positive(issue, 'invalid_value'))
        # Not classified under other kinds
        self.assertFalse(self.analyzer._looks_like_multi_copy_false_positive(issue, 'box_structure'))


# ---------------------------------------------------------------------------
# End-to-end AI-flag pipeline test (mock the AI response)
# ---------------------------------------------------------------------------

class AIFlagPipelineOnMultiCopyLayoutTests(unittest.TestCase):
    """Simulate the exact AI response that produced 100/100 on file 2745525.

    Verifies that with `self._is_multi_copy_layout=True`, the AI's ten known
    false-positive flags are all dropped, and a single
    "ADP Multi-Copy W-2 Layout Detected" info flag is added.
    """

    # Reconstruction of the AI JSON that scored file 2745525 at 100/100
    MOCK_AI_RESPONSE = {
        "overall_assessment": "LIKELY_FRAUDULENT",
        "confidence": 92,
        "font_consistency": {
            "consistent": True,
            "issues": [],
            "corroborating_indicators": [],
            "value_size_inconsistency": {
                "detected": False,
                "sizes_observed": 1,
                "fields": [],
            },
        },
        "date_year_tampering": {
            "detected": False,
            "issues": [],
            "year_styling_correct": True,
            "year_styling_notes": "",
        },
        "invalid_field_values": {
            "detected": True,
            "issues": [
                "Box 14 contains 'G1-1 GOC' which appears to be placeholder/template text rather than legitimate 'Other' compensation codes",
                "Multiple instances of identical 'G1-1 GOC' across all three copies suggests template reuse",
            ],
        },
        "visual_consistency": {
            "score": 40,
            "issues": [],
        },
        "template_authenticity": {
            "score": 30,
            "appears_to_be": "fabricated multi-copy template",
            "concerns": [],
        },
        "manipulation_indicators": {
            "detected": True,
            "indicators": [
                "Text clipping at cell boundaries indicates values were overlaid on fixed template (see lines_crossing_text)",
                "Box border inconsistencies suggest selective editing of form fields",
            ],
        },
        "redaction_analysis": {
            "redactions_present": False,
            "appears_compliance_related": False,
            "fields_redacted": [],
            "suspicious_redactions": [],
        },
        "box_numbering_structure": {
            "valid": False,
            "issues": [
                "CRITICAL: Box 12 shows four rows all labeled '12' without a/b/c/d letter suffixes - official W-2s must use 12a, 12b, 12c, 12d",
                "CRITICAL: Box 13 shows three separate rows all labeled '13' (13a, 13b, 13c implied but not properly formatted) - official W-2s have ONE Box 13 containing THREE CHECKBOXES",
                "This exact error pattern is characteristic of fraudulent W-2 templates and would never occur on legitimate payroll system output",
            ],
        },
        "overlapping_text": {
            "detected": False,
            "issues": [],
        },
        "lines_crossing_text": {
            "detected": True,
            "issues": [
                "Box 14 'Other' entries show top clipping: the tops of characters in 'G1-1 GOC' are truncated/shaved off flush with the cell's top border",
                "Box 12 code/amount values show bottom clipping where descenders or lower portions of numbers appear cut off by cell bottom border",
                "State code in Box 15 ('NY') shows character clipping at cell boundary",
            ],
        },
        "box_border_anomalies": {
            "detected": False,
            "issues": [],
        },
        "key_findings": [],
        "recommendation": "Escalate for manual review",
    }

    def _fresh_analyzer(self, is_multi_copy: bool):
        a = DocumentAnalyzer(use_ai=False)
        a.flags = []
        a.risk_score = 0
        a._is_multi_copy_layout = is_multi_copy
        return a

    def test_multi_copy_layout_suppresses_all_ten_false_positives(self):
        a = self._fresh_analyzer(is_multi_copy=True)
        a._apply_employment_ai_flags(self.MOCK_AI_RESPONSE, doc_type='W-2')

        titles = [f['title'] for f in a.flags]

        # None of the four false-positive flag titles should be present
        for bad_title in (
            'Invalid Box Numbering / Structure',
            'AI Detected Manipulation',
            'Form Line Crosses Through Text',
            'Invalid Field Value (AI)',
        ):
            self.assertNotIn(
                bad_title, titles,
                f"Expected {bad_title!r} to be suppressed on multi-copy layout",
            )

        # Exactly one audit-trail info flag should have been added
        audit_flags = [f for f in a.flags if f['title'] == 'ADP Multi-Copy W-2 Layout Detected']
        self.assertEqual(len(audit_flags), 1, "Expected exactly one audit-trail flag")
        self.assertEqual(audit_flags[0]['severity'], 'info')
        self.assertEqual(audit_flags[0]['score_impact'], 0)

        # Audit-trail description should enumerate the suppressed findings
        desc = audit_flags[0]['description']
        self.assertIn('Invalid Box Numbering / Structure', desc)
        self.assertIn('AI Detected Manipulation', desc)
        self.assertIn('Form Line Crosses Through Text', desc)
        self.assertIn('Invalid Field Value (AI)', desc)

        # Risk score contribution from suppressed flags should be 0
        self.assertEqual(a.risk_score, 0)

    def test_non_multi_copy_layout_still_fires_all_flags(self):
        # Guardrail: on a non-multi-copy form, the SAME AI response must still
        # trigger the critical flags (no accidental blanket-suppression).
        a = self._fresh_analyzer(is_multi_copy=False)
        a._apply_employment_ai_flags(self.MOCK_AI_RESPONSE, doc_type='W-2')

        titles = [f['title'] for f in a.flags]

        # Each of the four critical categories should be present
        self.assertIn('Invalid Box Numbering / Structure', titles)
        self.assertIn('AI Detected Manipulation', titles)
        self.assertIn('Form Line Crosses Through Text', titles)
        self.assertIn('Invalid Field Value (AI)', titles)

        # No audit-trail flag when we're not in multi-copy mode
        self.assertNotIn('ADP Multi-Copy W-2 Layout Detected', titles)

        # Risk score should be high (well above 0 — many critical flags)
        self.assertGreater(a.risk_score, 100)  # capped by caller, but pre-cap is high

    def test_multi_copy_layout_still_fires_genuine_tells(self):
        """A real font-size inconsistency on a multi-copy layout should still fire."""
        a = self._fresh_analyzer(is_multi_copy=True)
        response = dict(self.MOCK_AI_RESPONSE)
        response['font_consistency'] = {
            "consistent": False,
            "issues": ["values render at 2 distinct heights"],
            "corroborating_indicators": ["ink darkness bimodal detected"],
            "value_size_inconsistency": {
                "detected": True,
                "sizes_observed": 2,
                "fields": ["Box 1 wages larger than Box 2/4/6 tax figures"],
            },
        }
        a._apply_employment_ai_flags(response, doc_type='W-2')

        titles = [f['title'] for f in a.flags]
        # The genuine tells should still fire
        self.assertIn('Inconsistent Font Sizes', titles)
        # But the multi-copy false positives should still be suppressed
        self.assertNotIn('Invalid Box Numbering / Structure', titles)
        self.assertNotIn('Form Line Crosses Through Text', titles)

    def test_audit_trail_flag_added_only_once(self):
        """Multiple suppressed findings should collapse into ONE info flag."""
        a = self._fresh_analyzer(is_multi_copy=True)
        a._apply_employment_ai_flags(self.MOCK_AI_RESPONSE, doc_type='W-2')

        audit_flags = [f for f in a.flags if f['title'] == 'ADP Multi-Copy W-2 Layout Detected']
        self.assertEqual(len(audit_flags), 1)


# ---------------------------------------------------------------------------
# Prompt audit — verify the AI prompt actually contains the new caveats
# ---------------------------------------------------------------------------

class AIPromptContainsMultiCopyCaveatsTests(unittest.TestCase):

    def test_prompt_mentions_fold_and_detach(self):
        a = DocumentAnalyzer(use_ai=False)
        prompt = a._build_employment_ai_prompt('W-2', 'context')
        self.assertIn('FOLD AND DETACH HERE', prompt)

    def test_prompt_mentions_matching_values_across_copies(self):
        a = DocumentAnalyzer(use_ai=False)
        prompt = a._build_employment_ai_prompt('W-2', 'context')
        self.assertIn('IDENTICAL values across Copy', prompt)

    def test_prompt_mentions_compact_layout(self):
        a = DocumentAnalyzer(use_ai=False)
        prompt = a._build_employment_ai_prompt('W-2', 'context')
        self.assertIn('compact multi-copy', prompt.lower())

    def test_prompt_mentions_legit_box14_codes(self):
        a = DocumentAnalyzer(use_ai=False)
        prompt = a._build_employment_ai_prompt('W-2', 'context')
        # QOC, NYPSL, etc. should be listed
        self.assertIn('QOC', prompt)
        self.assertIn('NYPSL', prompt)


# ---------------------------------------------------------------------------
# Box 14 code recognition
# ---------------------------------------------------------------------------

class KnownBox14CodesUpdateTests(unittest.TestCase):

    def test_qoc_is_now_known(self):
        self.assertIn('QOC', DocumentAnalyzer.KNOWN_BOX14_CODES)

    def test_nypsl_is_now_known(self):
        self.assertIn('NYPSL', DocumentAnalyzer.KNOWN_BOX14_CODES)
        self.assertIn('NYPSL-E', DocumentAnalyzer.KNOWN_BOX14_CODES)

    def test_common_state_codes_present(self):
        for code in ('NYSDI', 'NYPFL', 'CASDI', 'NJSDI', 'WAPFML', 'MAPFML'):
            with self.subTest(code=code):
                self.assertIn(code, DocumentAnalyzer.KNOWN_BOX14_CODES)


if __name__ == '__main__':
    unittest.main(verbosity=2)

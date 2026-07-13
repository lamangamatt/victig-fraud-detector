"""
IRS Wage & Income Transcript fraud detection.

Added 2026-07-07 based on Myssy Clayson's forgery sample (KCC/Excalibur W-2s
with duplicate IRS transcript tracking number 110822371779).

Key insight (from Myssy):
    In a genuine IRS Wage & Income Transcript packet, the IRS masthead,
    "Sensitive Taxpayer Data" banner, "Wage and Income Transcript" title,
    Request Date, Response Date, and Tracking Number appear ONLY ON PAGE 1.
    Subsequent W-2s inside the same packet are additional
    "Form W-2 Wage and Tax Statement" sections without a repeated
    IRS masthead/tracking header block.

Fabrication signatures we detect:
    - A single document claiming to be page 1 of a transcript but the
      per-transcript identifiers (tracking number, request/response date,
      TIN, tax period) are copy-pasted from a real IRS transcript.
    - Multiple documents uploaded together that each claim to be page 1
      (each carries its own masthead + tracking block) but share the
      same tracking number — impossible for two separate transcript
      requests, and wrong for pages inside one packet.
    - IRS Wage & Income Transcripts sent to the taxpayer do not redact
      dollar amounts; a solid black bar over every wage/tax field is
      a fabrication tell (applicant redacted before sending).
    - Truncated/garbled employer names ("KURT CARS CONS LL",
      "EXCA SECU IN") and nonsensical partial addresses ("222 N",
      "3RD FL", "2175 G") — real IRS transcripts show full legal names
      and complete addresses.

This module is intentionally standalone from document_analyzer.py so it
can be unit-tested and evolved without touching the main analyzer.
"""

from __future__ import annotations

import io
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    import fitz  # PyMuPDF
    HAS_PYMUPDF = True
except ImportError:
    HAS_PYMUPDF = False

try:
    import pytesseract
    from PIL import Image
    HAS_TESSERACT = True
except ImportError:
    HAS_TESSERACT = False

import numpy as np


# ---------------------------------------------------------------------------
# Field extraction
# ---------------------------------------------------------------------------

# Tolerant regex — OCR sometimes drops or garbles punctuation
_RE_TITLE          = re.compile(r"Wage\s+and\s+Income\s+Transcript", re.I)
_RE_SENSITIVE      = re.compile(r"Sensitive\s+Taxpayer\s+Data", re.I)
_RE_REQUEST_DATE   = re.compile(r"Request\s*Date[:\s]*([0-9]{2}[-/][0-9]{2}[-/][0-9]{4})", re.I)
_RE_RESPONSE_DATE  = re.compile(r"Response\s*Date[:\s]*([0-9]{2}[-/][0-9]{2}[-/][0-9]{4})", re.I)
_RE_TRACKING       = re.compile(r"Tracking\s*Number[:\s]*([0-9]{8,20})", re.I)
_RE_TIN            = re.compile(r"TIN\s*Provided[:\s]*([X0-9\-]{6,15})", re.I)
_RE_TAX_PERIOD     = re.compile(r"Tax\s*Period(?:\s*Requested)?[:\s]*([0-9]{2}[-/][0-9]{2}[-/][0-9]{4})", re.I)
_RE_W2_SECTION     = re.compile(r"Form\s+W-?2\s+Wage\s+and\s+Tax\s+Statement", re.I)

# Employer name appears after "Employer Identification Number (EIN):",
# optionally after an EIN value row (XX-XXXNNNN). We use a two-pass
# approach in _extract_all_employer_names(): the regex here matches
# the header, and we skip EIN-value lines in Python to reliably get
# the entity name across both OCR layouts (label-then-value and
# label-value-interleaved).
_RE_EMPLOYER_ANCHOR = re.compile(
    r"Employer\s+Identification\s+Number\s*\(EIN\)[:\s]*",
    re.I,
)
_RE_EIN_VALUE = re.compile(r"^(?:XX-XXX[0-9]+|[0-9]{2}-[0-9]{7})$")
_RE_ADDRESS_START = re.compile(r"^\d")  # "9700 B", "6285 B", etc.
_RE_ENTITY_NAME_CANDIDATE = re.compile(r"^[A-Z][A-Z0-9 .,&'\-]{1,}$")

# Legacy single-name regex kept for parse_transcript_text backwards
# compatibility (used by callers that only want the first employer name).
_RE_EMPLOYER_HDR   = re.compile(
    r"Employer\s+Identification\s+Number.*?\n+\s*"
    r"(?:XX-XXX[0-9]+|[0-9]{2}-[0-9]{7})?\s*\n?\s*"
    r"([A-Z][A-Z0-9 .,&'\-]{2,}?)\s*\n",
    re.I | re.S,
)

# --- Myssy 2026-07-13 forgery signals -------------------------------------
# "Submission Type: Origin" instead of "Original" (fabricator dropped
# trailing "al" when redacting/converting the PDF).
_RE_SUBMISSION_TRUNCATED = re.compile(
    r"^[ \t]*Submission\s*Type[:\s]*(Origin|Origi|Orig)\s*$",
    re.I | re.M,
)
_RE_SUBMISSION_OK = re.compile(
    r"^[ \t]*Submission\s*Type[:\s]*Original\s*$",
    re.I | re.M,
)

# "Third Party Sick Pay Indicator: Un" instead of "Unanswered" (same
# truncation tell). Match on its own line to avoid catching valid
# "Unanswered" occurrences.
_RE_SICKPAY_TRUNCATED = re.compile(
    r"^[ \t]*Third\s*Party\s*Sick\s*Pay\s*Indicator[:\s]*(Un|Una|Unans|Unansw|Unanswe|Unanswer|Unanswere)\s*$",
    re.I | re.M,
)

# Replacement footer box: "NON-EMPLOYMENT INFORMATION REDACTED".
# Genuine IRS transcripts end with an IRS footer/URL, not this box.
_RE_NONEMP_REDACT_BOX = re.compile(
    r"NON[- ]?EMPLOYMENT\s+INFORMATION\s+REDACTED",
    re.I,
)

# Page-1 header block: Request Date populated but Response Date not.
# Detected via field-level checks, not this regex alone.


@dataclass
class TranscriptFields:
    """Fields parsed from a single uploaded document's OCR/text output."""

    source_file: str
    has_masthead: bool = False              # "Sensitive Taxpayer Data" banner present
    has_title: bool = False                 # "Wage and Income Transcript" title present
    tracking_number: Optional[str] = None
    request_date: Optional[str] = None
    response_date: Optional[str] = None
    tin_provided: Optional[str] = None
    tax_period: Optional[str] = None
    w2_section_count: int = 0
    employer_name: Optional[str] = None
    employer_names_all: List[str] = field(default_factory=list)  # every unique employer name
    raw_text: str = ""
    pdf_creation_date: Optional[str] = None
    pdf_mod_date: Optional[str] = None
    page_width_pts: Optional[float] = None
    page_height_pts: Optional[float] = None

    # --- Myssy 2026-07-13 forgery signals -----------------------------
    truncated_submission_types: int = 0    # "Submission Type: Origin" hits
    ok_submission_types: int = 0           # "Submission Type: Original" hits
    truncated_sickpay_indicators: int = 0  # "Sick Pay Indicator: Un" hits
    has_nonemp_redacted_box: bool = False  # replacement footer box present
    pdf_editor: Optional[str] = None       # /Producer or /Creator metadata
    pdf_subject: Optional[str] = None      # /Subject metadata

    @property
    def looks_like_page_one(self) -> bool:
        """A doc that carries the IRS masthead + tracking header block."""
        return bool(
            self.has_title
            and self.has_masthead
            and self.tracking_number
        )


def _first(regex: re.Pattern, text: str) -> Optional[str]:
    m = regex.search(text)
    return m.group(1).strip() if m else None


def parse_transcript_text(text: str, source_file: str = "") -> TranscriptFields:
    """Parse the identifying fields from an IRS transcript OCR/text blob."""

    f = TranscriptFields(source_file=source_file, raw_text=text or "")
    if not text:
        return f

    f.has_title = bool(_RE_TITLE.search(text))
    f.has_masthead = bool(_RE_SENSITIVE.search(text))
    f.tracking_number = _first(_RE_TRACKING, text)
    f.request_date = _first(_RE_REQUEST_DATE, text)
    f.response_date = _first(_RE_RESPONSE_DATE, text)
    f.tin_provided = _first(_RE_TIN, text)
    f.tax_period = _first(_RE_TAX_PERIOD, text)
    f.w2_section_count = len(_RE_W2_SECTION.findall(text))
    f.employer_name = _first(_RE_EMPLOYER_HDR, text)
    f.employer_names_all = _extract_all_employer_names(text)

    # Myssy 2026-07-13 signals
    f.truncated_submission_types = len(_RE_SUBMISSION_TRUNCATED.findall(text))
    f.ok_submission_types = len(_RE_SUBMISSION_OK.findall(text))
    f.truncated_sickpay_indicators = len(_RE_SICKPAY_TRUNCATED.findall(text))
    f.has_nonemp_redacted_box = bool(_RE_NONEMP_REDACT_BOX.search(text))

    return f


def extract_from_pdf(pdf_path: str, dpi: int = 300) -> TranscriptFields:
    """OCR + metadata extraction for a single IRS transcript PDF."""

    if not HAS_PYMUPDF:
        raise RuntimeError("PyMuPDF is required for IRS transcript analysis")

    doc = fitz.open(pdf_path)
    try:
        # Combine embedded text (if any) with OCR of every page
        text_parts: List[str] = []
        pw, ph = None, None
        for i, page in enumerate(doc):
            embedded = page.get_text() or ""
            text_parts.append(embedded)
            if i == 0:
                pw, ph = page.rect.width, page.rect.height
            if HAS_TESSERACT:
                mat = fitz.Matrix(dpi / 72, dpi / 72)
                pix = page.get_pixmap(matrix=mat)
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                text_parts.append(pytesseract.image_to_string(img))

        text = "\n".join(t for t in text_parts if t)
        fields = parse_transcript_text(text, source_file=pdf_path)
        fields.page_width_pts = pw
        fields.page_height_pts = ph

        meta = doc.metadata or {}
        fields.pdf_creation_date = meta.get("creationDate")
        fields.pdf_mod_date = meta.get("modDate")
        # Producer/Creator = the tool that wrote the PDF. Legitimate IRS
        # transcripts are produced by IRS internal tooling; forgeries
        # usually show a consumer PDF editor here.
        fields.pdf_editor = meta.get("producer") or meta.get("creator")
        fields.pdf_subject = meta.get("subject")
        return fields
    finally:
        doc.close()


def extract_from_image(image_path: str) -> TranscriptFields:
    """OCR + basic metadata for a JPEG/PNG of an IRS transcript."""

    if not HAS_TESSERACT:
        raise RuntimeError("pytesseract is required for image-based transcript analysis")

    with Image.open(image_path) as img:
        text = pytesseract.image_to_string(img)
        fields = parse_transcript_text(text, source_file=image_path)
        fields.page_width_pts = float(img.width)
        fields.page_height_pts = float(img.height)
        return fields


def extract_from_file(file_path: str) -> TranscriptFields:
    """Route to PDF or image extraction based on extension."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".pdf":
        return extract_from_pdf(file_path)
    return extract_from_image(file_path)


# ---------------------------------------------------------------------------
# Wage-redaction bar detection
# ---------------------------------------------------------------------------

def detect_wage_redaction_bar(pdf_path: str, dpi: int = 200) -> bool:
    """Detect a solid black bar covering the wage-fields column.

    IRS Wage & Income Transcripts sent to the taxpayer never blackout the
    dollar amounts. If we see a tall, contiguous, near-black rectangle
    aligned with the right-hand value column, that's an applicant-added
    redaction — a fabrication tell in this context.
    """

    if not HAS_PYMUPDF:
        return False
    try:
        doc = fitz.open(pdf_path)
        page = doc[0]
        mat = fitz.Matrix(dpi / 72, dpi / 72)
        pix = page.get_pixmap(matrix=mat)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        doc.close()
    except Exception:
        return False

    gray = np.array(img.convert("L"))
    h, w = gray.shape
    if h == 0 or w == 0:
        return False

    dark = (gray < 40).astype(np.int8)

    # Vectorized max-run-per-row using run-length via diff
    row_max = np.zeros(h, dtype=np.int32)
    for r in range(h):
        row = dark[r]
        if not row.any():
            continue
        d = np.diff(np.concatenate(([0], row, [0])))
        starts = np.where(d == 1)[0]
        ends = np.where(d == -1)[0]
        if len(starts):
            row_max[r] = int((ends - starts).max())

    # A wage-value blackout bar is a *tall* contiguous vertical band —
    # even a narrow one, because it only needs to cover the right-hand
    # dollar-values column. Genuine IRS transcripts include thin
    # horizontal separator rules around the "Sensitive Taxpayer Data"
    # masthead that span the full page width but are only 1-3 pixels
    # tall; we must not flag those.
    #
    # Signal: a contiguous run of rows where every row has a dark run
    # at least as wide as a short dollar amount (>=50 px at 200 dpi ~ 3+
    # characters), and the band is at least ~30 rows tall (multiple
    # text lines high).
    #
    # Empirically on the KCC/Excalibur forgeries this yields bands of
    # 350-560 rows; on clean multi-page IRS transcripts (including
    # Myssy's Maryville sample) the tallest such band is <=2 rows.

    def _longest_contiguous_run(mask: np.ndarray) -> int:
        if not mask.any():
            return 0
        d = np.diff(np.concatenate(([0], mask.astype(np.int8), [0])))
        starts = np.where(d == 1)[0]
        ends = np.where(d == -1)[0]
        if not len(starts):
            return 0
        return int((ends - starts).max())

    # Pixel thresholds scale with render DPI so the detector behaves
    # the same regardless of the caller-supplied dpi. At 200 dpi:
    #   min_dark_run_px = 50   (~3-4 characters wide at 10pt)
    #   min_band_rows   = 30   (~2 text lines tall)
    min_dark_run_px = max(20, int(round(50 * dpi / 200)))
    min_band_rows   = max(15, int(round(30 * dpi / 200)))

    band_height = _longest_contiguous_run(row_max >= min_dark_run_px)
    return band_height >= min_band_rows


# ---------------------------------------------------------------------------
# Batch analysis
# ---------------------------------------------------------------------------

_GARBLE_LEGIT_TAILS = (
    "LLC", "L.L.C.", "INC", "INC.", "CORP", "CORPORATION", "CO", "CO.",
    "COMPANY", "LP", "L.P.", "LLP", "PLLC", "PC", "P.C.", "TRUST",
    "PARTNERSHIP", "ENTERPRISES",
)


def _extract_all_employer_names(text: str) -> List[str]:
    """Extract every unique employer entity name from an IRS transcript.

    IRS Wage & Income Transcripts print each W-2 with a section:

        Employer:
         Employer Identification Number (EIN):
         XX-XXX1234
         ACME CORP
         123 Main St

    OCR ordering varies (sometimes value-then-label, sometimes
    label-then-value). We scan line-by-line: whenever we see the
    "Employer Identification Number" label, we consume the next
    non-address, non-EIN-value line as the entity name.

    Returns a list of unique names in first-seen order.
    """
    if not text:
        return []

    lines = [ln.strip() for ln in text.splitlines()]
    names: List[str] = []
    seen: set = set()
    i = 0
    while i < len(lines):
        if _RE_EMPLOYER_ANCHOR.search(lines[i] or ""):
            j = i + 1
            steps = 0
            while j < len(lines) and steps < 6:
                candidate = lines[j].strip()
                if not candidate:
                    j += 1; steps += 1
                    continue
                if _RE_EIN_VALUE.match(candidate):
                    j += 1; steps += 1
                    continue
                if _RE_ADDRESS_START.match(candidate):
                    j += 1; steps += 1
                    continue
                if candidate.lower().startswith("employee"):
                    break
                if _RE_ENTITY_NAME_CANDIDATE.match(candidate):
                    if candidate not in seen:
                        seen.add(candidate)
                        names.append(candidate)
                    break
                j += 1; steps += 1
            i = j + 1
        else:
            i += 1
    return names


def _has_full_corp_suffix(name: str) -> bool:
    """True if the name ends with a fully-spelled corporate suffix.

    Real IRS transcripts truncate everything into 3-4 char word groups,
    so a fully-spelled "LLC"/"INC"/"CORPORATION" ending would be
    anomalous inside a genuine transcript.
    """
    up = name.strip().upper()
    for suffix in _GARBLE_LEGIT_TAILS:
        if up.endswith(" " + suffix):
            return True
    return False


def _name_looks_short_truncated(name: str) -> bool:
    """True if the name's last word looks like an IRS-style truncation stub
    (1-2 chars) that isn't a fully-spelled corporate suffix like LLC."""
    up = name.strip().upper()
    tokens = up.split()
    if len(tokens) < 2:
        return False
    last = tokens[-1]
    # Fully spelled suffix → not a truncation stub
    if _has_full_corp_suffix(name):
        return False
    # A 1-2 char final word that isn't a well-known short suffix (LP, PC)
    if 1 <= len(last) <= 2 and last not in ("LP", "PC", "CO"):
        return True
    return False


def _has_single_char_stub(name: str) -> bool:
    """True if the last word is a single character (extreme truncation).

    IRS truncation typically leaves 2-4 char stubs ("IN" for INC, "LL"
    for LLC). A trailing single character like "C" (as in "BYER ENGI C")
    is unusually aggressive and shows up on fabrications where the
    editor clipped mid-character.
    """
    tokens = name.strip().split()
    return len(tokens) >= 2 and len(tokens[-1]) == 1


def _looks_truncated(name: str) -> bool:
    """DEPRECATED. Kept for backwards compatibility with older callers.

    Real IRS transcripts truncate employer names into 3-4 char word
    groups ("MARY ACAD", "EIGR IN", "INNO GENO LLC"), so "truncation"
    alone is not a reliable single-name signal. The productive
    detection now lives in `analyze_single_transcript()` via the
    per-document employer-name pattern analysis, which looks at all
    employer names in the document together.

    This function now returns True only for the specific pattern we've
    seen on fabrications but never on the clean IRS sample: a trailing
    single-character word (e.g. "BYER ENGI C") — more aggressive
    clipping than IRS uses.
    """
    if not name:
        return False
    return _has_single_char_stub(name.strip().upper())


def _looks_partial_address(name: str) -> bool:
    """Address text that looks incomplete (no city/state/ZIP).

    Real IRS transcripts show full addresses. Nonsensical fragments like
    "222 N", "3RD FL", "2175 G" indicate cropping/fabrication.
    """
    if not name:
        return False
    s = name.strip()
    # Very short (e.g. "222 N", "2175 G", "3RD FL") and no ZIP
    if len(s) < 12 and not re.search(r"\b\d{5}\b", s):
        return True
    return False


@dataclass
class TranscriptFlag:
    title: str
    description: str
    severity: str            # "critical" | "warning" | "info"
    score_impact: int
    scope: str = "document"  # "document" or "batch"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "score_impact": self.score_impact,
            "scope": self.scope,
        }


def analyze_single_transcript(fields: TranscriptFields,
                              wage_bar_redaction: bool = False) -> List[TranscriptFlag]:
    """Rules that apply to a single IRS transcript document in isolation."""

    flags: List[TranscriptFlag] = []

    if not fields.has_title:
        flags.append(TranscriptFlag(
            title="Missing IRS Transcript Title",
            description=(
                'Expected "Wage and Income Transcript" heading was not found. '
                "This document may not be a genuine IRS transcript, or the "
                "heading was cropped out."
            ),
            severity="warning",
            score_impact=15,
        ))

    if fields.has_title and not fields.has_masthead:
        flags.append(TranscriptFlag(
            title="Missing IRS Sensitive-Data Banner",
            description=(
                'The "This Product Contains Sensitive Taxpayer Data" banner is '
                "absent. Genuine IRS Wage & Income Transcripts always include "
                "this banner on page 1."
            ),
            severity="warning",
            score_impact=15,
        ))

    if fields.has_title and not fields.tracking_number:
        flags.append(TranscriptFlag(
            title="Missing Transcript Tracking Number",
            description=(
                "No Tracking Number found. Genuine IRS transcripts include a "
                "tracking number on page 1."
            ),
            severity="warning",
            score_impact=15,
        ))

    # Future- or wrong-year request/response date
    for label, val in (("Request Date", fields.request_date),
                       ("Response Date", fields.response_date)):
        if not val:
            continue
        try:
            dt = datetime.strptime(val, "%m-%d-%Y")
        except ValueError:
            try:
                dt = datetime.strptime(val, "%m/%d/%Y")
            except ValueError:
                continue
        today = datetime.now()
        if dt.date() > today.date():
            flags.append(TranscriptFlag(
                title=f"Future {label} on IRS Transcript",
                description=(
                    f"{label} is {val}, which is in the future. IRS transcript "
                    "request/response dates are stamped at generation and "
                    "cannot be future-dated."
                ),
                severity="critical",
                score_impact=40,
            ))

    if wage_bar_redaction:
        flags.append(TranscriptFlag(
            title="Wage Amounts Blacked Out",
            description=(
                "Dollar amounts on this transcript appear to be covered by a "
                "solid black bar. IRS Wage & Income Transcripts issued to the "
                "taxpayer do not redact dollar figures — this redaction was "
                "added by the applicant before submitting, and often hides "
                "fabricated numbers."
            ),
            severity="warning",
            score_impact=25,
        ))

    # Employer-name analysis. Real IRS transcripts already truncate
    # employer names into 3-4 char word groups (e.g. "EIGR IN",
    # "MARY ACAD", "INNO GENO LLC") — per Myssy 2026-07-13. So we
    # cannot flag a single name as "truncated" without false positives.
    # Instead we look for anomalies across ALL employer names in the doc:

    all_names = fields.employer_names_all or ([fields.employer_name]
                                              if fields.employer_name else [])
    all_names = [n for n in all_names if n]

    # Anomaly 1: any employer name ends with a single-character word
    # ("BYER ENGI C") — IRS truncation leaves 2-4 char stubs, never 1.
    single_stub_names = [n for n in all_names if _has_single_char_stub(n)]
    if single_stub_names:
        flags.append(TranscriptFlag(
            title="Over-Clipped Employer Name",
            description=(
                f"Employer name(s) {single_stub_names!r} end with a "
                "single-character word. Genuine IRS transcripts truncate "
                "employer names into 3-4 character word groups, never "
                "leaving a lone 1-char stub. This is the clipping pattern "
                "seen when a fabricator manually edits the PDF and drops "
                "characters mid-word."
            ),
            severity="warning",
            score_impact=20,
        ))

    # Note: we experimented with a "mixed truncation" flag (fires when
    # some names have a fully-spelled corporate suffix like "LLC" and
    # others are truncated). It produced a false positive on the clean
    # Maryville sample which has both 'EIGR IN' (truncated) and
    # 'INNO GENO LLC' (full suffix). Real IRS output is not internally
    # consistent — 3-char suffixes fit the "3-4 char word group" rule
    # and print unclipped. Removed until we have more clean samples.

    # ---- Myssy 2026-07-13 (Christopher Nicola) signals ----

    # "Submission Type: Origin" is a fabrication tell — the trailing
    # "al" was clipped when the PDF was converted to an editable format.
    # We only flag if we saw multiple truncated occurrences, because a
    # single stray "Origin" could just be an OCR artefact.
    if fields.truncated_submission_types >= 2:
        flags.append(TranscriptFlag(
            title='Truncated "Submission Type" Values',
            description=(
                f'Found {fields.truncated_submission_types} W-2 sections showing '
                '"Submission Type: Origin" instead of the correct "Original". '
                "Real IRS transcripts consistently show the full word "
                '"Original" right-justified. Truncated values typically appear '
                "when someone converts the IRS's uneditable PDF into an "
                "editable format and clips text while modifying the document."
            ),
            severity="critical",
            score_impact=35,
        ))

    # "Third Party Sick Pay Indicator: Un" — same fabrication tell.
    # Value should be a full word ("Unanswered", "Yes", "No").
    if fields.truncated_sickpay_indicators >= 2:
        flags.append(TranscriptFlag(
            title='Truncated "Sick Pay Indicator" Values',
            description=(
                f'Found {fields.truncated_sickpay_indicators} W-2 sections showing '
                'a truncated Third Party Sick Pay Indicator value (e.g. "Un" '
                'instead of "Unanswered"). Same PDF-conversion clipping pattern '
                'as truncated submission types.'
            ),
            severity="warning",
            score_impact=25,
        ))

    # Replacement footer box — real IRS transcripts end with an IRS URL/
    # signature footer, never a "NON-EMPLOYMENT INFORMATION REDACTED" box.
    if fields.has_nonemp_redacted_box:
        flags.append(TranscriptFlag(
            title='"Non-Employment Information Redacted" Replacement Box',
            description=(
                'Document contains a "NON-EMPLOYMENT INFORMATION REDACTED" box '
                'where the IRS footer should be. Genuine IRS Wage & Income '
                'Transcripts end with an IRS-generated footer, not a '
                'redaction-notice box added by the applicant. This is a '
                'strong indication the file was converted to an editable '
                'format and modified.'
            ),
            severity="critical",
            score_impact=40,
        ))

    # Missing Response Date when Request Date and other page-1 headers
    # are present. IRS transcript packets always include both dates on
    # page 1 — blanking the response date is a common fabrication tell.
    if fields.has_title and fields.has_masthead and fields.request_date \
            and not fields.response_date:
        flags.append(TranscriptFlag(
            title="Missing Response Date on IRS Transcript",
            description=(
                f'Request Date is populated ({fields.request_date}) but '
                'Response Date is blank. Genuine IRS Wage & Income Transcripts '
                'always include both dates on page 1 — blanking the response '
                'date is a common fabrication tell.'
            ),
            severity="warning",
            score_impact=25,
        ))

    # PDF metadata inconsistent with IRS output. Real IRS transcripts are
    # not stamped with a consumer PDF editor's producer string, nor with
    # a hand-typed subject like "Employment verification". We flag this
    # as informational unless we already have other signals.
    if fields.pdf_subject and fields.has_title:
        subj = fields.pdf_subject.strip().lower()
        # IRS transcripts have no /Subject or a system-generated one.
        # "Employment verification" (as on the Christopher Nicola sample)
        # is a give-away that a human re-saved this file.
        suspicious_subjects = ("employment verification", "redacted",
                               "verification", "transcript redacted")
        if any(s in subj for s in suspicious_subjects):
            flags.append(TranscriptFlag(
                title="PDF Metadata Rewritten by an Editor",
                description=(
                    f'PDF Subject metadata reads "{fields.pdf_subject}". '
                    'IRS-issued transcripts do not carry human-authored '
                    'subject strings like this. The file was almost certainly '
                    'opened in a PDF editor and re-saved — the IRS only '
                    'releases transcripts as uneditable PDFs.'
                ),
                severity="warning",
                score_impact=15,
            ))

    # Very tight sanity check on any obviously-partial address is deferred
    # to the batch analyzer where we have more context.

    return flags


def analyze_batch(items: List[TranscriptFields]) -> Tuple[List[TranscriptFlag], List[List[TranscriptFlag]]]:
    """Cross-document rules for an IRS-transcript batch upload.

    Returns:
        (batch_flags, per_doc_flags)
        - batch_flags applies to the whole submission
        - per_doc_flags[i] applies to items[i]
    """

    per_doc: List[List[TranscriptFlag]] = [[] for _ in items]
    batch: List[TranscriptFlag] = []

    if len(items) < 2:
        return batch, per_doc

    # Group documents that each present themselves as "page 1"
    page_ones = [(i, f) for i, f in enumerate(items) if f.looks_like_page_one]

    # ---- Duplicate tracking numbers across separate "page 1" documents ----
    by_tracking: Dict[str, List[int]] = {}
    for i, f in page_ones:
        by_tracking.setdefault(f.tracking_number, []).append(i)

    for tracking, idxs in by_tracking.items():
        if len(idxs) < 2:
            continue

        names = ", ".join(os.path.basename(items[i].source_file) for i in idxs)
        batch.append(TranscriptFlag(
            title="Duplicate IRS Transcript Tracking Number",
            description=(
                f"{len(idxs)} documents each present themselves as page 1 of an "
                f"IRS Wage & Income Transcript and share the same tracking "
                f'number "{tracking}". This is impossible: two separate '
                "transcript requests would receive different tracking numbers, "
                "and pages within a single transcript packet only carry the "
                "tracking header on page 1. Strong indicator that a real IRS "
                "transcript header was copy-pasted onto additional pages. "
                f"Files: {names}."
            ),
            severity="critical",
            score_impact=60,
            scope="batch",
        ))
        for i in idxs:
            per_doc[i].append(TranscriptFlag(
                title="Duplicate IRS Transcript Header",
                description=(
                    f'Shares tracking number "{tracking}" with '
                    f"{len(idxs) - 1} other document(s) in this submission "
                    "that also claim to be page 1 of a transcript."
                ),
                severity="critical",
                score_impact=60,
            ))

    # ---- Same tracking# but different PDF creation timestamps / page sizes ----
    for tracking, idxs in by_tracking.items():
        if len(idxs) < 2:
            continue

        created = {items[i].pdf_creation_date for i in idxs if items[i].pdf_creation_date}
        if len(created) > 1:
            batch.append(TranscriptFlag(
                title="Same Tracking Number, Different Creation Times",
                description=(
                    f'Documents sharing tracking number "{tracking}" have '
                    f"different PDF creation timestamps ({sorted(created)}). "
                    "A genuine IRS transcript packet is generated in one "
                    "operation and produces a single continuous PDF; "
                    "separately-created files cannot share a tracking number."
                ),
                severity="critical",
                score_impact=50,
                scope="batch",
            ))

        sizes = {(round(items[i].page_width_pts or 0, 1),
                  round(items[i].page_height_pts or 0, 1)) for i in idxs}
        if len(sizes) > 1:
            batch.append(TranscriptFlag(
                title="Same Tracking Number, Different Page Dimensions",
                description=(
                    f'Documents sharing tracking number "{tracking}" have '
                    f"different page dimensions ({sorted(sizes)}). Pages "
                    "from one IRS transcript packet are the same size."
                ),
                severity="warning",
                score_impact=25,
                scope="batch",
            ))

    # ---- Multiple docs claiming to be page 1 but with DIFFERENT tracking#s
    # is not itself suspicious — an applicant may legitimately submit two
    # different transcripts (e.g., for two tax years). We deliberately do
    # not flag that case.

    return batch, per_doc


# ---------------------------------------------------------------------------
# Combined batch report
# ---------------------------------------------------------------------------

def _risk_level(score: int) -> str:
    if score >= 65:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def analyze_files(file_paths: List[str]) -> Dict[str, Any]:
    """One-shot: extract every file, run single + batch checks, return a report."""

    items: List[TranscriptFields] = []
    wage_bar_flags: List[bool] = []
    for p in file_paths:
        try:
            f = extract_from_file(p)
        except Exception as e:
            items.append(TranscriptFields(source_file=p, raw_text=""))
            wage_bar_flags.append(False)
            continue
        items.append(f)
        ext = os.path.splitext(p)[1].lower()
        wage_bar_flags.append(detect_wage_redaction_bar(p) if ext == ".pdf" else False)

    per_doc_flags: List[List[TranscriptFlag]] = []
    for f, wb in zip(items, wage_bar_flags):
        per_doc_flags.append(analyze_single_transcript(f, wage_bar_redaction=wb))

    batch_flags, cross_doc_flags = analyze_batch(items)
    for i, extras in enumerate(cross_doc_flags):
        per_doc_flags[i].extend(extras)

    # Score per doc
    documents: List[Dict[str, Any]] = []
    total_score = 0
    for f, wb, flags in zip(items, wage_bar_flags, per_doc_flags):
        score = min(100, sum(fl.score_impact for fl in flags))
        total_score = max(total_score, score)  # batch severity = worst doc
        documents.append({
            "file": f.source_file,
            "fields": {
                "tracking_number": f.tracking_number,
                "request_date": f.request_date,
                "response_date": f.response_date,
                "tin_provided": f.tin_provided,
                "tax_period": f.tax_period,
                "employer_name": f.employer_name,
                "employer_names_all": f.employer_names_all,
                "has_masthead": f.has_masthead,
                "has_title": f.has_title,
                "w2_section_count": f.w2_section_count,
                "page_size_pts": (f.page_width_pts, f.page_height_pts),
                "pdf_creation_date": f.pdf_creation_date,
                "pdf_mod_date": f.pdf_mod_date,
                "pdf_editor": f.pdf_editor,
                "pdf_subject": f.pdf_subject,
                "wage_bar_redaction": wb,
                "truncated_submission_types": f.truncated_submission_types,
                "ok_submission_types": f.ok_submission_types,
                "truncated_sickpay_indicators": f.truncated_sickpay_indicators,
                "has_nonemp_redacted_box": f.has_nonemp_redacted_box,
            },
            "flags": [fl.as_dict() for fl in flags],
            "score": score,
            "risk_level": _risk_level(score),
        })

    batch_score_impact = sum(fl.score_impact for fl in batch_flags)
    total_score = min(100, total_score + batch_score_impact)

    return {
        "analyzed_at": datetime.now().isoformat(),
        "file_count": len(file_paths),
        "batch_flags": [fl.as_dict() for fl in batch_flags],
        "documents": documents,
        "risk_score": total_score,
        "risk_level": _risk_level(total_score),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("Usage: python irs_transcript.py <file1> [file2 ...]")
        sys.exit(1)

    report = analyze_files(sys.argv[1:])
    print(json.dumps(report, indent=2, default=str))

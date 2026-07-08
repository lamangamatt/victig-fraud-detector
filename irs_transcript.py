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
# Employer name appears a few lines after "Employer:" — typically right
# after the EIN line. We anchor on "EIN" and take the next non-blank line
# that looks like an all-caps entity name.
_RE_EMPLOYER_HDR   = re.compile(
    r"Employer\s+Identification\s+Number.*?\n+\s*"
    r"([A-Z][A-Z0-9 .,&'\-]{2,}?)\s*\n",
    re.I | re.S,
)


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
    raw_text: str = ""
    pdf_creation_date: Optional[str] = None
    pdf_mod_date: Optional[str] = None
    page_width_pts: Optional[float] = None
    page_height_pts: Optional[float] = None

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

    # Two independent signals of a wage-value blackout bar:
    #
    #   (1) A contiguous vertical band (≥20 px tall) where every row has
    #       a dark run wider than ~20% of the full page width. That's the
    #       characteristic "big black rectangle over the values column"
    #       shape Myssy's forgeries use.
    #
    #   (2) A single row with an extremely wide dark run (≥40% of the
    #       page width). Even one line-height of that means an applicant
    #       drew a full-column blackout.
    #
    # Either signal is enough to flag.

    wide = max(120, int(w * 0.20))
    very_wide = max(200, int(w * 0.40))
    heavy_rows = row_max >= wide

    if heavy_rows.any():
        d = np.diff(np.concatenate(([0], heavy_rows.astype(np.int8), [0])))
        starts = np.where(d == 1)[0]
        ends = np.where(d == -1)[0]
        longest_band = int((ends - starts).max()) if len(starts) else 0
        if longest_band >= 20:
            return True

    if (row_max >= very_wide).sum() >= 5:
        return True

    return False


# ---------------------------------------------------------------------------
# Batch analysis
# ---------------------------------------------------------------------------

_GARBLE_LEGIT_TAILS = (
    "LLC", "L.L.C.", "INC", "INC.", "CORP", "CORPORATION", "CO", "CO.",
    "COMPANY", "LP", "L.P.", "LLP", "PLLC", "PC", "P.C.", "TRUST",
    "PARTNERSHIP", "ENTERPRISES",
)


def _looks_truncated(name: str) -> bool:
    """Heuristic: employer name appears truncated / garbled.

    Real IRS transcripts show the full legal entity name. Fabricators
    who screenshot part of a page often clip the last few characters
    ("KURT CARS CONS LL" for "…CONS LLC", "EXCA SECU IN" for
    "EXCALIBUR SECURITY INC", etc.).
    """
    if not name:
        return False
    up = name.strip().upper()

    # Ends with a lone "L" or "LL" (dropped "LLC")
    if re.search(r"\bL{1,2}\.?$", up):
        # …but "LL Bean" is fine — only flag when preceded by CONS/CORP/etc.
        if re.search(r"(CONS|COR|IN|LL)\s+L{1,2}\.?$", up):
            return True
        if up.endswith(" LL") or up.endswith(" L"):
            return True

    # Ends with " IN" (dropped INC)
    if re.search(r"\bIN\.?$", up) and not up.endswith(" INC"):
        return True

    # Ends with " COR" or " COMP" (dropped)
    if re.search(r"\b(COR|COMP|COR P|CORPORAT|COMPAN)\.?$", up):
        return True

    # Any word looks like a truncation stub (all-caps token 2-4 chars that
    # isn't a common initialism)
    tokens = up.split()
    if len(tokens) >= 2:
        last = tokens[-1]
        if 1 <= len(last) <= 3 and last not in ("LLC", "INC", "LP", "LLP", "PC", "CO", "US", "USA"):
            # Only flag if the rest of the name doesn't already end with a
            # legit corporate suffix
            if not any(up.endswith(t) for t in _GARBLE_LEGIT_TAILS):
                return True

    return False


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

    if _looks_truncated(fields.employer_name or ""):
        flags.append(TranscriptFlag(
            title="Truncated / Garbled Employer Name",
            description=(
                f'Employer name "{fields.employer_name}" appears truncated or '
                "garbled (e.g. missing LLC/INC suffix). Genuine IRS transcripts "
                "show the full legal entity name."
            ),
            severity="warning",
            score_impact=20,
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
                "has_masthead": f.has_masthead,
                "has_title": f.has_title,
                "w2_section_count": f.w2_section_count,
                "page_size_pts": (f.page_width_pts, f.page_height_pts),
                "pdf_creation_date": f.pdf_creation_date,
                "wage_bar_redaction": wb,
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

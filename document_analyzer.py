"""
Document Analyzer v2.3
Enhanced fraud detection with AI vision analysis for employment documents.

v2.3 Updates (June 19, 2026 - based on Myssy Clayson's input):
- Added structural box-numbering checks (e.g., three "13" boxes without a/b/c suffixes)
- Added overlapping text / collision detection inside form fields
- AI vision prompt now explicitly validates official W-2/1099 box layout

v2.2 Updates (April 30, 2026):
- Added grayscale variance detection to catch "printed over template" fraud
- Detects inconsistent text darkness (multiple print passes)
- Detects bimodal darkness patterns (template overlay indicator)

v2.1 Updates (April 2026 - based on Myssy Clayson's input):
- Added future-dated document detection for W-2s and 1099s
- Added 87-prefix EIN flagging (high fraud risk)
- Added EIN geographic mismatch detection
- Enhanced invalid field value detection ("NOT NEEDED", etc.)
- Added Box 14 code validation
- Added employer name formatting checks
- Added 1099 bulk filing platform detection
- Added random account number pattern detection
"""

import os
import re
import base64
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import hashlib

# PDF handling
try:
    import fitz  # PyMuPDF
    HAS_PYMUPDF = True
except ImportError:
    HAS_PYMUPDF = False

# Image handling
from PIL import Image, ImageFilter, ImageChops, ImageStat
import io
import numpy as np

# OCR
try:
    import pytesseract
    HAS_TESSERACT = True
except ImportError:
    HAS_TESSERACT = False

# AI Analysis
try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


class DocumentAnalyzer:
    """Enhanced document fraud detection with AI capabilities."""
    
    # Known legitimate payroll software
    LEGITIMATE_CREATORS = {
        'adp': 'ADP Payroll',
        'paychex': 'Paychex',
        'gusto': 'Gusto',
        'workday': 'Workday',
        'ultipro': 'UltiPro/UKG',
        'ceridian': 'Ceridian Dayforce',
        'paylocity': 'Paylocity',
        'paycom': 'Paycom',
        'bamboohr': 'BambooHR',
        'namely': 'Namely',
        'zenefits': 'Zenefits',
        'quickbooks': 'QuickBooks',
        'sage': 'Sage',
        'oracle': 'Oracle HCM',
        'sap': 'SAP SuccessFactors',
        'kronos': 'Kronos/UKG',
        'adp workforce': 'ADP Workforce Now',
        'intuit': 'Intuit Payroll',
        'square': 'Square Payroll',
        'rippling': 'Rippling',
    }
    
    # Suspicious creation tools - weighted by risk
    # Scores reduced 2026-05-21 to reduce false positives from common legitimate scenarios
    SUSPICIOUS_CREATORS = {
        # High risk - image editors (these are genuinely suspicious)
        'photoshop': ('Adobe Photoshop', 45),
        'gimp': ('GIMP', 40),
        'illustrator': ('Adobe Illustrator', 40),
        'inkscape': ('Inkscape', 35),
        'affinity': ('Affinity', 35),
        'pixelmator': ('Pixelmator', 35),
        'paint.net': ('Paint.NET', 30),
        
        # Medium risk - document editors (reduced - HR legitimately uses these)
        'canva': ('Canva', 30),
        'microsoft word': ('Microsoft Word', 12),  # Reduced from 25 - HR uses Word
        'libreoffice': ('LibreOffice', 15),
        'openoffice': ('OpenOffice', 15),
        'pages': ('Apple Pages', 12),
        'google docs': ('Google Docs', 12),
        
        # PDF editors - medium-high risk
        'acrobat pro': ('Adobe Acrobat Pro', 20),  # Reduced - sometimes used legitimately
        'pdf editor': ('PDF Editor', 35),
        'foxit': ('Foxit PDF', 20),
        'nitro': ('Nitro PDF', 20),
        'smallpdf': ('SmallPDF', 30),
        'ilovepdf': ('iLovePDF', 30),
        'sejda': ('Sejda', 30),
        'pdf-xchange': ('PDF-XChange', 20),
        'pdfelement': ('PDFelement', 25),
        
        # Low/no risk - common legitimate tools
        'preview': ('macOS Preview', 5),  # Reduced from 15 - just scanning
        'microsoft print': ('Microsoft Print to PDF', 0),  # Reduced from 10 - completely normal
    }
    
    # Legitimate redaction tools - should not be penalized when redactions detected
    REDACTION_TOOLS = {
        'acrobat': 'Adobe Acrobat',
        'acrobat pro': 'Adobe Acrobat Pro',
        'preview': 'macOS Preview',
        'foxit': 'Foxit PDF',
        'pdf-xchange': 'PDF-XChange',
        'apple markup': 'iOS/iPadOS Markup',
        'markup': 'Markup Tool',
        'photos': 'Photos App',
        'snapseed': 'Snapseed',
        'picsart': 'PicsArt',
    }
    
    # Patterns that indicate intentional redaction
    REDACTION_PATTERNS = [
        r'xxx-xx-\d{4}',      # Redacted SSN (last 4 visible)
        r'\*{3}-\*{2}-\d{4}', # Redacted SSN with asterisks
        r'xxx-xx-xxxx',        # Fully redacted SSN
        r'\*{4,}',             # Multiple asterisks
        r'x{4,}',              # Multiple x's
        r'\[redacted\]',       # Explicit redaction marker
        r'\[removed\]',        # Removal marker
        r'account.*x{4}',      # Redacted account number
        r'x{4}\d{4}',          # Last 4 of account visible
    ]

    # EIN state prefix mapping (historical assignments)
    # Note: Online applications can get any prefix, but mismatches are still suspicious
    EIN_STATE_PREFIXES = {
        '01': ['AL'], '02': ['AL'], '03': ['FL'], '04': ['FL'], '05': ['FL'], '06': ['FL'],
        '10': ['GA'], '11': ['GA'], '12': ['GA'],
        '13': ['SC'], '14': ['SC'], '15': ['MS'], '16': ['MS'],
        '20': ['VA'], '21': ['VA'], '22': ['VA'], '23': ['WV'], '24': ['NC'], '25': ['NC'],
        '26': ['DE'], '27': ['MD'], '28': ['MD'], '29': ['DC'],
        '30': ['WI'], '31': ['WI'], '32': ['WI'], '33': ['IN'], '34': ['IN'], '35': ['KY'],
        '36': ['IL', 'IN'],  # Shared prefix
        '37': ['MI'], '38': ['MI'], '39': ['OH'], '40': ['OH'], '41': ['OH'],
        '42': ['TN'], '43': ['TN'], '44': ['OK'], '45': ['OK'],
        '46': ['KS'], '47': ['IA'], '48': ['MN'], '49': ['NE'],
        '50': ['ND'], '51': ['SD'], '52': ['MT'], '53': ['ID'], '54': ['WY'],
        '55': ['CO'], '56': ['CO'], '57': ['AZ'], '58': ['NM'], '59': ['UT'], '60': ['NV'],
        '61': ['CA'], '62': ['CA'], '63': ['CA'], '64': ['CA'], '65': ['CA'], '66': ['CA'],
        '67': ['OR'], '68': ['WA'], '69': ['AK'], '70': ['HI'],
        '71': ['AR'], '72': ['AR'], '73': ['LA'], '74': ['TX'], '75': ['TX'], '76': ['TX'],
        '77': ['MO'], '78': ['MO'],
        '80': ['NY'], '81': ['NY'], '82': ['NY'], '83': ['NY'], '84': ['NY'], '85': ['NY'],
        '86': ['NY'], '87': ['ONLINE'],  # IRS online applications - HIGH FRAUD RISK
        '88': ['ONLINE'],  # IRS online applications - HIGH FRAUD RISK
        '90': ['CT'], '91': ['RI'], '92': ['NJ'], '93': ['PA'], '94': ['PA'], '95': ['PA'],
        '98': ['MA'], '99': ['ME', 'VT', 'NH'],
    }
    
    # Known valid Box 14 codes (W-2)
    KNOWN_BOX14_CODES = {
        # Standard IRS codes
        'A', 'B', 'C', 'D', 'DD', 'E', 'EE', 'F', 'FF', 'G', 'GG', 'H', 'HH',
        'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'Y', 'Z',
        'AA', 'BB', 'CC',
        # Common employer-reported items (text labels)
        'UNION', 'DUES', 'RETIRE', '401K', '401(K)', '403B', '457', 'PENSION',
        'MEDICAL', 'DENTAL', 'VISION', 'HSA', 'FSA', 'LIFE', 'LTD', 'STD',
        'HEALTH', 'INSURANCE', 'PARKING', 'TRANSIT', 'EDUC', 'TUITION',
        'ROTH', 'SIMPLE', 'SEP', 'ERISA',
    }
    
    # AI-related indicators - highest risk
    AI_INDICATORS = [
        ('chatgpt', 50),
        ('openai', 45),
        ('anthropic', 45),
        ('midjourney', 50),
        ('dall-e', 50),
        ('stable diffusion', 50),
        ('ai generated', 50),
        ('generated by ai', 50),
    ]
    
    # Expected tax withholding ranges by income bracket (2024 US)
    TAX_BRACKETS = [
        (11600, 0.10, 0.15),    # 10% bracket - expect 5-15%
        (47150, 0.12, 0.20),    # 12% bracket - expect 10-20%
        (100525, 0.22, 0.28),   # 22% bracket - expect 18-28%
        (191950, 0.24, 0.32),   # 24% bracket - expect 20-32%
        (243725, 0.32, 0.38),   # 32% bracket - expect 28-38%
        (609350, 0.35, 0.42),   # 35% bracket - expect 32-42%
        (float('inf'), 0.37, 0.45),  # 37% bracket
    ]
    
    def __init__(self, use_ai: bool = True):
        self.flags: List[Dict] = []
        self.risk_score = 0
        self.use_ai = use_ai and HAS_ANTHROPIC and os.environ.get('ANTHROPIC_API_KEY')
        self.redactions_detected = False
        self.redaction_tool_used = None
        self.ai_client = anthropic.Anthropic() if self.use_ai else None
        
    def analyze(self, file_path: str, doc_type: str = "Pay Stub") -> Dict[str, Any]:
        """Main analysis entry point."""
        self.flags = []
        self.risk_score = 0
        self.redactions_detected = False
        self.redaction_tool_used = None
        
        results = {
            'file_path': file_path,
            'file_hash': self._compute_hash(file_path),
            'doc_type': doc_type,
            'analyzed_at': datetime.now().isoformat(),
            'metadata': {},
            'flags': [],
            'risk_score': 0,
            'risk_level': 'LOW',
            'extracted_data': {},
            'math_validation': None,
            'visual_analysis': None,
            'ai_analysis': None,
            'recommendations': [],
        }
        
        # Determine file type
        ext = Path(file_path).suffix.lower()
        
        if ext == '.pdf':
            results['metadata'] = self._analyze_pdf_metadata(file_path)
            text = self._extract_pdf_text(file_path)
            image = self._pdf_to_image(file_path)
            results['metadata']['file_type'] = 'PDF'
        else:
            results['metadata'] = self._analyze_image_metadata(file_path)
            text = self._ocr_image(file_path) if HAS_TESSERACT else ""
            image = Image.open(file_path)
            results['metadata']['file_type'] = 'Image'
        
        # Store image for AI analysis
        self._current_image = image
        self._current_image_path = file_path
        
        # Early redaction detection - must run before creator tool check
        # This sets self.redactions_detected which affects how we score editing tools
        if text:
            self._detect_redactions(text)
        
        # Run all checks
        self._check_metadata_flags(results['metadata'])
        self._check_creation_date(results['metadata'], doc_type)
        self._check_creator_tool(results['metadata'])  # Now aware of redactions
        self._check_file_anomalies(file_path, results['metadata'])
        
        if text:
            results['extracted_data'] = self._extract_document_data(text, doc_type)
            self._check_text_anomalies(text, doc_type)  # Runs additional text checks
            
            # NEW: Validate EIN and employer info if extracted
            extracted = results['extracted_data']
            if extracted.get('ein'):
                self._check_ein_validity(
                    extracted.get('ein'),
                    extracted.get('employer_state'),
                    extracted.get('employer_name')
                )
            
            if doc_type == "Pay Stub":
                results['math_validation'] = self._validate_pay_stub_math(text, results['extracted_data'])
            elif doc_type == "W-2":
                results['math_validation'] = self._validate_w2_math(text, results['extracted_data'])
                # NEW 2026-07-03: W-2 forgery formatting checks (Myssy Clayson sample)
                self._check_w2_formatting(text, results['extracted_data'])
            elif doc_type == "1099":
                # NEW: 1099 specific validation
                results['math_validation'] = self._validate_1099(text, results['extracted_data'])
        
        # Visual/forensic analysis
        if image:
            results['visual_analysis'] = self._analyze_visual_forensics(image)
        
        # AI Analysis - the big guns
        if self.use_ai and image:
            results['ai_analysis'] = self._run_ai_vision_analysis(file_path, doc_type, text, results)
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        # Post-processing: if W-2 has content-level critical/warning flags, don't let
        # "Metadata Missing" stay as Info — upgrade it to Warning so it contributes
        # to the score honestly (2026-07-03, Myssy Clayson improvement)
        if results.get('doc_type') == 'W-2':
            self._upgrade_metadata_flag_if_content_flagged()

        # Compile results
        results['flags'] = self.flags
        results['risk_score'] = max(0, min(self.risk_score, 100))
        results['risk_level'] = self._calculate_risk_level(results['risk_score'])
        
        return results
    
    def _compute_hash(self, file_path: str) -> str:
        """Compute SHA-256 hash of file for tracking."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()[:16]
    
    def _analyze_pdf_metadata(self, file_path: str) -> Dict:
        """Extract and analyze PDF metadata."""
        metadata = {
            'file_size': f"{os.path.getsize(file_path) / 1024:.1f} KB",
            'file_size_bytes': os.path.getsize(file_path),
        }
        
        if not HAS_PYMUPDF:
            return metadata
        
        try:
            doc = fitz.open(file_path)
            meta = doc.metadata
            
            metadata['pages'] = len(doc)
            metadata['creator'] = meta.get('creator', '')
            metadata['producer'] = meta.get('producer', '')
            metadata['author'] = meta.get('author', '')
            metadata['title'] = meta.get('title', '')
            metadata['subject'] = meta.get('subject', '')
            
            # Parse dates
            if meta.get('creationDate'):
                metadata['creation_date'] = self._parse_pdf_date(meta['creationDate'])
                metadata['creation_date_raw'] = meta['creationDate']
            
            if meta.get('modDate'):
                metadata['modification_date'] = self._parse_pdf_date(meta['modDate'])
                metadata['modification_date_raw'] = meta['modDate']
            
            # Check for incremental saves (sign of editing)
            metadata['has_incremental_saves'] = doc.is_repaired or doc.needs_pass
            
            # Check for embedded files/attachments
            metadata['has_attachments'] = len(doc.embfile_names()) > 0
            
            # Check for JavaScript (suspicious in a pay stub)
            has_js = False
            for page in doc:
                if page.get_text("dict").get("scripts"):
                    has_js = True
                    break
            metadata['has_javascript'] = has_js
            
            # Check for forms
            metadata['has_forms'] = doc.is_form_pdf
            
            # Get PDF version
            metadata['pdf_version'] = f"PDF {doc.metadata.get('format', 'Unknown')}"
            
            doc.close()
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def _analyze_image_metadata(self, file_path: str) -> Dict:
        """Extract image metadata (EXIF, etc.)."""
        metadata = {
            'file_size': f"{os.path.getsize(file_path) / 1024:.1f} KB",
            'file_size_bytes': os.path.getsize(file_path),
        }
        
        try:
            img = Image.open(file_path)
            metadata['format'] = img.format
            metadata['size'] = f"{img.width}x{img.height}"
            metadata['width'] = img.width
            metadata['height'] = img.height
            metadata['mode'] = img.mode
            metadata['dpi'] = img.info.get('dpi', 'Unknown')
            
            # EXIF data
            exif = img._getexif() if hasattr(img, '_getexif') and img._getexif() else {}
            if exif:
                # Common EXIF tags
                tag_names = {
                    271: 'camera_make',
                    272: 'camera_model', 
                    305: 'software',
                    306: 'datetime',
                    36867: 'datetime_original',
                    37521: 'datetime_digitized',
                }
                for tag_id, name in tag_names.items():
                    if tag_id in exif:
                        metadata[name] = str(exif[tag_id])
                
                if 'software' in metadata:
                    metadata['creator'] = metadata['software']
                if 'datetime' in metadata:
                    metadata['creation_date'] = metadata['datetime']
            
            # Check for editing indicators
            metadata['has_exif'] = bool(exif)
            
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def _parse_pdf_date(self, date_str: str) -> str:
        """Parse PDF date format (D:YYYYMMDDHHmmSS)."""
        try:
            if date_str.startswith('D:'):
                date_str = date_str[2:]
            date_str = re.sub(r"[+-]\d{2}'\d{2}'?$", '', date_str)
            date_str = date_str[:14]
            dt = datetime.strptime(date_str, '%Y%m%d%H%M%S')
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return date_str
    
    def _extract_pdf_text(self, file_path: str) -> str:
        """Extract text from PDF."""
        if not HAS_PYMUPDF:
            return ""
        
        try:
            doc = fitz.open(file_path)
            text = ""
            for page in doc:
                text += page.get_text()
            doc.close()
            return text
        except:
            return ""
    
    def _pdf_to_image(self, file_path: str, dpi: int = 200) -> Optional[Image.Image]:
        """Convert first page of PDF to image for visual analysis."""
        if not HAS_PYMUPDF:
            return None
        
        try:
            doc = fitz.open(file_path)
            page = doc[0]
            mat = fitz.Matrix(dpi/72, dpi/72)
            pix = page.get_pixmap(matrix=mat)
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            doc.close()
            return img
        except:
            return None
    
    def _ocr_image(self, file_path: str) -> str:
        """Run OCR on image."""
        if not HAS_TESSERACT:
            return ""
        
        try:
            img = Image.open(file_path)
            # Preprocess for better OCR
            if img.mode != 'RGB':
                img = img.convert('RGB')
            text = pytesseract.image_to_string(img)
            return text
        except:
            return ""
    
    def _check_metadata_flags(self, metadata: Dict):
        """Check metadata for suspicious indicators."""
        # Check if metadata is stripped
        creator = metadata.get('creator', '')
        producer = metadata.get('producer', '')
        
        if not creator and not producer:
            self._add_flag(
                'Metadata Missing',
                'Document metadata has been stripped or is missing. This is common with scanned documents but can also indicate tampering.',
                'info',
                10  # Reduced from 20 - too common with legitimate scans
            )
        
        # Check for JavaScript in PDF
        if metadata.get('has_javascript'):
            self._add_flag(
                'JavaScript Detected',
                'PDF contains JavaScript code. Legitimate pay stubs should not contain scripts.',
                'critical',
                35
            )
        
        # Check for unusual file size
        size_bytes = metadata.get('file_size_bytes', 0)
        if size_bytes < 5000:  # Less than 5KB
            self._add_flag(
                'Unusually Small File',
                f'File is only {size_bytes/1024:.1f}KB. This could indicate a digitally created document rather than a scan.',
                'info',
                8  # Reduced from 15 - small files can be legitimate
            )
        elif size_bytes > 10000000:  # More than 10MB
            self._add_flag(
                'Unusually Large File',
                f'File is {size_bytes/1024/1024:.1f}MB. This is unusually large for a single pay stub.',
                'info',
                5
            )
    
    def _check_creation_date(self, metadata: Dict, doc_type: str):
        """Check if creation date is suspicious - smart detection for portal downloads."""
        creation_date = metadata.get('creation_date')
        if not creation_date:
            return
        
        try:
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y:%m:%d %H:%M:%S', '%Y-%m-%d']:
                try:
                    created = datetime.strptime(creation_date.split()[0], fmt.split()[0])
                    break
                except:
                    continue
            else:
                return
            
            days_old = (datetime.now() - created).days
            hours_old = (datetime.now() - created).total_seconds() / 3600
            
            # Check modification date vs creation date FIRST - this is the real red flag
            mod_date = metadata.get('modification_date')
            was_modified = mod_date and mod_date != creation_date
            
            if was_modified:
                self._add_flag(
                    'Document Modified After Creation',
                    f'Created: {creation_date}, Modified: {mod_date}. The document was edited after initial creation. This is a significant fraud indicator.',
                    'critical',
                    30
                )
            
            # For recent creation dates, context matters:
            # - Pay stubs, bank statements are EXPECTED to be recently created (downloaded from portals)
            # - Modification after creation is the real red flag
            # - Only flag recent creation as suspicious if combined with other factors
            
            portal_download_types = ['Pay Stub', 'Bank Statement', 'W-2', 'Tax Document', '1099']
            is_portal_type = doc_type in portal_download_types
            
            if hours_old < 24:
                if is_portal_type and not was_modified:
                    # Normal for portal downloads - just informational
                    self._add_flag(
                        'Recently Downloaded',
                        f'Document was created within the last {int(hours_old)} hours. This is typical for documents downloaded from payroll or banking portals.',
                        'info',
                        0  # No risk score impact
                    )
                elif was_modified:
                    # Recently created AND modified - very suspicious
                    self._add_flag(
                        'Created and Modified Today',
                        f'Document was created AND modified within the last {int(hours_old)} hours. This suggests active editing.',
                        'critical',
                        25
                    )
                else:
                    # Unknown doc type, recently created - mild flag
                    self._add_flag(
                        'Created Today',
                        f'Document was created within the last {int(hours_old)} hours.',
                        'info',
                        5
                    )
            elif days_old < 7:
                if is_portal_type and not was_modified:
                    # Still normal for portal downloads
                    self._add_flag(
                        'Recently Created',
                        f'Document was created {days_old} days ago. Normal for documents downloaded from employer/bank portals.',
                        'info',
                        0
                    )
                elif not is_portal_type:
                    self._add_flag(
                        'Recently Created',
                        f'Document was created within the last week ({days_old} days ago).',
                        'info',
                        5
                    )
                
        except Exception:
            pass
    
    def _check_creator_tool(self, metadata: Dict):
        """Check if document was created with suspicious software.
        
        When redactions are detected, common redaction tools (Preview, Acrobat, etc.)
        are not penalized since candidates are often asked to redact sensitive info.
        """
        creator = (metadata.get('creator', '') or '').lower()
        producer = (metadata.get('producer', '') or '').lower()
        software = (metadata.get('software', '') or '').lower()
        
        combined = f"{creator} {producer} {software}"
        
        # Check for AI indicators first (highest risk) - always flag these
        for indicator, score in self.AI_INDICATORS:
            if indicator in combined:
                self._add_flag(
                    'AI Generation Detected',
                    f'Document metadata suggests AI-generated content: "{indicator}" found in creator info.',
                    'critical',
                    score
                )
                return
        
        # If redactions were detected, check if a legitimate redaction tool was used
        if self.redactions_detected:
            for tool_key, tool_name in self.REDACTION_TOOLS.items():
                if tool_key in combined:
                    self.redaction_tool_used = tool_name
                    self._add_flag(
                        f'Redaction Tool: {tool_name}',
                        f'Document was edited with {tool_name}, likely for redacting sensitive information as requested. '
                        'This is expected when candidates protect SSN, account numbers, or other PII.',
                        'info',
                        0  # No penalty when redaction tool + redactions detected
                    )
                    return
        
        # Check for suspicious editing tools
        for tool_key, (tool_name, score) in self.SUSPICIOUS_CREATORS.items():
            if tool_key in combined:
                # Reduce penalty if redactions detected but tool not in whitelist
                if self.redactions_detected:
                    adjusted_score = max(5, score // 3)  # Reduce to 1/3, minimum 5
                    self._add_flag(
                        f'Editing Software: {tool_name}',
                        f'Document was edited with {tool_name}. Redactions were detected, '
                        'which may explain the use of editing software.',
                        'info',
                        adjusted_score
                    )
                else:
                    severity = 'critical' if score >= 30 else 'warning'
                    self._add_flag(
                        f'Suspicious Software: {tool_name}',
                        f'Document was created/edited with {tool_name}. Legitimate payroll documents come directly from payroll systems.',
                        severity,
                        score
                    )
                return
        
        # Check for legitimate payroll software (reduces risk)
        for legit_key, legit_name in self.LEGITIMATE_CREATORS.items():
            if legit_key in combined:
                self._add_flag(
                    f'Legitimate Source: {legit_name}',
                    f'Document appears to originate from {legit_name} payroll system.',
                    'info',
                    -25  # Increased bonus from -15 - legitimate sources should offset other flags
                )
                return
    
    def _check_file_anomalies(self, file_path: str, metadata: Dict):
        """Check for file-level anomalies."""
        ext = Path(file_path).suffix.lower()
        
        # Check file extension vs actual content
        if ext == '.pdf':
            with open(file_path, 'rb') as f:
                header = f.read(10)
                if not header.startswith(b'%PDF'):
                    self._add_flag(
                        'File Type Mismatch',
                        'File has .pdf extension but does not appear to be a valid PDF.',
                        'critical',
                        40
                    )
    
    def _detect_redactions(self, text: str, images: List = None) -> bool:
        """Detect if document contains intentional redactions.
        
        Candidates are often asked to redact SSN, account numbers, etc.
        This is legitimate and expected behavior.
        """
        text_lower = text.lower()
        redaction_found = False
        redaction_types = []
        
        # Check text patterns for redactions
        for pattern in self.REDACTION_PATTERNS:
            if re.search(pattern, text_lower):
                redaction_found = True
                # Identify what type of redaction
                if 'xxx-xx' in pattern or 'ssn' in pattern or '\*{3}-\*{2}' in pattern:
                    redaction_types.append('SSN')
                elif 'account' in pattern or 'x{4}\\d{4}' in pattern:
                    redaction_types.append('Account Number')
                else:
                    redaction_types.append('Sensitive Data')
        
        # Check for visual redaction indicators (black boxes) in images
        if images and not redaction_found:
            for img in images[:3]:  # Check first 3 pages
                if self._detect_visual_redactions(img):
                    redaction_found = True
                    redaction_types.append('Visual Redaction')
                    break
        
        if redaction_found:
            self.redactions_detected = True
            unique_types = list(set(redaction_types))
            self._add_flag(
                'Appropriate Redactions Detected',
                f'Document contains redacted sensitive information ({"/ ".join(unique_types)}). '
                'This is expected when candidates are asked to protect SSN, account numbers, or other PII.',
                'info',
                -5  # Small bonus - shows candidate followed instructions
            )
        
        # Check for SSN over-truncation (IRS allows only first 5 digits to be hidden)
        self._check_ssn_truncation(text)
        
        return redaction_found
    
    def _check_ssn_truncation(self, text: str):
        """Check for improperly truncated SSNs.
        
        Per IRS rules (Pub 1586), employers may truncate the first 5 digits of SSN,
        but the last 4 digits MUST remain visible.
        
        Scoring:
        - Fully hidden (XXX-XX-XXXX) or last 4 visible (XXX-XX-1234): OK, no penalty
        - 1, 2, or 3 digits visible: SUSPICIOUS - why partial? Likely manipulation
        """
        text_lower = text.lower()
        
        # Pattern for partial visibility (1-3 digits) - THIS IS SUSPICIOUS
        # Why would someone show only 1-3 digits? This is the fraud indicator.
        partial_visible = [
            (r'[x\*_]{3}-[x\*_]{2}-[x\*_]{3}\d{1}', 1),  # Only last 1 digit visible
            (r'[x\*_]{3}-[x\*_]{2}-[x\*_]{2}\d{2}', 2),  # Only last 2 digits visible
            (r'[x\*_]{3}-[x\*_]{2}-[x\*_]{1}\d{3}', 3),  # Only last 3 digits visible
        ]
        
        for pattern, visible_count in partial_visible:
            if re.search(pattern, text_lower):
                self._add_flag(
                    'SSN Partially Visible',
                    f'SSN shows only {visible_count} digit(s) instead of the standard 4. '
                    'This unusual format could indicate document manipulation. '
                    'Legitimate documents show either last 4 digits (IRS standard) or fully redact the SSN.',
                    'warning',
                    20  # Suspicious - why would someone show only 1-3 digits?
                )
                return
        
        # Fully redacted SSN - acceptable (candidate privacy choice)
        fully_redacted = [
            r'xxx-xx-xxxx',
            r'\*{3}-\*{2}-\*{4}',
            r'\*{9}',
            r'x{9}',
            r'___-__-____',
        ]
        
        for pattern in fully_redacted:
            if re.search(pattern, text_lower):
                self._add_flag(
                    'SSN Fully Redacted',
                    'SSN is completely redacted. This is acceptable for candidate privacy.',
                    'info',
                    0  # No penalty - legitimate privacy choice
                )
                return
        
        # Properly truncated SSN (last 4 visible) - follows IRS guidelines
        proper_truncation = r'[x\*_]{3}-[x\*_]{2}-\d{4}'
        if re.search(proper_truncation, text_lower):
            self._add_flag(
                'SSN Properly Truncated',
                'SSN is truncated per IRS guidelines (first 5 digits hidden, last 4 visible).',
                'info',
                0  # No penalty - follows standard format
            )
    
    def _detect_visual_redactions(self, image) -> bool:
        """Detect black boxes or marker redactions in an image."""
        try:
            if isinstance(image, bytes):
                img = Image.open(io.BytesIO(image))
            elif isinstance(image, str):
                img = Image.open(image)
            else:
                img = image
            
            # Convert to grayscale
            gray = img.convert('L')
            img_array = np.array(gray)
            
            # Look for large dark rectangular regions (black boxes)
            # These are typically redaction marks
            dark_threshold = 30  # Very dark pixels
            dark_pixels = img_array < dark_threshold
            
            # Check if there are concentrated dark regions (potential redaction boxes)
            # This is a simplified check - looking for horizontal runs of dark pixels
            rows_with_dark_runs = 0
            for row in dark_pixels:
                # Look for runs of 20+ consecutive dark pixels
                run_length = 0
                max_run = 0
                for pixel in row:
                    if pixel:
                        run_length += 1
                        max_run = max(max_run, run_length)
                    else:
                        run_length = 0
                if max_run >= 20:
                    rows_with_dark_runs += 1
            
            # If multiple rows have dark runs, likely a redaction box
            if rows_with_dark_runs >= 5:
                return True
                
        except Exception:
            pass
        
        return False
    
    def _check_text_anomalies(self, text: str, doc_type: str):
        """Check extracted text for anomalies."""
        text_lower = text.lower()
        
        # Note: Redaction detection now happens earlier in analyze() before creator tool check
        
        # Check for placeholder text that wasn't replaced
        # Note: xxx-xx-xxxx removed - that's a legitimate SSN redaction, not a placeholder
        placeholders = ['lorem ipsum', 'john doe', 'jane doe', 
                       '[company name]', '[employee name]', 'sample', 'example',
                       'test document', 'draft']
        for placeholder in placeholders:
            if placeholder in text_lower:
                self._add_flag(
                    'Placeholder Text Found',
                    f'Document contains placeholder text: "{placeholder}". This suggests a template that wasn\'t fully customized.',
                    'critical',
                    30
                )
                break
        
        # Check for invalid text in fields that should be numeric or blank
        # ENHANCED: Added more invalid values based on real fraud samples
        invalid_field_values = ['n/a', 'not needed', 'not applicable', 'none', 'na', 'n.a.', 
                                'see attached', 'refer to', 'tbd', 'pending', 'not required',
                                'exempt', 'waived', 'n/d', 'nd']
        for invalid_val in invalid_field_values:
            # Look for these near dollar signs, box numbers, or common W2/pay stub fields
            patterns = [
                rf'\$\s*{re.escape(invalid_val)}',
                rf'box\s*\d+[:\s]*{re.escape(invalid_val)}',
                rf'wages[:\s]*{re.escape(invalid_val)}',
                rf'tax[:\s]*{re.escape(invalid_val)}',
                rf'gross[:\s]*{re.escape(invalid_val)}',
                rf'net[:\s]*{re.escape(invalid_val)}',
                rf'withholding[:\s]*{re.escape(invalid_val)}',
                rf'state\s*(?:id|employer)[:\s]*{re.escape(invalid_val)}',  # NEW: State ID field
                rf'employer\s*(?:state)?\s*id[:\s]*{re.escape(invalid_val)}',  # NEW
            ]
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    self._add_flag(
                        'Invalid Field Value',
                        f'Document contains "{invalid_val}" in a field that should be numeric or blank. Legitimate payroll systems use 0 or leave fields empty.',
                        'critical',
                        35
                    )
                    break
        
        # NEW: Check for future-dated tax documents (critical fraud indicator)
        current_year = datetime.now().year
        current_month = datetime.now().month
        
        if doc_type in ["W-2", "1099"]:
            # Find all 4-digit years in the document
            years_found = re.findall(r'\b(20[2-9]\d)\b', text)
            for year_str in years_found:
                doc_year = int(year_str)
                # A W-2 or 1099 for the current year shouldn't exist until January of the next year
                # (or late December at earliest)
                if doc_year > current_year:
                    self._add_flag(
                        'Future-Dated Document',
                        f'Document references tax year {doc_year}, but current year is {current_year}. Future-dated tax documents are impossible and indicate fabrication.',
                        'critical',
                        50
                    )
                    break
                elif doc_year == current_year and current_month < 12:
                    # Current year W-2/1099 before December is suspicious
                    self._add_flag(
                        'Premature Tax Year',
                        f'Document shows tax year {doc_year}, but W-2s/1099s for the current year are typically not issued until year-end or early next year.',
                        'warning',
                        20
                    )
                    break
        
        # Check for missing or suspicious year formats on W-2s
        if doc_type == "W-2":
            # Look for tax year - should be prominently displayed
            year_pattern = r'(?:tax\s*year|form\s*w-?2)[:\s]*(\d{4}|\d{2})'
            year_match = re.search(year_pattern, text_lower)
            
            # Check if year is missing entirely
            valid_years = [str(y) for y in range(current_year - 5, current_year + 1)]
            has_valid_year = any(year in text for year in valid_years)
            
            if not has_valid_year:
                self._add_flag(
                    'Missing Tax Year',
                    'W-2 does not contain a clearly visible tax year. This is required on all legitimate W-2 forms.',
                    'critical',
                    40
                )
            
            # NEW: Check Box 14 codes for validity
            self._check_box14_codes(text)
        
        # Check for inconsistent date formats
        date_patterns = [
            r'\d{1,2}/\d{1,2}/\d{2,4}',  # MM/DD/YYYY
            r'\d{1,2}-\d{1,2}-\d{2,4}',  # MM-DD-YYYY
            r'\d{4}-\d{2}-\d{2}',         # YYYY-MM-DD
        ]
        found_formats = set()
        for pattern in date_patterns:
            if re.search(pattern, text):
                found_formats.add(pattern)
        
        if len(found_formats) > 1:
            self._add_flag(
                'Inconsistent Date Formats',
                'Document uses multiple date formats, which is unusual for system-generated documents.',
                'warning',
                15
            )
        
        # Check for suspicious phrases
        suspicious_phrases = [
            'proof of income', 'verification purposes', 'this is to certify',
            'generated for', 'created for verification'
        ]
        for phrase in suspicious_phrases:
            if phrase in text_lower:
                self._add_flag(
                    'Unusual Language',
                    f'Document contains phrase "{phrase}" which is uncommon in legitimate payroll documents.',
                    'warning',
                    10
                )
                break
    
    def _check_box14_codes(self, text: str):
        """Validate Box 14 codes on W-2 forms."""
        # Look for Box 14 entries
        box14_pattern = r'box\s*14[^\n]*?([A-Z0-9]{2,10})\s+[\d,\.]+'
        matches = re.findall(box14_pattern, text, re.I)
        
        for code in matches:
            code_upper = code.upper()
            # Check if it's a known valid code
            is_valid = (
                code_upper in self.KNOWN_BOX14_CODES or
                any(known in code_upper for known in self.KNOWN_BOX14_CODES)
            )
            
            # Check if it looks like a random alphanumeric string (fraud indicator)
            if not is_valid and len(code) >= 4:
                # Random codes often have mixed letters and numbers with no pattern
                has_vowels = any(c in code_upper for c in 'AEIOU')
                has_consonants = any(c in code_upper for c in 'BCDFGHJKLMNPQRSTVWXYZ')
                has_numbers = any(c.isdigit() for c in code)
                
                if has_numbers and has_consonants and len(code) >= 5:
                    self._add_flag(
                        'Suspicious Box 14 Code',
                        f'Box 14 contains code "{code}" which is not a recognized payroll code and appears randomly generated.',
                        'warning',
                        15
                    )
    
    def _check_ein_validity(self, ein: str, employer_state: str = None, employer_name: str = None):
        """Validate EIN format and check for fraud indicators."""
        if not ein:
            return
        
        # Parse EIN prefix
        parts = ein.split('-')
        if len(parts) != 2:
            return
        
        prefix = parts[0]
        
        # Check for high-risk 87/88 prefix (IRS online applications)
        if prefix in ['87', '88']:
            self._add_flag(
                'High-Risk EIN Prefix',
                f'EIN {ein} uses the {prefix}- prefix, which is assigned via IRS online applications. This prefix is frequently associated with fraudulent EINs.',
                'warning',
                20
            )
        
        # Check geographic mismatch if we know the employer state
        if employer_state and prefix in self.EIN_STATE_PREFIXES:
            expected_states = self.EIN_STATE_PREFIXES[prefix]
            if 'ONLINE' not in expected_states:
                # Normalize state code
                state_upper = employer_state.upper().strip()
                state_abbrevs = {
                    'ALABAMA': 'AL', 'ALASKA': 'AK', 'ARIZONA': 'AZ', 'ARKANSAS': 'AR',
                    'CALIFORNIA': 'CA', 'COLORADO': 'CO', 'CONNECTICUT': 'CT', 'DELAWARE': 'DE',
                    'FLORIDA': 'FL', 'GEORGIA': 'GA', 'HAWAII': 'HI', 'IDAHO': 'ID',
                    'ILLINOIS': 'IL', 'INDIANA': 'IN', 'IOWA': 'IA', 'KANSAS': 'KS',
                    'KENTUCKY': 'KY', 'LOUISIANA': 'LA', 'MAINE': 'ME', 'MARYLAND': 'MD',
                    'MASSACHUSETTS': 'MA', 'MICHIGAN': 'MI', 'MINNESOTA': 'MN', 'MISSISSIPPI': 'MS',
                    'MISSOURI': 'MO', 'MONTANA': 'MT', 'NEBRASKA': 'NE', 'NEVADA': 'NV',
                    'NEW HAMPSHIRE': 'NH', 'NEW JERSEY': 'NJ', 'NEW MEXICO': 'NM', 'NEW YORK': 'NY',
                    'NORTH CAROLINA': 'NC', 'NORTH DAKOTA': 'ND', 'OHIO': 'OH', 'OKLAHOMA': 'OK',
                    'OREGON': 'OR', 'PENNSYLVANIA': 'PA', 'RHODE ISLAND': 'RI', 'SOUTH CAROLINA': 'SC',
                    'SOUTH DAKOTA': 'SD', 'TENNESSEE': 'TN', 'TEXAS': 'TX', 'UTAH': 'UT',
                    'VERMONT': 'VT', 'VIRGINIA': 'VA', 'WASHINGTON': 'WA', 'WEST VIRGINIA': 'WV',
                    'WISCONSIN': 'WI', 'WYOMING': 'WY', 'DISTRICT OF COLUMBIA': 'DC',
                }
                
                if state_upper in state_abbrevs:
                    state_upper = state_abbrevs[state_upper]
                elif len(state_upper) > 2:
                    state_upper = state_upper[:2]  # Try first two chars
                
                if state_upper not in expected_states:
                    self._add_flag(
                        'EIN Geographic Mismatch',
                        f'EIN prefix {prefix} is historically assigned to {expected_states}, but employer is in {employer_state}. While not impossible, this warrants verification.',
                        'warning',
                        15
                    )
        
        # Check for suspicious employer name formatting
        if employer_name:
            self._check_employer_name(employer_name)
    
    def _check_employer_name(self, employer_name: str):
        """Check employer/payer name for fraud indicators."""
        if not employer_name:
            return
        
        name_stripped = employer_name.strip()
        
        # Check for all lowercase (unprofessional, suggests hasty fabrication)
        if name_stripped and name_stripped == name_stripped.lower() and len(name_stripped) > 3:
            self._add_flag(
                'Improper Business Name Format',
                f'Payer/employer name "{name_stripped}" is entirely lowercase. Legitimate businesses use proper capitalization on tax documents.',
                'warning',
                10
            )
        
        # Check for potentially random/nonsense names
        # Look for strings with unusual consonant clusters or no vowels
        words = re.findall(r'[A-Za-z]{4,}', name_stripped)
        for word in words:
            word_lower = word.lower()
            vowels = sum(1 for c in word_lower if c in 'aeiou')
            consonants = len(word_lower) - vowels
            
            # Flag words with very few vowels relative to length (unusual for English)
            if len(word) >= 6 and vowels <= 1:
                self._add_flag(
                    'Unusual Employer Name',
                    f'Employer name contains "{word}" which does not appear to be a standard English word. Verify this business exists.',
                    'info',
                    10
                )
                break
    
    # -----------------------------------------------------------------------
    # W-2 FORGERY FORMATTING CHECKS (added 2026-07-03, Myssy Clayson sample)
    # -----------------------------------------------------------------------

    def _check_w2_formatting(self, text: str, data: Dict):
        """Run W-2-specific forgery formatting checks based on real fraud patterns.

        Added 2026-07-03 after Myssy Clayson forwarded a forged W-2 that scored
        only 10/100 because it passed all existing heuristics.  The forgery had:
          - Two W-2s printed on a single page
          - All monetary amounts written without cents (918 instead of 918.00)
          - Implausibly low wages ($360 and $918) with SS/Medicare withholding
          - Blank Box 15 employer state ID despite state wages/tax being present
        """
        self._check_w2_decimal_formatting(text, data)
        self._check_multiple_w2_on_page(text)
        self._check_low_wages_with_withholding(text, data)
        self._check_missing_box15_state_id(text, data)

    def _check_w2_decimal_formatting(self, text: str, data: Dict):
        """Flag W-2 monetary fields that lack IRS-required two-digit cents (.dd).

        IRS Publication 1141 requires that all dollar amounts on Copy A and
        equivalent employee copies include cents expressed as two digits after
        a decimal point (e.g. 918.00, not 918).  Forged W-2s created in word
        processors or image editors almost always omit the decimal entirely.

        Trigger: 3+ money fields present AND fewer than 50% contain a decimal.
        Severity: critical  |  Score impact: +40
        """
        # Collect all candidate monetary amounts from the OCR text.
        # We look for sequences of digits (with optional commas) that appear in
        # contexts typical of W-2 box values.  We accept amounts even without a
        # leading $ because OCR often drops the dollar sign on scanned forms.
        #
        # Strategy:
        #   1. Find every occurrence of a standalone number (2-6 digits,
        #      optionally with comma-grouping) that looks like a dollar amount.
        #   2. Separately count how many of those have an explicit ".dd" suffix.
        #   3. If 3+ found and <50% have decimals → flag.

        # Pattern A: values that definitely have decimals
        decimal_amounts = re.findall(
            r'(?<![\d.])\d{1,6}(?:,\d{3})*\.\d{2}(?![\d.])',
            text
        )

        # Pattern B: values that look like money but have NO decimal
        # (standalone integers that are plausibly a dollar amount 1-999999)
        no_decimal_amounts = re.findall(
            r'(?<![\d.,])(?<!\.)(\d{2,6})(?![\d.,])',
            text
        )
        # Filter to plausible wage/tax amounts (>= 1, exclude years/zip codes)
        no_decimal_filtered = [
            v for v in no_decimal_amounts
            if 1 <= int(v) <= 200000 and not re.match(r'^(19|20)\d{2}$', v)
            and not re.match(r'^\d{5}$', v)  # exclude zip codes
        ]

        total_fields = len(decimal_amounts) + len(no_decimal_filtered)
        if total_fields >= 3:
            decimal_pct = len(decimal_amounts) / total_fields
            if decimal_pct < 0.50:
                self._add_flag(
                    'Missing Decimal Formatting on Monetary Fields',
                    f'Only {len(decimal_amounts)} of {total_fields} detected monetary values '
                    f'include required cent formatting (e.g. 918.00).  '
                    f'IRS regulations require two-digit cents on all W-2 dollar amounts '
                    f'(Publication 1141).  Omitting decimals is a common pattern in '
                    f'forged W-2s created in word processors or image editors.',
                    'critical',
                    40
                )

    def _check_multiple_w2_on_page(self, text: str):
        """Flag documents that contain two or more W-2 forms on a single page.

        A single image or PDF page should contain exactly one W-2.  Multiple
        W-2s on one page indicate either a scan of an unofficial printout or a
        crudely assembled composite forgery.

        Detection: count distinct EINs or distinct "Employer identification
        number" headers.  Two or more triggers the flag.

        Severity: warning  |  Score impact: +25
        """
        # Count distinct EIN values (format: ##-#######)
        eins_found = re.findall(r'\b\d{2}-\d{7}\b', text)
        unique_eins = set(eins_found)

        # Count occurrences of the employer block header phrase
        employer_headers = re.findall(
            r'employer(?:\W{0,5})(?:identification|name)',
            text,
            re.IGNORECASE
        )

        # Also count W-2 header occurrences
        w2_headers = re.findall(
            r'(?:form\s*w-?2|wage\s*and\s*tax\s*statement)',
            text,
            re.IGNORECASE
        )

        multiple_eins    = len(unique_eins) >= 2
        multiple_headers = len(employer_headers) >= 2 or len(w2_headers) >= 2

        if multiple_eins or multiple_headers:
            details = []
            if multiple_eins:
                details.append(f'{len(unique_eins)} distinct EINs ({", ".join(sorted(unique_eins))})')
            if multiple_headers:
                details.append(
                    f'{len(employer_headers)} employer-name blocks and '
                    f'{len(w2_headers)} W-2 headers'
                )
            self._add_flag(
                'Multiple W-2 Forms on Single Page',
                f'This document appears to contain more than one W-2 form: '
                + '; '.join(details) + '.  '
                f'Legitimate W-2s are issued as individual pages.  '
                f'Multiple W-2s on one page indicate an unofficial print or a '
                f'composite forgery.',
                'warning',
                25
            )

    def _check_low_wages_with_withholding(self, text: str, data: Dict):
        """Flag implausibly low annual wages that still show tax withholding.

        Workers earning under $2,000 annually from a single employer are
        typically exempt from federal income tax withholding and often exempt
        from state withholding.  Fabricators sometimes forget to zero-out
        withholding when they reduce wages.

        Trigger: Box 1 wages < $2,000 AND any withholding > $0.
        Severity: warning  |  Score impact: +20
        """
        LOW_WAGE_THRESHOLD = 2000.0

        # Try extracted data first; fall back to regex scan of raw OCR text
        wages = data.get('wages')
        if wages is None:
            # Broader pattern: standalone amounts that appear near box 1 / wages labels
            wage_match = re.search(
                r'(?:box\s*1|wages[,\s]|tips)[^\n]{0,30}?(\d{1,7}(?:\.\d{2})?)',
                text, re.IGNORECASE
            )
            if wage_match:
                try:
                    wages = float(wage_match.group(1).replace(',', ''))
                except ValueError:
                    wages = None

        try:
            wages = float(wages) if wages is not None else None
        except (TypeError, ValueError):
            wages = None

        if wages is None or wages >= LOW_WAGE_THRESHOLD:
            return

        # Now check for any withholding
        withholding_fields = [
            data.get('federal_withheld'),
            data.get('social_security_tax'),
            data.get('medicare_tax'),
            data.get('state_tax'),
        ]
        has_withholding = any(v is not None and float(v) > 0 for v in withholding_fields)

        # Also scan raw text for withholding clues if structured data is missing
        if not has_withholding:
            wh_match = re.search(
                r'(?:federal.*withheld|ss.*tax|medicare.*tax|state.*tax|'
                r'social security tax withheld)[^\n]{0,20}?(\d+(?:\.\d{2})?)',
                text, re.IGNORECASE
            )
            if wh_match:
                try:
                    has_withholding = float(wh_match.group(1)) > 0
                except ValueError:
                    pass

        if has_withholding:
            self._add_flag(
                'Implausibly Low Wages With Tax Withholding',
                f'Box 1 wages of ${wages:,.2f} are below $2,000 yet the form shows '
                f'tax withholding.  Workers at this income level are generally exempt '
                f'from federal and state income tax withholding.  This pattern is '
                f'common in fabricated W-2s where the wage amount was reduced without '
                f'adjusting withholding lines.',
                'warning',
                20
            )

    def _check_missing_box15_state_id(self, text: str, data: Dict):
        """Flag W-2s with state wages/tax but no employer state ID (Box 15).

        Box 15 (Employer's state ID number) is required whenever Box 16 (state
        wages) or Box 17 (state income tax) are populated.  Forged forms often
        include state amounts while leaving the state ID blank because the
        fabricator doesn't have the employer's real state registration number.

        Severity: warning  |  Score impact: +15
        """
        # Check whether state wage/tax data is present
        state_wages = data.get('state_wages')
        state_tax   = data.get('state_tax')

        has_state_amounts = False
        try:
            if state_wages is not None and float(state_wages) > 0:
                has_state_amounts = True
        except (TypeError, ValueError):
            pass
        try:
            if not has_state_amounts and state_tax is not None and float(state_tax) > 0:
                has_state_amounts = True
        except (TypeError, ValueError):
            pass

        # Also look in raw OCR text for state wage/tax indicators
        if not has_state_amounts:
            if re.search(
                r'(?:box\s*1[67]|state\s*wages|state.*income\s*tax)[^\n]{0,20}?\d+',
                text, re.IGNORECASE
            ):
                has_state_amounts = True

        if not has_state_amounts:
            return

        # Now check whether a Box 15 state ID is populated.
        # Look for a non-blank value after box-15 / state employer ID labels.
        box15_match = re.search(
            r'(?:box\s*15|state(?:\s+employer)?[\s\']*s?\s*(?:id|identification)'
            r'(?:\s*number)?)[\s:]*([\w-]{3,})',
            text, re.IGNORECASE
        )
        if box15_match:
            # Found something — not blank, no need to flag
            return

        # Also accept a bare state-ID pattern: two letters then 8+ digits/dashes
        if re.search(r'\b[A-Z]{2}[-\s]?\d{6,}\b', text):
            return

        self._add_flag(
            'Missing Employer State ID (Box 15)',
            'State wages or state income tax are present on this W-2 but Box 15 '
            '(Employer\'s state ID number) appears to be blank.  All states that '
            'require income tax reporting also require the employer\'s state '
            'registration number.  A blank Box 15 alongside state amounts is a '
            'strong indicator that this W-2 was fabricated.',
            'warning',
            15
        )

    def _upgrade_metadata_flag_if_content_flagged(self):
        """After all checks: if a W-2 has content-level critical/warning flags,
        upgrade any 'Metadata Missing' flag from info to warning so it keeps its
        score contribution and isn't silently discounted.

        Added 2026-07-03 to prevent metadata-missing from being buried under
        benign explanations when content flags are clearly suspicious.
        """
        # Check whether any non-metadata flag is critical or warning
        content_severities = {
            f['severity']
            for f in self.flags
            if 'Metadata' not in f.get('title', '') and 'metadata' not in f.get('title', '').lower()
        }
        has_content_concerns = bool(
            content_severities & {'critical', 'warning'}
        )

        if not has_content_concerns:
            return

        for flag in self.flags:
            if (
                'metadata' in flag.get('title', '').lower()
                and flag.get('severity') == 'info'
            ):
                # Upgrade to warning and record a note in the description
                flag['severity'] = 'warning'
                flag['description'] += (
                    '  [Severity upgraded from info to warning because '
                    'content-level fraud indicators were also detected.]'
                )
                # The score was already added when _add_flag was called;
                # no re-add needed — just the label change matters for UI priority.

    # -----------------------------------------------------------------------

    def _extract_document_data(self, text: str, doc_type: str) -> Dict:
        """Extract structured data from document text."""
        data = {}
        
        # Common patterns
        ssn_match = re.search(r'(?:SSN|Social)[:\s]*(?:XXX-XX-|xxx-xx-|\*\*\*-\*\*-)(\d{4})', text, re.I)
        if ssn_match:
            data['ssn_last4'] = ssn_match.group(1)
        
        ein_match = re.search(r'(?:EIN|Employer ID|Employer.s.*ID)[:\s]*(\d{2}-\d{7})', text, re.I)
        if ein_match:
            data['ein'] = ein_match.group(1)
        
        # NEW: Extract employer/payer name (for validation)
        # Try various patterns to find employer name
        employer_patterns = [
            r'(?:employer|payer)[\s\']*s?\s*name[:\s]*([^\n]{3,50})',
            r'(?:from|payer)[:\s]*\n?\s*([A-Z][^\n]{2,50})',  # Capitalized name after "From" or "Payer"
            r'(?:company|business)\s*name[:\s]*([^\n]{3,50})',
        ]
        for pattern in employer_patterns:
            emp_match = re.search(pattern, text, re.I)
            if emp_match:
                data['employer_name'] = emp_match.group(1).strip()
                break
        
        # NEW: Extract state from employer address
        # Look for 2-letter state codes in address patterns
        state_pattern = r',\s*([A-Z]{2})\s+\d{5}'
        state_match = re.search(state_pattern, text)
        if state_match:
            data['employer_state'] = state_match.group(1)
        
        # Extract all money amounts
        amounts = re.findall(r'\$[\d,]+\.?\d*', text)
        if amounts:
            # Parse and sort amounts
            parsed = []
            for amt in amounts:
                try:
                    val = float(amt.replace('$', '').replace(',', ''))
                    parsed.append(val)
                except:
                    pass
            if parsed:
                data['amounts_found'] = len(parsed)
                data['largest_amount'] = max(parsed)
                data['smallest_amount'] = min(parsed)
        
        # Pay stub specific extraction
        if doc_type == "Pay Stub":
            patterns = {
                'gross_pay': [
                    r'(?:gross\s*pay|gross\s*earnings?|total\s*earnings?)[:\s]*\$?([\d,]+\.?\d*)',
                    r'(?:current\s*gross)[:\s]*\$?([\d,]+\.?\d*)',
                ],
                'net_pay': [
                    r'(?:net\s*pay|take\s*home|net\s*amount)[:\s]*\$?([\d,]+\.?\d*)',
                    r'(?:current\s*net)[:\s]*\$?([\d,]+\.?\d*)',
                ],
                'federal_tax': [
                    r'(?:federal\s*tax|fed\s*tax|federal\s*withholding)[:\s]*\$?([\d,]+\.?\d*)',
                    r'(?:fed\s*w/?h)[:\s]*\$?([\d,]+\.?\d*)',
                ],
                'state_tax': [
                    r'(?:state\s*tax|state\s*withholding)[:\s]*\$?([\d,]+\.?\d*)',
                ],
                'pay_period': [
                    r'(?:pay\s*period|period)[:\s]*(\d{1,2}/\d{1,2}/\d{2,4})\s*(?:to|-)\s*(\d{1,2}/\d{1,2}/\d{2,4})',
                ],
                'pay_date': [
                    r'(?:pay\s*date|check\s*date)[:\s]*(\d{1,2}/\d{1,2}/\d{2,4})',
                ],
                'hourly_rate': [
                    r'(?:hourly\s*rate|rate)[:\s]*\$?([\d,]+\.?\d*)',
                ],
                'hours_worked': [
                    r'(?:hours|regular\s*hours)[:\s]*([\d.]+)',
                ],
            }
            
            for field, field_patterns in patterns.items():
                for pattern in field_patterns:
                    match = re.search(pattern, text, re.I)
                    if match:
                        if field == 'pay_period':
                            data['pay_period_start'] = match.group(1)
                            data['pay_period_end'] = match.group(2)
                        else:
                            val = match.group(1).replace(',', '')
                            try:
                                data[field] = float(val) if '.' in val else int(val)
                            except:
                                data[field] = val
                        break
        
        # W-2 specific extraction
        elif doc_type == "W-2":
            w2_patterns = {
                'wages': r'(?:box\s*1|wages,?\s*tips)[:\s]*\$?([\d,]+\.?\d*)',
                'federal_withheld': r'(?:box\s*2|federal.*withheld)[:\s]*\$?([\d,]+\.?\d*)',
                'social_security_wages': r'(?:box\s*3|social\s*security\s*wages)[:\s]*\$?([\d,]+\.?\d*)',
                'social_security_tax': r'(?:box\s*4|social\s*security\s*tax)[:\s]*\$?([\d,]+\.?\d*)',
                'medicare_wages': r'(?:box\s*5|medicare\s*wages)[:\s]*\$?([\d,]+\.?\d*)',
                'medicare_tax': r'(?:box\s*6|medicare\s*tax)[:\s]*\$?([\d,]+\.?\d*)',
                'state_wages': r'(?:box\s*16|state\s*wages)[:\s]*\$?([\d,]+\.?\d*)',
                'state_tax': r'(?:box\s*17|state.*tax)[:\s]*\$?([\d,]+\.?\d*)',
            }
            
            for field, pattern in w2_patterns.items():
                match = re.search(pattern, text, re.I)
                if match:
                    val = match.group(1).replace(',', '')
                    try:
                        data[field] = float(val)
                    except:
                        data[field] = val
        
        return data
    
    def _validate_pay_stub_math(self, text: str, data: Dict) -> Dict:
        """Comprehensive pay stub math validation."""
        result = {'valid': True, 'checks': [], 'errors': []}
        
        gross = data.get('gross_pay')
        net = data.get('net_pay')
        federal_tax = data.get('federal_tax')
        state_tax = data.get('state_tax')
        hourly_rate = data.get('hourly_rate')
        hours = data.get('hours_worked')
        
        # Check 1: Net cannot exceed gross
        if gross and net:
            if net > gross:
                result['valid'] = False
                result['errors'].append({
                    'check': 'Net vs Gross',
                    'error': f'Net pay (${net:,.2f}) exceeds gross pay (${gross:,.2f})',
                    'severity': 'critical'
                })
                self._add_flag(
                    'Math Error: Net > Gross',
                    f'Net pay (${net:,.2f}) cannot exceed gross pay (${gross:,.2f}). This is impossible and indicates fraud.',
                    'critical',
                    45
                )
            else:
                deductions = gross - net
                deduction_pct = (deductions / gross) * 100
                result['checks'].append(f'Deduction rate: {deduction_pct:.1f}%')
                
                # Check reasonable deduction range
                if deduction_pct < 10 and gross > 1000:
                    self._add_flag(
                        'Suspiciously Low Deductions',
                        f'Only {deduction_pct:.1f}% deducted from gross pay. Federal + state taxes alone typically exceed 15%.',
                        'warning',
                        20
                    )
                elif deduction_pct > 60:
                    self._add_flag(
                        'Unusually High Deductions',
                        f'{deduction_pct:.1f}% deducted. This exceeds typical maximum combined tax rates.',
                        'warning',
                        15
                    )
        
        # Check 2: Hours × Rate = Gross (approximately)
        if hourly_rate and hours and gross:
            expected_gross = hourly_rate * hours
            if abs(expected_gross - gross) > gross * 0.1:  # More than 10% off
                result['errors'].append({
                    'check': 'Hours × Rate',
                    'error': f'Hours ({hours}) × Rate (${hourly_rate}) = ${expected_gross:,.2f}, but gross is ${gross:,.2f}',
                    'severity': 'warning'
                })
                self._add_flag(
                    'Hours/Rate Mismatch',
                    f'Calculated gross (${expected_gross:,.2f}) doesn\'t match stated gross (${gross:,.2f}).',
                    'warning',
                    15
                )
        
        # Check 3: Tax withholding reasonableness
        if gross and federal_tax:
            annual_gross = gross * 26  # Assume bi-weekly
            fed_rate = federal_tax / gross
            
            # Find expected bracket
            expected_min, expected_max = 0.05, 0.40
            for bracket_max, min_rate, max_rate in self.TAX_BRACKETS:
                if annual_gross <= bracket_max:
                    expected_min, expected_max = min_rate - 0.05, max_rate + 0.05
                    break
            
            if fed_rate < expected_min or fed_rate > expected_max:
                self._add_flag(
                    'Federal Tax Rate Anomaly',
                    f'Federal withholding rate ({fed_rate*100:.1f}%) is outside expected range ({expected_min*100:.0f}%-{expected_max*100:.0f}%) for this income level.',
                    'warning',
                    15
                )
        
        return result
    
    def _validate_w2_math(self, text: str, data: Dict) -> Dict:
        """Comprehensive W-2 validation."""
        result = {'valid': True, 'checks': [], 'errors': []}
        
        wages = data.get('wages')
        federal = data.get('federal_withheld')
        ss_wages = data.get('social_security_wages')
        ss_tax = data.get('social_security_tax')
        medicare_wages = data.get('medicare_wages')
        medicare_tax = data.get('medicare_tax')
        
        # Check 1: Federal withholding rate
        if wages and federal:
            fed_rate = federal / wages
            if fed_rate > 0.50:
                result['valid'] = False
                result['errors'].append({
                    'check': 'Federal Rate',
                    'error': f'Federal withholding ({fed_rate*100:.1f}%) exceeds maximum possible rate'
                })
                self._add_flag(
                    'Impossible Federal Tax Rate',
                    f'Federal withholding is {fed_rate*100:.1f}% of wages. Maximum federal rate is 37%.',
                    'critical',
                    40
                )
            else:
                result['checks'].append(f'Federal rate: {fed_rate*100:.1f}%')
        
        # Check 2: Social Security tax calculation (6.2% of wages up to cap)
        SS_RATE = 0.062
        SS_CAP_2024 = 168600
        
        if ss_wages and ss_tax:
            expected_ss = min(ss_wages, SS_CAP_2024) * SS_RATE
            if abs(ss_tax - expected_ss) > 100:  # Allow $100 tolerance
                result['errors'].append({
                    'check': 'SS Tax',
                    'error': f'SS tax should be ~${expected_ss:,.2f} but is ${ss_tax:,.2f}'
                })
                self._add_flag(
                    'Social Security Tax Mismatch',
                    f'SS tax (${ss_tax:,.2f}) doesn\'t match expected (${expected_ss:,.2f} = 6.2% of wages).',
                    'warning',
                    20
                )
            else:
                result['checks'].append(f'SS tax verified: ${ss_tax:,.2f}')
        
        # Check 3: Medicare tax calculation (1.45% of all wages)
        MEDICARE_RATE = 0.0145
        
        if medicare_wages and medicare_tax:
            expected_med = medicare_wages * MEDICARE_RATE
            if abs(medicare_tax - expected_med) > 50:
                result['errors'].append({
                    'check': 'Medicare Tax', 
                    'error': f'Medicare tax should be ~${expected_med:,.2f} but is ${medicare_tax:,.2f}'
                })
                self._add_flag(
                    'Medicare Tax Mismatch',
                    f'Medicare tax (${medicare_tax:,.2f}) doesn\'t match expected (${expected_med:,.2f} = 1.45% of wages).',
                    'warning',
                    20
                )
            else:
                result['checks'].append(f'Medicare tax verified: ${medicare_tax:,.2f}')
        
        # Check 4: Wages consistency
        if wages and ss_wages and medicare_wages:
            if wages != ss_wages or wages != medicare_wages:
                # This can be legitimate (wages above SS cap), but flag it
                if wages > SS_CAP_2024 and ss_wages == SS_CAP_2024:
                    result['checks'].append('Wages above SS cap - expected difference')
                elif abs(wages - ss_wages) > 1000 or abs(wages - medicare_wages) > 1000:
                    self._add_flag(
                        'Wage Amounts Inconsistent',
                        f'Box 1 (${wages:,.2f}), Box 3 (${ss_wages:,.2f}), Box 5 (${medicare_wages:,.2f}) show significant differences.',
                        'warning',
                        10
                    )
        
        return result
    
    def _validate_1099(self, text: str, data: Dict) -> Dict:
        """Validate 1099 forms for fraud indicators."""
        result = {'valid': True, 'checks': [], 'errors': []}
        
        text_lower = text.lower()
        
        # Extract 1099 specific data
        nec_match = re.search(r'(?:box\s*1|nonemployee\s*compensation)[:\s]*\$?([\d,]+\.?\d*)', text, re.I)
        if nec_match:
            try:
                compensation = float(nec_match.group(1).replace(',', ''))
                data['nonemployee_compensation'] = compensation
                result['checks'].append(f'Compensation: ${compensation:,.2f}')
            except:
                pass
        
        # Check for bulk filing platform indicators
        bulk_filing_indicators = ['tax1099.com', 'track1099', 'efile4biz', '1099-etc']
        for indicator in bulk_filing_indicators:
            if indicator in text_lower:
                self._add_flag(
                    'Bulk E-Filing Platform',
                    f'Document appears to have been filed through {indicator}. While legitimate, these platforms have minimal payer identity verification.',
                    'info',
                    5
                )
                break
        
        # Check for random alphanumeric account numbers (common in fraud)
        account_match = re.search(r'account\s*(?:number|#|no\.?)?[:\s]*([A-Z0-9]{8,14})', text, re.I)
        if account_match:
            account_num = account_match.group(1)
            # Check if it looks randomly generated (mix of letters and numbers, no pattern)
            has_letters = any(c.isalpha() for c in account_num)
            has_numbers = any(c.isdigit() for c in account_num)
            if has_letters and has_numbers and len(account_num) >= 10:
                self._add_flag(
                    'Random Account Number Pattern',
                    f'Account number "{account_num}" appears randomly generated. This pattern is common with bulk e-filing platforms used in fraud schemes.',
                    'info',
                    5
                )
        
        # Check for multiple payers from same address (requires session tracking)
        # This would need to be implemented at a higher level for batch analysis
        
        return result
    
    def _analyze_visual_forensics(self, image: Image.Image) -> Dict:
        """Perform visual forensic analysis on the document image."""
        results = {
            'checks_performed': [],
            'anomalies': []
        }
        
        if image is None:
            return results
        
        try:
            # Convert to RGB if needed
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            
            # Check 1: Aspect ratio
            width, height = image.size
            aspect = width / height
            results['aspect_ratio'] = round(aspect, 3)
            results['checks_performed'].append('Aspect ratio check')
            
            if aspect < 0.6 or aspect > 0.9:
                if not (0.7 < aspect < 0.8):  # Not close to letter/A4
                    self._add_flag(
                        'Unusual Document Dimensions',
                        f'Aspect ratio ({aspect:.2f}) differs from standard letter (0.77) or A4 (0.71) paper.',
                        'info',
                        5
                    )
            
            # Check 2: Resolution/DPI estimation
            results['resolution'] = f"{width}x{height}"
            if width < 800 or height < 1000:
                self._add_flag(
                    'Low Resolution',
                    f'Document resolution ({width}x{height}) is below typical scan quality. May indicate screenshot or low-quality source.',
                    'warning',
                    10
                )
            
            # Check 3: Color analysis - pay stubs are usually mostly white/light
            results['checks_performed'].append('Color distribution analysis')
            
            # Calculate mean brightness
            gray = image.convert('L')
            stat = ImageStat.Stat(gray)
            mean_brightness = stat.mean[0]
            results['mean_brightness'] = round(mean_brightness, 1)
            
            if mean_brightness < 180:  # Document should be mostly white
                self._add_flag(
                    'Unusual Color Profile',
                    f'Document is darker than typical (brightness: {mean_brightness:.0f}/255). Legitimate pay stubs are usually on white paper.',
                    'info',
                    5
                )
            
            # Check 4: Edge detection for potential copy-paste artifacts
            results['checks_performed'].append('Edge artifact analysis')
            edges = image.filter(ImageFilter.FIND_EDGES)
            edge_stat = ImageStat.Stat(edges.convert('L'))
            edge_intensity = edge_stat.mean[0]
            results['edge_intensity'] = round(edge_intensity, 2)
            
            # Very high edge intensity might indicate manipulation
            if edge_intensity > 30:
                results['anomalies'].append('High edge intensity detected')
            
            # Check 5: Noise analysis (requires scipy)
            try:
                results['checks_performed'].append('Noise pattern analysis')
                
                # Look for uniform noise (natural) vs irregular noise (edited)
                small = image.resize((100, 140))
                small_array = np.array(small.convert('L'), dtype=float)
                
                # Calculate local variance
                from scipy import ndimage
                local_var = ndimage.generic_filter(small_array, np.var, size=5)
                var_of_var = np.var(local_var)
                results['noise_uniformity'] = round(var_of_var, 2)
            except ImportError:
                # scipy not available, skip noise analysis
                pass
            
            # Check 6: Grayscale variance detection (NEW - catches "printed over template" fraud)
            # When documents are printed multiple times or text is overlaid on templates,
            # the text appears in different shades of black/gray
            results['checks_performed'].append('Grayscale variance analysis')
            
            gray_array = np.array(gray, dtype=float)
            
            # Find dark pixels (text regions) - threshold at 180 to catch text
            dark_mask = gray_array < 180
            if np.sum(dark_mask) > 100:  # Need minimum text pixels
                dark_pixels = gray_array[dark_mask]
                
                # Calculate statistics on text darkness
                text_mean = np.mean(dark_pixels)
                text_std = np.std(dark_pixels)
                text_min = np.min(dark_pixels)
                text_max = np.max(dark_pixels)
                darkness_range = text_max - text_min
                
                results['text_darkness'] = {
                    'mean': round(text_mean, 1),
                    'std': round(text_std, 1),
                    'range': round(darkness_range, 1),
                    'min': round(text_min, 1),
                    'max': round(text_max, 1)
                }
                
                # High standard deviation in text darkness indicates multiple print passes
                # Legitimate single-pass prints have consistent ink density
                # Calibrated against Myssy's samples: legit=50.1, fraud=51-59
                if text_std > 55:
                    self._add_flag(
                        'Inconsistent Text Darkness',
                        f'Text appears in multiple shades of black (std dev: {text_std:.1f}). '
                        f'This pattern often indicates printing over an existing template or multiple print passes.',
                        'warning',
                        20
                    )
                    results['anomalies'].append('Multiple ink densities detected')
                elif text_std > 50:
                    # Borderline - note but don't heavily penalize
                    self._add_flag(
                        'Slightly Elevated Text Variance',
                        f'Text darkness shows moderate variation (std dev: {text_std:.1f}). '
                        f'Worth reviewing but may be normal scanning artifacts.',
                        'info',
                        5
                    )
                
                # Also check for bimodal distribution (two distinct darkness levels)
                # This is a stronger indicator of template overlay
                # Only flag if std is already elevated AND we have true bimodal pattern
                if darkness_range > 100 and text_std > 52:
                    # Look for clustering - if there are two distinct groups of dark values
                    dark_text = dark_pixels[dark_pixels < 60]  # Very dark (original template text)
                    medium_text = dark_pixels[(dark_pixels >= 60) & (dark_pixels < 120)]  # Medium gray (added text)
                    
                    # Need substantial amounts of BOTH to indicate overlay
                    if len(dark_text) > 100 and len(medium_text) > 100:
                        dark_ratio = len(medium_text) / len(dark_text)
                        if 0.3 < dark_ratio < 4:  # Both groups are substantial
                            self._add_flag(
                                'Bimodal Text Darkness Pattern',
                                f'Document contains two distinct levels of text darkness '
                                f'(dark: {len(dark_text)} px, medium: {len(medium_text)} px). '
                                f'This is a strong indicator of text being overlaid on an existing form.',
                                'critical',
                                30
                            )
                            results['anomalies'].append('Bimodal darkness distribution (template overlay likely)')
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _run_ai_vision_analysis(self, file_path: str, doc_type: str, text: str, 
                                 current_results: Dict) -> Dict:
        """Run comprehensive AI vision analysis using Claude."""
        if not self.use_ai:
            return {'available': False, 'reason': 'AI analysis not configured'}
        
        try:
            # Prepare image for API
            ext = Path(file_path).suffix.lower()
            
            if ext == '.pdf':
                # Use the converted image
                if self._current_image:
                    img_buffer = io.BytesIO()
                    self._current_image.save(img_buffer, format='PNG')
                    img_data = base64.standard_b64encode(img_buffer.getvalue()).decode('utf-8')
                    media_type = 'image/png'
                else:
                    return {'available': False, 'reason': 'Could not convert PDF to image'}
            else:
                with open(file_path, 'rb') as f:
                    img_data = base64.standard_b64encode(f.read()).decode('utf-8')
                media_type = f'image/{ext[1:]}'
                if ext == '.jpg':
                    media_type = 'image/jpeg'
            
            # Build context from current findings
            context = f"""
Document Type: {doc_type}
Creator Software: {current_results.get('metadata', {}).get('creator', 'Unknown')}
Creation Date: {current_results.get('metadata', {}).get('creation_date', 'Unknown')}
Current Risk Score: {self.risk_score}
Flags Found So Far: {len(self.flags)}
"""
            
            # Comprehensive prompt for fraud detection
            prompt = f"""You are an expert forensic document analyst specializing in employment verification fraud detection. Analyze this {doc_type} image for signs of fraud or manipulation.

CONTEXT:
{context}

ANALYZE FOR:

1. **Font Consistency** (Only flag when combined with other indicators)
   IMPORTANT: These documents are commonly scanned, photocopied, or exported as PDFs,
   which NATURALLY produces font-weight variation, slight typeface differences, and
   inconsistent rendering quality. Font variation ALONE is NOT evidence of fraud.

   ACCEPTABLE variation (do NOT flag):
   - Differences in font weight between headers and body text
   - Slightly darker or lighter text due to scanning or photocopying
   - Mixed clarity between sections of the same document
   - PDFs generated from payroll systems vs. scanned copies
   - Slight differences in typeface or rendering quality from reproduction

   ONLY flag font-related issues when combined with at least one other indicator:
   - Mismatched employer names or EIN inconsistencies
   - Altered numbers (income, wages, taxes) that do not align across fields
   - Misaligned totals or inconsistent arithmetic
   - Signs of digital editing (cut/paste artifacts, layering, overwriting text)
   - Different font styles used within the SAME numeric field or line item in a
     suspicious way (not just general document variation between sections)

   Treat font differences as a formatting artifact of reproduction, NOT a fraud
   signal, unless supported by substantive inconsistencies in the data itself.

2. **Year/Date Tampering** (CRITICAL - Very common on fake W-2s)
   - Is the tax year clearly visible and in the same font as other text?
   - Look for years that appear printed ON TOP of other text (overprint)
   - Check for black boxes, white boxes, or rectangles covering original dates with new dates overlaid
   - Look for dates where the font color or darkness differs from surrounding text
   - Check if year digits appear misaligned or at different baselines
   - Look for any rectangular areas that seem to cover/redact original content
   - **W-2/1099 SPECIFIC**: The tax year on official IRS forms (W-2, 1099) is displayed LARGER and BOLDER than the rest of the text. If the year appears in the same size/weight as other text, this is suspicious - it may be a template or fabricated form.

3. **Invalid Field Values**
   - Check for "N/A", "Not Needed", "None", or similar text in boxes that should contain numbers or be blank
   - Legitimate W-2s and pay stubs use $0.00 or leave fields empty - never "N/A"

4. **Visual Consistency**
   - Is text alignment uniform throughout?
   - Do numbers align properly in columns?
   - Are there any visible cut/paste lines, edges, or artifacts?
   - Look for areas with different compression, blur, or sharpness levels

5. **Template Authenticity** 
   - Does this look like a genuine payroll system output (ADP, Paychex, etc.)?
   - Is the layout consistent with professional payroll software?
   - Are logos/headers crisp or potentially copied/pasted?

6. **Manipulation Indicators**
   - Any signs of image editing (blur around certain text, sharpening differences)?
   - Inconsistent shadows or lighting around text elements?
   - Text that appears to float or not sit naturally on the background?
   - Different quality/resolution in different areas of the document?
   - White or colored rectangles that might be covering original content?

7. **Box Numbering & Form Structure** (CRITICAL for W-2 / 1099)
   Official IRS forms have a STRICT layout. Deviations are strong fraud indicators.
   - **W-2 Box 12**: Must be split into 12a, 12b, 12c, 12d (four separate rows, each
     with its own letter suffix). Each row has a small "Code" field and an amount.
   - **W-2 Box 13**: A SINGLE box containing THREE CHECKBOXES (Statutory employee,
     Retirement plan, Third-party sick pay). It is NOT three separate rows.
     - 🚨 If you see three rows each labeled "13" (without a/b/c suffixes), this is
       a malformed/fabricated form. Genuine W-2s never label three separate rows
       all as "13".
     - 🚨 If a box is repeated (e.g., "13/13/13" or "14/14") without a/b/c/d
       letter suffixes, flag it as a structural anomaly.
   - **W-2 Box 14**: "Other" — typically one or two free-form lines.
   - **1099**: Box numbers follow the official IRS form layout for the specific
     1099 variant (NEC, MISC, etc.). Duplicate box numbers without suffixes are
     a red flag.
   - Compare against an authentic IRS form layout. Any duplicated box number
     without proper a/b/c/d suffix is structurally invalid.

8. **Overlapping Text / Field Collisions**
   - Look for words that physically overlap or collide with checkboxes, borders,
     or other form elements.
   - Look for text that runs into or through checkbox shapes (e.g., a line of text
     appearing to strike through or underline a checkbox).
   - Look for text from one field bleeding into an adjacent field.
   - Look for words within the same field that overlap each other (e.g., one word
     printed on top of another).
   - These collisions are almost never present on genuine system-generated W-2s
     and strongly suggest the document was assembled from a template or edited
     by hand.

9. **Form Lines Crossing Through Text** (CRITICAL)
   - Look for horizontal/vertical lines, dashed lines, or perforation marks that
     physically cut THROUGH numbers, letters, or words (not between rows).
   - Pay special attention to the state tax row (boxes 15, 16, 17): does a dashed
     or solid line cut through the State code (e.g. "MO"), Employer's state ID
     number, or any dollar amounts in those boxes?
   - On genuine W-2s, text sits cleanly inside fields. When a line crosses through
     the middle of characters, it almost always means the text was overlaid on top
     of the form image rather than rendered by a real payroll system.
   - Report exact box numbers where this occurs.

10. **Inconsistent or Missing Box Borders** (CRITICAL for W-2)
    - Compare the border thickness/darkness/completeness of each box against its
      neighbors.
    - In the state tax row, box 15 must have the same complete border as boxes 16
      and 17. If box 15 is missing its top border, has a noticeably lighter border,
      or has a partial/broken border while 16 and 17 are intact, this is a strong
      indicator that box 15 was edited or rebuilt over an original form.
    - Also check the Box 12 a/b/c/d rows and Box 13 area for missing dividers or
      borders that differ from the rest of the form.
    - Report which specific box(es) have border anomalies.

RESPOND IN THIS JSON FORMAT:
{{
    "overall_assessment": "LIKELY_LEGITIMATE" | "SUSPICIOUS" | "LIKELY_FRAUDULENT",
    "confidence": 0-100,
    "font_consistency": {{
        "consistent": true/false,
        "issues": ["only list font issues that are corroborated by other fraud indicators (data inconsistencies, digital editing signs, etc). Do NOT list scan/photocopy artifacts."],
        "corroborating_indicators": ["list the OTHER fraud indicators that support each font flag (e.g., 'altered numbers in same field', 'mismatched EIN'). If empty, do not flag font issues."]
    }},
    "date_year_tampering": {{
        "detected": true/false,
        "issues": ["describe any year/date tampering: overprints, covered text, font differences in dates"],
        "year_styling_correct": true/false,
        "year_styling_notes": "For W-2/1099: Is the tax year displayed larger/bolder than other text as on official IRS forms? Note if missing or incorrect."
    }},
    "invalid_field_values": {{
        "detected": true/false,
        "issues": ["list any N/A, Not Needed, or similar invalid text in numeric fields"]
    }},
    "visual_consistency": {{
        "score": 0-100,
        "issues": ["list of visual issues found"]
    }},
    "template_authenticity": {{
        "score": 0-100,
        "appears_to_be": "description of apparent source",
        "concerns": ["list of concerns"]
    }},
    "manipulation_indicators": {{
        "detected": true/false,
        "indicators": ["list of specific indicators: blur, cut lines, rectangles covering text, etc."]
    }},
    "box_numbering_structure": {{
        "valid": true/false,
        "issues": ["list any structural box-numbering problems, e.g. 'Three rows labeled 13 without a/b/c suffixes — Box 13 should be a single box with three checkboxes', 'Duplicate Box 14 without suffix', etc."]
    }},
    "overlapping_text": {{
        "detected": true/false,
        "issues": ["list specific overlap/collision issues, e.g. 'Word \"employee\" collides with checkbox in Box 13', 'Text bleeding from Box 12 into Box 13'"]
    }},
    "lines_crossing_text": {{
        "detected": true/false,
        "issues": ["list each instance of a form line cutting through text, with box numbers, e.g. 'Dashed perforation line crosses through Employer state ID 14244519 in Box 15', 'Horizontal line cuts through MO state code'"]
    }},
    "box_border_anomalies": {{
        "detected": true/false,
        "issues": ["list each box with missing, lighter, or broken borders compared to neighbors, e.g. 'Box 15 missing top border while Boxes 16 and 17 are intact'"]
    }},
    "key_findings": ["most important findings, max 5"],
    "recommendation": "brief recommendation for the reviewer"
}}"""

            response = self.ai_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1500,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": media_type,
                                    "data": img_data,
                                },
                            },
                            {
                                "type": "text",
                                "text": prompt
                            }
                        ],
                    }
                ],
            )
            
            # Parse the response
            response_text = response.content[0].text
            
            # Try to extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                try:
                    ai_result = json.loads(json_match.group())
                    
                    # Add flags based on AI findings
                    assessment = ai_result.get('overall_assessment', '')
                    confidence = ai_result.get('confidence', 50)
                    
                    if assessment == 'LIKELY_FRAUDULENT':
                        self._add_flag(
                            'AI Analysis: Likely Fraudulent',
                            f"AI detected significant fraud indicators with {confidence}% confidence. Key findings: {', '.join(ai_result.get('key_findings', [])[:3])}",
                            'critical',
                            35
                        )
                    elif assessment == 'SUSPICIOUS':
                        self._add_flag(
                            'AI Analysis: Suspicious Elements',
                            f"AI identified suspicious elements ({confidence}% confidence). Review recommended: {ai_result.get('recommendation', 'Manual review advised')}",
                            'warning',
                            20
                        )
                    else:
                        self._add_flag(
                            'AI Analysis: Appears Legitimate',
                            f"AI analysis found no significant fraud indicators ({confidence}% confidence).",
                            'info',
                            -10
                        )
                    
                    # Add font consistency flags - only when corroborated by other indicators
                    # (per Trish Gustin feedback June 2026: scanning/photocopying naturally
                    # produces font variation; flag only when other fraud signals support it)
                    font_check = ai_result.get('font_consistency', {})
                    if font_check.get('consistent') == False:
                        font_issues = font_check.get('issues', [])
                        corroborating = font_check.get('corroborating_indicators', [])
                        # Only flag if AI provided corroborating indicators
                        if corroborating and font_issues:
                            for issue in font_issues[:3]:
                                self._add_flag(
                                    'Font Mismatch with Corroborating Indicators',
                                    f"{issue} (supported by: {', '.join(corroborating[:2])})",
                                    'warning',
                                    10
                                )
                    
                    # Add date/year tampering flags
                    date_check = ai_result.get('date_year_tampering', {})
                    if date_check.get('detected'):
                        date_issues = date_check.get('issues', [])
                        for issue in date_issues[:2]:
                            self._add_flag(
                                'Date/Year Tampering Detected',
                                issue,
                                'critical',
                                35
                            )
                    
                    # Check W-2/1099 year styling (should be larger/bolder)
                    if doc_type in ['W-2', '1099'] and date_check.get('year_styling_correct') == False:
                        year_notes = date_check.get('year_styling_notes', 'Tax year does not appear in larger/bolder font as expected on official IRS forms.')
                        self._add_flag(
                            'Tax Year Styling Incorrect',
                            f'{year_notes} On official W-2 and 1099 forms, the tax year is displayed larger and bolder than other text. '
                            'This discrepancy may indicate a template or fabricated document.',
                            'warning',
                            20
                        )
                    
                    # Add invalid field value flags from AI
                    invalid_check = ai_result.get('invalid_field_values', {})
                    if invalid_check.get('detected'):
                        invalid_issues = invalid_check.get('issues', [])
                        for issue in invalid_issues[:2]:
                            self._add_flag(
                                'Invalid Field Value (AI)',
                                issue,
                                'critical',
                                30
                            )
                    
                    # Add manipulation indicator flags
                    if ai_result.get('manipulation_indicators', {}).get('detected'):
                        indicators = ai_result['manipulation_indicators'].get('indicators', [])
                        for indicator in indicators[:2]:
                            self._add_flag(
                                'AI Detected Manipulation',
                                indicator,
                                'critical',
                                15
                            )
                    
                    # Add box numbering / structural flags (NEW v2.3 - Myssy's request)
                    # Catches things like three "13" boxes without a/b/c suffixes,
                    # which a legitimate W-2 would never have.
                    box_check = ai_result.get('box_numbering_structure', {})
                    if box_check.get('valid') == False:
                        box_issues = box_check.get('issues', [])
                        for issue in box_issues[:3]:
                            self._add_flag(
                                'Invalid Box Numbering / Structure',
                                f'{issue} Official IRS forms have a strict box layout; deviations strongly suggest fabrication or template editing.',
                                'critical',
                                35
                            )
                    
                    # Add overlapping text / collision flags (NEW v2.3 - Myssy's request)
                    # Genuine system-generated W-2s do not have words colliding with
                    # checkboxes or other field elements.
                    overlap_check = ai_result.get('overlapping_text', {})
                    if overlap_check.get('detected'):
                        overlap_issues = overlap_check.get('issues', [])
                        for issue in overlap_issues[:3]:
                            self._add_flag(
                                'Overlapping Text Detected',
                                f'{issue} Text overlapping form fields or checkboxes is rare on system-generated documents and suggests manual editing or template assembly.',
                                'warning',
                                20
                            )
                    
                    # Lines crossing through text (NEW v2.4 - Myssy's St. Luke's W-2 feedback)
                    # Perforation/form lines should NEVER cut through characters on a
                    # real system-generated W-2.
                    lines_check = ai_result.get('lines_crossing_text', {})
                    if lines_check.get('detected'):
                        for issue in lines_check.get('issues', [])[:3]:
                            self._add_flag(
                                'Form Line Crosses Through Text',
                                f'{issue} Form lines or perforation marks cutting through characters strongly suggest the text was overlaid on top of the form image rather than rendered by a payroll system.',
                                'critical',
                                30
                            )
                    
                    # Inconsistent / missing box borders (NEW v2.4)
                    # Genuine W-2s have uniform borders across all boxes in a row.
                    border_check = ai_result.get('box_border_anomalies', {})
                    if border_check.get('detected'):
                        for issue in border_check.get('issues', [])[:3]:
                            self._add_flag(
                                'Inconsistent Box Borders',
                                f'{issue} Genuine W-2s have uniform border weight across boxes in the same row; missing or lighter borders suggest the box was rebuilt or edited.',
                                'warning',
                                20
                            )
                    
                    return {
                        'available': True,
                        'result': ai_result,
                        'raw_response': response_text
                    }
                    
                except json.JSONDecodeError:
                    pass
            
            # If JSON parsing failed, return raw response
            return {
                'available': True,
                'result': {'raw_analysis': response_text},
                'parsing_note': 'Could not parse structured response'
            }
            
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations = []
        
        risk_score = self.risk_score
        flags = self.flags
        
        critical_flags = [f for f in flags if f.get('severity') == 'critical']
        warning_flags = [f for f in flags if f.get('severity') == 'warning']
        
        if risk_score >= 65 or len(critical_flags) >= 2:
            recommendations.append("⛔ HIGH RISK: Request alternative documentation or direct employer verification")
            recommendations.append("📞 Contact the employer directly using independently verified contact information")
            recommendations.append("🔍 Request original documents if only copies were provided")
        elif risk_score >= 35 or len(critical_flags) >= 1:
            recommendations.append("⚠️ ELEVATED RISK: Additional verification recommended")
            recommendations.append("📋 Cross-reference with other provided documents")
            recommendations.append("📞 Consider direct employer verification for this candidate")
        else:
            recommendations.append("✅ Document appears legitimate based on automated analysis")
            recommendations.append("👁️ Perform standard visual review as part of normal process")
        
        # Specific recommendations based on flags
        for flag in critical_flags:
            if 'AI' in flag['title'] or 'Photoshop' in flag['title']:
                recommendations.append("🤖 AI/editing software detected - request original payroll system export")
            if 'Math' in flag['title']:
                recommendations.append("🧮 Mathematical errors found - likely fabricated document")
            if 'Created Today' in flag['title']:
                recommendations.append("📅 Document created very recently - verify pay period dates match")
        
        return recommendations[:5]  # Max 5 recommendations
    
    def _add_flag(self, title: str, description: str, severity: str, score_impact: int):
        """Add a fraud indicator flag."""
        self.flags.append({
            'title': title,
            'description': description,
            'severity': severity,
            'score_impact': score_impact
        })
        self.risk_score += score_impact
    
    def _calculate_risk_level(self, score: int) -> str:
        """Calculate overall risk level from score.
        
        Thresholds adjusted 2026-05-21 to reduce false positives:
        - HIGH: 65+ (was 50) - Strong fraud indicators
        - MEDIUM: 35-64 (was 25-49) - Needs review
        - LOW: 0-34 (was 0-24) - Appears legitimate
        """
        if score >= 65:
            return 'HIGH'
        elif score >= 35:
            return 'MEDIUM'
        else:
            return 'LOW'


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyzer = DocumentAnalyzer(use_ai=True)
        results = analyzer.analyze(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "Pay Stub")
        
        print(f"\n{'='*60}")
        print(f"DOCUMENT FRAUD ANALYSIS REPORT")
        print(f"{'='*60}")
        print(f"\nRisk Level: {results['risk_level']}")
        print(f"Risk Score: {results['risk_score']}/100")
        print(f"\nFlags ({len(results['flags'])}):")
        for flag in results['flags']:
            icon = '🔴' if flag['severity'] == 'critical' else '🟡' if flag['severity'] == 'warning' else '🔵'
            print(f"  {icon} {flag['title']}")
            print(f"     {flag['description']}")
        
        print(f"\nRecommendations:")
        for rec in results['recommendations']:
            print(f"  • {rec}")
        
        if results.get('ai_analysis', {}).get('available'):
            print(f"\nAI Analysis Available: Yes")
            ai = results['ai_analysis'].get('result', {})
            if 'overall_assessment' in ai:
                print(f"  Assessment: {ai['overall_assessment']}")
                print(f"  Confidence: {ai.get('confidence', 'N/A')}%")
    else:
        print("Usage: python document_analyzer.py <file_path> [doc_type]")

# VICTIG Document Fraud Detector

A web-based tool for detecting potential fraud in employment verification documents.

## Features

- **Metadata Analysis**: Checks PDF creation date, software used, modification history
- **Math Validation**: Verifies pay stub calculations (gross - deductions = net)
- **Creator Detection**: Flags documents made with Photoshop, Canva, AI tools
- **Visual Analysis**: Basic consistency checks on document structure
- **AI Analysis**: Optional Claude-powered deep analysis

## Supported Documents

- Pay Stubs
- W-2 Forms
- 1099 Forms
- Offer Letters
- Diplomas/Transcripts

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Install Tesseract OCR (for text extraction)
brew install tesseract  # macOS
# apt install tesseract-ocr  # Ubuntu/Debian

# Run the app
streamlit run app.py
```

The app will open at `http://localhost:8501`

## Deployment for Team (30 users)

### Option 1: Streamlit Cloud (Easiest)
1. Push to GitHub
2. Connect to [share.streamlit.io](https://share.streamlit.io)
3. Deploy with one click
4. Share URL with team

### Option 2: Internal Server
```bash
# Run on a server accessible to your network
streamlit run app.py --server.address 0.0.0.0 --server.port 8501
```

### Option 3: Docker
```dockerfile
FROM python:3.11-slim
RUN apt-get update && apt-get install -y tesseract-ocr
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.address", "0.0.0.0"]
```

## Configuration

### Enable AI Analysis (Optional)
Set your Anthropic API key:
```bash
export ANTHROPIC_API_KEY=your_key_here
```

### Authentication (Recommended for Production)
Add to `app.py`:
```python
import streamlit_authenticator as stauth
# Configure user credentials
```

Or use Streamlit Cloud's built-in auth.

## Fraud Detection Logic

### High Risk Indicators (🔴)
- Document created with Photoshop, Canva, or AI tools
- Creation date within last 48 hours for older pay periods
- Math errors (net pay > gross pay)
- AI-generated content detected
- SSN over-truncated (more than 5 digits hidden - see Knowledge Base)

### Medium Risk Indicators (🟡)
- Recently created document (within 7 days)
- Unusual deduction percentages
- Metadata stripped from document
- Non-standard document dimensions

### Low Risk / Positive Indicators (🟢)
- Created by known payroll systems (ADP, Paychex, Gusto, etc.)
- Math validates correctly
- Consistent formatting
- Appropriate redactions (SSN last 4 visible, per IRS rules)

## Knowledge Base

### SSN Truncation Rules (IRS)
The IRS allows employers to truncate Social Security Numbers on employee documents, but **only the first 5 digits** may be hidden. The last 4 digits must remain visible.

**Acceptable formats (no penalty):**
- `XXX-XX-1234` ✓ (IRS standard - last 4 visible)
- `***-**-1234` ✓
- `XXX-XX-XXXX` ✓ (fully redacted - acceptable for privacy)
- `***-**-****` ✓

**Suspicious formats (penalty):**
- `XXX-XX-XXX4` ⚠️ (only 1 digit visible) +20 points
- `XXX-XX-XX34` ⚠️ (only 2 digits visible) +20 points  
- `XXX-XX-X234` ⚠️ (only 3 digits visible) +20 points

**Why is 1-3 visible suspicious?**
Legitimate documents either:
1. Show the last 4 digits (IRS standard), OR
2. Fully redact the SSN (candidate privacy)

Showing only 1-3 digits is unusual and could indicate:
- Document manipulation (someone changed digits)
- Attempt to make a fake SSN look partially real
- Cut-and-paste from multiple sources

**Reference:** IRS Pub 1586 - Truncated Taxpayer Identification Numbers

### W-2 and 1099 Year Styling
On official IRS W-2 and 1099 forms, the **tax year is displayed larger and bolder** than the surrounding text. This is a deliberate design feature.

**What to look for:**
- The year (e.g., "2025") should be prominently styled
- It should be noticeably larger than field labels and values
- It should be bolder/heavier weight than other text

**Suspicious indicators:**
- Year appears in same size/weight as other text
- Year looks like it was typed in rather than printed as part of form
- Year font doesn't match the rest of the form

If the year is NOT larger/bolder, this suggests:
1. A template document (someone recreated the form)
2. A modified/fabricated document
3. An unofficial reproduction

### Legitimate Redactions
Candidates may be asked to redact certain information for privacy/compliance:
- Bank account numbers (partial redaction OK)
- Home addresses
- Dependent SSNs

These redactions are expected and should not trigger fraud flags when done with standard tools (Preview, Acrobat, phone markup apps).

## Roadmap

- [ ] Database to track reviewed documents
- [ ] Employer template library
- [ ] EIN/Company verification via API
- [ ] Error Level Analysis (ELA) for image forensics
- [ ] Batch upload processing
- [ ] Audit trail / reporting
- [ ] Integration with VICTIG systems

## Tech Stack

- **Frontend**: Streamlit
- **PDF Processing**: PyMuPDF
- **OCR**: Tesseract
- **AI**: Anthropic Claude (optional)

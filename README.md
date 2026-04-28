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

### Medium Risk Indicators (🟡)
- Recently created document (within 7 days)
- Unusual deduction percentages
- Metadata stripped from document
- Non-standard document dimensions

### Low Risk / Positive Indicators (🟢)
- Created by known payroll systems (ADP, Paychex, Gusto, etc.)
- Math validates correctly
- Consistent formatting

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

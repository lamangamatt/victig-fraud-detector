# VICTIG Fraud Detector Improvements
## Based on Myssy Clayson's High-Risk Document Samples (April 2026)

### Summary
Myssy provided 9 sample documents showing common fraud patterns in W-2s and 1099s:
- 4 W-2 documents with various red flags
- 3 1099-NEC documents showing shell company network fraud
- 2 images (TDK Technologies W2, IMG_6960.jpeg) - need visual analysis

---

## NEW DETECTION RULES TO ADD

### 1. Future-Dated Tax Documents (CRITICAL - +50 points)
**Pattern:** Tax year on W-2/1099 is in the future
**Example:** "2026" W-2 dated during 2026 but claiming to be year-end reporting
**Implementation:**
```python
# In _check_text_anomalies or new method
current_year = datetime.now().year
tax_year_match = re.search(r'(?:tax\s*year|form\s*w-?2|20)\s*(\d{4})', text, re.I)
if tax_year_match:
    doc_year = int(tax_year_match.group(1))
    if doc_year > current_year:
        self._add_flag(
            'Future-Dated Document',
            f'Document claims tax year {doc_year} but current year is {current_year}. This is impossible.',
            'critical',
            50
        )
```

### 2. EIN Geographic Mismatch (WARNING - +15 points)
**Pattern:** EIN prefix doesn't match employer state
**Example:** Texas company with 36- prefix (Illinois/Indiana)
**Implementation:**
```python
EIN_STATE_PREFIXES = {
    '01': ['AL'], '02': ['AL'], '03': ['FL'], '04': ['FL'],
    # ... full mapping
    '36': ['IL', 'IN'],
    '75': ['TX'],
    '87': ['ANY'],  # Online applications - flag separately
}

def _check_ein_state_match(self, ein: str, employer_state: str):
    if not ein:
        return
    prefix = ein.split('-')[0]
    expected_states = EIN_STATE_PREFIXES.get(prefix, [])
    if employer_state not in expected_states and 'ANY' not in expected_states:
        self._add_flag(
            'EIN Geographic Mismatch',
            f'EIN prefix {prefix} is typically assigned to {expected_states}, but employer is in {employer_state}.',
            'warning',
            15
        )
```

### 3. 87-Prefix EIN (WARNING - +20 points)
**Pattern:** EIN starts with 87-
**Example:** 87-2974244, 87-2992934
**Reason:** 87- prefix EINs are assigned via IRS online applications and are frequently used in fraud schemes
**Implementation:**
```python
if ein and ein.startswith('87-'):
    self._add_flag(
        'High-Risk EIN Prefix',
        f'EIN {ein} uses the 87- prefix, which is associated with online EIN applications and has elevated fraud risk.',
        'warning',
        20
    )
```

### 4. Invalid Field Values - Text in Numeric Fields (CRITICAL - +35 points)
**Pattern:** "N/A", "NOT NEEDED", "None", "See attached" in fields that should be numeric or blank
**Example:** "NOT NEEDED" in State Employer ID field, "OB3QOT" in Box 14
**Already partially implemented but needs expansion:**
```python
INVALID_FIELD_INDICATORS = [
    'n/a', 'not needed', 'not applicable', 'none', 'na', 'n.a.',
    'see attached', 'refer to', 'tbd', 'pending', 'not required',
    'exempt', 'waived'  # These might be legitimate but flag for review
]
```

### 5. Suspicious Box 14 Codes (WARNING - +15 points)
**Pattern:** Unrecognized codes in Box 14 that look random
**Example:** "OB3QOT 174.15"
**Implementation:**
```python
KNOWN_BOX14_CODES = [
    'C', 'D', 'DD', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'Y', 'Z', 'AA', 'BB', 'EE', 'FF', 'GG', 'HH',
    # Common Box 14 labels
    'UNION', 'RETIRE', '401K', 'MEDICAL', 'DENTAL', 'VISION', 'HSA', 'FSA', 'LIFE', 'LTD', 'STD',
]

def _check_box14_codes(self, text: str):
    box14_match = re.search(r'box\s*14[:\s]*([A-Z0-9]{3,})', text, re.I)
    if box14_match:
        code = box14_match.group(1).upper()
        if code not in KNOWN_BOX14_CODES and not any(k in code for k in KNOWN_BOX14_CODES):
            self._add_flag(
                'Unrecognized Box 14 Code',
                f'Box 14 contains "{code}" which is not a standard payroll code. May indicate fabrication.',
                'warning',
                15
            )
```

### 6. Shell Company Detection - Multiple Payers at Same Address (CRITICAL - +40 points)
**Pattern:** Multiple 1099s from different "companies" all at the same address/phone
**Example:** Dillman Holdings, A2U Properties, yinzer rentals - all at 134 Suhan Dr
**Implementation:**
```python
# Requires tracking across multiple documents in a session
def _check_payer_address_patterns(self, payer_address: str, payer_phone: str):
    if not hasattr(self, '_payer_addresses'):
        self._payer_addresses = {}
    
    address_key = self._normalize_address(payer_address)
    if address_key in self._payer_addresses:
        previous_payer = self._payer_addresses[address_key]
        self._add_flag(
            'Shell Company Pattern Detected',
            f'Multiple payers using same address: Current payer and "{previous_payer}" both at {payer_address}. This is a strong fraud indicator.',
            'critical',
            40
        )
    else:
        self._payer_addresses[address_key] = payer_name
```

### 7. Improper Business Name Formatting (INFO - +10 points)
**Pattern:** Lowercase or improperly formatted business name
**Example:** "yinzer rentals" instead of "Yinzer Rentals"
**Implementation:**
```python
def _check_business_name_formatting(self, payer_name: str):
    if payer_name and payer_name == payer_name.lower():
        self._add_flag(
            'Improper Business Name Format',
            f'Payer name "{payer_name}" is not properly capitalized. Legitimate businesses use proper capitalization on tax forms.',
            'info',
            10
        )
```

### 8. Recipient Address Inconsistencies (WARNING - +20 points)
**Pattern:** Same recipient (same SSN) with different addresses on related documents
**Example:** "2509 Detroit Street" vs "20509 Detroit Street"
**Implementation:**
```python
# Requires tracking across documents
def _check_address_consistency(self, recipient_ssn_last4: str, recipient_address: str):
    if not hasattr(self, '_recipient_addresses'):
        self._recipient_addresses = {}
    
    if recipient_ssn_last4 in self._recipient_addresses:
        previous_address = self._recipient_addresses[recipient_ssn_last4]
        if self._addresses_differ_suspiciously(previous_address, recipient_address):
            self._add_flag(
                'Recipient Address Inconsistency',
                f'Same SSN with different addresses: "{previous_address}" vs "{recipient_address}".',
                'warning',
                20
            )
```

### 9. Bulk Filing Platform Indicators (INFO - +5 points)
**Pattern:** Random alphanumeric account numbers typical of bulk filing platforms
**Example:** "Y38EHXW2EOYR", "IIABK18MRI1Y"
**Implementation:**
```python
def _check_account_number_pattern(self, account_number: str):
    # Random alphanumeric pattern typical of tax1099.com, etc.
    if account_number and re.match(r'^[A-Z0-9]{10,12}$', account_number):
        self._add_flag(
            'Bulk Filing Platform Detected',
            f'Account number format suggests use of a bulk e-filing platform. These platforms have minimal identity verification.',
            'info',
            5
        )
```

### 10. Unusual/Random Employer Names (WARNING - +15 points)
**Pattern:** Business names that appear random or nonsensical
**Example:** "JELUFUNA"
**Implementation:**
```python
import enchant  # Or similar dictionary

def _check_employer_name_validity(self, employer_name: str):
    # Check if name contains recognizable words
    words = re.findall(r'[A-Za-z]{3,}', employer_name)
    dictionary = enchant.Dict("en_US")
    
    unrecognized = [w for w in words if not dictionary.check(w.lower()) and not dictionary.check(w.capitalize())]
    
    if len(unrecognized) == len(words) and len(words) > 0:
        self._add_flag(
            'Unusual Employer Name',
            f'Employer name "{employer_name}" does not contain recognizable English words. Verify this business exists.',
            'warning',
            15
        )
```

---

## ENHANCED AI PROMPT ADDITIONS

Add these to the AI vision analysis prompt:

```
7. **1099-Specific Fraud Indicators**
   - Check if payer information matches standard business formatting
   - Look for signs the form came from a bulk filing platform (tax1099.com watermarks, generic formatting)
   - Check if account numbers look system-generated vs meaningful
   - Look for multiple payers with similar formatting suggesting batch creation

8. **W-2 Year Validation**
   - Verify the tax year shown is not in the future
   - Check if the year font matches the rest of the document
   - Look for signs the year was changed/edited
```

---

## PRIORITY ORDER FOR IMPLEMENTATION

1. **CRITICAL (Implement First)**
   - Future-dated documents check
   - Invalid field values expansion ("NOT NEEDED", etc.)
   - 87-prefix EIN flagging

2. **HIGH (Implement Next)**
   - Shell company address pattern detection
   - Recipient address inconsistency tracking
   - EIN geographic mismatch

3. **MEDIUM (Nice to Have)**
   - Unusual employer name detection
   - Improper business name formatting
   - Box 14 code validation

4. **LOW (Enhancement)**
   - Bulk filing platform indicators
   - Account number pattern analysis

---

## TESTING

Use Myssy's samples to validate:
1. `Carilion W2 2022.pdf` - Old W-2, should flag year discrepancy
2. `MINTED W2.pdf` - Should flag "NOT NEEDED" in fields
3. `W2 2026.pdf` - Should flag future year
4. `Taxes 2025.pdf` - Need to analyze
5. `Rachel Leduc 1.pdf`, `RachelLeduc 2.pdf`, `RachelLeduc 3.pdf` - Shell company detection
6. `TDK Technologies W2.jpg`, `IMG_6960.jpeg` - Visual analysis

---

## NOTES

- Myssy's samples show sophisticated fraud patterns that go beyond simple image editing
- The 1099 shell company pattern is particularly concerning - organized fraud
- Consider adding a "batch analysis" mode to detect cross-document patterns
- Tax1099.com and similar platforms are legitimate but exploitable - note their presence without over-flagging

*Document prepared by Molesley based on Myssy Clayson's input, April 30, 2026*

---

## 2026-07-03 Changes — Myssy Clayson Forgery Sample

### Background
Myssy forwarded a real-world forged W-2 JPEG (two W-2s on one page, "Aretha L Hall", 2020)
that the detector wrongly scored **10/100 LOW RISK**.  The form had:
- Two W-2s (two employers: OUTREACH FAMILY SERVICES and LOYALTY HEALTHCARE BEHAVIORAL COUNS) on a single page
- All monetary amounts written without cents (918, 360, 57, etc. instead of 918.00, 360.00)
- Low wages ($360 and $918) with SS/Medicare withholding present
- Blank Box 15 employer state ID despite state wages/tax amounts

### New Detection Rules Added (document_analyzer.py)

#### 1. Missing Decimal Formatting on Monetary Fields (CRITICAL, +40)
Checks that at least 50% of detected monetary amounts have `.dd` cent formatting.
IRS Publication 1141 requires two-digit cents on all W-2 dollar amounts.
Forged W-2s created in word processors/image editors almost always omit this.

#### 2. Multiple W-2 Forms on Single Page (WARNING, +25)
Counts distinct EINs and employer-name block headers.
Two or more on one page triggers the flag.

#### 3. Implausibly Low Wages With Tax Withholding (WARNING, +20)
Box 1 wages < $2,000 AND any withholding > $0.
Workers at this income level are generally exempt from federal/state withholding.

#### 4. Missing Employer State ID / Box 15 (WARNING, +15)
State wages or state tax present but Box 15 (employer state ID) is blank.
Fabricators often include state amounts without knowing the employer's state registration number.

#### 5. Metadata Flag Upgrade for W-2 with Content Flags
After all checks: if a W-2 has critical/warning content flags,
any "Metadata Missing" flag is upgraded from info → warning so it doesn't
get buried under benign explanations.

### Results
Before: **10/100 LOW**
After:  **100/100 HIGH**

New flags that fired on Myssy's sample:
- `critical` Missing Decimal Formatting on Monetary Fields (+40)
- `warning`  Multiple W-2 Forms on Single Page (+25)

(Plus pre-existing flags: Missing Tax Year +40, Metadata Missing +10)

### Also Fixed
Pre-existing Python 3.9 f-string syntax error on line 726 (nested quotes in f-string).

*Changes implemented by Molesley, 2026-07-03*

---

## 2026-07-07 Changes — IRS Wage & Income Transcript Batch Detection

### Background
Myssy forwarded two W-2 PDFs (`KCC_W2_Redacted.pdf`, `Excalibur_W2_Redacted.pdf`)
that each present themselves as page 1 of an IRS Wage & Income Transcript.
Both share tracking number **110822371779**, request date 07-07-2026,
response date 07-07-2026, TIN XXX-XX-5229, and tax period 12-31-2024. But
they were created 5 hours apart and have different page dimensions — a
genuine IRS transcript packet is a single continuous PDF, so this is
impossible. The existing single-document detector rated both LOW/25 and
missed the actual fraud entirely.

### New Module: `irs_transcript.py`

Rather than pile more onto `document_analyzer.py`, this fraud pattern got
its own standalone module because:

1. It requires **cross-document comparison** (a paradigm the existing
   detector doesn't support).
2. It has a **document-type-specific rule set** (IRS transcript structure).
3. It benefits from being independently unit-testable.

### New Doc Type: "IRS Transcript"

Added to the Streamlit UI's document-type dropdown. When selected, the
uploader switches to multi-file mode and routes to the batch analyzer.

### New Detection Rules

Single-document rules (`analyze_single_transcript`):
- **Missing IRS Transcript Title** (warning, +15)
- **Missing IRS Sensitive-Data Banner** (warning, +15)
- **Missing Transcript Tracking Number** (warning, +15)
- **Future Request/Response Date** (critical, +40 each)
- **Wage Amounts Blacked Out** (warning, +25) — solid black bar over
  values column, detected via pixel-run analysis
- **Truncated / Garbled Employer Name** (warning, +20) — e.g. "KURT CARS
  CONS LL" (dropped LLC), "EXCA SECU IN" (dropped INC)

Batch rules (`analyze_batch`):
- **Duplicate IRS Transcript Tracking Number** (critical, +60) — two
  documents each claim page-1 status but share tracking number
- **Same Tracking Number, Different Creation Times** (critical, +50) —
  PDF creation timestamps differ despite shared tracking number
- **Same Tracking Number, Different Page Dimensions** (warning, +25)

### Results

Before: both files rated LOW / 25/100, tool cleared the applicant.
After:  overall batch verdict **HIGH / 100/100**, each individual doc
        HIGH / 100/100, with all three batch flags firing on the
        smoking-gun duplicate tracking number.

Regression test: `test_myssy_2026_07_07.py`

*Changes implemented by Molesley, 2026-07-07*

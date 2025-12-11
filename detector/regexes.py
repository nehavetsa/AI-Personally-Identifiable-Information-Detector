# detector/regexes.py
import re
from collections import Counter
import math

# Basic regex patterns
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
PHONE_RE = re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?(?:\d{10}|\d{3}[-.\s]\d{3}[-.\s]\d{4})\b')
SSN_RE = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
AADHAAR_RE = re.compile(r'\b\d{12}\b')
# Credit-card loose: 13-19 digits allowing separators
CC_RE = re.compile(r'\b(?:\d[ -]*?){13,19}\b')

# API key heuristics (examples)
API_KEY_RE = re.compile(r'\b(?:AKIA|AIza|sk_live|sk_test|xox[bp]-[A-Za-z0-9-]+|eyJ[A-Za-z0-9_\-\.=]+)\b')
PASSWORD_HINT_RE = re.compile(r'(?i)(password|passwd|pwd|secret|token|api_key|apikey)[\s:=]+([^\s,;\'"]{4,})')

# token pattern for entropy check
TOKEN_CANDIDATE_RE = re.compile(r'\b[A-Za-z0-9\-_]{16,}\b')

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    probs = [c / len(s) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def luhn_check(number_str: str) -> bool:
    # remove non-digit chars
    digits = [int(ch) for ch in re.sub(r'\D', '', number_str)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

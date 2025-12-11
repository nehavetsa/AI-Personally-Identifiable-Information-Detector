# detector/core.py
from .ner import detect_entities
from .redactor import apply_redactions

from .regexes import (EMAIL_RE, PHONE_RE, SSN_RE, AADHAAR_RE,
                      CC_RE, API_KEY_RE, PASSWORD_HINT_RE, TOKEN_CANDIDATE_RE,
                      shannon_entropy, luhn_check)

def detect_text(text: str, entropy_threshold: float = 3.5):
    findings = []
    text = text or ""

    # 1) Regex exact matches (high precision)
    for m in EMAIL_RE.finditer(text):
        findings.append({"type":"EMAIL", "match": m.group(0), "method":"regex"})

    for m in PHONE_RE.finditer(text):
        findings.append({"type":"PHONE", "match": m.group(0), "method":"regex"})

    for m in SSN_RE.finditer(text):
        findings.append({"type":"SSN", "match": m.group(0), "method":"regex"})

    for m in AADHAAR_RE.finditer(text):
        findings.append({"type":"AADHAAR", "match": m.group(0), "method":"regex"})

    # credit card candidate detection + Luhn
    for m in CC_RE.finditer(text):
        tok = m.group(0)
        if luhn_check(tok):
            findings.append({"type":"CREDIT_CARD", "match": tok, "method":"luhn+regex"})
        else:
            # still record as suspicious if length big and digits exist
            digits_only = ''.join(ch for ch in tok if ch.isdigit())
            if 13 <= len(digits_only) <= 19:
                findings.append({"type":"CREDIT_CARD_POSSIBLE", "match": tok, "method":"regex"})

    # contextual PII (NER)
    ner_findings = detect_entities(text)
    if ner_findings:
        findings.extend(ner_findings)

    
    # API keys heuristics
    for m in API_KEY_RE.finditer(text):
        findings.append({"type":"API_KEY", "match": m.group(0), "method":"regex"})

    # password hints
    for m in PASSWORD_HINT_RE.finditer(text):
        findings.append({"type":"PASSWORD_LIKE", "match": m.group(2), "method":"keyword+value"})

    # high-entropy tokens (random-looking)
    for m in TOKEN_CANDIDATE_RE.finditer(text):
        tok = m.group(0)
        ent = shannon_entropy(tok)
        if ent >= entropy_threshold:
            findings.append({"type":"HIGH_ENTROPY_TOKEN", "match": tok, "method":"entropy", "entropy": ent})

    # aggregate decision heuristics
    decision = "ALLOW"
    # block if Aadhaar, CC, API key exact detected
        # -------- aggregate decision heuristics --------
    types = {f["type"] for f in findings}

    # 1) BLOCK: high-risk deterministic PII
    if {"AADHAAR", "CREDIT_CARD", "API_KEY"} & types:
        decision = "BLOCK"

    # 2) REDACT: contextual/entity-based PII
    elif any(t in ("PERSON", "ORG", "GPE", "LOC") for t in types):
        decision = "REDACT"

    # 3) FLAG: medium-risk PII (email, phone, entropy tokens, etc.)
    elif findings:
        decision = "FLAG"

    # 4) ALLOW: nothing detected
    else:
        decision = "ALLOW"

    redacted_text = apply_redactions(text, findings)

    return {
        "decision": decision,
        "findings": findings,
        "redacted_text": redacted_text
    }

if __name__ == "__main__":
    test_text = """
    My name is Neha Vetsa. 
    My email is neha@example.com and my phone number is +91 9876543210.
    My Aadhaar number is 1234 5678 9123.
    My credit card is 4242 4242 4242 4242.
    My API key looks like sk_live_ABCDEF1234567890.
    Password: mypass123!
    """
    result = detect_text(test_text)
    redacted = apply_redactions(test_text, result["findings"])

    print("\n===== TEST STRING RESULTS =====")
    print("Decision:", result["decision"])
    print("Findings:", result["findings"])
    print("\nRedacted Text:\n", redacted)

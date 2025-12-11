import re

# ----------------------------------------------------
# Helper Masking Functions
# ----------------------------------------------------

def mask_email(email: str):
    """Mask email but preserve structure."""
    if "@" not in email:
        return "*" * len(email)

    user, domain = email.split("@", 1)

    # Mask username except first 2 chars
    masked_user = user[:2] + "*" * max(1, (len(user) - 2))

    # Mask domain: preserve first letter + TLD
    if "." in domain:
        domain_name, tld = domain.split(".", 1)
        masked_domain = domain_name[0] + "***." + tld
    else:
        masked_domain = "***"

    return masked_user + "@" + masked_domain


def mask_phone(phone: str):
    """Mask phone number except last 4 digits."""
    digits = ''.join(c for c in phone if c.isdigit())
    if len(digits) <= 4:
        return "X" * len(digits)

    masked = "X" * (len(digits) - 4) + digits[-4:]
    return masked


def mask_last4(value: str):
    """Preserve last 4 digits for cards / Aadhaar."""
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) <= 4:
        return "X" * len(digits)

    masked = "X" * (len(digits) - 4) + digits[-4:]
    return masked


def mask_full(value: str):
    return "*" * len(value)


def mask_format_preserve(value: str):
    """Mask everything but keep alpha-numeric structure length."""
    return re.sub(r"[A-Za-z0-9]", "X", value)


# ----------------------------------------------------
# MAIN REDACTION PIPELINE
# ----------------------------------------------------

def apply_redactions(text: str, findings: list):
    """Apply redaction to the original text based on findings."""
    redacted = text

    # Sort to avoid substring replacement conflicts
    findings = sorted(findings, key=lambda f: len(f.get("match", "")), reverse=True)

    for f in findings:
        original = f.get("match") or f.get("entity")
        if not original:
            continue

        t = f["type"]

        # --------------- CUSTOM RULES --------------- #

        if t == "EMAIL":
            masked = mask_email(original)

        elif t == "PHONE":
            masked = mask_phone(original)

        elif t in ("CREDIT_CARD", "AADHAAR"):
            masked = mask_last4(original)

        elif t in ("API_KEY", "HIGH_ENTROPY_TOKEN"):
            masked = mask_format_preserve(original)

        elif t == "PASSWORD_LIKE":
            masked = "******"

        # NER PII (PERSON, ORG, LOC)
        elif t in ("PERSON", "ORG", "GPE", "LOC"):
            masked = "****"

        else:
            masked = mask_full(original)

        # Replace all occurrences globally
        redacted = re.sub(re.escape(original), masked, redacted)

    return redacted

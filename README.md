# AI-Personally-Identifiable-Information-Detector

This project is an end-to-end PII Detection and Redaction Pipeline built using: 
-Python
-Regex-based pattern recognition
-Named Entity Recognition (NER)
-Entropy-based secret detection
-Luhn checksum validation
-Flask (Backend API)
-Streamlit (Frontend UI)

It identifies sensitive data in raw text or uploaded files and safely redacts it, following real-world security compliance standards (GDPR, HIPAA, PCI DSS).

Tech Stack:
Programming Language: Python 
Backend: Flask
Frontend: Streamlit

This system is suitable for:
-Data preprocessing
-Privacy-preserving ML workflows
-Compliance audits
-Secure log/file sanitization
-Enterprise-ready document scrubbing

What is PII?
PII stands for Personally Identifiable Information — any data that can uniquely identify an individual.

This system detects:
-Category	Examples
-Direct PII	Email, Phone numbers, Aadhaar, Credit Card numbers
-Secrets	API keys, tokens, high-entropy strings
-Contextual PII	Person names, Organizations, Locations
-Credential-like data	Password-like fields

Features:
Detects PII using a combination of:
-Regex patterns
-Entropy scanning for secrets/tokens
-Luhn check for valid credit cards
-Named Entity Recognition (NER) for:
PERSON
ORGANIZATION
GPE (Cities/Countries)
LOC (Locations)

Redaction Engine:
-Automatically masks PII following industry standards:

PII Types followed by their Redaction Rule:
Email:	Keep first 2 characters, mask rest
Phone:	Show last 4 digits only
Aadhaar:	Mask first 8 digits
Credit Card:	Mask all except last 4 digits
API Keys:	Fully masked (XXXX...)
Password-like:	******
Names (NER):	****

Fully modular → easily extendable.

Flask Backend API:
Provides endpoints:
POST /detect

Input:
{"text": "My email is test@example.com"}


Output:
{
  "decision": "FLAG",
  "findings": [...],
  "redacted_text": "My email is te**@e***.com"
}


Streamlit Frontend:
Features:
-Paste custom text
-Upload files (PDF, TXT, DOCX, CSV)
-Preview extracted text
-See PII findings
-View redacted output
-Runs locally in the browser.

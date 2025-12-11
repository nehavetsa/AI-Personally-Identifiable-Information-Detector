# tests/test_detector.py
from detector.core import detect_text

def test_email_detection():
    out = detect_text("reach: john.doe@example.com")
    assert out["decision"] in ("FLAG","BLOCK")
    assert any(f["type"] == "EMAIL" for f in out["findings"])

def test_aadhaar_block():
    out = detect_text("user id: 123412341234")
    assert out["decision"] == "BLOCK"
    assert any(f["type"] == "AADHAAR" for f in out["findings"])

def test_credit_card_luhn():
    # 4111 1111 1111 1111 is a valid Visa test number
    out = detect_text("card: 4111 1111 1111 1111")
    assert out["decision"] == "BLOCK"
    assert any(f["type"] == "CREDIT_CARD" for f in out["findings"])

def test_high_entropy_token():
    out = detect_text("token: XyZ9AbC0EfGh12qRstUv")
    assert any(f["type"] == "HIGH_ENTROPY_TOKEN" or f["type"] == "API_KEY" for f in out["findings"])

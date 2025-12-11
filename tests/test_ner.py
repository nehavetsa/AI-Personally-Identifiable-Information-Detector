from detector.ner import detect_entities

def test_detect_person():
    text = "My name is Rahul Sharma."
    ents = detect_entities(text)
    assert any(e["type"] == "PERSON" for e in ents)

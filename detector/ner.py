import spacy

# load spaCy model at module-import time (fast)
nlp = spacy.load("en_core_web_sm")

NER_LABELS = {"PERSON", "ORG", "GPE", "LOC"}

def detect_entities(text: str):
    """Detect contextual entities using spaCy NER."""
    doc = nlp(text)
    entities = []

    for ent in doc.ents:
        if ent.label_ in NER_LABELS:
            entities.append({
                "entity": ent.text,
                "type": ent.label_
            })

    return entities

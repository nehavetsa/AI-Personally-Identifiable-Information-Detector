from flask import Flask, request, jsonify, send_file
from detector.core import detect_text
from detector.redactor import apply_redactions
import tempfile

@app.route("/redact-file", methods=["POST"])
def redact_file():
    uploaded = request.files["file"]
    if not uploaded:
        return jsonify({"error": "No file uploaded"}), 400

    text = uploaded.read().decode("utf-8", errors="ignore")

    result = detect_text(text)
    redacted = apply_redactions(text, result["findings"])

    # create temporary redacted file
    temp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
    temp.write(redacted.encode("utf-8"))
    temp.close()

    return send_file(temp.name, as_attachment=True, download_name="redacted.txt")

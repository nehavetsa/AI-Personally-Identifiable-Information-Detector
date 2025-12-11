import streamlit as st
import requests
import json
import docx
import pandas as pd
from io import StringIO
import PyPDF2

API_URL = "http://127.0.0.1:5000/detect"

st.set_page_config(page_title="PII Detector", layout="wide")

st.title("🔍 PII Detection & Redaction Tool")
st.write("Paste text or upload a file. The system will detect & mask sensitive information.")

# --------------------------------------------------------------------
# Helper functions to extract text from uploaded files
# --------------------------------------------------------------------

def read_pdf(file):
    reader = PyPDF2.PdfReader(file)
    text = ""
    for page in reader.pages:
        text += page.extract_text() + "\n"
    return text

def read_docx(file):
    doc = docx.Document(file)
    text = "\n".join([para.text for para in doc.paragraphs])
    return text

def read_txt(file):
    return file.read().decode("utf-8")

def read_csv(file):
    df = pd.read_csv(file)
    return df.to_string()


# --------------------------------------------------------------------
# Input Handling (Either text area or file upload)
# --------------------------------------------------------------------

input_text = ""

input_mode = st.radio("Choose Input Method:", ["Paste Text", "Upload File"])

if input_mode == "Paste Text":
    input_text = st.text_area("Enter text:", height=250)

else:
    uploaded_file = st.file_uploader("Upload a file:", type=["pdf", "txt", "docx", "csv"])
    
    if uploaded_file is not None:
        file_type = uploaded_file.name.split(".")[-1].lower()

        if file_type == "pdf":
            input_text = read_pdf(uploaded_file)

        elif file_type == "txt":
            input_text = read_txt(uploaded_file)

        elif file_type == "docx":
            input_text = read_docx(uploaded_file)

        elif file_type == "csv":
            input_text = read_csv(uploaded_file)

        st.success("File uploaded successfully!")
        st.subheader("📄 Extracted Text:")
        st.code(input_text, language="text")


# --------------------------------------------------------------------
# Run analysis
# --------------------------------------------------------------------

if st.button("Analyze Text"):
    if not input_text.strip():
        st.warning("Please enter or upload some text.")
    else:
        response = requests.post(API_URL, json={"text": input_text})

        if response.status_code != 200:
            st.error("⚠️ Backend API not responding.")
        else:
            result = response.json()

            st.subheader("📌 Decision:")
            st.write(f"**{result['decision']}**")

            st.subheader("📊 Findings:")
            st.json(result["findings"])

            st.subheader("✂️ Redacted Output:")
            st.code(result["redacted_text"], language="text")

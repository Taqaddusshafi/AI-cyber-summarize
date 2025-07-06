import streamlit as st
from gemini_summarize import summarize_cve
from nvd_api import get_cve_details
from predict_severity import predict_severity

st.set_page_config(page_title="CyberIntel-AI", layout="centered")

st.title("🛡️ CyberIntel-AI: CVE Summarizer + Threat Analyzer")
st.markdown("""
Upload a `.txt` file **or** enter a **CVE ID** to get an AI-generated vulnerability summary, predicted severity, and threat insight.
""")

# --- Tabs ---
tab1, tab2 = st.tabs(["📄 Upload CVE File", "🌐 Search by CVE ID"])

# --- File Upload Tab ---
with tab1:
    uploaded_file = st.file_uploader("Upload CVE text file", type=["txt"])

    if uploaded_file:
        text = uploaded_file.read().decode("utf-8")
        st.subheader("📄 Raw CVE Input")
        st.code(text[:500] + "..." if len(text) > 500 else text)

        if st.button("Summarize File", key="file"):
            with st.spinner("🔍 Gemini is generating the summary..."):
                summary = summarize_cve(text)
                severity = predict_severity(text)

            st.subheader("✅ AI Summary")
            st.success(summary)

            st.subheader("📊 Predicted Severity")
            st.info(f"🧠 Severity Level: **{severity}**")

# --- CVE ID Tab ---
with tab2:
    cve_id = st.text_input("Enter CVE ID (e.g., CVE-2023-12345):")

    if cve_id:
        if st.button("Fetch & Summarize CVE", key="cve"):
            with st.spinner("🌐 Fetching CVE data from NVD..."):
                text = get_cve_details(cve_id)

                if isinstance(text, dict) and text.get("error"):
                    st.error(text["error"])
                else:
                    st.subheader("📄 CVE Description from NVD")
                    st.code(text[:500] + "..." if len(text) > 500 else text)

                    with st.spinner("🔍 Gemini is generating the summary..."):
                        summary = summarize_cve(text)
                        severity = predict_severity(text)

                    st.subheader("✅ AI Summary")
                    st.success(summary)

                    st.subheader("📊 Predicted Severity")
                    st.info(f"🧠 Severity Level: **{severity}**")

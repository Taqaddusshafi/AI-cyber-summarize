import os
import requests
from dotenv import load_dotenv
import streamlit as st

load_dotenv()
API_KEY = st.secrets["NVD_API_KEY"]

def fetch_from_nvd(cve_id, use_key=True):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apikey": API_KEY} if (use_key and API_KEY) else {}
    params = {"cveId": cve_id}

    print(f"\n🔍 Trying {'with' if use_key else 'without'} API key...")
    print("📌 CVE ID:", repr(cve_id))
    print("🌐 Request URL:", url)
    print("🔧 Params:", params)
    print("📦 Headers:", headers)

    response = requests.get(url, headers=headers, params=params)
    print("📥 Status Code:", response.status_code)

    return response

def get_cve_details(cve_id_raw):
    cve_id = cve_id_raw.strip()

    # Step 1: Try with API key
    response = fetch_from_nvd(cve_id, use_key=True)

    # Step 2: If 404, try without API key
    if response.status_code == 404:
        print("⚠️ 404 with API key — trying without key...")
        response = fetch_from_nvd(cve_id, use_key=False)

    # Step 3: Parse if successful
    if response.status_code == 200:
        try:
            item = response.json()['vulnerabilities'][0]['cve']
            description = item['descriptions'][0]['value']

            # Try CVSS v3.1, fallback to v2
            try:
                cvss = item['metrics']['cvssMetricV31'][0]['cvssData']
            except (KeyError, IndexError):
                cvss = item['metrics']['cvssMetricV2'][0]['cvssData']

            score = cvss.get('baseScore', 'N/A')
            severity = cvss.get('baseSeverity', 'N/A')

            # Extract CWE
            cwe = "N/A"
            for weakness in item.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    if desc['lang'] == 'en':
                        cwe = desc['value']
                        break

            return f"""
✅ CVE ID: {cve_id}
📝 Description: {description}
🛡️ Severity: {severity}
📊 CVSS Score: {score}
⚠️ CWE: {cwe}
"""
        except Exception as e:
            return f"❌ Data parsing error: {e}"

    elif response.status_code == 403:
        return "❌ 403 Forbidden: API key may be invalid or not authorized."
    elif response.status_code == 429:
        return "❌ 429 Too Many Requests: Rate limit exceeded. Use API key or slow down."
    elif response.status_code == 404:
        return f"❌ 404: CVE '{cve_id}' not found or not yet published."
    else:
        return f"❌ {response.status_code} Error: {response.reason}"


# 🧪 Example Usage
if __name__ == "__main__":
    print(get_cve_details("CVE-2024-3400"))

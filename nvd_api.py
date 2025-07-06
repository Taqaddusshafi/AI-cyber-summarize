import os
import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("NVD_API_KEY")

def get_cve_details(cve_id):
    base_url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    headers = {"apiKey": API_KEY} if API_KEY else {}

    response = requests.get(base_url, headers=headers)

    if response.status_code == 200:
        cve_data = response.json()
        try:
            description = cve_data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
            return description
        except Exception:
            return "❌ CVE data not found or in unsupported format."
    elif response.status_code == 403:
        return "❌ Error: 403 - Forbidden. Check if API key is valid and added to headers."
    elif response.status_code == 429:
        return "❌ Error: 429 - Rate limit exceeded. Try again later."
    else:
        return f"❌ Error: {response.status_code} - Unable to fetch CVE data."

import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()  

api_key = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=api_key)

model = genai.GenerativeModel('models/gemini-2.5-pro')

def summarize_cve(text):
    prompt = f"""
    You are a cybersecurity analyst.
    Summarize the following vulnerability in simple, non-technical language.
    Include:
    - Severity
    - Affected software
    - How the attack works
    - How to fix or mitigate it

    Vulnerability:
    {text}
    """
    
    response = model.generate_content(prompt)
    return response.text

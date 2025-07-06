import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report
import joblib

# --- Sample data ---
data = {
    "description": [
        "Remote attackers can execute arbitrary code via buffer overflow.",
        "Improper input validation leads to privilege escalation.",
        "Memory corruption causes crash and denial of service.",
        "Authentication bypass via token misconfiguration.",
        "Exposure of sensitive info through verbose error messages.",
        "Local attackers can gain root access due to insecure file permissions.",
        "Improper access control allows unauthorized admin actions.",
        "Weak encryption allows attackers to decrypt user passwords.",
        "Cross-site scripting vulnerability in login module.",
        "Race condition in memory allocator leads to crash.",
        "SQL injection through unsanitized search query.",
        "Stack-based buffer overflow leads to code execution.",
        "Hardcoded credentials allow full system compromise.",
        "Use-after-free in browser leads to RCE.",
        "DoS via malformed HTTP request headers.",
        "Directory traversal leads to sensitive file read.",
        "Session fixation via predictable session IDs.",
        "Open redirect allows phishing attacks.",
        "CRLF injection in HTTP headers.",
        "CSRF in admin settings endpoint.",
        "Broken access control in APIs.",
        "Insecure deserialization leading to code injection.",
        "Default password still active in production environment.",
        "Insufficient password complexity requirements.",
        "No rate limiting on login endpoint enables brute force.",
        "Improper cleanup leads to temp file info leak.",
        "Insecure CORS policy allows cross-origin attacks.",
        "Missing authentication in admin panel.",
        "Exposed .git folder reveals source code.",
        "Old vulnerable jQuery library used in production."
    ],
    "severity": [
        "CRITICAL", "HIGH", "MEDIUM", "HIGH", "LOW",
        "CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM",
        "HIGH", "CRITICAL", "CRITICAL", "CRITICAL", "MEDIUM",
        "HIGH", "LOW", "LOW", "LOW", "MEDIUM",
        "HIGH", "CRITICAL", "LOW", "MEDIUM", "LOW",
        "HIGH", "CRITICAL", "HIGH", "MEDIUM", "HIGH"
    ]
}

# --- Load data ---
df = pd.DataFrame(data)

# --- Split the data with stratified sampling to avoid class imbalance ---
X_train, X_test, y_train, y_test = train_test_split(
    df["description"], df["severity"],
    test_size=0.2, stratify=df["severity"],
    random_state=42
)

# --- Create pipeline: TF-IDF + Naive Bayes ---
model = Pipeline([
    ("tfidf", TfidfVectorizer()),
    ("clf", MultinomialNB())
])

# --- Train the model ---
model.fit(X_train, y_train)

# --- Evaluate ---
y_pred = model.predict(X_test)
print("\n📊 Classification Report:\n")
print(classification_report(y_test, y_pred, zero_division=0))

# --- Save the trained model ---
joblib.dump(model, "severity_model.pkl")
print("✅ Model saved to severity_model.pkl")

import joblib

# Load the trained model
model = joblib.load("severity_model.pkl")

def predict_severity(description):
    return model.predict([description])[0]

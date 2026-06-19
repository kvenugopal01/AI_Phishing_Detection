# simple flask app for prediction
from flask import Flask, render_template, request, jsonify
import joblib
import os
import numpy as np
from feature_extraction import extract_all_features

app = Flask(__name__)

# load our trained model file
model_file = "phishing_model.pkl"
if os.path.exists(model_file):
    model = joblib.load(model_file)
    print("Model loaded successfully!")
else:
    model = None
    print("Warning: Model file not found!")

@app.route("/")
def home():
    # render the index HTML page
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    if model is None:
        return jsonify({"error": "No trained model found."}), 500
        
    req_data = request.json
    if not req_data or "url" not in req_data:
        return jsonify({"error": "URL parameter missing!"}), 400
        
    user_url = req_data["url"]
    
    try:
        # call feature extraction logic
        res = extract_all_features(user_url)
        feats = res["features_array"]
        details = res["features_details"]
        
        # convert to numpy array and predict class
        np_arr = np.array(feats).reshape(1, -1)
        pred = model.predict(np_arr)[0]
        probs = model.predict_proba(np_arr)[0]
        
        # map probabilities to correct class
        model_classes = list(model.classes_)
        idx_phish = model_classes.index(-1)
        idx_safe = model_classes.index(1)
        
        prob_phish = float(probs[idx_phish])
        prob_safe = float(probs[idx_safe])
        
        if pred == -1:
            verdict = "phishing"
            confidence = prob_phish
        else:
            verdict = "safe"
            confidence = prob_safe
            
        # return result dictionary as JSON
        output = {
            "success": True,
            "url": user_url,
            "domain": res["domain"],
            "resolved_ip": res["resolved_ip"],
            "verdict": verdict,
            "confidence": round(confidence * 100, 2),
            "features_details": details
        }
        return jsonify(output)
        
    except Exception as err:
        print("Error during prediction route:", err)
        return jsonify({"success": False, "error": str(err)}), 500

if __name__ == "__main__":
    # run on port 5001 to avoid default macOS conflicts
    app.run(debug=True, port=5001)

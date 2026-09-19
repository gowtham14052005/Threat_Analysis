#!/usr/bin/env python3
"""
PhishGuard SVM Inference Script
Accepts a JSON feature array from standard input or arguments, loads joblib artifacts, and returns predictions.
"""

import sys
import os
import json
import joblib
import numpy as np

def run_predict():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    svm_path = os.path.join(script_dir, "model", "phishing_svm.joblib")
    scaler_path = os.path.join(script_dir, "model", "scaler.joblib")
    
    try:
        model = joblib.load(svm_path)
        scaler = joblib.load(scaler_path)
    except Exception as e:
        print(json.dumps({"error": f"Failed to load model: {str(e)}"}))
        sys.exit(1)
        
    if len(sys.argv) > 1:
        raw_input = sys.argv[1]
    else:
        raw_input = sys.stdin.read()
        
    try:
        data = json.loads(raw_input)
        if isinstance(data, list):
            feature_vector = np.array(data, dtype=float).reshape(1, -1)
        elif isinstance(data, dict) and "features" in data:
            feature_vector = np.array(data["features"], dtype=float).reshape(1, -1)
        else:
            raise ValueError("Input must be a JSON array of 30 feature values or an object with 'features'.")
            
        scaled_vector = scaler.transform(feature_vector)
        decision_val = float(model.decision_function(scaled_vector)[0])
        probabilities = model.predict_proba(scaled_vector)[0]
        prediction = int(model.predict(scaled_vector)[0]) # 1: Phishing, 0: Legitimate
        
        prob_phishing = float(probabilities[1])
        prob_legitimate = float(probabilities[0])
        
        output = {
            "prediction": prediction,
            "is_phishing": bool(prediction == 1),
            "probability_phishing": prob_phishing,
            "probability_legitimate": prob_legitimate,
            "decision_function": decision_val,
        }
        print(json.dumps(output))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    run_predict()

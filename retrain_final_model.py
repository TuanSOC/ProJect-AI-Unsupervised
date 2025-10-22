#!/usr/bin/env python3
"""
Final retrain với contamination 0.01 và tất cả improvements
"""

import json
import os
import logging
from optimized_sqli_detector import OptimizedSQLIDetector

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def retrain_final_model():
    """Retrain model với contamination 0.01 và tất cả improvements"""
    
    print("Final Model Retraining")
    print("=" * 50)
    
    # Load training data
    clean_logs = []
    data_path = 'sqli_logs_clean_100k.jsonl'
    
    if not os.path.exists(data_path):
        print(f"Training data not found: {data_path}")
        return
    
    with open(data_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                try:
                    clean_logs.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
    
    print(f"Loaded {len(clean_logs)} training logs")
    
    # Create detector with contamination 0.01
    detector = OptimizedSQLIDetector(
        contamination=0.01,  # Final optimized value
        random_state=42,
        n_estimators=200,
        max_features=0.8,
        n_jobs=-1
    )
    
    # Train model
    print("Training model...")
    X_scaled, feature_names = detector.train(clean_logs)
    
    # Save model
    model_path = 'models/optimized_sqli_detector.pkl'
    detector.save_model(model_path)
    
    print(f"Model saved to {model_path}")
    print(f"Score percentiles: {detector.score_percentiles}")
    print(f"Recommended threshold: {detector.sqli_score_threshold}")
    
    # Test with sample logs
    print("\nTesting with sample logs...")
    
    test_cases = [
        {
            "name": "Real SQLi - benchmark",
            "log": {
                "time": "2025-10-22T08:47:41+0700",
                "remote_ip": "192.168.205.2",
                "method": "GET",
                "uri": "/DVWA/vulnerabilities/sqli/index.php",
                "query_string": "?id=%27+or+benchmark%2810000000%2CMD5%281%29%29%23&Submit=Submit",
                "status": 200,
                "payload": "id=%27+or+benchmark%2810000000%2CMD5%281%29%29%23&Submit=Submit",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
            }
        },
        {
            "name": "Normal request",
            "log": {
                "time": "2025-10-22T08:47:41+0700",
                "remote_ip": "192.168.205.2",
                "method": "GET",
                "uri": "/DVWA/vulnerabilities/csrf/index.php",
                "query_string": "?id=1&Submit=Submit",
                "status": 200,
                "payload": "id=1&Submit=Submit",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
            }
        }
    ]
    
    for test_case in test_cases:
        log = test_case["log"]
        name = test_case["name"]
        
        try:
            is_anomaly, score, patterns, confidence = detector.predict_single(log)
            print(f"{name}: {is_anomaly} (Score: {score:.3f}, Patterns: {patterns}, Confidence: {confidence})")
        except Exception as e:
            print(f"{name}: ERROR - {e}")
    
    print("\nFinal model training completed!")
    print("Key improvements applied:")
    print("  OK: Contamination 0.01 (optimized for clean data)")
    print("  OK: Method field added")
    print("  OK: IP detection with ipaddress")
    print("  OK: Cookie weights normalized")
    print("  OK: Percentile-based thresholds")
    print("  OK: Input length limits (4096 chars)")
    print("  OK: Robust query string parsing")
    print("  OK: Fixed predict_batch error handling")
    print("  OK: Metadata storage for thresholds")

if __name__ == "__main__":
    retrain_final_model()

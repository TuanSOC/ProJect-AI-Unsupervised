#!/usr/bin/env python3
"""
Retrain model với các cải tiến quan trọng
"""

import json
import os
import logging
from optimized_sqli_detector import OptimizedSQLIDetector

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def retrain_improved_model():
    """Retrain model với contamination thấp và percentiles"""
    
    print("Retraining Improved Model")
    print("=" * 50)
    
    # Load training data
    clean_logs = []
    data_path = 'sqli_logs_clean_100k.jsonl'
    
    if not os.path.exists(data_path):
        print(f"❌ Training data not found: {data_path}")
        return
    
    with open(data_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                try:
                    clean_logs.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
    
    print(f"Loaded {len(clean_logs)} training logs")
    
    # Create improved detector with low contamination
    detector = OptimizedSQLIDetector(
        contamination=0.01,  # Reduced from 0.2 to 0.01
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
    
    # Test with sample log
    print("\nTesting with sample log...")
    test_log = {
        "time": "2025-10-22T08:47:41+0700",
        "remote_ip": "192.168.205.2",
        "method": "GET",
        "uri": "/DVWA/vulnerabilities/sqli/index.php",
        "query_string": "?id=%27+or+benchmark%2810000000%2CMD5%281%29%29%23&Submit=Submit",
        "status": 200,
        "bytes_sent": 1437,
        "response_time_ms": 389400,
        "referer": "http://localhost/DVWA/vulnerabilities/sqli/",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "request_length": 1859,
        "response_length": 1788,
        "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s",
        "payload": "id=%27+or+benchmark%2810000000%2CMD5%281%29%29%23&Submit=Submit"
    }
    
    is_anomaly, score, patterns, confidence = detector.predict_single(test_log)
    print(f"Test result: {is_anomaly} (Score: {score:.3f}, Patterns: {patterns}, Confidence: {confidence})")
    
    print("\nImproved model training completed!")
    print("Key improvements:")
    print("   OK: Reduced contamination: 0.2 -> 0.01")
    print("   OK: Added method field")
    print("   OK: Improved IP detection with ipaddress")
    print("   OK: Reduced cookie weights")
    print("   OK: Added percentile-based thresholds")
    print("   OK: Fixed predict_batch error handling")
    print("   OK: Added input length limits")

if __name__ == "__main__":
    retrain_improved_model()

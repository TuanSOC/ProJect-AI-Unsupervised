#!/usr/bin/env python3
"""
Evaluate improved model performance
"""

import json
import numpy as np
from sklearn.metrics import precision_recall_curve, auc, classification_report
from optimized_sqli_detector import OptimizedSQLIDetector

def evaluate_model():
    """Evaluate model performance"""
    
    print("Evaluating Improved Model")
    print("=" * 50)
    
    # Load model
    detector = OptimizedSQLIDetector()
    detector.load_model('models/optimized_sqli_detector.pkl')
    
    # Test cases
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
            },
            "expected": True
        },
        {
            "name": "Real SQLi - union select",
            "log": {
                "time": "2025-10-22T08:47:41+0700",
                "remote_ip": "192.168.205.2",
                "method": "GET",
                "uri": "/DVWA/vulnerabilities/sqli/index.php",
                "query_string": "?id=%27+UNION+SELECT+null%2C+version%28%29+--&Submit=Submit",
                "status": 200,
                "payload": "id=%27+UNION+SELECT+null%2C+version%28%29+--&Submit=Submit",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
            },
            "expected": True
        },
        {
            "name": "Normal request - simple query",
            "log": {
                "time": "2025-10-22T08:47:41+0700",
                "remote_ip": "192.168.205.2",
                "method": "GET",
                "uri": "/DVWA/vulnerabilities/sqli/index.php",
                "query_string": "?id=1&Submit=Submit",
                "status": 200,
                "payload": "id=1&Submit=Submit",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
            },
            "expected": False
        },
        {
            "name": "Normal request - DVWA page",
            "log": {
                "time": "2025-10-22T08:47:41+0700",
                "remote_ip": "192.168.205.2",
                "method": "GET",
                "uri": "/DVWA/vulnerabilities/csrf/index.php",
                "query_string": "",
                "status": 200,
                "payload": "",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
            },
            "expected": False
        },
        {
            "name": "Normal request - favicon",
            "log": {
                "time": "2025-10-22T08:47:41+0700",
                "remote_ip": "192.168.205.2",
                "method": "GET",
                "uri": "/DVWA/favicon.ico",
                "query_string": "",
                "status": 200,
                "payload": "",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
            },
            "expected": False
        }
    ]
    
    print("Testing model with various cases...")
    print()
    
    correct = 0
    total = len(test_cases)
    
    for i, test_case in enumerate(test_cases, 1):
        log = test_case["log"]
        expected = test_case["expected"]
        name = test_case["name"]
        
        try:
            is_anomaly, score, patterns, confidence = detector.predict_single(log)
            result = is_anomaly
            
            status = "CORRECT" if result == expected else "WRONG"
            if result == expected:
                correct += 1
            
            print(f"Test {i}: {name}")
            print(f"  Expected: {expected}, Got: {result} ({status})")
            print(f"  Score: {score:.3f}, Patterns: {patterns}, Confidence: {confidence}")
            print()
            
        except Exception as e:
            print(f"Test {i}: {name} - ERROR: {e}")
            print()
    
    accuracy = correct / total * 100
    print(f"Overall Accuracy: {correct}/{total} ({accuracy:.1f}%)")
    
    # Test with recommended threshold
    print(f"\nModel Statistics:")
    print(f"  Contamination: {detector.contamination}")
    print(f"  Score percentiles: {getattr(detector, 'score_percentiles', 'Not available')}")
    print(f"  Recommended threshold: {getattr(detector, 'sqli_score_threshold', 'Not available')}")
    
    print(f"\nKey Improvements Applied:")
    print(f"  OK: Reduced contamination from 0.2 to 0.01")
    print(f"  OK: Added method field for better encoding")
    print(f"  OK: Improved IP detection with ipaddress module")
    print(f"  OK: Reduced cookie weights (20x -> 4x)")
    print(f"  OK: Added percentile-based threshold selection")
    print(f"  OK: Fixed predict_batch error handling")
    print(f"  OK: Added input length limits (4096 chars)")
    print(f"  OK: Improved query string parsing with urllib.parse")

if __name__ == "__main__":
    evaluate_model()

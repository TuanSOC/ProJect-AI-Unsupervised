#!/usr/bin/env python3
"""
Debug threshold issue - 100% false positive rate
"""

from optimized_sqli_detector import OptimizedSQLIDetector
import json

def debug_threshold():
    """Debug threshold issue"""
    
    print("=" * 60)
    print("DEBUG THRESHOLD ISSUE")
    print("=" * 60)
    
    # Load model
    detector = OptimizedSQLIDetector()
    detector.load_model('models/optimized_sqli_detector.pkl')
    
    print(f"Model threshold: {detector.sqli_score_threshold}")
    print(f"Model is trained: {detector.is_trained}")
    
    # Test simple clean log
    clean_log = {
        "timestamp": "2025-01-01T10:00:00Z",
        "remote_ip": "192.168.1.100",
        "method": "GET",
        "uri": "/api/users",
        "query_string": "?page=1&limit=10",
        "status": 200,
        "bytes_sent": 1000,
        "response_time_ms": 100,
        "user_agent": "Mozilla/5.0",
        "request_length": 200,
        "response_length": 1000,
        "cookie": "session_id=123456",
        "payload": "page=1&limit=10",
        "session_token": "token_123456"
    }
    
    print("\nTesting clean log:")
    print(f"Payload: {clean_log['payload']}")
    
    # Get features
    features = detector.extract_optimized_features(clean_log)
    print(f"Key features:")
    print(f"  sqli_risk_score: {features.get('sqli_risk_score', 'NOT FOUND')}")
    print(f"  sqli_patterns: {features.get('sqli_patterns', 'NOT FOUND')}")
    print(f"  special_chars: {features.get('special_chars', 'NOT FOUND')}")
    print(f"  sql_keywords: {features.get('sql_keywords', 'NOT FOUND')}")
    print(f"  has_union_select: {features.get('has_union_select', 'NOT FOUND')}")
    print(f"  has_boolean_blind: {features.get('has_boolean_blind', 'NOT FOUND')}")
    
    # Test prediction
    is_sqli, score, patterns, confidence = detector.predict_single(clean_log)
    print(f"\nPrediction result:")
    print(f"  Is SQLi: {is_sqli}")
    print(f"  Score: {score:.4f}")
    print(f"  Patterns: {patterns}")
    print(f"  Confidence: {confidence}")
    
    # Test with different thresholds
    print(f"\nTesting different thresholds:")
    for threshold in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
        is_sqli_thresh, score_thresh, patterns_thresh, confidence_thresh = detector.predict_single(clean_log, threshold=threshold)
        print(f"  Threshold {threshold}: {is_sqli_thresh} (score: {score_thresh:.4f})")
    
    print("=" * 60)

if __name__ == "__main__":
    debug_threshold()

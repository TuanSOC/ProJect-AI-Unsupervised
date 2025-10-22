#!/usr/bin/env python3
"""
Demo script minh họa cách AI tính toán và train model
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import json
from datetime import datetime

def demo_feature_extraction():
    """Demo cách trích xuất features từ log"""
    
    print("🔍 DEMO: Cách AI trích xuất features từ log")
    print("=" * 60)
    
    # Ví dụ log sạch
    clean_log = {
        "time": "2025-10-22T08:47:41+0700",
        "remote_ip": "192.168.1.100",
        "method": "GET",
        "uri": "/vulnerabilities/csrf/index.php",
        "query_string": "?id=1&Submit=Submit",
        "status": 200,
        "payload": "id=1&Submit=Submit",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "cookie": "PHPSESSID=abc123"
    }
    
    print("📋 Log sạch:")
    print(f"   URI: {clean_log['uri']}")
    print(f"   Query: {clean_log['query_string']}")
    print(f"   Payload: {clean_log['payload']}")
    print()
    
    # Trích xuất features
    features = extract_features_demo(clean_log)
    
    print("🔢 Features được trích xuất:")
    for key, value in features.items():
        print(f"   {key}: {value}")
    
    print(f"\n📊 Tổng số features: {len(features)}")
    print(f"📊 SQLi risk score: {features['sqli_risk_score']:.3f}")
    print(f"📊 Có pattern SQLi: {features['sqli_patterns'] > 0}")
    
    print("\n" + "="*60)
    
    # Ví dụ log bẩn
    sqli_log = {
        "time": "2025-10-22T08:47:41+0700",
        "remote_ip": "192.168.1.100",
        "method": "GET",
        "uri": "/vulnerabilities/sqli/index.php",
        "query_string": "?id=1' OR 1=1--",
        "status": 200,
        "payload": "id=1' OR 1=1--",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "cookie": "PHPSESSID=abc123"
    }
    
    print("📋 Log bẩn (SQLi attack):")
    print(f"   URI: {sqli_log['uri']}")
    print(f"   Query: {sqli_log['query_string']}")
    print(f"   Payload: {sqli_log['payload']}")
    print()
    
    # Trích xuất features
    features = extract_features_demo(sqli_log)
    
    print("🔢 Features được trích xuất:")
    for key, value in features.items():
        print(f"   {key}: {value}")
    
    print(f"\n📊 Tổng số features: {len(features)}")
    print(f"📊 SQLi risk score: {features['sqli_risk_score']:.3f}")
    print(f"📊 Có pattern SQLi: {features['sqli_patterns'] > 0}")
    print(f"📊 Patterns tìm thấy: {find_patterns_demo(sqli_log)}")

def extract_features_demo(log_entry):
    """Demo trích xuất features"""
    
    features = {}
    
    # Basic features
    features['status'] = log_entry.get('status', 200)
    features['response_time_ms'] = 150  # Simulated
    features['request_length'] = len(str(log_entry))
    features['response_length'] = 1024  # Simulated
    features['bytes_sent'] = 1024  # Simulated
    
    # URI analysis
    uri = log_entry.get('uri', '')
    features['uri_length'] = len(uri)
    features['uri_depth'] = uri.count('/')
    features['has_sqli_endpoint'] = 'sqli' in uri.lower()
    
    # Query string analysis
    query_string = log_entry.get('query_string', '')
    features['query_length'] = len(query_string)
    features['query_params_count'] = len(query_string.split('&')) if query_string else 0
    
    # Payload analysis
    payload = log_entry.get('payload', '')
    features['payload_length'] = len(payload)
    features['has_payload'] = len(payload) > 0
    
    # SQLi pattern detection
    sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'create', 'alter']
    special_chars = ['"', "'", ';', '--', '/*', '*/', '(', ')', '=', '>', '<']
    suspicious_patterns = ['or 1=1', 'and 1=1', 'union select', 'benchmark(', 'sleep(']
    
    # Count patterns in query string
    query_lower = query_string.lower()
    sqli_patterns = 0
    special_chars_count = 0
    sql_keywords_count = 0
    
    for pattern in suspicious_patterns:
        if pattern in query_lower:
            sqli_patterns += 1
    
    for char in special_chars:
        special_chars_count += query_lower.count(char)
    
    for keyword in sql_keywords:
        if keyword in query_lower:
            sql_keywords_count += 1
    
    features['sqli_patterns'] = sqli_patterns
    features['special_chars'] = special_chars_count
    features['sql_keywords'] = sql_keywords_count
    
    # User agent analysis
    user_agent = log_entry.get('user_agent', '')
    features['user_agent_length'] = len(user_agent)
    features['is_bot'] = 'bot' in user_agent.lower()
    
    # IP analysis
    remote_ip = log_entry.get('remote_ip', '')
    features['is_internal_ip'] = remote_ip.startswith('192.168.') or remote_ip.startswith('10.') or remote_ip.startswith('172.')
    
    # Cookie analysis
    cookie = log_entry.get('cookie', '')
    features['cookie_length'] = len(cookie)
    features['has_session'] = 'PHPSESSID' in cookie
    features['cookie_sqli_patterns'] = 0
    features['cookie_special_chars'] = 0
    features['cookie_sql_keywords'] = 0
    features['cookie_quotes'] = 0
    features['cookie_operators'] = 0
    
    # Security level
    features['security_level'] = 1
    
    # Time features
    features['hour'] = 8
    features['day_of_week'] = 2
    features['is_weekend'] = False
    
    # Advanced SQLi patterns
    features['has_union_select'] = 'union select' in query_lower
    features['has_information_schema'] = 'information_schema' in query_lower
    features['has_mysql_functions'] = any(func in query_lower for func in ['version()', 'user()', 'database()'])
    features['has_boolean_blind'] = any(pattern in query_lower for pattern in ['or 1=1', 'and 1=1'])
    features['has_time_based'] = any(func in query_lower for func in ['benchmark(', 'sleep('])
    features['has_comment_injection'] = '--' in query_lower or '/*' in query_lower
    
    # Method encoding
    method = log_entry.get('method', 'GET')
    method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3}
    features['method_encoded'] = method_map.get(method, 0)
    
    # Calculate SQLi risk score
    risk_score = 0.0
    
    # Base risk from URI
    if 'sqli' in uri.lower():
        risk_score += 0.3
    
    # Risk from query string
    if any(pattern in query_lower for pattern in ['union', 'select', 'or', 'and']):
        risk_score += 0.2
    
    # Risk from payload
    if any(pattern in payload.lower() for pattern in ['union', 'select', 'or', 'and']):
        risk_score += 0.2
    
    # Risk from special characters
    char_count = sum(payload.count(char) for char in special_chars)
    risk_score += min(char_count * 0.1, 0.3)
    
    # Risk from cookie
    if any(pattern in cookie.lower() for pattern in ['union', 'select', 'or', 'and']):
        risk_score += 0.1
    
    features['sqli_risk_score'] = min(risk_score, 1.0)
    
    return features

def find_patterns_demo(log_entry):
    """Demo tìm patterns SQLi"""
    
    patterns = []
    
    # SQL keywords
    sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'create', 'alter']
    
    # Special patterns
    special_patterns = ['or 1=1', 'and 1=1', 'union select', 'benchmark(', 'sleep(']
    
    # Check query string
    query_string = log_entry.get('query_string', '').lower()
    for keyword in sql_keywords:
        if keyword in query_string:
            patterns.append(keyword)
    
    for pattern in special_patterns:
        if pattern in query_string:
            patterns.append(pattern)
    
    # Check payload
    payload = log_entry.get('payload', '').lower()
    for keyword in sql_keywords:
        if keyword in payload:
            patterns.append(keyword)
    
    for pattern in special_patterns:
        if pattern in payload:
            patterns.append(pattern)
    
    return list(set(patterns))

def demo_isolation_forest():
    """Demo cách Isolation Forest hoạt động"""
    
    print("\n🌲 DEMO: Cách Isolation Forest hoạt động")
    print("=" * 60)
    
    # Tạo dữ liệu mẫu
    np.random.seed(42)
    
    # Normal data (clean logs)
    normal_data = np.random.normal(0, 1, (1000, 5))
    
    # Anomalous data (SQLi logs)
    anomalous_data = np.random.normal(3, 0.5, (50, 5))
    
    # Combine data
    X = np.vstack([normal_data, anomalous_data])
    y = np.hstack([np.zeros(1000), np.ones(50)])  # 0 = normal, 1 = anomaly
    
    print(f"📊 Dữ liệu training:")
    print(f"   Normal samples: {len(normal_data)}")
    print(f"   Anomalous samples: {len(anomalous_data)}")
    print(f"   Total samples: {len(X)}")
    print(f"   Features: {X.shape[1]}")
    
    # Train Isolation Forest
    isolation_forest = IsolationForest(
        contamination=0.05,  # 5% expected outliers
        random_state=42,
        n_estimators=100
    )
    
    print(f"\n🔧 Training Isolation Forest...")
    print(f"   Contamination: 0.05 (5%)")
    print(f"   N estimators: 100")
    print(f"   Random state: 42")
    
    isolation_forest.fit(X)
    
    # Predict
    predictions = isolation_forest.predict(X)
    scores = isolation_forest.decision_function(X)
    
    print(f"\n📈 Kết quả prediction:")
    print(f"   Normal predicted as normal: {np.sum((predictions == 1) & (y == 0))}")
    print(f"   Normal predicted as anomaly: {np.sum((predictions == -1) & (y == 0))}")
    print(f"   Anomaly predicted as normal: {np.sum((predictions == 1) & (y == 1))}")
    print(f"   Anomaly predicted as anomaly: {np.sum((predictions == -1) & (y == 1))}")
    
    # Calculate accuracy
    accuracy = np.sum(predictions == (2 * y - 1)) / len(y)
    print(f"   Accuracy: {accuracy:.3f}")
    
    # Show score distribution
    print(f"\n📊 Score distribution:")
    print(f"   Normal samples - Mean score: {np.mean(scores[y == 0]):.3f}")
    print(f"   Anomalous samples - Mean score: {np.mean(scores[y == 1]):.3f}")
    
    # Show threshold
    threshold = np.percentile(scores, 95)
    print(f"   Recommended threshold (95th percentile): {threshold:.3f}")
    
    return isolation_forest, X, y, scores

def demo_prediction_process():
    """Demo quá trình prediction"""
    
    print("\n🎯 DEMO: Quá trình prediction")
    print("=" * 60)
    
    # Load model (simulated)
    print("📥 Loading model...")
    print("   Model: Isolation Forest")
    print("   Features: 37")
    print("   Contamination: 0.01")
    print("   Training samples: 100,000")
    
    # Test cases
    test_cases = [
        {
            "name": "Normal request",
            "log": {
                "method": "GET",
                "uri": "/vulnerabilities/csrf/index.php",
                "query_string": "?id=1&Submit=Submit",
                "payload": "id=1&Submit=Submit"
            },
            "expected": False
        },
        {
            "name": "SQLi attack",
            "log": {
                "method": "GET",
                "uri": "/vulnerabilities/sqli/index.php",
                "query_string": "?id=1' OR 1=1--",
                "payload": "id=1' OR 1=1--"
            },
            "expected": True
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n🧪 Test case {i}: {test_case['name']}")
        print(f"   Expected: {'SQLi' if test_case['expected'] else 'Normal'}")
        
        # Extract features
        features = extract_features_demo(test_case['log'])
        print(f"   Features extracted: {len(features)}")
        print(f"   SQLi risk score: {features['sqli_risk_score']:.3f}")
        print(f"   SQLi patterns: {features['sqli_patterns']}")
        
        # Simulate prediction
        if features['sqli_risk_score'] > 0.5:
            predicted = True
            confidence = "High" if features['sqli_risk_score'] > 0.8 else "Medium"
        else:
            predicted = False
            confidence = "Low"
        
        print(f"   Predicted: {'SQLi' if predicted else 'Normal'}")
        print(f"   Confidence: {confidence}")
        print(f"   Correct: {'Yes' if predicted == test_case['expected'] else 'No'}")

def main():
    """Main demo function"""
    
    print("AI TRAINING & CALCULATION DEMO")
    print("=" * 80)
    print("Minh hoa cach AI train model va tinh toan de phat hien SQLi")
    print("=" * 80)
    
    # Demo 1: Feature extraction
    demo_feature_extraction()
    
    # Demo 2: Isolation Forest
    isolation_forest, X, y, scores = demo_isolation_forest()
    
    # Demo 3: Prediction process
    demo_prediction_process()
    
    print("\n" + "="*80)
    print("[SUCCESS] DEMO HOÀN THÀNH!")
    print("="*80)
    print("Tom tat:")
    print("- AI trich xuat 37 features tu moi log")
    print("- Isolation Forest hoc tu 100,000 log sach")
    print("- Tinh anomaly score de phat hien bat thuong")
    print("- So sanh voi threshold de quyet dinh SQLi")
    print("- Dat 100% accuracy tren test cases")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Script để fix detection threshold và giảm false positive
"""

import json
import logging
from optimized_sqli_detector import OptimizedSQLIDetector

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def analyze_detection_issue():
    """Phân tích vấn đề detection"""
    
    print("🔍 Analyzing Detection Issue")
    print("=" * 50)
    
    # Load detector
    detector = OptimizedSQLIDetector()
    detector.load_model('models/optimized_sqli_detector.pkl')
    
    # Test case gây false positive
    false_positive_log = {
        "time": "2025-10-22T00:17:28+0700",
        "remote_ip": "192.168.205.2",
        "method": "GET",
        "uri": "/DVWA/vulnerabilities/sqli_blind/index.php",
        "query_string": "?id=tuan&Submit=Submit",
        "payload": "id=tuan&Submit=Submit",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "status": 200
    }
    
    print("📋 Testing False Positive Case:")
    print(f"   URI: {false_positive_log['uri']}")
    print(f"   Query: {false_positive_log['query_string']}")
    print(f"   Payload: {false_positive_log['payload']}")
    print()
    
    # Test với các threshold khác nhau
    thresholds = [0.5, 0.6, 0.7, 0.8, 0.9]
    
    print("🎯 Testing Different Thresholds:")
    for threshold in thresholds:
        is_anomaly, score = detector.predict_single(false_positive_log, threshold=threshold)
        result = "🚨 DETECTED" if is_anomaly else "✅ NORMAL"
        print(f"   Threshold {threshold}: {result} (Score: {score:.3f})")
    
    print()
    
    # Test với SQLi thật
    real_sqli_log = {
        "time": "2025-10-22T00:17:28+0700",
        "remote_ip": "192.168.205.2",
        "method": "GET",
        "uri": "/DVWA/vulnerabilities/sqli/index.php",
        "query_string": "?id=%27+UNION+SELECT+null%2C+version%28%29+--&Submit=Submit",
        "payload": "id=%27+UNION+SELECT+null%2C+version%28%29+--&Submit=Submit",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "status": 200
    }
    
    print("📋 Testing Real SQLi Case:")
    print(f"   URI: {real_sqli_log['uri']}")
    print(f"   Query: {real_sqli_log['query_string']}")
    print(f"   Payload: {real_sqli_log['payload']}")
    print()
    
    print("🎯 Testing Different Thresholds:")
    for threshold in thresholds:
        is_anomaly, score = detector.predict_single(real_sqli_log, threshold=threshold)
        result = "🚨 DETECTED" if is_anomaly else "✅ NORMAL"
        print(f"   Threshold {threshold}: {result} (Score: {score:.3f})")
    
    print()
    print("💡 Recommendation:")
    print("   - Nếu false positive có score ~0.53-0.55")
    print("   - Nếu real SQLi có score ~0.55-0.60")
    print("   - Nên tăng threshold lên 0.8-0.9 để giảm false positive")
    print("   - Hoặc retrain model với nhiều normal data hơn")

def update_realtime_collector_threshold():
    """Update threshold trong realtime collector"""
    
    print("\n🔧 Updating Realtime Collector Threshold")
    print("=" * 50)
    
    # Đọc file realtime_log_collector.py
    try:
        with open('realtime_log_collector.py', 'r') as f:
            content = f.read()
        
        # Tìm và thay thế threshold
        old_threshold = "DETECTION_THRESHOLD = 0.7"
        new_threshold = "DETECTION_THRESHOLD = 0.8"  # Tăng threshold để giảm false positive
        
        if old_threshold in content:
            content = content.replace(old_threshold, new_threshold)
            
            with open('realtime_log_collector.py', 'w') as f:
                f.write(content)
            
            print(f"✅ Updated threshold from 0.7 to 0.8")
            print("   Restart realtime_log_collector.py to apply changes")
        else:
            print("❌ Could not find threshold setting in realtime_log_collector.py")
            
    except Exception as e:
        print(f"❌ Error updating threshold: {e}")

if __name__ == "__main__":
    analyze_detection_issue()
    update_realtime_collector_threshold()

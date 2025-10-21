#!/usr/bin/env python3
"""
Script để retrain model với balanced data để giảm false positive
"""

import json
import logging
import random
from optimized_sqli_detector import OptimizedSQLIDetector

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_normal_logs():
    """Tạo normal logs để balance training data"""
    
    normal_logs = []
    
    # Normal request patterns
    normal_patterns = [
        # Login requests
        {"uri": "/login.php", "query_string": "?username=admin&password=password", "payload": "username=admin&password=password"},
        {"uri": "/auth/login", "query_string": "?user=john&pass=123456", "payload": "user=john&pass=123456"},
        {"uri": "/user/login", "query_string": "?email=user@example.com&password=secret", "payload": "email=user@example.com&password=secret"},
        
        # Search requests
        {"uri": "/search.php", "query_string": "?q=product&category=electronics", "payload": "q=product&category=electronics"},
        {"uri": "/products", "query_string": "?name=laptop&price=1000", "payload": "name=laptop&price=1000"},
        {"uri": "/api/search", "query_string": "?term=book&type=all", "payload": "term=book&type=all"},
        
        # Navigation requests
        {"uri": "/home", "query_string": "", "payload": ""},
        {"uri": "/about", "query_string": "", "payload": ""},
        {"uri": "/contact", "query_string": "", "payload": ""},
        {"uri": "/products/123", "query_string": "", "payload": ""},
        
        # Form submissions
        {"uri": "/contact.php", "query_string": "?name=John&email=john@example.com&message=Hello", "payload": "name=John&email=john@example.com&message=Hello"},
        {"uri": "/register", "query_string": "?username=newuser&email=new@example.com&password=password123", "payload": "username=newuser&email=new@example.com&password=password123"},
        
        # API requests
        {"uri": "/api/users", "query_string": "?limit=10&offset=0", "payload": "limit=10&offset=0"},
        {"uri": "/api/products", "query_string": "?category=electronics&sort=price", "payload": "category=electronics&sort=price"},
        
        # File requests
        {"uri": "/images/logo.png", "query_string": "", "payload": ""},
        {"uri": "/css/style.css", "query_string": "", "payload": ""},
        {"uri": "/js/app.js", "query_string": "", "payload": ""},
        
        # DVWA normal requests
        {"uri": "/DVWA/vulnerabilities/brute/index.php", "query_string": "?username=admin&password=password&Login=Login", "payload": "username=admin&password=password&Login=Login"},
        {"uri": "/DVWA/vulnerabilities/exec/index.php", "query_string": "?ip=127.0.0.1&Submit=Submit", "payload": "ip=127.0.0.1&Submit=Submit"},
        {"uri": "/DVWA/vulnerabilities/sqli/index.php", "query_string": "?id=1&Submit=Submit", "payload": "id=1&Submit=Submit"},
        {"uri": "/DVWA/vulnerabilities/sqli_blind/index.php", "query_string": "?id=1&Submit=Submit", "payload": "id=1&Submit=Submit"},
    ]
    
    # Generate variations
    for pattern in normal_patterns:
        for i in range(5):  # 5 variations per pattern
            log = {
                "time": f"2025-10-22T00:17:28+0700",
                "remote_ip": f"192.168.1.{random.randint(1, 254)}",
                "method": random.choice(["GET", "POST"]),
                "uri": pattern["uri"],
                "query_string": pattern["query_string"],
                "payload": pattern["payload"],
                "user_agent": random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                ]),
                "status": random.choice([200, 200, 200, 404, 403]),  # Mostly 200
                "bytes_sent": random.randint(1000, 10000),
                "response_time_ms": random.randint(100, 1000)
            }
            normal_logs.append(log)
    
    return normal_logs

def retrain_balanced_model():
    """Retrain model với balanced data"""
    
    print("🔄 Retraining Model with Balanced Data")
    print("=" * 50)
    
    # Load existing training data
    try:
        with open('sqli_logs_clean_100k.jsonl', 'r') as f:
            existing_logs = [json.loads(line.strip()) for line in f if line.strip()]
        print(f"✅ Loaded {len(existing_logs)} existing logs")
    except Exception as e:
        print(f"❌ Error loading existing logs: {e}")
        return False
    
    # Generate normal logs
    print("📝 Generating normal logs...")
    normal_logs = generate_normal_logs()
    print(f"✅ Generated {len(normal_logs)} normal logs")
    
    # Combine data (50% normal, 50% existing)
    combined_logs = normal_logs + existing_logs[:len(normal_logs)]
    random.shuffle(combined_logs)
    
    print(f"📊 Total training data: {len(combined_logs)} logs")
    print(f"   - Normal logs: {len(normal_logs)}")
    print(f"   - Existing logs: {len(existing_logs[:len(normal_logs)])}")
    
    # Train new model
    print("🤖 Training new model...")
    detector = OptimizedSQLIDetector()
    detector.train(combined_logs)
    
    # Save model
    model_path = 'models/optimized_sqli_detector.pkl'
    detector.save_model(model_path)
    print(f"✅ Model saved to {model_path}")
    
    # Test new model
    print("\n🧪 Testing New Model")
    print("-" * 30)
    
    # Test false positive case
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
    
    is_anomaly, score = detector.predict_single(false_positive_log, threshold=0.7)
    result = "🚨 DETECTED" if is_anomaly else "✅ NORMAL"
    print(f"False Positive Test: {result} (Score: {score:.3f})")
    
    # Test real SQLi
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
    
    is_anomaly, score = detector.predict_single(real_sqli_log, threshold=0.7)
    result = "🚨 DETECTED" if is_anomaly else "✅ NORMAL"
    print(f"Real SQLi Test: {result} (Score: {score:.3f})")
    
    print("\n✅ Model retraining completed!")
    print("   Restart realtime_log_collector.py to use the new model")
    
    return True

if __name__ == "__main__":
    retrain_balanced_model()

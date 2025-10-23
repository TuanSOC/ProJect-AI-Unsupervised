#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Performance Test Suite - 1000 Logs (500 Clean + 500 SQLi)
Test hiệu năng AI model với dataset lớn
"""

import json
import time
import random
from datetime import datetime
from optimized_sqli_detector import OptimizedSQLIDetector
import numpy as np

def generate_clean_logs(count=500):
    """Tạo 500 log sạch (clean requests)"""
    clean_logs = []
    
    # Các pattern request sạch thường gặp
    clean_patterns = [
        {"uri": "/index.php", "query_string": "?page=1&limit=10"},
        {"uri": "/login.php", "query_string": "?username=admin&password=123456"},
        {"uri": "/search.php", "query_string": "?q=hello+world&type=all"},
        {"uri": "/products.php", "query_string": "?category=electronics&sort=price"},
        {"uri": "/user/profile.php", "query_string": "?id=123&view=public"},
        {"uri": "/api/users", "query_string": "?page=1&per_page=20"},
        {"uri": "/blog/post.php", "query_string": "?id=456&comment=true"},
        {"uri": "/shop/cart.php", "query_string": "?action=add&product_id=789"},
        {"uri": "/news/article.php", "query_string": "?id=101&category=tech"},
        {"uri": "/forum/topic.php", "query_string": "?id=202&page=1"},
        {"uri": "/gallery/image.php", "query_string": "?id=303&size=large"},
        {"uri": "/download/file.php", "query_string": "?id=404&type=pdf"},
        {"uri": "/contact/form.php", "query_string": "?subject=inquiry&priority=normal"},
        {"uri": "/about/team.php", "query_string": "?department=engineering"},
        {"uri": "/services/web.php", "query_string": "?package=premium&duration=12"},
    ]
    
    for i in range(count):
        pattern = random.choice(clean_patterns)
        log = {
            "time": f"2025-01-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}+0700",
            "remote_ip": f"192.168.1.{random.randint(1,254)}",
            "method": random.choice(["GET", "POST"]),
            "uri": pattern["uri"],
            "query_string": pattern["query_string"],
            "status": random.choice([200, 200, 200, 404, 200]),  # Mostly 200
            "bytes_sent": random.randint(1000, 50000),
            "response_time_ms": random.randint(50, 500),
            "referer": "https://example.com/",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "request_length": random.randint(200, 2000),
            "response_length": random.randint(1000, 50000),
            "cookie": f"session_id={random.randint(100000, 999999)}; user_pref=default",
            "payload": pattern["query_string"].replace("?", ""),
            "session_token": f"token_{random.randint(100000, 999999)}"
        }
        clean_logs.append(log)
    
    return clean_logs

def generate_sqli_logs(count=500):
    """Tạo 500 log có SQLi attacks"""
    sqli_logs = []
    
    # Các loại SQLi attacks
    sqli_patterns = [
        # Union-based SQLi
        {"payload": "id=1' UNION SELECT username,password FROM users--", "type": "Union-based"},
        {"payload": "id=1' UNION ALL SELECT 1,2,3,4,5--", "type": "Union-based"},
        {"payload": "id=1' UNION SELECT NULL,version(),user(),database()--", "type": "Union-based"},
        
        # Boolean-based Blind SQLi
        {"payload": "id=1' AND 1=1--", "type": "Boolean Blind"},
        {"payload": "id=1' AND 1=2--", "type": "Boolean Blind"},
        {"payload": "id=1' AND (SELECT COUNT(*) FROM users)>0--", "type": "Boolean Blind"},
        {"payload": "id=1' AND (SELECT LENGTH(username) FROM users LIMIT 1)>5--", "type": "Boolean Blind"},
        
        # Time-based Blind SQLi
        {"payload": "id=1'; WAITFOR DELAY '00:00:05'--", "type": "Time-based"},
        {"payload": "id=1' AND (SELECT SLEEP(5))--", "type": "Time-based"},
        {"payload": "id=1'; SELECT pg_sleep(5)--", "type": "Time-based"},
        
        # Error-based SQLi
        {"payload": "id=1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--", "type": "Error-based"},
        {"payload": "id=1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "type": "Error-based"},
        
        # Base64 Encoded SQLi
        {"payload": "data=JyBPUiAxPTEtLQ==", "type": "Base64 Encoded"},
        {"payload": "id=MScgQU5EIChTRUxFQ1QgMSBGUk9NIChTRUxFQ1QgQ09VTlQoKiksIENPTkNBVCh1c2VyKCksIEZMT09SKFJBTkQoKSoyKSkgeCBGUk9NI--", "type": "Base64 Encoded"},
        
        # NoSQL Injection
        {"payload": "id=1'; return db.users.find({username: {$ne: null}})--", "type": "NoSQL"},
        {"payload": "id=1'; db.users.find({$where: 'this.username == this.password'})--", "type": "NoSQL"},
        
        # Overlong UTF-8
        {"payload": "id=%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c/etc/passwd", "type": "Overlong UTF-8"},
        {"payload": "id=%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c", "type": "Overlong UTF-8"},
        
        # Double URL Encoded
        {"payload": "id=%2527%2520%254f%2552%2520%2531%253d%2531%252d%252d", "type": "Double URL Encoded"},
        {"payload": "id=%2527%2520%2555%254e%2549%254f%254e%2520%2553%2545%254c%2545%2543%2554%2520%2531%252c%2532%252c%2533%252d%252d", "type": "Double URL Encoded"},
        
        # Cookie-based SQLi
        {"payload": "id=1", "cookie": "user_id=1'; DROP TABLE users--; session=abc123", "type": "Cookie-based"},
        {"payload": "id=1", "cookie": "admin=1' OR '1'='1; auth_token=xyz789", "type": "Cookie-based"},
        
        # Function-based SQLi
        {"payload": "id=1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--", "type": "Function-based"},
        {"payload": "id=1' AND LENGTH((SELECT username FROM users LIMIT 1))>3--", "type": "Function-based"},
        
        # Comment Injection
        {"payload": "id=1'/**/OR/**/1=1--", "type": "Comment Injection"},
        {"payload": "id=1'/*comment*/UNION/*comment*/SELECT/*comment*/1,2,3--", "type": "Comment Injection"},
        
        # Stacked Queries
        {"payload": "id=1'; INSERT INTO logs VALUES ('hacked');--", "type": "Stacked Queries"},
        {"payload": "id=1'; UPDATE users SET password='hacked' WHERE id=1;--", "type": "Stacked Queries"},
    ]
    
    for i in range(count):
        pattern = random.choice(sqli_patterns)
        log = {
            "time": f"2025-01-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}+0700",
            "remote_ip": f"192.168.1.{random.randint(1,254)}",
            "method": random.choice(["GET", "POST"]),
            "uri": "/vulnerabilities/sqli/index.php",
            "query_string": f"?{pattern['payload']}",
            "status": random.choice([200, 404, 500]),  # Mixed status codes
            "bytes_sent": random.randint(1000, 100000),
            "response_time_ms": random.randint(100, 5000),
            "referer": "https://example.com/",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "request_length": random.randint(500, 5000),
            "response_length": random.randint(1000, 100000),
            "cookie": pattern.get("cookie", f"session_id={random.randint(100000, 999999)}; user_pref=default"),
            "payload": pattern["payload"],
            "session_token": f"token_{random.randint(100000, 999999)}"
        }
        log["sqli_type"] = pattern["type"]  # Thêm thông tin loại SQLi
        sqli_logs.append(log)
    
    return sqli_logs

def run_performance_test():
    """Chạy test hiệu năng với 1000 logs"""
    print("=" * 80)
    print("AI SQLi DETECTION PERFORMANCE TEST - 1000 LOGS")
    print("=" * 80)
    print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Load AI model
    print("Loading AI Model...")
    detector = OptimizedSQLIDetector()
    detector.load_model("models/optimized_sqli_detector.pkl")
    print("Model loaded successfully!")
    print()
    
    # Generate test data
    print("Generating Test Data...")
    clean_logs = generate_clean_logs(500)
    sqli_logs = generate_sqli_logs(500)
    all_logs = clean_logs + sqli_logs
    random.shuffle(all_logs)  # Shuffle để test ngẫu nhiên
    print(f"Generated {len(clean_logs)} clean logs + {len(sqli_logs)} SQLi logs = {len(all_logs)} total")
    print()
    
    # Performance metrics
    results = {
        "total_logs": len(all_logs),
        "clean_logs": len(clean_logs),
        "sqli_logs": len(sqli_logs),
        "true_positives": 0,  # SQLi detected correctly
        "false_positives": 0,  # Clean logs detected as SQLi
        "true_negatives": 0,  # Clean logs not detected
        "false_negatives": 0,  # SQLi not detected
        "processing_times": [],
        "detection_details": [],
        "sqli_type_accuracy": {},
        "start_time": time.time()
    }
    
    print("Starting Detection Test...")
    print("-" * 80)
    
    for i, log in enumerate(all_logs):
        start_time = time.time()
        
        # Detect SQLi
        is_sqli, score, patterns, confidence = detector.predict_single(log)
        
        processing_time = time.time() - start_time
        results["processing_times"].append(processing_time)
        
        # Determine ground truth
        is_actual_sqli = "sqli_type" in log
        
        # Update metrics
        if is_actual_sqli and is_sqli:
            results["true_positives"] += 1
            status = "TP"
        elif not is_actual_sqli and not is_sqli:
            results["true_negatives"] += 1
            status = "TN"
        elif not is_actual_sqli and is_sqli:
            results["false_positives"] += 1
            status = "FP"
        else:  # is_actual_sqli and not is_sqli
            results["false_negatives"] += 1
            status = "FN"
        
        # Store detection details
        detection_detail = {
            "log_index": i + 1,
            "is_actual_sqli": is_actual_sqli,
            "is_detected_sqli": is_sqli,
            "score": score,
            "confidence": confidence,
            "patterns": patterns,
            "processing_time": processing_time,
            "sqli_type": log.get("sqli_type", "Clean"),
            "status": status
        }
        results["detection_details"].append(detection_detail)
        
        # Update SQLi type accuracy
        if is_actual_sqli:
            sqli_type = log["sqli_type"]
            if sqli_type not in results["sqli_type_accuracy"]:
                results["sqli_type_accuracy"][sqli_type] = {"total": 0, "detected": 0}
            results["sqli_type_accuracy"][sqli_type]["total"] += 1
            if is_sqli:
                results["sqli_type_accuracy"][sqli_type]["detected"] += 1
        
        # Progress indicator
        if (i + 1) % 100 == 0:
            print(f"Progress: {i + 1}/{len(all_logs)} logs processed...")
    
    results["end_time"] = time.time()
    results["total_time"] = results["end_time"] - results["start_time"]
    
    print()
    print("=" * 80)
    print("PERFORMANCE TEST RESULTS")
    print("=" * 80)
    
    # Calculate metrics
    total_logs = results["total_logs"]
    tp = results["true_positives"]
    tn = results["true_negatives"]
    fp = results["false_positives"]
    fn = results["false_negatives"]
    
    accuracy = (tp + tn) / total_logs if total_logs > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    avg_processing_time = np.mean(results["processing_times"])
    min_processing_time = np.min(results["processing_times"])
    max_processing_time = np.max(results["processing_times"])
    
    # Print results
    print(f"OVERALL METRICS:")
    print(f"   Total Logs Processed: {total_logs}")
    print(f"   Clean Logs: {results['clean_logs']}")
    print(f"   SQLi Logs: {results['sqli_logs']}")
    print()
    
    print(f"DETECTION RESULTS:")
    print(f"   True Positives (TP): {tp} - SQLi detected correctly")
    print(f"   True Negatives (TN): {tn} - Clean logs not detected")
    print(f"   False Positives (FP): {fp} - Clean logs detected as SQLi")
    print(f"   False Negatives (FN): {fn} - SQLi not detected")
    print()
    
    print(f"PERFORMANCE METRICS:")
    print(f"   Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"   Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"   Recall: {recall:.4f} ({recall*100:.2f}%)")
    print(f"   F1-Score: {f1_score:.4f} ({f1_score*100:.2f}%)")
    print(f"   False Positive Rate: {false_positive_rate:.4f} ({false_positive_rate*100:.2f}%)")
    print(f"   False Negative Rate: {false_negative_rate:.4f} ({false_negative_rate*100:.2f}%)")
    print()
    
    print(f"PROCESSING PERFORMANCE:")
    print(f"   Total Processing Time: {results['total_time']:.2f} seconds")
    print(f"   Average Time per Log: {avg_processing_time:.4f} seconds")
    print(f"   Min Processing Time: {min_processing_time:.4f} seconds")
    print(f"   Max Processing Time: {max_processing_time:.4f} seconds")
    print(f"   Logs per Second: {total_logs/results['total_time']:.2f}")
    print()
    
    print(f"SQLi TYPE DETECTION ACCURACY:")
    for sqli_type, stats in results["sqli_type_accuracy"].items():
        accuracy = stats["detected"] / stats["total"] if stats["total"] > 0 else 0
        print(f"   {sqli_type}: {stats['detected']}/{stats['total']} ({accuracy*100:.1f}%)")
    print()
    
    # Performance rating
    if accuracy >= 0.99 and false_positive_rate <= 0.01:
        rating = "EXCELLENT"
    elif accuracy >= 0.95 and false_positive_rate <= 0.05:
        rating = "VERY GOOD"
    elif accuracy >= 0.90 and false_positive_rate <= 0.10:
        rating = "GOOD"
    elif accuracy >= 0.80:
        rating = "ACCEPTABLE"
    else:
        rating = "NEEDS IMPROVEMENT"
    
    print(f"OVERALL RATING: {rating}")
    print("=" * 80)
    
    # Save detailed report
    report_filename = f"performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"Detailed report saved to: {report_filename}")
    
    return results

if __name__ == "__main__":
    try:
        results = run_performance_test()
        print("\nPerformance test completed successfully!")
    except Exception as e:
        print(f"\nError during performance test: {e}")
        import traceback
        traceback.print_exc()

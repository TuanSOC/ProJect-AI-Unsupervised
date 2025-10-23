#!/usr/bin/env python3
"""
Debug threshold issue in _is_real_threat filter
"""

import json
import sys
import os
import numpy as np

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from realtime_log_collector import RealtimeLogCollector

def debug_threshold_issue():
    """Debug threshold issue in _is_real_threat filter"""
    
    print("=" * 80)
    print("DEBUGGING THRESHOLD ISSUE IN _is_real_threat FILTER")
    print("=" * 80)
    
    # Initialize collector
    collector = RealtimeLogCollector(
        log_path="/var/log/apache2/access_full_json.log",
        webhook_url="http://localhost:5000/api/realtime-detect"
    )
    
    # Test case that was blocked
    test_log = {
        "time": "2025-10-23T15:15:07+0700",
        "remote_ip": "192.168.205.2",
        "method": "GET",
        "uri": "/DVWA/vulnerabilities/sqli_blind/index.php",
        "query_string": "?id=m%C3%ACnh+ch%E1%BB%A7+y%E1%BA%BFu+detect+sqli+m%C3%A0+ha+%E1%BB%ABm+%40Thanhdat+m%C3%A0+c%C3%A1i+%C4%91o%E1%BA%A1n+base64+%C4%91%E1%BA%A7u+c%E1%BB%A7a+n%C3%B3+ngh%C4%A9a+l%C3%A0+g%C3%AC+th%E1%BA%BF+..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C+%3A%29%29%29+path+traversal+m%C3%A0+v%C3%AD+d%E1%BB%A5+nh%C6%B0+n%C3%B3+c%C5%A9ng+d%E1%BA%A1ng+ch%C3%A8n+v%C3%A0o+payload+th%C3%AC+c%C3%B3+n%C3%AAn+l%C3%A0m+cho+AI+n%C3%B3+hi%E1%BB%83u+l%C3%A0+b%E1%BA%A5t+th%C6%B0%E1%BB%9Dng+ko+C%C3%B3+%C4%91%E1%BB%83+khuya+xem+ng%E1%BB%93i+xem+m%E1%BA%A5y+c%C3%A1i+c%C3%B4ng+th%E1%BB%A9c+ngu+m%E1%BA%B9+c%C3%A1i+%C4%91%E1%BA%A7u+g%E1%BA%A7n+hi%E1%BB%83u+r%E1%BB%93i+MScgQU5EIChTRUxFQ1QgMSBGUk9NIChTRUxFQ1QgQ09VTlQoKiksIENPTkNBVCh1c2VyKCksIEZMT09SKFJBTkQoKSoyKSkgeCBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgR1JPVVAgQlkgeCkgYSkgLS0g%23&Submit=Submit",
        "status": 404,
        "bytes_sent": 4709,
        "response_time_ms": 9861,
        "referer": "http://localhost/DVWA/vulnerabilities/sqli_blind/",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "request_length": 3375,
        "response_length": 5021,
        "cookie": "wz-user=admin; wz-api=default; wz-token=eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzU4Nzg3NTMxLCJleHAiOjE3NTg3ODg0MzEsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AesxoYn2Mswm57ZVr629sOm17LOZ9CZsYHZrBA9iJD0VIX6dhKYvdmliAam4Bz0t0ESzWhJBxRzWDcp0mbTaQfp7AItpDAA7FYRdttfxSzWRRQDQfJqdn92jw7mKWhVmfNdVi0LIuX3v5NBuEDo5DxQg4qOl0dVw4fWMVRpXkmTVqSQv; security_authentication=Fe26.2**0b0867848a70274f49c818e99c198bd4102ceb8974cd525082ce5776fb8e8c36*bt1d6pcVRjEu19un5Jvw7w*-L2I70BJALAVmDIMBIOAJY-ZFN5GxhzRtvaSxo9KyRnR-g5ePzgQBIEQmtMOZHl48IaTEjb2udup33PDNAu-e_qD5nrt_08mQGGCFRaLb_-q3U1iU-Y6N-XhdsE2tVOujUq9N-HUlJpOlgWd2KAHYy4WoTUnFVZZHvh6ZZttfNlIYgZKwzcjvafOHJlFV_ZdE1OO74rBvBuAXloTx5YJiA**d1dd55bddb24a94e17b8b9b692a4de94376a478cdb5705ea0410b2b452176ccc*yIBWZjhJtUNQOSbGOXUq-Ycj4CRKFUdKWCbHwIapAwY; security=low; __next_hmr_refresh_hash__=eaef24bda92b27543c11ee4808b99ea8633457081244afec; PHPSESSID=e16qs57nkd675aj4u44nv78r6s",
        "payload": "id=m%C3%ACnh+ch%E1%BB%A7+y%E1%BA%BFu+detect+sqli+m%C3%A0+ha+%E1%BB%ABm+%40Thanhdat+m%C3%A0+c%C3%A1i+%C4%91o%E1%BA%A1n+base64+%C4%91%E1%BA%A7u+c%E1%BB%A7a+n%C3%B3+ngh%C4%A9a+l%C3%A0+g%C3%AC+th%E1%BA%BF+..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C+%3A%29%29%29+path+traversal+m%C3%A0+v%C3%AD+d%E1%BB%A5+nh%C6%B0+n%C3%B3+c%C5%A9ng+d%E1%BA%A1ng+ch%C3%A8n+v%C3%A0o+payload+th%C3%AC+c%C3%B3+n%C3%AAn+l%C3%A0m+cho+AI+n%C3%B3+hi%E1%BB%83u+l%C3%A0+b%E1%BA%A5t+th%C6%B0%E1%BB%9Dng+ko+C%C3%B3+%C4%91%E1%BB%83+khuya+xem+ng%E1%BB%93i+xem+m%E1%BA%A5y+c%C3%A1i+c%C3%B4ng+th%E1%BB%A9c+ngu+m%E1%BA%B9+c%C3%A1i+%C4%91%E1%BA%A7u+g%E1%BA%A7n+hi%E1%BB%83u+r%E1%BB%93i+MScgQU5EIChTRUxFQ1QgMSBGUk9NIChTRUxFQ1QgQ09VTlQoKiksIENPTkNBVCh1c2VyKCksIEZMT09SKFJBTkQoKSoyKSkgeCBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgR1JPVVAgQlkgeCkgYSkgLS0g%23&Submit=Submit",
        "session_token": "e16qs57nkd675aj4u44nv78r6s"
    }
    
    # Get detection result
    detection_result = collector.detect_sqli_realtime(test_log)
    print(f"Detection Result: {detection_result}")
    
    if not detection_result or not detection_result.get('is_sqli'):
        print("❌ No SQLi detected, cannot debug threshold")
        return
    
    score = detection_result.get('score', 0)
    print(f"\n1. AI Model Score: {score:.4f}")
    
    # Check model threshold
    model_threshold = 0.5  # Default
    if hasattr(collector.detector, 'sqli_score_threshold') and collector.detector.sqli_score_threshold:
        raw_threshold = collector.detector.sqli_score_threshold
        model_threshold = 1 / (1 + np.exp(-raw_threshold))
        print(f"2. Raw Threshold: {raw_threshold:.4f}")
        print(f"3. Normalized Threshold: {model_threshold:.4f}")
    else:
        print(f"2. Using Default Threshold: {model_threshold:.4f}")
    
    print(f"4. Score vs Threshold: {score:.4f} {'>=' if score >= model_threshold else '<'} {model_threshold:.4f}")
    print(f"5. Threshold Check: {'PASS' if score >= model_threshold else 'FAIL'}")
    
    # Check other conditions
    print(f"\n6. Checking other conditions:")
    
    # Get features
    features = collector.detector.extract_optimized_features(test_log)
    print(f"   - has_union_select: {features.get('has_union_select', 0)}")
    print(f"   - has_information_schema: {features.get('has_information_schema', 0)}")
    print(f"   - base64_sqli_patterns: {features.get('base64_sqli_patterns', 0)}")
    print(f"   - has_nosql_patterns: {features.get('has_nosql_patterns', 0)}")
    print(f"   - has_overlong_utf8: {features.get('has_overlong_utf8', 0)}")
    print(f"   - sqli_risk_score: {features.get('sqli_risk_score', 0)}")
    
    # Check advanced patterns
    has_advanced_patterns = (
        features.get('has_union_select', 0) == 1 or
        features.get('has_information_schema', 0) == 1 or
        features.get('has_mysql_functions', 0) == 1 or
        features.get('has_boolean_blind', 0) == 1 or
        features.get('has_time_based', 0) == 1 or
        features.get('has_comment_injection', 0) == 1 or
        features.get('base64_sqli_patterns', 0) > 0 or
        features.get('has_nosql_patterns', 0) == 1 or
        features.get('has_nosql_operators', 0) == 1 or
        features.get('has_json_injection', 0) == 1 or
        features.get('has_overlong_utf8', 0) == 1
    )
    print(f"   - has_advanced_patterns: {has_advanced_patterns}")
    
    # Check SQL content
    query_string = test_log.get('query_string', '')
    payload = test_log.get('payload', '')
    suspicious_content = query_string + ' ' + payload
    
    sql_keywords = [
        'union', 'select', 'insert', 'update', 'delete', 'drop', 'exec', 'script',
        'benchmark', 'sleep', 'waitfor', 'version', 'user', 'database', 'table',
        'information_schema', 'mysql', 'or 1=1', 'and 1=1', "' or '", '" or "',
        '--', '/*', '*/', '0x', 'char(', 'ascii(', 'substring', 'concat',
        'load_file', 'into outfile', 'xp_cmdshell', 'sp_executesql',
        '%c0%ae', '%c1%9c', '%c0%af', '%c1%9d',  # Overlong UTF-8
        'base64', 'encoded', 'urlencoded', 'double encoded',
        'nosql', 'mongodb', '$where', '$ne', '$gt', '$regex',
        'json', 'javascript', 'eval', 'function'
    ]
    
    has_sql_content = any(keyword in suspicious_content.lower() for keyword in sql_keywords)
    print(f"   - has_sql_content: {has_sql_content}")
    
    # Check risk score
    risk_score = features.get('sqli_risk_score', 0)
    has_high_risk = risk_score >= 30
    print(f"   - risk_score: {risk_score}")
    print(f"   - has_high_risk: {has_high_risk}")
    
    # Final result
    final_result = (has_sql_content or has_advanced_patterns or has_high_risk)
    print(f"\n7. Final _is_real_threat result: {final_result}")
    
    print(f"\n" + "="*80)
    print("THRESHOLD DEBUG COMPLETE")
    print("="*80)

if __name__ == "__main__":
    debug_threshold_issue()

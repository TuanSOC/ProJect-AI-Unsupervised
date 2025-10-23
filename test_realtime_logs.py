#!/usr/bin/env python3
"""
Test realtime logs directly - Debug why realtime collector doesn't detect
"""

from optimized_sqli_detector import OptimizedSQLIDetector
import json
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_realtime_logs():
    """Test the exact logs from realtime collector"""
    
    print("=" * 80)
    print("TEST REALTIME LOGS - DEBUG DETECTION")
    print("=" * 80)
    
    # Load model
    detector = OptimizedSQLIDetector()
    detector.load_model('models/optimized_sqli_detector.pkl')
    
    # Test logs từ realtime collector
    test_logs = [
        {
            "name": "Overlong UTF-8 Payload",
            "log": {
                "time": "2025-10-23T13:21:58+0700",
                "remote_ip": "192.168.205.2",
                "method": "GET",
                "uri": "/DVWA/vulnerabilities/sqli/index.php",
                "query_string": "?id=%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2Fetc%2Fpasswd&Submit=Submit",
                "status": 200,
                "bytes_sent": 1437,
                "response_time_ms": 13586,
                "referer": "http://localhost/DVWA/vulnerabilities/sqli/",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
                "request_length": 2164,
                "response_length": 1788,
                "cookie": "wz-user=admin; wz-api=default; wz-token=eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzU4Nzg3NTMxLCJleHAiOjE3NTg3ODg0MzEsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AesxoYn2Mswm57ZVr629sOm17LOZ9CZsYHZrBA9iJD0VIX6dhKYvdmliAam4Bz0t0ESzWhJBxRzWDcp0mbTaQfp7AItpDAA7FYRdttfxSzWRRQDQfJqdn92jw7mKWhVmfNdVi0LIuX3v5NBuEDo5DxQg4qOl0dVw4fWMVRpXkmTVqSQv; security_authentication=Fe26.2**0b0867848a70274f49c818e99c198bd4102ceb8974cd525082ce5776fb8e8c36*bt1d6pcVRjEu19un5Jvw7w*-L2I70BJALAVmDIMBIOAJY-ZFN5GxhzRtvaSxo9KyRnR-g5ePzgQBIEQmtMOZHl48IaTEjb2udup33PDNAu-e_qD5nrt_08mQGGCFRaLb_-q3U1iU-Y6N-XhdsE2tVOujUq9N-HUlJpOlgWd2KAHYy4WoTUnFVZZHvh6ZZttfNlIYgZKwzcjvafOHJlFV_ZdE1OO74rBvBuAXloTx5YJiA**d1dd55bddb24a94e17b8b9b692a4de94376a478cdb5705ea0410b2b452176ccc*yIBWZjhJtUNQOSbGOXUq-Ycj4CRKFUdKWCbHwIapAwY; security=low; __next_hmr_refresh_hash__=eaef24bda92b27543c11ee4808b99ea8633457081244afec; PHPSESSID=e16qs57nkd675aj4u44nv78r6s",
                "payload": "id=%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2Fetc%2Fpasswd&Submit=Submit",
                "session_token": "e16qs57nkd675aj4u44nv78r6s"
            }
        },
        {
            "name": "Base64 Payload",
            "log": {
                "time": "2025-10-23T13:23:46+0700",
                "remote_ip": "192.168.205.2",
                "method": "GET",
                "uri": "/DVWA/vulnerabilities/sqli/index.php",
                "query_string": "?id=MScgQU5EIChTRUxFQ1QgMSBGUk9NIChTRUxFQ1QgQ09VTlQoKiksIENPTkNBVCh1c2VyKCksIEZMT09SKFJBTkQoKSoyKSkgeCBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgR1JPVVAgQlkgeCkgYSkgLS0g%23&Submit=Submit",
                "status": 200,
                "bytes_sent": 1437,
                "response_time_ms": 11654,
                "referer": "http://localhost/DVWA/vulnerabilities/sqli/?id=-999.9%2BUNION%2BALL%2BSELECT%2B%2528SELECT%2BCAST%2528CHAR%2528114%2529%252BCHAR%252851%2529%252BCHAR%2528100%2529%252BCHAR%2528109%2529%252BCHAR%252848%2529%252BCHAR%2528118%2529%252BCHAR%252851%2529%252BCHAR%252895%2529%252BCHAR%2528104%2529%252BCHAR%2528118%2529%252BCHAR%2528106%2529%252BCHAR%252895%2529%252BCHAR%2528105%2529%252BCHAR%2528110%2529%252BCHAR%2528106%2529%252BCHAR%2528101%2529%252BCHAR%252899%2529%252BCHAR%2528116%2529%252BCHAR%2528105%2529%252BCHAR%2528111%2529%252BCHAR%2528110%2529%2BAS%2BNVARCHAR%25284000%2529%2529%2529%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL&Submit=Submit",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
                "request_length": 2723,
                "response_length": 1789,
                "cookie": "wz-user=admin; wz-api=default; wz-token=eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzU4Nzg3NTMxLCJleHAiOjE3NTg3ODg0MzEsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AesxoYn2Mswm57ZVr629sOm17LOZ9CZsYHZrBA9iJD0VIX6dhKYvdmliAam4Bz0t0ESzWhJBxRzWDcp0mbTaQfp7AItpDAA7FYRdttfxSzWRRQDQfJqdn92jw7mKWhVmfNdVi0LIuX3v5NBuEDo5DxQg4qOl0dVw4fWMVRpXkmTVqSQv; security_authentication=Fe26.2**0b0867848a70274f49c818e99c198bd4102ceb8974cd525082ce5776fb8e8c36*bt1d6pcVRjEu19un5Jvw7w*-L2I70BJALAVmDIMBIOAJY-ZFN5GxhzRtvaSxo9KyRnR-g5ePzgQBIEQmtMOZHl48IaTEjb2udup33PDNAu-e_qD5nrt_08mQGGCFRaLb_-q3U1iU-Y6N-XhdsE2tVOujUq9N-HUlJpOlgWd2KAHYy4WoTUnFVZZHvh6ZZttfNlIYgZKwzcjvafOHJlFV_ZdE1OO74rBvBuAXloTx5YJiA**d1dd55bddb24a94e17b8b9b692a4de94376a478cdb5705ea0410b2b452176ccc*yIBWZjhJtUNQOSbGOXUq-Ycj4CRKFUdKWCbHwIapAwY; security=low; __next_hmr_refresh_hash__=eaef24bda92b27543c11ee4808b99ea8633457081244afec; PHPSESSID=e16qs57nkd675aj4u44nv78r6s",
                "payload": "id=MScgQU5EIChTRUxFQ1QgMSBGUk9NIChTRUxFQ1QgQ09VTlQoKiksIENPTkNBVCh1c2VyKCksIEZMT09SKFJBTkQoKSoyKSkgeCBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgR1JPVVAgQlkgeCkgYSkgLS0g%23&Submit=Submit",
                "session_token": "e16qs57nkd675aj4u44nv78r6s"
            }
        }
    ]
    
    for i, test_case in enumerate(test_logs):
        print(f"\n{'='*60}")
        print(f"TEST {i+1}: {test_case['name']}")
        print(f"{'='*60}")
        
        log = test_case['log']
        print(f"URI: {log['uri']}")
        print(f"Query: {log['query_string'][:100]}...")
        print(f"Payload: {log['payload'][:100]}...")
        
        try:
            # Test detection
            is_sqli, score, patterns, confidence = detector.predict_single(log)
            
            print(f"\nDetection Result:")
            print(f"  Is SQLi: {is_sqli}")
            print(f"  Score: {score:.4f}")
            print(f"  Patterns: {patterns}")
            print(f"  Confidence: {confidence}")
            
            # Get detailed features
            features = detector.extract_optimized_features(log)
            
            print(f"\nKey Features:")
            print(f"  sqli_risk_score: {features.get('sqli_risk_score', 'NOT FOUND')}")
            print(f"  sqli_patterns: {features.get('sqli_patterns', 'NOT FOUND')}")
            print(f"  has_base64_payload: {features.get('has_base64_payload', 'NOT FOUND')}")
            print(f"  has_base64_query: {features.get('has_base64_query', 'NOT FOUND')}")
            print(f"  base64_sqli_patterns: {features.get('base64_sqli_patterns', 'NOT FOUND')}")
            print(f"  special_chars: {features.get('special_chars', 'NOT FOUND')}")
            print(f"  sql_keywords: {features.get('sql_keywords', 'NOT FOUND')}")
            print(f"  has_union_select: {features.get('has_union_select', 'NOT FOUND')}")
            print(f"  has_boolean_blind: {features.get('has_boolean_blind', 'NOT FOUND')}")
            print(f"  has_information_schema: {features.get('has_information_schema', 'NOT FOUND')}")
            print(f"  has_overlong_utf8: {features.get('has_overlong_utf8', 'NOT FOUND')}")
            
            if is_sqli:
                print(f"\n✅ SQLi DETECTED!")
            else:
                print(f"\n❌ SQLi NOT DETECTED!")
                
                # Analyze why not detected
                risk_score = features.get('sqli_risk_score', 0)
                has_pattern = features.get('sqli_patterns', 0) > 0
                has_base64 = features.get('has_base64_payload', 0) == 1 or features.get('has_base64_query', 0) == 1
                base64_patterns = features.get('base64_sqli_patterns', 0)
                has_overlong = features.get('has_overlong_utf8', 0) == 1
                
                print(f"\nAnalysis:")
                if risk_score < 50:
                    print(f"  -> Risk score too low: {risk_score} < 50")
                if not has_pattern:
                    print(f"  -> No SQLi patterns found: {features.get('sqli_patterns', 0)}")
                if not has_base64:
                    print(f"  -> Base64 not detected: payload={features.get('has_base64_payload', 0)}, query={features.get('has_base64_query', 0)}")
                if base64_patterns == 0:
                    print(f"  -> No Base64 SQLi patterns found: {base64_patterns}")
                if not has_overlong:
                    print(f"  -> No Overlong UTF-8 detected: {has_overlong}")
        
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*80)
    print("TEST COMPLETED!")
    print("="*80)

if __name__ == "__main__":
    test_realtime_logs()

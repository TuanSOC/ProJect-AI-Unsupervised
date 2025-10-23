#!/usr/bin/env python3
"""
Test specific log that's causing issues
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

def test_specific_log():
    """Test the specific log that's causing issues"""
    
    print("=" * 80)
    print("TEST SPECIFIC LOG - DEBUG ISSUES")
    print("=" * 80)
    
    # Load model
    detector = OptimizedSQLIDetector()
    detector.load_model('models/optimized_sqli_detector.pkl')
    
    # Test the specific log that's causing issues
    test_log = {
        "time": "2025-10-23T14:30:19+0700",
        "remote_ip": "192.168.205.2",
        "method": "GET",
        "uri": "/DVWA/vulnerabilities/sqli/index.php",
        "query_string": "?id=admin%27%29+or+%28%271%27%3D%271%27%23&Submit=Submit",
        "status": 500,
        "bytes_sent": 0,
        "response_time_ms": 16685,
        "referer": "http://localhost/DVWA/vulnerabilities/sqli/?id=%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2Fetc%2Fpasswd&Submit=Submit",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "request_length": 2244,
        "response_length": 295,
        "cookie": "wz-user=admin; wz-api=default; wz-token=eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzU4Nzg3NTMxLCJleHAiOjE3NTg3ODg0MzEsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AesxoYn2Mswm57ZVr629sOm17LOZ9CZsYHZrBA9iJD0VIX6dhKYvdmliAam4Bz0t0ESzWhJBxRzWDcp0mbTaQfp7AItpDAA7FYRdttfxSzWRRQDQfJqdn92jw7mKWhVmfNdVi0LIuX3v5NBuEDo5DxQg4qOl0dVw4fWMVRpXkmTVqSQv; security_authentication=Fe26.2**0b0867848a70274f49c818e99c198bd4102ceb8974cd525082ce5776fb8e8c36*bt1d6pcVRjEu19un5Jvw7w*-L2I70BJALAVmDIMBIOAJY-ZFN5GxhzRtvaSxo9KyRnR-g5ePzgQBIEQmtMOZHl48IaTEjb2udup33PDNAu-e_qD5nrt_08mQGGCFRaLb_-q3U1iU-Y6N-XhdsE2tVOujUq9N-HUlJpOlgWd2KAHYy4WoTUnFVZZHvh6ZZttfNlIYgZKwzcjvafOHJlFV_ZdE1OO74rBvBuAXloTx5YJiA**d1dd55bddb24a94e17b8b9b692a4de94376a478cdb5705ea0410b2b452176ccc*yIBWZjhJtUNQOSbGOXUq-Ycj4CRKFUdKWCbHwIapAwY; security=low; __next_hmr_refresh_hash__=eaef24bda92b27543c11ee4808b99ea8633457081244afec; PHPSESSID=e16qs57nkd675aj4u44nv78r6s",
        "payload": "id=admin%27%29+or+%28%271%27%3D%271%27%23&Submit=Submit",
        "session_token": "e16qs57nkd675aj4u44nv78r6s"
    }
    
    print(f"URI: {test_log['uri']}")
    print(f"Query: {test_log['query_string']}")
    print(f"Payload: {test_log['payload']}")
    print(f"Status: {test_log['status']}")
    
    try:
        # Test detection
        is_sqli, score, patterns, confidence = detector.predict_single(test_log)
        
        print(f"\nDetection Result:")
        print(f"  Is SQLi: {is_sqli}")
        print(f"  Score: {score:.4f}")
        print(f"  Patterns: {patterns}")
        print(f"  Confidence: {confidence}")
        
        # Get detailed features
        features = detector.extract_optimized_features(test_log)
        
        print(f"\nKey Features:")
        print(f"  sqli_risk_score: {features.get('sqli_risk_score', 'NOT FOUND')}")
        print(f"  sqli_patterns: {features.get('sqli_patterns', 'NOT FOUND')}")
        print(f"  special_chars: {features.get('special_chars', 'NOT FOUND')}")
        print(f"  sql_keywords: {features.get('sql_keywords', 'NOT FOUND')}")
        print(f"  has_union_select: {features.get('has_union_select', 'NOT FOUND')}")
        print(f"  has_boolean_blind: {features.get('has_boolean_blind', 'NOT FOUND')}")
        print(f"  has_comment_injection: {features.get('has_comment_injection', 'NOT FOUND')}")
        
        if is_sqli:
            print(f"\n✅ SQLi DETECTED!")
        else:
            print(f"\n❌ SQLi NOT DETECTED!")
            
            # Analyze why not detected
            risk_score = features.get('sqli_risk_score', 0)
            has_pattern = features.get('sqli_patterns', 0) > 0
            
            print(f"\nAnalysis:")
            if risk_score < 50:
                print(f"  -> Risk score too low: {risk_score} < 50")
            if not has_pattern:
                print(f"  -> No SQLi patterns found: {features.get('sqli_patterns', 0)}")
    
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*80)
    print("TEST COMPLETED!")
    print("="*80)

if __name__ == "__main__":
    test_specific_log()

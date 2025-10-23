#!/usr/bin/env python3
"""
Retrain model on Ubuntu with current scikit-learn version
"""

from optimized_sqli_detector import OptimizedSQLIDetector
import sklearn
import sys

def retrain_ubuntu_model():
    """Retrain model on Ubuntu"""
    
    print("=" * 60)
    print("RETRAIN UBUNTU MODEL")
    print("=" * 60)
    
    print(f"Python version: {sys.version}")
    print(f"scikit-learn version: {sklearn.__version__}")
    
    try:
        # Create detector
        detector = OptimizedSQLIDetector()
        
        # Train with current scikit-learn version
        print("Training model with current scikit-learn version...")
        detector.train_from_path('sqli_logs_clean_100k.jsonl')
        
        print("✅ Model retrained successfully!")
        
        # Test model loading
        print("Testing model loading...")
        detector2 = OptimizedSQLIDetector()
        detector2.load_model('models/optimized_sqli_detector.pkl')
        print("✅ Model loaded successfully!")
        
        # Test with Base64 payload
        test_log = {
            "time": "2025-10-23T12:56:15+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/sqli_blind/index.php",
            "query_string": "?id=MScgQU5EIChTRUxFQ1QgMSBGUk9NIChTRUxFQ1QgQ09VTlQoKiksIENPTkNBVCh1c2VyKCksIEZMT09SKFJBTkQoKSoyKSkgeCBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgR1JPVVAgQlkgeCkgYSkgLS0g%23&Submit=Submit",
            "status": 404,
            "bytes_sent": 4709,
            "response_time_ms": 5255,
            "referer": "http://localhost/DVWA/vulnerabilities/sqli_blind/",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
            "request_length": 1992,
            "response_length": 5020,
            "cookie": "wz-user=admin; wz-api=default; wz-token=eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzU4Nzg3NTMxLCJleHAiOjE3NTg3ODg0MzEsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AesxoYn2Mswm57ZVr629sOm17LOZ9CZsYHZrBA9iJD0VIX6dhKYvdmliAam4Bz0t0ESzWhJBxRzWDcp0mbTaQfp7AItpDAA7FYRdttfxSzWRRQDQfJqdn92jw7mKWhVmfNdVi0LIuX3v5NBuEDo5DxQg4qOl0dVw4fWMVRpXkmTVqSQv; security_authentication=Fe26.2**0b0867848a70274f49c818e99c198bd4102ceb8974cd525082ce5776fb8e8c36*bt1d6pcVRjEu19un5Jvw7w*-L2I70BJALAVmDIMBIOAJY-ZFN5GxhzRtvaSxo9KyRnR-g5ePzgQBIEQmtMOZHl48IaTEjb2udup33PDNAu-e_qD5nrt_08mQGGCFRaLb_-q3U1iU-Y6N-XhdsE2tVOujUq9N-HUlJpOlgWd2KAHYy4WoTUnFVZZHvh6ZZttfNlIYgZKwzcjvafOHJlFV_ZdE1OO74rBvBuAXloTx5YJiA**d1dd55bddb24a94e17b8b9b692a4de94376a478cdb5705ea0410b2b452176ccc*yIBWZjhJtUNQOSbGOXUq-Ycj4CRKFUdKWCbHwIapAwY; security=low; __next_hmr_refresh_hash__=eaef24bda92b27543c11ee4808b99ea8633457081244afec; PHPSESSID=e16qs57nkd675aj4u44nv78r6s",
            "payload": "id=MScgQU5EIChTRUxFQ1QgMSBGUk9NIChTRUxFQ1QgQ09VTlQoKiksIENPTkNBVCh1c2VyKCksIEZMT09SKFJBTkQoKSoyKSkgeCBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgR1JPVVAgQlkgeCkgYSkgLS0g%23&Submit=Submit",
            "session_token": "e16qs57nkd675aj4u44nv78r6s"
        }
        
        print("Testing Base64 payload detection...")
        is_sqli, score, patterns, confidence = detector2.predict_single(test_log)
        
        print(f"Base64 Test Result:")
        print(f"  Is SQLi: {is_sqli}")
        print(f"  Score: {score:.4f}")
        print(f"  Patterns: {patterns}")
        print(f"  Confidence: {confidence}")
        
        if is_sqli:
            print("✅ Base64 SQLi detection working!")
        else:
            print("❌ Base64 SQLi detection failed!")
            
            # Get features for analysis
            features = detector2.extract_optimized_features(test_log)
            print(f"  Risk Score: {features.get('sqli_risk_score', 0):.2f}")
            print(f"  Base64 Payload: {features.get('has_base64_payload', 0)}")
            print(f"  Base64 Query: {features.get('has_base64_query', 0)}")
            print(f"  Base64 SQLi Patterns: {features.get('base64_sqli_patterns', 0)}")
        
        print("=" * 60)
        print("RETRAIN COMPLETED!")
        print("=" * 60)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    retrain_ubuntu_model()

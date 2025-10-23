#!/usr/bin/env python3
"""
Debug why some SQLi payloads are not being detected
"""

import json
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from realtime_log_collector import RealtimeLogCollector

def debug_missed_detections():
    """Debug why some SQLi payloads are not detected"""
    
    print("=" * 80)
    print("DEBUGGING MISSED SQLi DETECTIONS")
    print("=" * 80)
    
    # Initialize collector
    collector = RealtimeLogCollector(
        log_path="/var/log/apache2/access_full_json.log",
        webhook_url="http://localhost:5000/api/realtime-detect"
    )
    
    # Test cases from the logs
    test_cases = [
        {
            "name": "Complex CHAR SQLi (DETECTED)",
            "log": {
                "time": "2025-10-23T15:15:30+0700",
                "remote_ip": "192.168.205.2",
                "method": "GET",
                "uri": "/DVWA/vulnerabilities/sqli_blind/index.php",
                "query_string": "?id=-999.9%2BUNION%2BALL%2BSELECT%2B%2528SELECT%2BCAST%2528CHAR%2528114%2529%252BCHAR%252851%2529%252BCHAR%2528100%2529%252BCHAR%2528109%2529%252BCHAR%252848%2529%252BCHAR%2528118%2529%252BCHAR%252851%2529%252BCHAR%252895%2529%252BCHAR%2528104%2529%252BCHAR%2528118%2529%252BCHAR%2528106%2529%252BCHAR%252895%2529%252BCHAR%2528105%2529%252BCHAR%2528110%2529%252BCHAR%2528106%2529%252BCHAR%2528101%2529%252BCHAR%252899%2529%252BCHAR%2528116%2529%252BCHAR%2528105%2529%252BCHAR%2528111%2529%252BCHAR%2528110%2529%2BAS%2BNVARCHAR%25284000%2529%2529%2529%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL&Submit=Submit",
                "status": 404,
                "bytes_sent": 4709,
                "response_time_ms": 7815,
                "referer": "http://localhost/DVWA/vulnerabilities/sqli_blind/",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
                "request_length": 2919,
                "response_length": 5021,
                "cookie": "wz-user=admin; wz-api=default; wz-token=eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzU4Nzg3NTMxLCJleHAiOjE3NTg3ODg0MzEsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AesxoYn2Mswm57ZVr629sOm17LOZ9CZsYHZrBA9iJD0VIX6dhKYvdmliAam4Bz0t0ESzWhJBxRzWDcp0mbTaQfp7AItpDAA7FYRdttfxSzWRRQDQfJqdn92jw7mKWhVmfNdVi0LIuX3v5NBuEDo5DxQg4qOl0dVw4fWMVRpXkmTVqSQv; security_authentication=Fe26.2**0b0867848a70274f49c818e99c198bd4102ceb8974cd525082ce5776fb8e8c36*bt1d6pcVRjEu19un5Jvw7w*-L2I70BJALAVmDIMBIOAJY-ZFN5GxhzRtvaSxo9KyRnR-g5ePzgQBIEQmtMOZHl48IaTEjb2udup33PDNAu-e_qD5nrt_08mQGGCFRaLb_-q3U1iU-Y6N-XhdsE2tVOujUq9N-HUlJpOlgWd2KAHYy4WoTUnFVZZHvh6ZZttfNlIYgZKwzcjvafOHJlFV_ZdE1OO74rBvBuAXloTx5YJiA**d1dd55bddb24a94e17b8b9b692a4de94376a478cdb5705ea0410b2b452176ccc*yIBWZjhJtUNQOSbGOXUq-Ycj4CRKFUdKWCbHwIapAwY; security=low; __next_hmr_refresh_hash__=eaef24bda92b27543c11ee4808b99ea8633457081244afec; PHPSESSID=e16qs57nkd675aj4u44nv78r6s",
                "payload": "id=-999.9%2BUNION%2BALL%2BSELECT%2B%2528SELECT%2BCAST%2528CHAR%2528114%2529%252BCHAR%252851%2529%252BCHAR%2528100%2529%252BCHAR%2528109%2529%252BCHAR%252848%2529%252BCHAR%2528118%2529%252BCHAR%252851%2529%252BCHAR%252895%2529%252BCHAR%2528104%2529%252BCHAR%2528118%2529%252BCHAR%2528106%2529%252BCHAR%252895%2529%252BCHAR%2528105%2529%252BCHAR%2528110%2529%252BCHAR%2528106%2529%252BCHAR%2528101%2529%252BCHAR%252899%2529%252BCHAR%2528116%2529%252BCHAR%2528105%2529%252BCHAR%2528111%2529%252BCHAR%2528110%2529%2BAS%2BNVARCHAR%25284000%2529%2529%2529%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL&Submit=Submit",
                "session_token": "e16qs57nkd675aj4u44nv78r6s"
            }
        },
        {
            "name": "Vietnamese Text + Base64 SQLi (MISSED)",
            "log": {
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
        },
        {
            "name": "Overlong UTF-8 SQLi (MISSED)",
            "log": {
                "time": "2025-10-23T15:15:21+0700",
                "remote_ip": "192.168.205.2",
                "method": "GET",
                "uri": "/DVWA/vulnerabilities/sqli_blind/index.php",
                "query_string": "?id=%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2Fetc%2Fpasswd&Submit=Submit",
                "status": 404,
                "bytes_sent": 4709,
                "response_time_ms": 10102,
                "referer": "http://localhost/DVWA/vulnerabilities/sqli_blind/",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
                "request_length": 3000,
                "response_length": 5021,
                "cookie": "wz-user=admin; wz-api=default; wz-token=eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzU4Nzg3NTMxLCJleHAiOjE3NTg3ODg0MzEsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AesxoYn2Mswm57ZVr629sOm17LOZ9CZsYHZrBA9iJD0VIX6dhKYvdmliAam4Bz0t0ESzWhJBxRzWDcp0mbTaQfp7AItpDAA7FYRdttfxSzWRRQDQfJqdn92jw7mKWhVmfNdVi0LIuX3v5NBuEDo5DxQg4qOl0dVw4fWMVRpXkmTVqSQv; security_authentication=Fe26.2**0b0867848a70274f49c818e99c198bd4102ceb8974cd525082ce5776fb8e8c36*bt1d6pcVRjEu19un5Jvw7w*-L2I70BJALAVmDIMBIOAJY-ZFN5GxhzRtvaSxo9KyRnR-g5ePzgQBIEQmtMOZHl48IaTEjb2udup33PDNAu-e_qD5nrt_08mQGGCFRaLb_-q3U1iU-Y6N-XhdsE2tVOujUq9N-HUlJpOlgWd2KAHYy4WoTUnFVZZHvh6ZZttfNlIYgZKwzcjvafOHJlFV_ZdE1OO74rBvBuAXloTx5YJiA**d1dd55bddb24a94e17b8b9b692a4de94376a478cdb5705ea0410b2b452176ccc*yIBWZjhJtUNQOSbGOXUq-Ycj4CRKFUdKWCbHwIapAwY; security=low; __next_hmr_refresh_hash__=eaef24bda92b27543c11ee4808b99ea8633457081244afec; PHPSESSID=e16qs57nkd675aj4u44nv78r6s",
                "payload": "id=%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2Fetc%2Fpasswd&Submit=Submit",
                "session_token": "e16qs57nkd675aj4u44nv78r6s"
            }
        }
    ]
    
    detected_count = 0
    total_count = len(test_cases)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i}: {test_case['name']} ---")
        
        # Test detection
        result = collector.detect_sqli_realtime(test_case['log'])
        
        if result and result.get('is_sqli'):
            print(f"🚨 SQLi DETECTED!")
            print(f"   Score: {result.get('score', 0):.4f}")
            print(f"   Patterns: {result.get('detected_patterns', [])}")
            print(f"   Confidence: {result.get('confidence', 'N/A')}")
            detected_count += 1
        else:
            print(f"❌ SQLi NOT DETECTED")
            print(f"   Result: {result}")
            
            # Debug: Check individual features
            print(f"   Debug - Checking features:")
            try:
                features = collector.detector.extract_optimized_features(test_case['log'])
                print(f"   - has_sqli_pattern: {features.get('has_sqli_pattern', 0)}")
                print(f"   - sqli_risk_score: {features.get('sqli_risk_score', 0)}")
                print(f"   - has_union_select: {features.get('has_union_select', 0)}")
                print(f"   - has_base64_payload: {features.get('has_base64_payload', 0)}")
                print(f"   - has_overlong_utf8: {features.get('has_overlong_utf8', 0)}")
                print(f"   - base64_sqli_patterns: {features.get('base64_sqli_patterns', 0)}")
            except Exception as e:
                print(f"   Error extracting features: {e}")
    
    print(f"\n" + "="*80)
    print(f"DETECTION RESULTS: {detected_count}/{total_count} detected")
    print(f"Detection Rate: {(detected_count/total_count)*100:.1f}%")
    print("="*80)
    
    if detected_count < total_count:
        print("⚠️ Some SQLi attacks were missed. Check the feature extraction logic.")
    else:
        print("🎉 All SQLi attacks were detected!")

if __name__ == "__main__":
    debug_missed_detections()

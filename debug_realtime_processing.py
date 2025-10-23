#!/usr/bin/env python3
"""
Debug why realtime collector is not processing all SQLi logs
"""

import json
import sys
import os
import time
from datetime import datetime

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from realtime_log_collector import RealtimeLogCollector

def debug_realtime_processing():
    """Debug realtime processing logic"""
    
    print("=" * 80)
    print("DEBUGGING REALTIME PROCESSING LOGIC")
    print("=" * 80)
    
    # Initialize collector
    collector = RealtimeLogCollector(
        log_path="/var/log/apache2/access_full_json.log",
        webhook_url="http://localhost:5000/api/realtime-detect"
    )
    
    # Test the specific logs that appeared in the realtime output
    test_logs = [
        {
            "name": "Vietnamese Text + Base64 SQLi",
            "raw_log": '''{ 	"time": "2025-10-23T15:15:07+0700", 	"remote_ip": "192.168.205.2", 	"method": "GET", 	"uri": "/DVWA/vulnerabilities/sqli_blind/index.php", 	"query_string": "?id=m%C3%ACnh+ch%E1%BB%A7+y%E1%BA%BFu+detect+sqli+m%C3%A0+ha+%E1%BB%ABm+%40Thanhdat+m%C3%A0+c%C3%A1i+%C4%91o%E1%BA%A1n+base64+%C4%91%E1%BA%A7u+c%E1%BB%A7a+n%C3%B3+ngh%C4%A9a+l%C3%A0+g%C3%AC+th%E1%BA%BF+..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C+%3A%29%29%29+path+traversal+m%C3%A0+v%C3%AD+d%E1%BB%A5+nh%C6%B0+n%C3%B3+c%C5%A9ng+d%E1%BA%A1ng+ch%C3%A8n+v%C3%A0o+payload+th%C3%AC+c%C3%B3+n%C3%AAn+l%C3%A0m+cho+AI+n%C3%B3+hi%E1%BB%83u+l%C3%A0+b%E1%BA%A5t+th%C6%B0%E1%BB%9Dng+ko+C%C3%B3+%C4%91%E1%BB%83+khuya+xem+ng%E1%BB%93i+xem+m%E1%BA%A5y+c%C3%A1i+c%C3%B4ng+th%E1%BB%A9c+ngu+m%E1%BA%B9+c%C3%A1i+%C4%91%E1%BA%A7u+g%E1%BA%A7n+hi%E1%BB%83u+r%E1%BB%93i+MScgQU5EIChTRUxFQ1QgMSBGUk9NIChTRUxFQ1QgQ09VTlQoKiksIENPTkNBVCh1c2VyKCksIEZMT09SKFJBTkQoKSoyKSkgeCBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgR1JPVVAgQlkgeCkgYSkgLS0g%23&Submit=Submit", 	"status": 404, 	"bytes_sent": 4709, 	"response_time_ms": 9861, 	"referer": "http://localhost/DVWA/vulnerabilities/sqli_blind/?id=-999.9%2BUNION%2BALL%2BSELECT%2B%2528SELECT%2BCAST%2528CHAR%2528114%2529%252BCHAR%252851%2529%252BCHAR%2528100%2529%252BCHAR%2528109%2529%252BCHAR%252848%2529%252BCHAR%2528118%2529%252BCHAR%252851%2529%252BCHAR%252895%2529%252BCHAR%2528104%2529%252BCHAR%2528118%2529%252BCHAR%2528106%2529%252BCHAR%252895%2529%252BCHAR%2528105%2529%252BCHAR%2528110%2529%252BCHAR%2528106%2529%252BCHAR%2528101%2529%252BCHAR%252899%2529%252BCHAR%2528116%2529%252BCHAR%2528105%2529%252BCHAR%2528111%2529%252BCHAR%2528110%2529%2BAS%2BNVARCHAR%25284000%2529%2529%2529%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL%252CNULL&Submit=Submit", 	"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", 	"request_length": 3375, 	"response_length": 5021, 	"cookie": "wz-user=admin; wz-api=default; wz-token=eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzU4Nzg3NTMxLCJleHAiOjE3NTg3ODg0MzEsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AesxoYn2Mswm57ZVr629sOm17LOZ9CZsYHZrBA9iJD0VIX6dhKYvdmliAam4Bz0t0ESzWhJBxRzWDcp0mbTaQfp7AItpDAA7FYRdttfxSzWRRQDQfJqdn92jw7mKWhVmfNdVi0LIuX3v5NBuEDo5DxQg4qOl0dVw4fWMVRpXkmTVqSQv; security_authentication=Fe26.2**0b0867848a70274f49c818e99c198bd4102ceb8974cd525082ce5776fb8e8c36*bt1d6pcVRjEu19un5Jvw7w*-L2I70BJALAVmDIMBIOAJY-ZFN5GxhzRtvaSxo9KyRnR-g5ePzgQBIEQmtMOZHl48IaTEjb2udup33PDNAu-e_qD5nrt_08mQGGCFRaLb_-q3U1iU-Y6N-XhdsE2tVOujUq9N-HUlJpOlgWd2KAHYy4WoTUnFVZZHvh6ZZttfNlIYgZKwzcjvafOHJlFV_ZdE1OO74rBvBuAXloTx5YJiA**d1dd55bddb24a94e17b8b9b692a4de94376a478cdb5705ea0410b2b452176ccc*yIBWZjhJtUNQOSbGOXUq-Ycj4CRKFUdKWCbHwIapAwY; security=low; __next_hmr_refresh_hash__=eaef24bda92b27543c11ee4808b99ea8633457081244afec; PHPSESSID=e16qs57nkd675aj4u44nv78r6s", 	"payload": "id=m%C3%ACnh+ch%E1%BB%A7+y%E1%BA%BFu+detect+sqli+m%C3%A0+ha+%E1%BB%ABm+%40Thanhdat+m%C3%A0+c%C3%A1i+%C4%91o%E1%BA%A1n+base64+%C4%91%E1%BA%A7u+c%E1%BB%A7a+n%C3%B3+ngh%C4%A9a+l%C3%A0+g%C3%AC+th%E1%BA%BF+..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C+%3A%29%29%29+path+traversal+m%C3%A0+v%C3%AD+d%E1%BB%A5+nh%C6%B0+n%C3%B3+c%C5%A9ng+d%E1%BA%A1ng+ch%C3%A8n+v%C3%A0o+payload+th%C3%AC+c%C3%B3+n%C3%AAn+l%C3%A0m+cho+AI+n%C3%B3+hi%E1%BB%83u+l%C3%A0+b%E1%BA%A5t+th%C6%B0%E1%BB%9Dng+ko+C%C3%B3+%C4%91%E1%BB%83+khuya+xem+ng%E1%BB%93i+xem+m%E1%BA%A5y+c%C3%A1i+c%C3%B4ng+th%E1%BB%A9c+ngu+m%E1%BA%B9+c%C3%A1i+%C4%91%E1%BA%A7u+g%E1%BA%A7n+hi%E1%BB%83u+r%E1%BB%93i+MScgQU5EIChTRUxFQ1QgMSBGUk9NIChTRUxFQ1QgQ09VTlQoKiksIENPTkNBVCh1c2VyKCksIEZMT09SKFJBTkQoKSoyKSkgeCBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgR1JPVVAgQlkgeCkgYSkgLS0g%23&Submit=Submit", 	"session_token": "e16qs57nkd675aj4u44nv78r6s" 	}'''
        },
        {
            "name": "Overlong UTF-8 SQLi",
            "raw_log": '''{ 	"time": "2025-10-23T15:15:21+0700", 	"remote_ip": "192.168.205.2", 	"method": "GET", 	"uri": "/DVWA/vulnerabilities/sqli_blind/index.php", 	"query_string": "?id=%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2Fetc%2Fpasswd&Submit=Submit", 	"status": 404, 	"bytes_sent": 4709, 	"response_time_ms": 10102, 	"referer": "http://localhost/DVWA/vulnerabilities/sqli_blind/?id=m%C3%ACnh+ch%E1%BB%A7+y%E1%BA%BFu+detect+sqli+m%C3%A0+ha+%E1%BB%ABm+%40Thanhdat+m%C3%A0+c%C3%A1i+%C4%91o%E1%BA%A1n+base64+%C4%91%E1%BA%A7u+c%E1%BB%A7a+n%C3%B3+ngh%C4%A9a+l%C3%A0+g%C3%AC+th%E1%BA%BF+..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C+%3A%29%29%29+path+traversal+m%C3%A0+v%C3%AD+d%E1%BB%A5+nh%C6%B0+n%C3%B3+c%C5%A9ng+d%E1%BA%A1ng+ch%C3%A8n+v%C3%A0o+payload+th%C3%AC+c%C3%B3+n%C3%AAn+l%C3%A0m+cho+AI+n%C3%B3+hi%E1%BB%83u+l%C3%A0+b%E1%BA%A5t+th%C6%B0%E1%BB%9Dng+ko+C%C3%B3+%C4%91%E1%BB%83+khuya+xem+ng%E1%BB%93i+xem+m%E1%BA%A5y+c%C3%A1i+c%C3%B4ng+th%E1%BB%A9c+ngu+m%E1%BA%B9+c%C3%A1i+%C4%91%E1%BA%A7u+g%E1%BA%A7n+hi%E1%BB%83u+r%E1%BB%93i+MScgQU5EIChTRUxFQ1QgMSBGUk9NIChTRUxFQ1QgQ09VTlQoKiksIENPTkNBVCh1c2VyKCksIEZMT09SKFJBTkQoKSoyKSkgeCBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgR1JPVVAgQlkgeCkgYSkgLS0g%23&Submit=Submit", 	"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", 	"request_length": 3000, 	"response_length": 5021, 	"cookie": "wz-user=admin; wz-api=default; wz-token=eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzU4Nzg3NTMxLCJleHAiOjE3NTg3ODg0MzEsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AesxoYn2Mswm57ZVr629sOm17LOZ9CZsYHZrBA9iJD0VIX6dhKYvdmliAam4Bz0t0ESzWhJBxRzWDcp0mbTaQfp7AItpDAA7FYRdttfxSzWRRQDQfJqdn92jw7mKWhVmfNdVi0LIuX3v5NBuEDo5DxQg4qOl0dVw4fWMVRpXkmTVqSQv; security_authentication=Fe26.2**0b0867848a70274f49c818e99c198bd4102ceb8974cd525082ce5776fb8e8c36*bt1d6pcVRjEu19un5Jvw7w*-L2I70BJALAVmDIMBIOAJY-ZFN5GxhzRtvaSxo9KyRnR-g5ePzgQBIEQmtMOZHl48IaTEjb2udup33PDNAu-e_qD5nrt_08mQGGCFRaLb_-q3U1iU-Y6N-XhdsE2tVOujUq9N-HUlJpOlgWd2KAHYy4WoTUnFVZZHvh6ZZttfNlIYgZKwzcjvafOHJlFV_ZdE1OO74rBvBuAXloTx5YJiA**d1dd55bddb24a94e17b8b9b692a4de94376a478cdb5705ea0410b2b452176ccc*yIBWZjhJtUNQOSbGOXUq-Ycj4CRKFUdKWCbHwIapAwY; security=low; __next_hmr_refresh_hash__=eaef24bda92b27543c11ee4808b99ea8633457081244afec; PHPSESSID=e16qs57nkd675aj4u44nv78r6s", 	"payload": "id=%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2525c0%2525ae%2525c0%2525ae%2525c1%25259c%2Fetc%2Fpasswd&Submit=Submit", 	"session_token": "e16qs57nkd675aj4u44nv78r6s" 	}'''
        }
    ]
    
    for i, test_case in enumerate(test_logs, 1):
        print(f"\n--- Test Case {i}: {test_case['name']} ---")
        
        # Test robust parsing
        print("1. Testing robust JSON parsing...")
        parsed_log = collector._parse_log_line_robust(test_case['raw_log'])
        
        if parsed_log:
            print(f"   ✅ JSON parsed successfully")
            print(f"   Time: {parsed_log.get('time', 'N/A')}")
            print(f"   URI: {parsed_log.get('uri', 'N/A')}")
            print(f"   Query: {parsed_log.get('query_string', 'N/A')[:50]}...")
        else:
            print(f"   ❌ JSON parsing failed")
            continue
        
        # Test SQLi detection
        print("2. Testing SQLi detection...")
        detection_result = collector.detect_sqli_realtime(parsed_log)
        
        if detection_result and detection_result.get('is_sqli'):
            print(f"   🚨 SQLi DETECTED!")
            print(f"   Score: {detection_result.get('score', 0):.4f}")
            print(f"   Patterns: {detection_result.get('detected_patterns', [])}")
        else:
            print(f"   ❌ SQLi NOT DETECTED")
            continue
        
        # Test _is_real_threat filter
        print("3. Testing _is_real_threat filter...")
        is_threat = collector._is_real_threat(parsed_log, detection_result)
        
        if is_threat:
            print(f"   ✅ Passed _is_real_threat filter")
        else:
            print(f"   ❌ Blocked by _is_real_threat filter")
            print(f"   This is why it's not showing in realtime output!")
        
        # Test process_log_line
        print("4. Testing process_log_line...")
        try:
            collector.process_log_line(parsed_log)
            print(f"   ✅ process_log_line completed")
        except Exception as e:
            print(f"   ❌ process_log_line failed: {e}")
    
    print(f"\n" + "="*80)
    print("REALTIME PROCESSING DEBUG COMPLETE")
    print("="*80)
    print("If SQLi is detected but not showing in realtime output,")
    print("the issue is likely in the _is_real_threat filter logic.")

if __name__ == "__main__":
    debug_realtime_processing()

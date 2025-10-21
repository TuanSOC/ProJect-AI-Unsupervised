#!/usr/bin/env python3
"""
Test script để kiểm tra việc bắt payload từ log
"""

import json
from realtime_log_collector import RealtimeLogCollector

def test_payload_capture():
    """Test việc bắt payload từ log entries"""
    
    # Tạo collector instance
    collector = RealtimeLogCollector()
    
    # Test log entries từ terminal output
    test_logs = [
        # Log với query string
        {
            "time": "2025-10-21T22:16:37+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/brute/index.php",
            "query_string": "?username=admin&password=password&Login=Login",
            "status": 200,
            "payload": "username=admin&password=password&Login=Login"
        },
        # Log POST không có payload
        {
            "time": "2025-10-21T22:15:55+0700",
            "remote_ip": "192.168.205.2",
            "method": "POST",
            "uri": "/DVWA/vulnerabilities/exec/index.php",
            "query_string": "",
            "status": 200,
            "payload": "",
            "referer": "http://localhost/DVWA/vulnerabilities/exec/"
        },
        # Log với file include
        {
            "time": "2025-10-21T22:15:50+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/fi/index.php",
            "query_string": "?page=include.php",
            "status": 200,
            "payload": "page=include.php"
        }
    ]
    
    print("🔍 Testing Payload Capture")
    print("=" * 50)
    
    for i, log_data in enumerate(test_logs, 1):
        print(f"\n📋 Test {i}: {log_data['method']} {log_data['uri']}")
        print("-" * 30)
        
        # Parse log entry
        log_entry = collector._process_formatted_log(log_data.copy())
        
        # Display results
        print(f"Query String: {log_entry.get('query_string', 'N/A')}")
        print(f"Payload: {log_entry.get('payload', 'N/A')}")
        print(f"Combined Payload: {log_entry.get('combined_payload', 'N/A')}")
        print(f"Query Params: {log_entry.get('query_params', {})}")
        print(f"Payload Params: {log_entry.get('payload_params', {})}")
        
        # Check for potential SQLi patterns
        combined = log_entry.get('combined_payload', '')
        if combined:
            sql_patterns = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter']
            found_patterns = [pattern for pattern in sql_patterns if pattern.lower() in combined.lower()]
            if found_patterns:
                print(f"⚠️  Potential SQL patterns: {found_patterns}")
            else:
                print("✅ No obvious SQL patterns detected")
        else:
            print("ℹ️  No payload to analyze")
    
    print("\n" + "=" * 50)
    print("✅ Payload capture test completed!")

if __name__ == "__main__":
    test_payload_capture()

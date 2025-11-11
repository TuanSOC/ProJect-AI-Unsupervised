#!/usr/bin/env python3
"""
Test script cho Wazuh SIEM Realtime Detector
Test với log mẫu từ Wazuh
"""

import json
import sys
import io

# Fix encoding cho Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from wazuh_siem_realtime_detector import WazuhSIEMRealtimeDetector

# Log mẫu từ Wazuh
wazuh_log_sample = {
    "timestamp": "2025-11-08T01:24:00.552+0700",
    "agent": {
        "id": "001",
        "name": "web-server",
        "ip": "192.168.15.10"
    },
    "manager": {
        "name": "Wazuh"
    },
    "id": "1762539840.48299",
    "full_log": "{ \"time\": \"2025-11-08T01:23:59.%f+0700\", \"remote_ip\": \"192.168.15.12\", \"method\": \"GET\", \"uri\": \"/dvwa/vulnerabilities/sqli/index.php\", \"query_string\": \"?id=1%27%29+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%23&Submit=Submit\", \"status\": 302, \"bytes_sent\": 0, \"response_time_ms\": 21436, \"referer\": \"http://192.168.15.10/dvwa/vulnerabilities/sqli/\", \"user_agent\": \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0\", \"request_length\": 671, \"response_length\": 300, \"cookie\": \"PHPSESSID=mt47dt30bksq1rh6tfom88q62l; security=impossible\", \"payload\": \"1%27%29+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%23\", \"session_token\": \"mt47dt30bksq1rh6tfom88q62l\" }",
    "decoder": {
        "name": "json"
    },
    "data": {
        "status": "302",
        "time": "2025-11-08T01:23:59.%f+0700",
        "remote_ip": "192.168.15.12",
        "method": "GET",
        "uri": "/dvwa/vulnerabilities/sqli/index.php",
        "query_string": "?id=1%27%29+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%23&Submit=Submit",
        "bytes_sent": "0",
        "response_time_ms": "21436",
        "referer": "http://192.168.15.10/dvwa/vulnerabilities/sqli/",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0",
        "request_length": "671",
        "response_length": "300",
        "cookie": "PHPSESSID=mt47dt30bksq1rh6tfom88q62l; security=impossible",
        "payload": "1%27%29+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%23",
        "session_token": "mt47dt30bksq1rh6tfom88q62l"
    },
    "location": "/var/log/apache2/access_full_json.log"
}

def test_wazuh_siem_detector():
    """Test Wazuh SIEM detector với log mẫu"""
    print("=" * 90)
    print("TEST WAZUH SIEM REALTIME SQLI DETECTOR".center(90))
    print("=" * 90)
    
    # Convert log to JSON string
    log_line = json.dumps(wazuh_log_sample)
    
    print("\nLog Entry tu Wazuh:")
    print(f"   Timestamp: {wazuh_log_sample['timestamp']}")
    print(f"   Agent: {wazuh_log_sample['agent']['name']} ({wazuh_log_sample['agent']['ip']})")
    print(f"   Manager: {wazuh_log_sample['manager']['name']}")
    print(f"   Location: {wazuh_log_sample['location']}")
    
    data = wazuh_log_sample['data']
    print(f"   IP: {data.get('remote_ip', '')}")
    print(f"   Method: {data.get('method', '')}")
    print(f"   URI: {data.get('uri', '')}")
    print(f"   Query: {data.get('query_string', '')[:80]}...")
    print(f"   Payload: {data.get('payload', '')[:80]}...")
    print(f"   Status: {data.get('status', '')}")
    print(f"   Response Time: {data.get('response_time_ms', '')}ms")
    
    # Decode query để xem rõ hơn
    import urllib.parse
    decoded_query = urllib.parse.unquote_plus(data.get('query_string', ''))
    print(f"\nDecoded Query: {decoded_query}")
    
    # Khởi tạo detector
    try:
        detector = WazuhSIEMRealtimeDetector()
        if not detector.detector:
            print("\nKhong the load model!")
            return
        print("\nModel loaded successfully!")
    except Exception as e:
        print(f"\nLoi khi khoi tao detector: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Parse log
    print("\n" + "=" * 90)
    print("PARSING WAZUH LOG".center(90))
    print("=" * 90)
    
    log_entry = detector._parse_wazuh_log(log_line)
    if not log_entry:
        print("Khong the parse log!")
        return
    
    print("\nLog parsed successfully!")
    print(f"   Remote IP: {log_entry.get('remote_ip', '')}")
    print(f"   Method: {log_entry.get('method', '')}")
    print(f"   URI: {log_entry.get('uri', '')}")
    print(f"   Query String: {log_entry.get('query_string', '')[:80]}...")
    print(f"   Payload: {log_entry.get('payload', '')[:80]}...")
    print(f"   Wazuh Agent: {log_entry.get('wazuh_agent_name', '')}")
    print(f"   Wazuh Location: {log_entry.get('wazuh_location', '')}")
    
    # Detect SQLi
    print("\n" + "=" * 90)
    print("DETECTING SQLI".center(90))
    print("=" * 90)
    
    detection_result = detector.detect_sqli_realtime(log_entry)
    
    if not detection_result:
        print("\nKhong the detect!")
        return
    
    print("\nDETECTION RESULT:")
    print(f"   Is SQLi: {detection_result['is_sqli']}")
    print(f"   Score: {detection_result['score']:.4f}")
    print(f"   Confidence: {detection_result['confidence']}")
    print(f"   Threat Level: {detection_result['threat_level']}")
    print(f"   Detected Patterns: {detection_result.get('detected_patterns', [])}")
    
    if detection_result.get('detailed_analysis'):
        detailed = detection_result['detailed_analysis']
        risk_assessment = detailed.get('risk_assessment', {})
        final_assessment = detailed.get('final_assessment', {})
        
        print("\nDETAILED ANALYSIS:")
        print(f"   Risk Score: {risk_assessment.get('risk_score', 0):.2f}")
        print(f"   Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}")
        print(f"   Overall Risk: {final_assessment.get('overall_risk', 'UNKNOWN')}")
        print(f"   Recommendation: {final_assessment.get('recommendation', 'UNKNOWN')}")
    
    # Test save log
    if detection_result['is_sqli']:
        print("\n" + "=" * 90)
        print("TESTING WAZUH SIEM LOG SAVE".center(90))
        print("=" * 90)
        
        # Save to test file
        import os
        import platform
        if platform.system() == 'Windows':
            test_log_path = os.path.join(os.getcwd(), 'test_ai-engine-sqli.jsonl')
        else:
            test_log_path = '/tmp/test_ai-engine-sqli.jsonl'
        
        # Update log path trong detector instance
        import wazuh_siem_realtime_detector
        original_path = wazuh_siem_realtime_detector._wazuh_siem_log_path
        wazuh_siem_realtime_detector._wazuh_siem_log_path = test_log_path
        
        detector.save_wazuh_siem_log(log_entry, detection_result)
        
        # Restore original path
        wazuh_siem_realtime_detector._wazuh_siem_log_path = original_path
        
        if os.path.exists(test_log_path):
            print(f"\nLog da duoc luu vao: {test_log_path}")
            with open(test_log_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    saved_log = json.loads(content)
                    print("\nSaved Log Content:")
                    print(json.dumps(saved_log, indent=2, ensure_ascii=False))
                else:
                    print(f"\nWarning: Log file rong: {test_log_path}")
        else:
            print(f"\nWarning: Log file khong duoc tao: {test_log_path}")
            print(f"   Thư mục: {os.path.dirname(test_log_path)}")
            print(f"   Thư mục tồn tại: {os.path.exists(os.path.dirname(test_log_path))}")
    
    print("\n" + "=" * 90)
    print("TEST COMPLETED".center(90))
    print("=" * 90)

if __name__ == "__main__":
    test_wazuh_siem_detector()


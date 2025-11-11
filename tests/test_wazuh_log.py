#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test AI detector với log từ Wazuh
"""

import json
import sys
import io
from datetime import datetime
from realtime_log_collector import RealtimeLogCollector
import logging

# Fix encoding trên Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Setup logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def test_wazuh_log():
    """Test với log từ Wazuh"""
    
    # Log từ Wazuh
    wazuh_log = {
        "timestamp": "2025-11-08T01:24:00.552+0700",
        "agent": {"id": "001", "name": "web-server", "ip": "192.168.15.10"},
        "manager": {"name": "Wazuh"},
        "id": "1762539840.48299",
        "full_log": "{ \"time\": \"2025-11-08T01:23:59.%f+0700\", \"remote_ip\": \"192.168.15.12\", \"method\": \"GET\", \"uri\": \"/dvwa/vulnerabilities/sqli/index.php\", \"query_string\": \"?id=1%27%29+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%23&Submit=Submit\", \"status\": 302, \"bytes_sent\": 0, \"response_time_ms\": 21436, \"referer\": \"http://192.168.15.10/dvwa/vulnerabilities/sqli/\", \"user_agent\": \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0\", \"request_length\": 671, \"response_length\": 300, \"cookie\": \"PHPSESSID=mt47dt30bksq1rh6tfom88q62l; security=impossible\", \"payload\": \"1%27%29+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%23\", \"session_token\": \"mt47dt30bksq1rh6tfom88q62l\" }",
        "decoder": {"name": "json"},
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
    
    print("=" * 90)
    print("TEST AI DETECTOR VỚI LOG TỪ WAZUH".center(90))
    print("=" * 90)
    
    # Parse log entry từ Wazuh format
    data = wazuh_log['data']
    
    log_entry = {
        'time': data.get('time', datetime.now().isoformat()),
        'remote_ip': data.get('remote_ip', ''),
        'method': data.get('method', 'GET'),
        'uri': data.get('uri', ''),
        'query_string': data.get('query_string', ''),
        'status': int(data.get('status', 0)),
        'bytes_sent': int(data.get('bytes_sent', 0)),
        'response_time_ms': int(data.get('response_time_ms', 0)),
        'referer': data.get('referer', ''),
        'user_agent': data.get('user_agent', ''),
        'request_length': int(data.get('request_length', 0)),
        'response_length': int(data.get('response_length', 0)),
        'cookie': data.get('cookie', ''),
        'payload': data.get('payload', ''),
        'body': data.get('payload', ''),
        'session_token': data.get('session_token', '')
    }
    
    print("\n📋 Log Entry từ Wazuh:")
    print(f"   Timestamp: {wazuh_log['timestamp']}")
    print(f"   Agent: {wazuh_log['agent']['name']} ({wazuh_log['agent']['ip']})")
    print(f"   IP: {log_entry['remote_ip']}")
    print(f"   Method: {log_entry['method']}")
    print(f"   URI: {log_entry['uri']}")
    print(f"   Query: {log_entry['query_string']}")
    print(f"   Payload: {log_entry['payload']}")
    print(f"   Status: {log_entry['status']}")
    print(f"   Response Time: {log_entry['response_time_ms']}ms")
    print(f"   Cookie: {log_entry['cookie']}")
    
    # Decode query để xem rõ hơn
    import urllib.parse
    decoded_query = urllib.parse.unquote_plus(log_entry['query_string'])
    print(f"\n🔍 Decoded Query: {decoded_query}")
    
    # Khởi tạo collector
    try:
        collector = RealtimeLogCollector()
        if not collector.detector:
            print("\n❌ Không thể load model!")
            return
        print("\n✅ Model loaded successfully!")
    except Exception as e:
        print(f"\n❌ Lỗi khi khởi tạo collector: {e}")
        return
    
    # Detect SQLi
    print("\n" + "=" * 90)
    print("🔍 AI DETECTION RESULTS".center(90))
    print("=" * 90)
    
    result = collector.detect_sqli_realtime(log_entry)
    
    if not result:
        print("❌ Không thể detect (lỗi)")
        return
    
    print(f"\n🎯 Detection Results:")
    print(f"   Is SQLi: {result.get('is_sqli', False)}")
    print(f"   Score: {result.get('score', 0):.4f}")
    
    patterns = result.get('detected_patterns', 'N/A')
    if isinstance(patterns, list):
        patterns_str = ', '.join(patterns)
    else:
        patterns_str = str(patterns)
    print(f"   Patterns: {patterns_str}")
    print(f"   Confidence: {result.get('confidence', 'Unknown')}")
    
    # Threat level
    threat_level = result.get('threat_level', 'UNKNOWN')
    threat_emoji = {
        'NONE': '⚪',
        'LOW': '🟢',
        'MEDIUM': '🟡',
        'HIGH': '🟠',
        'CRITICAL': '🔴'
    }
    emoji = threat_emoji.get(threat_level, '❓')
    print(f"\n{emoji} Threat Level: {threat_level}")
    
    # Detailed analysis
    detailed = result.get('detailed_analysis', {})
    if detailed:
        risk_assessment = detailed.get('risk_assessment', {})
        final_assessment = detailed.get('final_assessment', {})
        
        print(f"\n📊 Risk Assessment:")
        print(f"   Risk Score: {risk_assessment.get('risk_score', 0):.2f}")
        print(f"   Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}")
        print(f"   Overall Risk: {final_assessment.get('overall_risk', 'UNKNOWN')}")
        print(f"   Recommendation: {final_assessment.get('recommendation', 'UNKNOWN')}")
        
        # Attack vectors
        attack_vectors = detailed.get('attack_vectors', {})
        if attack_vectors.get('attack_vectors'):
            print(f"\n⚔️ Attack Vectors: {', '.join(attack_vectors.get('attack_vectors', []))}")
        
        # Patterns
        pattern_analysis = detailed.get('pattern_analysis', {})
        if pattern_analysis.get('detected_patterns'):
            print(f"🔍 Detected Patterns: {', '.join(pattern_analysis.get('detected_patterns', []))}")
        
        # Encoding
        encoding_analysis = detailed.get('encoding_analysis', {})
        if encoding_analysis.get('encoding_types'):
            print(f"🔐 Encoding Types: {', '.join(encoding_analysis.get('encoding_types', []))}")
        
        # Database
        database_analysis = detailed.get('database_analysis', {})
        if database_analysis.get('database_types'):
            print(f"🗄️ Database Types: {', '.join(database_analysis.get('database_types', []))}")
        
        # Evasion
        evasion_analysis = detailed.get('evasion_analysis', {})
        if evasion_analysis.get('evasion_techniques'):
            print(f"🎭 Evasion Techniques: {', '.join(evasion_analysis.get('evasion_techniques', []))}")
    
    print("\n" + "=" * 90)
    
    # Kết luận
    if result.get('is_sqli', False):
        print("✅ AI DETECTED SQLi ATTACK!")
        if threat_level == 'CRITICAL':
            print("🔴 CRITICAL THREAT - IMMEDIATE ACTION REQUIRED!")
        elif threat_level == 'HIGH':
            print("🟠 HIGH THREAT - BLOCK AND INVESTIGATE!")
        elif threat_level == 'MEDIUM':
            print("🟡 MEDIUM THREAT - MONITOR AND LOG!")
    else:
        print("⚪ No SQLi detected")
    
    print("=" * 90)

if __name__ == "__main__":
    test_wazuh_log()


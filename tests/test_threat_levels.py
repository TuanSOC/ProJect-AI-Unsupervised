#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Demo script để test các loại threat level: LOW, MEDIUM, HIGH, CRITICAL
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
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def print_result(title, log_entry, result):
    """In kết quả phân loại threat level"""
    print("\n" + "=" * 80)
    print(f"🔍 {title}")
    print("=" * 80)
    
    if not result:
        print("❌ Không thể detect (model chưa load hoặc lỗi)")
        return
    
    print(f"\n📋 Log Entry:")
    print(f"   IP: {log_entry.get('remote_ip', 'Unknown')}")
    print(f"   URI: {log_entry.get('uri', 'Unknown')}")
    print(f"   Query: {log_entry.get('query_string', 'None')}")
    print(f"   Payload: {log_entry.get('payload', 'None')[:100]}...")
    
    print(f"\n🎯 Detection Results:")
    print(f"   Is SQLi: {result.get('is_sqli', False)}")
    print(f"   Score: {result.get('score', 0):.4f}")
    print(f"   Patterns: {result.get('detected_patterns', 'N/A')}")
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
        print(f"   AI Risk: {risk_assessment.get('ai_risk', 'UNKNOWN')}")
        
        print(f"\n🎯 Final Assessment:")
        print(f"   Overall Risk: {final_assessment.get('overall_risk', 'UNKNOWN')}")
        print(f"   Confidence: {final_assessment.get('confidence', 'UNKNOWN')}")
        print(f"   Recommendation: {final_assessment.get('recommendation', 'UNKNOWN')}")
        
        # Attack vectors
        attack_vectors = detailed.get('attack_vectors', {})
        if attack_vectors.get('attack_vectors'):
            print(f"\n⚔️ Attack Vectors: {attack_vectors.get('attack_vectors', [])}")
        
        # Patterns
        pattern_analysis = detailed.get('pattern_analysis', {})
        if pattern_analysis.get('detected_patterns'):
            print(f"🔍 Detected Patterns: {pattern_analysis.get('detected_patterns', [])}")
    
    print("=" * 80)

def main():
    """Test các loại threat level"""
    
    print("\n" + "DEMO THREAT LEVEL CLASSIFICATION".center(80))
    print("=" * 80)
    
    # Khởi tạo collector
    try:
        collector = RealtimeLogCollector()
        if not collector.detector:
            print("❌ Không thể load model! Vui lòng kiểm tra file model.")
            return
        print("✅ Model loaded successfully!")
    except Exception as e:
        print(f"❌ Lỗi khi khởi tạo collector: {e}")
        return
    
    # ========== TEST 1: LOW THREAT ==========
    # Query đơn giản, không có pattern SQLi rõ ràng
    log_low = {
        'time': datetime.now().isoformat(),
        'remote_ip': '192.168.1.100',
        'method': 'GET',
        'uri': '/index.php',
        'query_string': 'id=123&name=test',
        'status': 200,
        'bytes_sent': 1024,
        'response_time_ms': 50,
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'cookie': 'session_id=abc123',
        'payload': '',
        'body': '',
        'request_length': 200,
        'response_length': 1024
    }
    
    result_low = collector.detect_sqli_realtime(log_low)
    print_result("TEST 1: LOW THREAT (Query đơn giản)", log_low, result_low)
    
    # ========== TEST 2: MEDIUM THREAT ==========
    # Có một số SQL keywords nhưng không rõ ràng là SQLi
    log_medium = {
        'time': datetime.now().isoformat(),
        'remote_ip': '192.168.1.101',
        'method': 'GET',
        'uri': '/search.php',
        'query_string': 'keyword=select&type=user',
        'status': 200,
        'bytes_sent': 2048,
        'response_time_ms': 100,
        'user_agent': 'Mozilla/5.0',
        'cookie': 'session_id=xyz789',
        'payload': '',
        'body': '',
        'request_length': 300,
        'response_length': 2048
    }
    
    result_medium = collector.detect_sqli_realtime(log_medium)
    print_result("TEST 2: MEDIUM THREAT (Có SQL keywords nhưng không rõ ràng)", log_medium, result_medium)
    
    # ========== TEST 3: HIGH THREAT ==========
    # Có pattern SQLi rõ ràng nhưng không phải pattern nguy hiểm nhất
    log_high = {
        'time': datetime.now().isoformat(),
        'remote_ip': '192.168.1.102',
        'method': 'GET',
        'uri': '/login.php',
        'query_string': 'id=1+OR+1=1',
        'status': 200,
        'bytes_sent': 512,
        'response_time_ms': 150,
        'user_agent': 'Mozilla/5.0',
        'cookie': 'session_id=test123',
        'payload': '',
        'body': '',
        'request_length': 250,
        'response_length': 512
    }
    
    result_high = collector.detect_sqli_realtime(log_high)
    print_result("TEST 3: HIGH THREAT (Pattern SQLi: OR 1=1)", log_high, result_high)
    
    # ========== TEST 4: CRITICAL THREAT ==========
    # Pattern SQLi rất nguy hiểm: UNION SELECT với information_schema
    log_critical = {
        'time': datetime.now().isoformat(),
        'remote_ip': '192.168.1.103',
        'method': 'GET',
        'uri': '/vulnerabilities/sqli/index.php',
        'query_string': 'id=1+UNION+SELECT+*+FROM+information_schema.tables--',
        'status': 200,
        'bytes_sent': 4096,
        'response_time_ms': 200,
        'user_agent': 'Mozilla/5.0',
        'cookie': 'PHPSESSID=abc123; security=low',
        'payload': '',
        'body': '',
        'request_length': 400,
        'response_length': 4096
    }
    
    result_critical = collector.detect_sqli_realtime(log_critical)
    print_result("TEST 4: CRITICAL THREAT (UNION SELECT + information_schema)", log_critical, result_critical)
    
    # ========== TEST 5: CRITICAL THREAT - Base64 Encoded ==========
    # SQLi được encode bằng Base64
    log_critical_b64 = {
        'time': datetime.now().isoformat(),
        'remote_ip': '192.168.1.104',
        'method': 'POST',
        'uri': '/api/user.php',
        'query_string': '',
        'status': 200,
        'bytes_sent': 1024,
        'response_time_ms': 180,
        'user_agent': 'Mozilla/5.0',
        'cookie': 'session_id=test',
        'payload': 'data=JyBPUiAxPTEtLQ==',  # Base64 encoded: ' OR 1=1--
        'body': 'data=JyBPUiAxPTEtLQ==',
        'request_length': 350,
        'response_length': 1024
    }
    
    result_critical_b64 = collector.detect_sqli_realtime(log_critical_b64)
    print_result("TEST 5: CRITICAL THREAT (Base64 Encoded SQLi)", log_critical_b64, result_critical_b64)
    
    # ========== TEST 6: CRITICAL THREAT - Time-based ==========
    # Time-based SQLi attack
    log_critical_time = {
        'time': datetime.now().isoformat(),
        'remote_ip': '192.168.1.105',
        'method': 'GET',
        'uri': '/test.php',
        'query_string': 'id=1+AND+SLEEP(5)--',
        'status': 200,
        'bytes_sent': 512,
        'response_time_ms': 5000,  # Response time cao do SLEEP
        'user_agent': 'Mozilla/5.0',
        'cookie': '',
        'payload': '',
        'body': '',
        'request_length': 200,
        'response_length': 512
    }
    
    result_critical_time = collector.detect_sqli_realtime(log_critical_time)
    print_result("TEST 6: CRITICAL THREAT (Time-based SQLi: SLEEP)", log_critical_time, result_critical_time)
    
    # ========== TEST 7: CRITICAL THREAT - NoSQL Injection ==========
    # NoSQL injection attack
    log_critical_nosql = {
        'time': datetime.now().isoformat(),
        'remote_ip': '192.168.1.106',
        'method': 'POST',
        'uri': '/api/search',
        'query_string': '',
        'status': 200,
        'bytes_sent': 2048,
        'response_time_ms': 120,
        'user_agent': 'Mozilla/5.0',
        'cookie': '',
        'payload': '{"username": {"$ne": null}, "password": {"$ne": null}}',
        'body': '{"username": {"$ne": null}, "password": {"$ne": null}}',
        'request_length': 500,
        'response_length': 2048
    }
    
    result_critical_nosql = collector.detect_sqli_realtime(log_critical_nosql)
    print_result("TEST 7: CRITICAL THREAT (NoSQL Injection)", log_critical_nosql, result_critical_nosql)
    
    # ========== TEST 8: NONE (Clean Log) ==========
    # Log hoàn toàn sạch, không có gì đáng ngờ
    log_none = {
        'time': datetime.now().isoformat(),
        'remote_ip': '192.168.1.107',
        'method': 'GET',
        'uri': '/css/style.css',
        'query_string': '',
        'status': 200,
        'bytes_sent': 5120,
        'response_time_ms': 10,
        'user_agent': 'Mozilla/5.0',
        'cookie': '',
        'payload': '',
        'body': '',
        'request_length': 150,
        'response_length': 5120
    }
    
    result_none = collector.detect_sqli_realtime(log_none)
    print_result("TEST 8: NONE (Clean Log - Static Resource)", log_none, result_none)
    
    # ========== TỔNG KẾT ==========
    print("\n" + "=" * 80)
    print("📊 TỔNG KẾT PHÂN LOẠI THREAT LEVEL")
    print("=" * 80)
    
    results = [
        ("TEST 1", result_low, "LOW"),
        ("TEST 2", result_medium, "MEDIUM"),
        ("TEST 3", result_high, "HIGH"),
        ("TEST 4", result_critical, "CRITICAL"),
        ("TEST 5", result_critical_b64, "CRITICAL (Base64)"),
        ("TEST 6", result_critical_time, "CRITICAL (Time-based)"),
        ("TEST 7", result_critical_nosql, "CRITICAL (NoSQL)"),
        ("TEST 8", result_none, "NONE")
    ]
    
    for test_name, result, expected in results:
        if result:
            threat_level = result.get('threat_level', 'UNKNOWN')
            risk_score = result.get('detailed_analysis', {}).get('risk_assessment', {}).get('risk_score', 0)
            is_sqli = result.get('is_sqli', False)
            
            status = "✅" if threat_level == expected or (expected.startswith("CRITICAL") and threat_level == "CRITICAL") or (expected == "NONE" and threat_level == "NONE") else "⚠️"
            
            print(f"{status} {test_name}:")
            print(f"   Threat Level: {threat_level} (Expected: {expected})")
            print(f"   Is SQLi: {is_sqli}")
            print(f"   Risk Score: {risk_score:.2f}")
            print()
        else:
            print(f"❌ {test_name}: Không thể detect")
    
    print("=" * 80)
    print("✅ Demo hoàn tất!")
    print("=" * 80)

if __name__ == "__main__":
    main()


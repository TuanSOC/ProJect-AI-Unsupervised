#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Demo script comprehensive để test các loại threat level với nhiều trường hợp khác nhau
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
    level=logging.WARNING,  # Giảm log noise
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def print_result(title, log_entry, result, expected_level=None):
    """In kết quả phân loại threat level"""
    print("\n" + "=" * 90)
    print(f"🔍 {title}")
    if expected_level:
        print(f"   Expected: {expected_level}")
    print("=" * 90)
    
    if not result:
        print("❌ Không thể detect (model chưa load hoặc lỗi)")
        return None
    
    print(f"\n📋 Log Entry:")
    print(f"   IP: {log_entry.get('remote_ip', 'Unknown')}")
    print(f"   URI: {log_entry.get('uri', 'Unknown')}")
    query = log_entry.get('query_string', '')[:80]
    payload = log_entry.get('payload', '')[:80]
    print(f"   Query: {query}{'...' if len(log_entry.get('query_string', '')) > 80 else ''}")
    if payload:
        print(f"   Payload: {payload}{'...' if len(log_entry.get('payload', '')) > 80 else ''}")
    
    print(f"\n🎯 Detection Results:")
    print(f"   Is SQLi: {result.get('is_sqli', False)}")
    print(f"   Score: {result.get('score', 0):.4f}")
    patterns = result.get('detected_patterns', 'N/A')
    if isinstance(patterns, list):
        patterns_str = ', '.join(patterns[:5])
        if len(patterns) > 5:
            patterns_str += f" (+{len(patterns)-5} more)"
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
    
    # Detailed analysis
    detailed = result.get('detailed_analysis', {})
    if detailed:
        risk_assessment = detailed.get('risk_assessment', {})
        final_assessment = detailed.get('final_assessment', {})
        
        risk_score = risk_assessment.get('risk_score', 0)
        risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
        overall_risk = final_assessment.get('overall_risk', 'UNKNOWN')
        recommendation = final_assessment.get('recommendation', 'UNKNOWN')
        
        print(f"\n{emoji} Threat Level: {threat_level}")
        print(f"\n📊 Risk Assessment:")
        print(f"   Risk Score: {risk_score:.2f}")
        print(f"   Risk Level: {risk_level}")
        print(f"   Overall Risk: {overall_risk}")
        print(f"   Recommendation: {recommendation}")
        
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
        
        return {
            'threat_level': threat_level,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'overall_risk': overall_risk,
            'is_sqli': result.get('is_sqli', False)
        }
    
    return None

def create_log_entry(base_ip, uri, query_string='', payload='', method='GET', **kwargs):
    """Helper function để tạo log entry"""
    return {
        'time': datetime.now().isoformat(),
        'remote_ip': base_ip,
        'method': method,
        'uri': uri,
        'query_string': query_string,
        'status': kwargs.get('status', 200),
        'bytes_sent': kwargs.get('bytes_sent', 1024),
        'response_time_ms': kwargs.get('response_time_ms', 100),
        'user_agent': kwargs.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
        'cookie': kwargs.get('cookie', ''),
        'payload': payload,
        'body': payload if method == 'POST' else '',
        'request_length': kwargs.get('request_length', 200),
        'response_length': kwargs.get('response_length', 1024),
        **kwargs
    }

def main():
    """Test comprehensive các loại threat level"""
    
    print("\n" + "COMPREHENSIVE THREAT LEVEL CLASSIFICATION TEST".center(90))
    print("=" * 90)
    
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
    
    results_summary = []
    test_num = 1
    
    # ========== CATEGORY 1: LOW THREAT ==========
    print("\n" + "📌 CATEGORY 1: LOW THREAT (Clean/Safe Queries)".center(90))
    print("=" * 90)
    
    # Test 1.1: Simple numeric query
    log = create_log_entry('192.168.1.100', '/index.php', 'id=123')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num}.1: Simple Numeric Query", log, result, "NONE/LOW")
    if summary:
        results_summary.append(("1.1", "Simple Numeric", summary))
    test_num += 1
    
    # Test 1.2: Alphanumeric query
    log = create_log_entry('192.168.1.101', '/search.php', 'q=hello&type=user')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.2: Alphanumeric Query", log, result, "NONE/LOW")
    if summary:
        results_summary.append(("1.2", "Alphanumeric", summary))
    
    # Test 1.3: Static resource
    log = create_log_entry('192.168.1.102', '/css/style.css')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.3: Static Resource", log, result, "NONE")
    if summary:
        results_summary.append(("1.3", "Static Resource", summary))
    
    # ========== CATEGORY 2: MEDIUM THREAT ==========
    print("\n" + "📌 CATEGORY 2: MEDIUM THREAT (Suspicious but not critical)".center(90))
    print("=" * 90)
    
    # Test 2.1: Simple OR 1=1
    log = create_log_entry('192.168.1.110', '/login.php', 'id=1+OR+1=1')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num}.1: Simple OR 1=1", log, result, "MEDIUM/HIGH")
    if summary:
        results_summary.append(("2.1", "OR 1=1", summary))
    test_num += 1
    
    # Test 2.2: Comment injection
    log = create_log_entry('192.168.1.111', '/test.php', 'id=1--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.2: Comment Injection (--)", log, result, "MEDIUM")
    if summary:
        results_summary.append(("2.2", "Comment --", summary))
    
    # Test 2.3: Hash comment
    log = create_log_entry('192.168.1.112', '/test.php', 'id=1%23')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.3: Hash Comment (#)", log, result, "MEDIUM")
    if summary:
        results_summary.append(("2.3", "Hash Comment", summary))
    
    # Test 2.4: Time-based (simple)
    log = create_log_entry('192.168.1.113', '/test.php', 'id=1+AND+SLEEP(2)', response_time_ms=2000)
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.4: Time-based (SLEEP)", log, result, "MEDIUM/HIGH")
    if summary:
        results_summary.append(("2.4", "Time-based SLEEP", summary))
    
    # ========== CATEGORY 3: HIGH THREAT ==========
    print("\n" + "📌 CATEGORY 3: HIGH THREAT (Clear SQLi patterns)".center(90))
    print("=" * 90)
    
    # Test 3.1: UNION SELECT
    log = create_log_entry('192.168.1.120', '/users.php', 'id=1+UNION+SELECT+1,2,3--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num}.1: UNION SELECT", log, result, "HIGH/CRITICAL")
    if summary:
        results_summary.append(("3.1", "UNION SELECT", summary))
    test_num += 1
    
    # Test 3.2: Boolean blind
    log = create_log_entry('192.168.1.121', '/login.php', "id=admin'+OR+'1'='1")
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.2: Boolean Blind (OR '1'='1')", log, result, "HIGH")
    if summary:
        results_summary.append(("3.2", "Boolean Blind", summary))
    
    # Test 3.3: String concatenation
    log = create_log_entry('192.168.1.122', '/test.php', "id=1'+CONCAT('a','b')+'1")
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.3: String Concatenation", log, result, "HIGH")
    if summary:
        results_summary.append(("3.3", "String Concat", summary))
    
    # ========== CATEGORY 4: CRITICAL THREAT ==========
    print("\n" + "📌 CATEGORY 4: CRITICAL THREAT (Information disclosure)".center(90))
    print("=" * 90)
    
    # Test 4.1: Information schema
    log = create_log_entry('192.168.1.130', '/vulnerabilities/sqli/index.php', 
                          'id=1+UNION+SELECT+*+FROM+information_schema.tables--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num}.1: Information Schema", log, result, "CRITICAL")
    if summary:
        results_summary.append(("4.1", "Information Schema", summary))
    test_num += 1
    
    # Test 4.2: Database functions
    log = create_log_entry('192.168.1.131', '/test.php', 'id=1+UNION+SELECT+version(),user(),database()--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.2: Database Functions", log, result, "CRITICAL")
    if summary:
        results_summary.append(("4.2", "DB Functions", summary))
    
    # Test 4.3: File operations
    log = create_log_entry('192.168.1.132', '/test.php', 'id=1+UNION+SELECT+LOAD_FILE(\'/etc/passwd\')--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.3: File Operations (LOAD_FILE)", log, result, "CRITICAL")
    if summary:
        results_summary.append(("4.3", "LOAD_FILE", summary))
    
    # Test 4.4: Base64 encoded SQLi
    log = create_log_entry('192.168.1.133', '/api/user.php', '', 
                          'data=JyBPUiAxPTEtLQ==', method='POST')  # Base64: ' OR 1=1--
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.4: Base64 Encoded SQLi", log, result, "CRITICAL")
    if summary:
        results_summary.append(("4.4", "Base64 Encoded", summary))
    
    # Test 4.5: Double Base64
    import base64
    payload1 = base64.b64encode("' OR 1=1--".encode()).decode()
    payload2 = base64.b64encode(payload1.encode()).decode()
    log = create_log_entry('192.168.1.134', '/api/test.php', '', 
                          f'data={payload2}', method='POST')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.5: Double Base64 Encoded", log, result, "CRITICAL")
    if summary:
        results_summary.append(("4.5", "Double Base64", summary))
    
    # ========== CATEGORY 5: ENCODING VARIANTS ==========
    print("\n" + "📌 CATEGORY 5: ENCODING VARIANTS".center(90))
    print("=" * 90)
    
    # Test 5.1: URL encoded
    log = create_log_entry('192.168.1.140', '/test.php', 'id=1%27+OR+1%3D1--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num}.1: URL Encoded (Single)", log, result, "HIGH/CRITICAL")
    if summary:
        results_summary.append(("5.1", "URL Encoded", summary))
    test_num += 1
    
    # Test 5.2: Double URL encoded
    log = create_log_entry('192.168.1.141', '/test.php', 'id=1%2527+OR+1%253D1--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.2: Double URL Encoded", log, result, "HIGH/CRITICAL")
    if summary:
        results_summary.append(("5.2", "Double URL", summary))
    
    # Test 5.3: Hex encoded
    log = create_log_entry('192.168.1.142', '/test.php', 'id=1+OR+0x31=0x31')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.3: Hex Encoded", log, result, "HIGH")
    if summary:
        results_summary.append(("5.3", "Hex Encoded", summary))
    
    # Test 5.4: CHAR() encoding
    log = create_log_entry('192.168.1.143', '/test.php', 'id=1+OR+CHAR(49)=CHAR(49)')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.4: CHAR() Encoding", log, result, "HIGH")
    if summary:
        results_summary.append(("5.4", "CHAR()", summary))
    
    # ========== CATEGORY 6: OBFUSCATION TECHNIQUES ==========
    print("\n" + "📌 CATEGORY 6: OBFUSCATION TECHNIQUES".center(90))
    print("=" * 90)
    
    # Test 6.1: Case variation
    log = create_log_entry('192.168.1.150', '/test.php', 'id=1+UnIoN+SeLeCt+1,2,3--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num}.1: Case Variation", log, result, "HIGH/CRITICAL")
    if summary:
        results_summary.append(("6.1", "Case Variation", summary))
    test_num += 1
    
    # Test 6.2: Comment injection with spaces
    log = create_log_entry('192.168.1.151', '/test.php', 'id=1/**/OR/**/1=1--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.2: Comment Injection (/**/)", log, result, "HIGH")
    if summary:
        results_summary.append(("6.2", "Comment /**/", summary))
    
    # Test 6.3: Overlong UTF-8
    log = create_log_entry('192.168.1.152', '/test.php', 'id=1%c0%ae%c0%ae%c0%af')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.3: Overlong UTF-8", log, result, "CRITICAL")
    if summary:
        results_summary.append(("6.3", "Overlong UTF-8", summary))
    
    # Test 6.4: Whitespace variants
    log = create_log_entry('192.168.1.153', '/test.php', 'id=1%09OR%0A1=1--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.4: Whitespace Variants", log, result, "HIGH")
    if summary:
        results_summary.append(("6.4", "Whitespace", summary))
    
    # ========== CATEGORY 7: DATABASE-SPECIFIC ==========
    print("\n" + "📌 CATEGORY 7: DATABASE-SPECIFIC ATTACKS".center(90))
    print("=" * 90)
    
    # Test 7.1: MySQL
    log = create_log_entry('192.168.1.160', '/test.php', 'id=1+UNION+SELECT+*+FROM+mysql.user--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num}.1: MySQL Specific", log, result, "CRITICAL")
    if summary:
        results_summary.append(("7.1", "MySQL", summary))
    test_num += 1
    
    # Test 7.2: MSSQL
    log = create_log_entry('192.168.1.161', '/test.php', 'id=1;EXEC+xp_cmdshell+\'dir\'--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.2: MSSQL (xp_cmdshell)", log, result, "CRITICAL")
    if summary:
        results_summary.append(("7.2", "MSSQL", summary))
    
    # Test 7.3: PostgreSQL
    log = create_log_entry('192.168.1.162', '/test.php', 'id=1+UNION+SELECT+pg_sleep(5)--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.3: PostgreSQL (pg_sleep)", log, result, "CRITICAL")
    if summary:
        results_summary.append(("7.3", "PostgreSQL", summary))
    
    # Test 7.4: Oracle
    log = create_log_entry('192.168.1.163', '/test.php', 'id=1+UNION+SELECT+*+FROM+all_users--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.4: Oracle (all_users)", log, result, "CRITICAL")
    if summary:
        results_summary.append(("7.4", "Oracle", summary))
    
    # ========== CATEGORY 8: NoSQL INJECTION ==========
    print("\n" + "📌 CATEGORY 8: NoSQL INJECTION".center(90))
    print("=" * 90)
    
    # Test 8.1: MongoDB $ne
    log = create_log_entry('192.168.1.170', '/api/search', '', 
                          '{"username": {"$ne": null}, "password": {"$ne": null}}', method='POST')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num}.1: MongoDB $ne", log, result, "CRITICAL")
    if summary:
        results_summary.append(("8.1", "MongoDB $ne", summary))
    test_num += 1
    
    # Test 8.2: MongoDB $regex
    log = create_log_entry('192.168.1.171', '/api/search', '', 
                          '{"username": {"$regex": ".*"}}', method='POST')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.2: MongoDB $regex", log, result, "CRITICAL")
    if summary:
        results_summary.append(("8.2", "MongoDB $regex", summary))
    
    # Test 8.3: MongoDB $where
    log = create_log_entry('192.168.1.172', '/api/search', '', 
                          '{"$where": "this.username == this.password"}', method='POST')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.3: MongoDB $where", log, result, "CRITICAL")
    if summary:
        results_summary.append(("8.3", "MongoDB $where", summary))
    
    # ========== CATEGORY 9: ATTACK VECTORS ==========
    print("\n" + "📌 CATEGORY 9: DIFFERENT ATTACK VECTORS".center(90))
    print("=" * 90)
    
    # Test 9.1: URI path
    log = create_log_entry('192.168.1.180', '/users/1+UNION+SELECT+1,2,3--', '')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num}.1: URI Path SQLi", log, result, "HIGH/CRITICAL")
    if summary:
        results_summary.append(("9.1", "URI Path", summary))
    test_num += 1
    
    # Test 9.2: POST body
    log = create_log_entry('192.168.1.181', '/api/login', '', 
                          'username=admin\'+OR+\'1\'=\'1&password=test', method='POST')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.2: POST Body SQLi", log, result, "HIGH/CRITICAL")
    if summary:
        results_summary.append(("9.2", "POST Body", summary))
    
    # Test 9.3: Cookie
    log = create_log_entry('192.168.1.182', '/test.php', '', '', 
                          cookie="session_id=abc123; user_id=1'+UNION+SELECT+1--")
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.3: Cookie SQLi", log, result, "HIGH/CRITICAL")
    if summary:
        results_summary.append(("9.3", "Cookie", summary))
    
    # Test 9.4: User-Agent
    log = create_log_entry('192.168.1.183', '/test.php', '', '', 
                          user_agent="Mozilla/5.0' UNION SELECT 1,2,3--")
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.4: User-Agent SQLi", log, result, "HIGH")
    if summary:
        results_summary.append(("9.4", "User-Agent", summary))
    
    # ========== CATEGORY 10: ADVANCED ATTACKS ==========
    print("\n" + "📌 CATEGORY 10: ADVANCED ATTACKS".center(90))
    print("=" * 90)
    
    # Test 10.1: Stacked queries
    log = create_log_entry('192.168.1.190', '/test.php', 'id=1;DROP+TABLE+users--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num}.1: Stacked Queries (DROP TABLE)", log, result, "CRITICAL")
    if summary:
        results_summary.append(("10.1", "Stacked DROP", summary))
    test_num += 1
    
    # Test 10.2: Second-order SQLi
    log = create_log_entry('192.168.1.191', '/register.php', '', 
                          'username=test\';DROP+TABLE+users--', method='POST')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.2: Second-order SQLi", log, result, "CRITICAL")
    if summary:
        results_summary.append(("10.2", "Second-order", summary))
    
    # Test 10.3: Time-based blind (complex)
    log = create_log_entry('192.168.1.192', '/test.php', 
                          'id=1+AND+IF(ASCII(SUBSTRING(database(),1,1))=115,SLEEP(5),0)--',
                          response_time_ms=5000)
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.3: Complex Time-based Blind", log, result, "CRITICAL")
    if summary:
        results_summary.append(("10.3", "Complex Time-based", summary))
    
    # Test 10.4: Error-based
    log = create_log_entry('192.168.1.193', '/test.php', 'id=1+AND+EXTRACTVALUE(1,CONCAT(0x7e,version(),0x7e))--')
    result = collector.detect_sqli_realtime(log)
    summary = print_result(f"TEST {test_num-1}.4: Error-based (EXTRACTVALUE)", log, result, "CRITICAL")
    if summary:
        results_summary.append(("10.4", "Error-based", summary))
    
    # ========== TỔNG KẾT ==========
    print("\n" + "=" * 90)
    print("📊 TỔNG KẾT PHÂN LOẠI THREAT LEVEL".center(90))
    print("=" * 90)
    
    # Group by threat level
    threat_levels = {'NONE': [], 'LOW': [], 'MEDIUM': [], 'HIGH': [], 'CRITICAL': []}
    for test_id, test_name, summary in results_summary:
        threat_level = summary['threat_level']
        threat_levels[threat_level].append((test_id, test_name, summary))
    
    for level in ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
        tests = threat_levels[level]
        if tests:
            print(f"\n{level} ({len(tests)} tests):")
            for test_id, test_name, summary in tests:
                print(f"  {test_id}: {test_name:30s} - Risk Score: {summary['risk_score']:6.2f} - {summary['risk_level']}")
    
    # Statistics
    total = len(results_summary)
    sqli_detected = sum(1 for _, _, s in results_summary if s['is_sqli'])
    critical = len(threat_levels['CRITICAL'])
    high = len(threat_levels['HIGH'])
    medium = len(threat_levels['MEDIUM'])
    low = len(threat_levels['LOW'])
    none = len(threat_levels['NONE'])
    
    print("\n" + "=" * 90)
    print("📈 STATISTICS".center(90))
    print("=" * 90)
    print(f"Total Tests: {total}")
    print(f"SQLi Detected: {sqli_detected} ({sqli_detected/total*100:.1f}%)")
    print(f"Threat Levels:")
    print(f"  CRITICAL: {critical} ({critical/total*100:.1f}%)")
    print(f"  HIGH:     {high} ({high/total*100:.1f}%)")
    print(f"  MEDIUM:   {medium} ({medium/total*100:.1f}%)")
    print(f"  LOW:      {low} ({low/total*100:.1f}%)")
    print(f"  NONE:     {none} ({none/total*100:.1f}%)")
    print("=" * 90)
    print("✅ Comprehensive test hoàn tất!")
    print("=" * 90)

if __name__ == "__main__":
    main()


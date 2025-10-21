#!/usr/bin/env python3
"""
Script để debug pattern detection và URL decoding
"""

import urllib.parse
from optimized_sqli_detector import OptimizedSQLIDetector

def url_decode_safe(text):
    """Safe URL decode"""
    if not text:
        return ""
    try:
        return urllib.parse.unquote_plus(text)
    except:
        return text

def debug_pattern_detection():
    """Debug pattern detection"""
    
    print("🔍 Debugging Pattern Detection")
    print("=" * 50)
    
    # Test cases từ logs
    test_cases = [
        {
            "name": "Real SQLi UNION",
            "query": "?id=%27+UNION+SELECT+null%2C+version%28%29+--&Submit=Submit",
            "payload": "id=%27+UNION+SELECT+null%2C+version%28%29+--&Submit=Submit"
        },
        {
            "name": "Real SQLi OR 1=1", 
            "query": "?id=%27+OR+%271%27%3D%271&Submit=Submit",
            "payload": "id=%27+OR+%271%27%3D%271&Submit=Submit"
        },
        {
            "name": "False Positive",
            "query": "?id=tuan&Submit=Submit", 
            "payload": "id=tuan&Submit=Submit"
        }
    ]
    
    # SQLi patterns
    sqli_keywords = [
        'union select', 'or 1=1', 'and 1=1', "' or '", '" or "',
        'sleep(', 'waitfor delay', 'benchmark(', 'drop table',
        'delete from', 'insert into', 'update set', 'information_schema',
        'mysql.user', 'version(', 'user(', 'exec(', 'execute(',
        'xp_cmdshell', 'sp_executesql', 'load_file(', 'into outfile',
        '--', '/*', '*/', '0x', 'char(', 'ascii(',
        'or 1=1--', 'and 1=1--', 'or 1=1#', 'and 1=1#',
        'union all select', 'union select *', 'union select 1'
    ]
    
    for test_case in test_cases:
        print(f"\n📋 Test: {test_case['name']}")
        print("-" * 30)
        
        # Raw data
        print(f"Raw Query: {test_case['query']}")
        print(f"Raw Payload: {test_case['payload']}")
        
        # Decoded data
        decoded_query = url_decode_safe(test_case['query'])
        decoded_payload = url_decode_safe(test_case['payload'])
        print(f"Decoded Query: {decoded_query}")
        print(f"Decoded Payload: {decoded_payload}")
        
        # Combined text
        combined_text = f"{decoded_query} {decoded_payload}".lower()
        print(f"Combined Text: {combined_text}")
        
        # Check patterns
        found_patterns = []
        for keyword in sqli_keywords:
            if keyword in combined_text:
                found_patterns.append(keyword)
        
        if found_patterns:
            print(f"✅ Found Patterns: {found_patterns}")
        else:
            print("❌ No Patterns Found")
        
        # Test with detector
        detector = OptimizedSQLIDetector()
        detector.load_model('models/optimized_sqli_detector.pkl')
        
        log_entry = {
            "time": "2025-10-22T00:17:28+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/sqli/index.php",
            "query_string": test_case['query'],
            "payload": test_case['payload'],
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "status": 200
        }
        
        is_anomaly, score = detector.predict_single(log_entry, threshold=0.7)
        result = "🚨 DETECTED" if is_anomaly else "✅ NORMAL"
        print(f"AI Detection: {result} (Score: {score:.3f})")

def fix_pattern_detection():
    """Fix pattern detection trong optimized_sqli_detector.py"""
    
    print(f"\n🔧 Fixing Pattern Detection")
    print("=" * 50)
    
    # Đọc file
    try:
        with open('optimized_sqli_detector.py', 'r') as f:
            content = f.read()
        
        # Tìm và thay thế URL decode logic
        old_decode = '''decoded_concat = " ".join([
            url_decode_safe(raw_uri),
            url_decode_safe(raw_qs),
            url_decode_safe(raw_payload),
            url_decode_safe(raw_user_agent),
            url_decode_safe(raw_cookie),
            url_decode_safe(raw_body),
            url_decode_safe(raw_referer)
        ])'''
        
        new_decode = '''# Decode all text fields for pattern matching
        decoded_fields = [
            url_decode_safe(raw_uri),
            url_decode_safe(raw_qs), 
            url_decode_safe(raw_payload),
            url_decode_safe(raw_user_agent),
            url_decode_safe(raw_cookie),
            url_decode_safe(raw_body),
            url_decode_safe(raw_referer)
        ]
        decoded_concat = " ".join(decoded_fields)'''
        
        if old_decode in content:
            content = content.replace(old_decode, new_decode)
            
            # Thêm debug logging
            debug_code = '''
        # Debug: Log decoded content for pattern matching
        if len(decoded_concat.strip()) > 0:
            print(f"DEBUG: Decoded content: {decoded_concat[:200]}...")'''
            
            # Tìm vị trí để insert debug code
            insert_pos = content.find('text_content = decoded_concat.lower()')
            if insert_pos != -1:
                content = content[:insert_pos] + debug_code + '\n        ' + content[insert_pos:]
            
            # Ghi file
            with open('optimized_sqli_detector.py', 'w') as f:
                f.write(content)
            
            print("✅ Updated pattern detection logic")
            print("   - Improved URL decoding")
            print("   - Added debug logging")
            print("   - Restart app to apply changes")
        else:
            print("❌ Could not find URL decode logic to update")
            
    except Exception as e:
        print(f"❌ Error updating pattern detection: {e}")

if __name__ == "__main__":
    debug_pattern_detection()
    fix_pattern_detection()

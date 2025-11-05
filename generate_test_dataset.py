#!/usr/bin/env python3
"""
Generate test dataset: 5000 logs (2000 SQLi phức tạp + 3000 clean)
"""

import json
import random
import urllib.parse
import base64
import re
from datetime import datetime, timedelta

# SQLi payloads phức tạp và lạ - Mở rộng với nhiều obfuscation techniques
COMPLEX_SQLI_PAYLOADS = [
    # Basic SQLi
    "1' OR '1'='1",
    "1' OR '1'='1'--",
    "1' OR '1'='1'#",
    "1' OR '1'='1'/*",
    "admin'--",
    "admin'#",
    "admin'/*",
    
    # Union-based SQLi
    "1' UNION SELECT NULL--",
    "1' UNION SELECT 1,2,3--",
    "1' UNION SELECT 1,2,3,4,5--",
    "1' UNION SELECT * FROM users--",
    "1' UNION ALL SELECT NULL,NULL,NULL--",
    "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
    
    # Boolean-based blind SQLi
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1' AND 'a'='a",
    "1' AND 'a'='b",
    "1' AND ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1))>50--",
    "1' AND LENGTH((SELECT password FROM users WHERE id=1))>10--",
    
    # Time-based SQLi
    "1'; WAITFOR DELAY '00:00:05'--",
    "1'; SELECT SLEEP(5)--",
    "1' OR SLEEP(5)--",
    "1'; BENCHMARK(5000000,MD5('test'))--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    
    # Error-based SQLi
    "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT password FROM users WHERE id=1), 0x7e))--",
    "1' AND UPDATEXML(1, CONCAT(0x7e, (SELECT password FROM users WHERE id=1), 0x7e), 1)--",
    "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT password FROM users WHERE id=1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    
    # Information gathering
    "1' UNION SELECT @@version--",
    "1' UNION SELECT user()--",
    "1' UNION SELECT database()--",
    "1' UNION SELECT * FROM information_schema.tables--",
    "1' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",
    "1' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
    
    # Stacked queries
    "1'; DROP TABLE users--",
    "1'; DELETE FROM users WHERE id=1--",
    "1'; INSERT INTO users (username, password) VALUES ('hacker', 'pass')--",
    "1'; UPDATE users SET password='hacked' WHERE id=1--",
    
    # Obfuscated SQLi - Unicode
    "1' OR 1=1--",
    "1' OR 1=1#",
    "1' OR 1=1/*",
    "1' OR 1=1/**/",
    "1' OR 1=1/**/--",
    
    # Obfuscated SQLi - Hex
    "1' OR 0x31=0x31--",
    "1' UNION SELECT 0x31,0x32,0x33--",
    "1' OR CHAR(49)=CHAR(49)--",
    
    # Obfuscated SQLi - Case variation
    "1' UnIoN SeLeCt 1,2,3--",
    "1' Or 1=1--",
    "1' AnD 1=1--",
    
    # Obfuscated SQLi - Comment injection
    "1'/**/OR/**/1=1--",
    "1'/*comment*/OR/*comment*/1=1--",
    "1' OR 1=1/**/--",
    
    # NoSQL injection
    "{\"$where\": \"this.password == this.username\"}",
    "{\"$ne\": null}",
    "{\"$gt\": \"\"}",
    "{\"$regex\": \".*\"}",
    "{\"$or\": [{\"username\": \"admin\"}, {\"password\": \"admin\"}]}",
    
    # JSON injection
    "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
    "{\"username\": \"admin\", \"password\": {\"$regex\": \".*\"}}",
    
    # Overlong UTF-8
    "%c0%ae%c0%ae%c0%af",
    "%c1%9c%c1%9c%c1%9d",
    
    # Double encoding
    "%2527 OR 1=1--",
    "%2527 UNION SELECT 1,2,3--",
    
    # Base64 encoded (simple)
    "MScgT1IgJzEnPScx",
    "MScgVU5JT04gU0VMRUNUIDEsMiwz--",
    # Base64 encoded (complex - case 2 style)
    "MScgQU5EIEFTQ0lJKFNVQlNUUklORygoU0VMRUNUIHBhc3N3b3JkIEZST00gdXNlcnMgV0hFUkUgaWQ9MSksMSwxKSk+NTA",
    # Base64 encoded (nested)
    "MScgT1IgJzEnPScx",  # Will be nested encoded
    # Base64 with missing padding
    "MScgT1IgJzEnPScx",  # Without padding
    "MScgVU5JT04gU0VMRUNUIDEsMiwz",  # Without padding
    
    # Advanced time-based
    "1' AND IF(ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1))>50, SLEEP(5), 0)--",
    "1' AND (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1))>50) THEN SLEEP(5) ELSE 0 END)--",
    
    # Advanced error-based
    "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT password FROM users WHERE id=1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    
    # Second-order SQLi
    "admin'; INSERT INTO logs (username, action) VALUES ('admin', '1' OR '1'='1');--",
    
    # Cookie-based SQLi
    "session_id=1' OR 1=1--",
    "token=admin' OR 'a'='a",
    
    # User-Agent SQLi
    "Mozilla/5.0' UNION SELECT 1,2,3--",
    
    # Referer SQLi
    "http://example.com' OR 1=1--",
    
    # Complex obfuscated
    "1'/**/UnIoN/**/SeLeCt/**/1,2,3/**/--",
    "1'/**/UnIoN/**/AlL/**/SeLeCt/**/1,2,3/**/--",
    "1'/**/UnIoN/**/SeLeCt/**/NULL,NULL,NULL/**/--",
    
    # Database-specific
    "1'; EXEC xp_cmdshell('dir')--",
    "1'; EXEC sp_executesql N'SELECT * FROM users'--",
    "1'; SELECT load_file('/etc/passwd')--",
    "1'; SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/shell.php'--",
    
    # Advanced obfuscation - Triple encoding
    "%252527 OR 1=1--",
    "%252527 UNION SELECT 1,2,3--",
    
    # Advanced obfuscation - Mixed encoding
    "1'/**/UnIoN/**/SeLeCt/**/1,2,3/**/FrOm/**/users/**/--",
    "1'/**/Or/**/1=1/**/AnD/**/1=1/**/--",
    
    # Advanced obfuscation - Whitespace injection
    "1'/**/OR/**/1=1/**/--",
    "1'/**/OR/**/'1'='1/**/--",
    "1'/**/UNION/**/SELECT/**/NULL,NULL,NULL/**/--",
    
    # Advanced obfuscation - Character substitution
    "1' OR 1=1--",
    "1' OR 1=1--",
    "1' OR 1=1--",
    
    # Advanced obfuscation - XOR encoding
    "1' OR 1=1 XOR 1=1--",
    "1' OR 1=1 XOR 1=2--",
    
    # Advanced obfuscation - Concatenation
    "1' OR '1'='1' || '1'='1--",
    "1' OR CONCAT('1','1')='11'--",
    
    # Advanced obfuscation - Hex encoding
    "1' OR 0x31=0x31--",
    "1' UNION SELECT 0x31,0x32,0x33--",
    "1' OR CHAR(49)=CHAR(49)--",
    "1' OR CHAR(0x31)=CHAR(0x31)--",
    
    # Advanced obfuscation - Comment injection variations
    "1'/**/OR/**/1=1/**/--",
    "1'/*!OR*/1=1--",
    "1'/*!50000OR*/1=1--",
    "1'/*!50000OR*//*!500001*/=1--",
    
    # Advanced obfuscation - Case variation with comments
    "1'/**/UnIoN/**/SeLeCt/**/1,2,3/**/--",
    "1'/**/UnIoN/**/AlL/**/SeLeCt/**/NULL,NULL,NULL/**/--",
    "1'/**/Or/**/1=1/**/AnD/**/1=1/**/--",
    
    # Advanced obfuscation - Multiple injection points
    "id=1' OR '1'='1&name=admin'--",
    "id=1' UNION SELECT 1,2,3&name=admin'--",
    
    # Advanced obfuscation - WAF bypass techniques
    "1'/**/OR/**/1=1/**/--",
    "1'/**/OR/**/'1'='1/**/--",
    "1'/**/UNION/**/SELECT/**/1,2,3/**/--",
    "1'/**/OR/**/1=1/**/AnD/**/1=1/**/--",
    
    # Advanced obfuscation - Function name obfuscation
    "1' OR CONCAT('1','1')='11'--",
    "1' OR CHAR(49)=CHAR(49)--",
    "1' OR ASCII(SUBSTRING('test',1,1))=116--",
    
    # Advanced obfuscation - String concatenation
    "1' OR '1'='1' || '1'='1'--",
    "1' OR CONCAT('1','1')=CONCAT('1','1')--",
    
    # Advanced obfuscation - Time-based with obfuscation
    "1'/**/OR/**/SLEEP(5)/**/--",
    "1'/**/OR/**/IF(1=1,SLEEP(5),0)/**/--",
    "1'/**/OR/**/(SELECT/**/SLEEP(5))/**/--",
    
    # Advanced obfuscation - Error-based with obfuscation
    "1'/**/OR/**/EXTRACTVALUE(1,CONCAT(0x7e,(SELECT/**/password/**/FROM/**/users/**/WHERE/**/id=1),0x7e))/**/--",
    "1'/**/OR/**/UPDATEXML(1,CONCAT(0x7e,(SELECT/**/password/**/FROM/**/users/**/WHERE/**/id=1),0x7e),1)/**/--",
    
    # Advanced obfuscation - Boolean-based with obfuscation
    "1'/**/OR/**/1=1/**/AnD/**/1=1/**/--",
    "1'/**/OR/**/'1'='1'/**/AnD/**/'1'='1'/**/--",
    "1'/**/OR/**/ASCII(SUBSTRING((SELECT/**/password/**/FROM/**/users/**/WHERE/**/id=1),1,1))>50/**/--",
    
    # Advanced obfuscation - Union-based with obfuscation
    "1'/**/UnIoN/**/SeLeCt/**/1,2,3/**/FrOm/**/users/**/--",
    "1'/**/UnIoN/**/AlL/**/SeLeCt/**/NULL,NULL,NULL/**/FrOm/**/users/**/--",
    "1'/**/UnIoN/**/SeLeCt/**/1,2,3,4,5/**/FrOm/**/users/**/WHERE/**/id=1/**/--",
    
    # Advanced obfuscation - NoSQL with obfuscation
    "{\"$where\": \"this.password == this.username\"}",
    "{\"$ne\": null, \"$gt\": \"\"}",
    "{\"$regex\": \".*\", \"$or\": [{\"username\": \"admin\"}, {\"password\": \"admin\"}]}",
    
    # Advanced obfuscation - JSON injection with obfuscation
    "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}, \"$or\": [{\"username\": \"admin\"}, {\"password\": \"admin\"}]}",
    "{\"username\": \"admin\", \"password\": {\"$regex\": \".*\"}, \"$where\": \"this.password == this.username\"}",
    
    # Advanced obfuscation - Overlong UTF-8 variations
    "%c0%ae%c0%ae%c0%af",
    "%c1%9c%c1%9c%c1%9d",
    "%2525c0%2525ae%2525c0%2525ae%2525c0%2525af",
    "%2525c1%25259c%2525c1%25259c%2525c1%25259d",
    
    # Advanced obfuscation - Multiple encoding layers
    "1' OR 1=1--",  # Will be encoded multiple times
    
    # Advanced obfuscation - Cookie injection
    "session_id=1' OR 1=1--",
    "token=admin' OR 'a'='a",
    "auth=1'/**/OR/**/1=1/**/--",
    
    # Advanced obfuscation - User-Agent injection
    "Mozilla/5.0'/**/UNION/**/SELECT/**/1,2,3/**/--",
    "Mozilla/5.0'/**/OR/**/1=1/**/--",
    
    # Advanced obfuscation - Referer injection
    "http://example.com'/**/OR/**/1=1/**/--",
    "http://example.com'/**/UNION/**/SELECT/**/1,2,3/**/--",
    
    # Advanced obfuscation - Body injection with multiple fields
    "username=admin'/**/OR/**/1=1/**/--&password=test",
    "username=admin'/**/UNION/**/SELECT/**/1,2,3/**/--&password=test",
    
    # Advanced obfuscation - Query string injection with multiple params
    "id=1'/**/OR/**/1=1/**/--&name=admin'/**/OR/**/1=1/**/--",
    "id=1'/**/UNION/**/SELECT/**/1,2,3/**/--&name=admin'/**/UNION/**/SELECT/**/1,2,3/**/--",
]

# Clean payloads mẫu
CLEAN_PAYLOADS = [
    "id=123",
    "page=1",
    "category=electronics",
    "search=product",
    "user=john",
    "email=user@example.com",
    "action=view",
    "type=list",
    "sort=price",
    "filter=new",
    "limit=10",
    "offset=0",
    "q=laptop",
    "keyword=test",
    "name=admin",
    "status=active",
    "tag=featured",
    "lang=en",
    "format=json",
    "version=1.0",
]

# Base URIs
BASE_URIS = [
    "/dvwa/vulnerabilities/sqli/",
    "/dvwa/vulnerabilities/sqli_blind/",
    "/dvwa/vulnerabilities/sqli_blind/",
    "/login.php",
    "/search.php",
    "/products.php",
    "/user/profile.php",
    "/api/users",
    "/api/products",
    "/admin/users",
    "/admin/products",
    "/dashboard",
    "/settings",
    "/account",
    "/cart",
    "/checkout",
    "/payment",
    "/orders",
    "/history",
]

def url_encode(s):
    """URL encode"""
    return urllib.parse.quote(s)

def double_encode(s):
    """Double URL encode"""
    return urllib.parse.quote(urllib.parse.quote(s))

def base64_encode(s):
    """Base64 encode"""
    try:
        return base64.b64encode(s.encode()).decode()
    except:
        return s

def triple_encode(s):
    """Triple URL encode"""
    return urllib.parse.quote(urllib.parse.quote(urllib.parse.quote(s)))

def nested_base64_encode(s):
    """Nested base64 encode (base64 of base64)"""
    try:
        first = base64.b64encode(s.encode()).decode()
        return base64.b64encode(first.encode()).decode()
    except:
        return s

def mixed_encoding(s):
    """Mixed encoding: some parts URL encoded, some base64"""
    parts = s.split(' ')
    encoded_parts = []
    for p in parts:
        if random.random() > 0.5:
            encoded_parts.append(urllib.parse.quote(p))
        else:
            try:
                encoded_parts.append(base64.b64encode(p.encode()).decode())
            except:
                encoded_parts.append(p)
    return ' '.join(encoded_parts)

def obfuscate_with_comments(s):
    """Obfuscate with SQL comments"""
    # Replace spaces with /**/
    return s.replace(' ', '/**/')

def obfuscate_with_case_variation(s):
    """Obfuscate with case variation"""
    result = []
    for char in s:
        if char.isalpha() and random.random() > 0.5:
            result.append(char.swapcase())
        else:
            result.append(char)
    return ''.join(result)

def add_whitespace_injection(s):
    """Add whitespace injection patterns"""
    # Add /**/ randomly
    result = []
    for char in s:
        result.append(char)
        if char == ' ' and random.random() > 0.7:
            result.append('/**/')
    return ''.join(result)

def generate_sqli_log(payload, index):
    """Generate SQLi log entry with advanced obfuscation"""
    # Random encoding variations (expanded)
    encoding_type = random.choice([
        'none', 'url', 'double_url', 'triple_url', 
        'base64', 'nested_base64', 'mixed', 
        'comments', 'case_variation', 'whitespace_injection',
        'mixed_complex'
    ])
    
    if encoding_type == 'url':
        encoded_payload = url_encode(payload)
    elif encoding_type == 'double_url':
        encoded_payload = double_encode(payload)
    elif encoding_type == 'triple_url':
        encoded_payload = triple_encode(payload)
    elif encoding_type == 'base64':
        encoded_payload = base64_encode(payload)
        # Sometimes add +NTA or space padding issues
        if random.random() > 0.8:
            encoded_payload += "+NTA"  # Simulate padding issue
    elif encoding_type == 'nested_base64':
        encoded_payload = nested_base64_encode(payload)
    elif encoding_type == 'mixed':
        encoded_payload = mixed_encoding(payload)
    elif encoding_type == 'comments':
        encoded_payload = obfuscate_with_comments(payload)
    elif encoding_type == 'case_variation':
        encoded_payload = obfuscate_with_case_variation(payload)
    elif encoding_type == 'whitespace_injection':
        encoded_payload = add_whitespace_injection(payload)
    elif encoding_type == 'mixed_complex':
        # Combine multiple obfuscation techniques
        if random.random() > 0.5:
            temp = obfuscate_with_comments(payload)
            temp = obfuscate_with_case_variation(temp)
            if random.random() > 0.5:
                encoded_payload = url_encode(temp)
            else:
                encoded_payload = base64_encode(temp)
        else:
            encoded_payload = mixed_encoding(payload)
            if random.random() > 0.5:
                encoded_payload = double_encode(encoded_payload)
    else:
        encoded_payload = payload
    
    # Random field injection
    field = random.choice(['query_string', 'payload', 'body', 'cookie'])
    
    log_entry = {
        "time": (datetime.now() - timedelta(seconds=random.randint(0, 86400))).isoformat(),
        "remote_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "method": random.choice(["GET", "POST"]),
        "uri": random.choice(BASE_URIS),
        "query_string": "",
        "payload": "",
        "body": "",
        "cookie": "",
        "status": random.choice([200, 200, 200, 404, 500]),
        "bytes_sent": random.randint(100, 10000),
        "response_time_ms": random.randint(10, 500),
        "request_length": random.randint(100, 5000),
        "response_length": random.randint(100, 10000),
        "referer": random.choice(["", "http://example.com", "https://google.com"]),
        "user_agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]),
    }
    
    # Inject payload vào field được chọn
    if field == 'query_string':
        log_entry["query_string"] = f"id={encoded_payload}"
    elif field == 'payload':
        log_entry["payload"] = f"data={encoded_payload}"
        log_entry["method"] = "POST"
    elif field == 'body':
        log_entry["body"] = f"username={encoded_payload}&password=test"
        log_entry["method"] = "POST"
    elif field == 'cookie':
        log_entry["cookie"] = f"session={encoded_payload}; token=abc123"
    
    return log_entry

def generate_clean_log(index):
    """Generate clean log entry"""
    log_entry = {
        "time": (datetime.now() - timedelta(seconds=random.randint(0, 86400))).isoformat(),
        "remote_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "method": random.choice(["GET", "POST", "GET", "GET"]),
        "uri": random.choice(BASE_URIS),
        "query_string": random.choice(CLEAN_PAYLOADS) if random.random() > 0.3 else "",
        "payload": "",
        "body": "",
        "cookie": f"session={random.randint(1000, 9999)}; csrf_token=abc123" if random.random() > 0.5 else "",
        "status": random.choice([200, 200, 200, 200, 404]),
        "bytes_sent": random.randint(100, 10000),
        "response_time_ms": random.randint(10, 500),
        "request_length": random.randint(100, 5000),
        "response_length": random.randint(100, 10000),
        "referer": random.choice(["", "http://example.com", "https://google.com"]),
        "user_agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]),
    }
    
    # Random POST body
    if log_entry["method"] == "POST" and random.random() > 0.5:
        log_entry["body"] = f"username=user{random.randint(1, 100)}&password=pass123"
    
    return log_entry

def main():
    print("Generating test dataset: 5000 logs (2000 SQLi + 3000 clean)...")
    
    sqli_logs = []
    clean_logs = []
    
    # Generate 2000 SQLi logs
    print("Generating 2000 SQLi logs...")
    for i in range(2000):
        payload = random.choice(COMPLEX_SQLI_PAYLOADS)
        log_entry = generate_sqli_log(payload, i)
        # Đánh dấu là SQLi
        log_entry['_is_sqli'] = True
        sqli_logs.append(log_entry)
        if (i + 1) % 200 == 0:
            print(f"  Generated {i + 1}/2000 SQLi logs...")
    
    # Generate 3000 clean logs
    print("Generating 3000 clean logs...")
    for i in range(3000):
        log_entry = generate_clean_log(i)
        # Đảm bảo clean logs không có SQLi patterns
        # Decode và check lại
        from optimized_sqli_detector import url_decode_safe
        import base64
        
        def decode_base64_safe(s):
            try:
                if len(s) > 4:
                    decoded = base64.b64decode(s, validate=True)
                    return decoded.decode('utf-8', errors='ignore')
            except:
                pass
            return s
        
        # Decode và check
        qs = log_entry.get('query_string', '')
        payload = log_entry.get('payload', '')
        body = log_entry.get('body', '')
        
        decoded_qs = url_decode_safe(url_decode_safe(qs))
        decoded_payload = url_decode_safe(url_decode_safe(payload))
        decoded_body = url_decode_safe(url_decode_safe(body))
        
        # Base64 decode nếu có
        if '=' in decoded_qs:
            parts = decoded_qs.split('=', 1)
            if len(parts) > 1:
                base64_part = parts[1].split('&')[0]
                if len(base64_part) > 4:
                    decoded_qs += ' ' + decode_base64_safe(base64_part)
        
        if '=' in decoded_payload:
            parts = decoded_payload.split('=', 1)
            if len(parts) > 1:
                base64_part = parts[1].split('&')[0]
                if len(base64_part) > 4:
                    decoded_payload += ' ' + decode_base64_safe(base64_part)
        
        text_content = f"{decoded_qs} {decoded_payload} {decoded_body}".lower()
        
        # Kiểm tra xem có SQLi patterns không
        sqli_keywords = ['union', 'select', 'delete from', 'insert into', 'update set', 
                        'or 1=1', 'and 1=1', 'sleep', 'waitfor', 'benchmark', 
                        'drop table', 'information_schema', 'exec', 'xp_cmdshell',
                        '--', '#', '/*', '*/', '$where', '$ne', '$gt', '$regex']
        
        has_sqli = any(kw in text_content for kw in sqli_keywords)
        
        # Nếu có SQLi patterns → bỏ qua hoặc regenerate
        if has_sqli:
            # Regenerate cho đến khi không có SQLi patterns
            attempts = 0
            while has_sqli and attempts < 10:
                log_entry = generate_clean_log(i + attempts)
                qs = log_entry.get('query_string', '')
                payload = log_entry.get('payload', '')
                body = log_entry.get('body', '')
                
                decoded_qs = url_decode_safe(url_decode_safe(qs))
                decoded_payload = url_decode_safe(url_decode_safe(payload))
                decoded_body = url_decode_safe(url_decode_safe(body))
                
                text_content = f"{decoded_qs} {decoded_payload} {decoded_body}".lower()
                has_sqli = any(kw in text_content for kw in sqli_keywords)
                attempts += 1
        
        # Đánh dấu là clean
        log_entry['_is_sqli'] = False
        clean_logs.append(log_entry)
    
    # Shuffle và combine
    all_logs = sqli_logs + clean_logs
    random.shuffle(all_logs)
    
    # Save to file
    output_file = "test_dataset_5000.jsonl"
    print(f"\nSaving to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        for log in all_logs:
            f.write(json.dumps(log, ensure_ascii=False) + '\n')
    
    print(f"[OK] Test dataset saved to {output_file}")
    print(f"   - Total logs: {len(all_logs)}")
    print(f"   - SQLi logs: {len(sqli_logs)}")
    print(f"   - Clean logs: {len(clean_logs)}")

if __name__ == '__main__':
    main()


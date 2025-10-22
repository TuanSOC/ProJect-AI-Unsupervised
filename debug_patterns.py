#!/usr/bin/env python3
"""
Debug pattern detection để xem tại sao patterns = N/A
"""

import json
import urllib.parse

def url_decode_safe(text):
    """URL decode an toàn"""
    if not text:
        return ""
    try:
        return urllib.parse.unquote(text)
    except:
        return text

def debug_pattern_detection():
    """Debug pattern detection với real log"""
    
    # Real log từ user
    log_entry = {
        "time": "2025-10-22T08:47:41+0700",
        "remote_ip": "192.168.205.2", 
        "method": "GET",
        "uri": "/DVWA/vulnerabilities/sqli/index.php",
        "query_string": "?id=%27+or+benchmark%2810000000%2CMD5%281%29%29%23&Submit=Submit",
        "status": 200,
        "bytes_sent": 1437,
        "response_time_ms": 389400,
        "referer": "http://localhost/DVWA/vulnerabilities/sqli/",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "request_length": 1859,
        "response_length": 1788,
        "cookie": "wz-user=admin; wz-api=default; wz-token=eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzU4Nzg3NTMxLCJleHAiOjE3NTg3ODg0MzEsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AesxoYn2Mswm57ZVr629sOm17LOZ9CZsYHZrBA9iJD0VIX6dhKYvdmliAam4Bz0t0ESzWhJBxRzWDcp0mbTaQfp7AItpDAA7FYRdttfxSzWRRQDQfJqdn92jw7mKWhVmfNdVi0LIuX3v5NBuEDo5DxQg4qOl0dVw4fWMVRpXkmTVqSQv; security_authentication=Fe26.2**0b0867848a70274f49c818e99c198bd4102ceb8974cd525082ce5776fb8e8c36*bt1d6pcVRjEu19un5Jvw7w*-L2I70BJALAVmDIMBIOAJY-ZFN5GxhzRtvaSxo9KyRnR-g5ePzgQBIEQmtMOZHl48IaTEjb2udup33PDNAu-e_qD5nrt_08mQGGCFRaLb_-q3U1iU-Y6N-XhdsE2tVOujUq9N-HUlJpOlgWd2KAHYy4WoTUnFVZZHvh6ZZttfNlIYgZKwzcjvafOHJlFV_ZdE1OO74rBvBuAXloTx5YJiA**d1dd55bddb24a94e17b8b9b692a4de94376a478cdb5705ea0410b2b452176ccc*yIBWZjhJtUNQOSbGOXUq-Ycj4CRKFUdKWCbHwIapAwY; security=low; __next_hmr_refresh_hash__=eaef24bda92b27543c11ee4808b99ea8633457081244afec; PHPSESSID=e16qs57nkd675aj4u44nv78r6s",
        "payload": "id=%27+or+benchmark%2810000000%2CMD5%281%29%29%23&Submit=Submit",
        "session_token": "e16qs57nkd675aj4u44nv78r6s"
    }
    
    print("Debug Pattern Detection")
    print("=" * 50)
    
    # Extract raw fields
    raw_uri = log_entry.get('uri', '')
    raw_qs = log_entry.get('query_string', '')
    raw_payload = log_entry.get('payload', '')
    raw_user_agent = log_entry.get('user_agent', '')
    raw_cookie = log_entry.get('cookie', '')
    raw_body = log_entry.get('body', '')
    raw_referer = log_entry.get('referer', '')
    
    print(f"Raw URI: {raw_uri}")
    print(f"Raw Query: {raw_qs}")
    print(f"Raw Payload: {raw_payload}")
    print()
    
    # Decode
    decoded_uri = url_decode_safe(raw_uri)
    decoded_qs = url_decode_safe(raw_qs)
    decoded_payload = url_decode_safe(raw_payload)
    
    print(f"Decoded URI: {decoded_uri}")
    print(f"Decoded Query: {decoded_qs}")
    print(f"Decoded Payload: {decoded_payload}")
    print()
    
    # Combine all text
    decoded_concat = " ".join([
        url_decode_safe(raw_uri),
        url_decode_safe(raw_qs),
        url_decode_safe(raw_payload),
        url_decode_safe(raw_user_agent),
        url_decode_safe(raw_cookie),
        url_decode_safe(raw_body),
        url_decode_safe(raw_referer)
    ])
    text_content = decoded_concat.lower()
    
    print(f"Combined Text: {text_content[:200]}...")
    print()
    
    # SQLi keywords từ optimized_sqli_detector.py
    sqli_keywords = [
        'union select', 'or 1=1', 'and 1=1', "' or '", '" or "',
        'sleep(', 'waitfor delay', 'benchmark(', 'drop table',
        'delete from', 'insert into', 'update set', 'information_schema',
        'mysql.user', 'version(', 'user(', 'exec(', 'execute(',
        'xp_cmdshell', 'sp_executesql', 'load_file(', 'into outfile',
        '--', '/*', '*/', '0x', 'char(', 'ascii(',
        # Additional SQLi patterns
        'or 1=1--', 'and 1=1--', 'or 1=1#', 'and 1=1#',
        'union all select', 'union select *', 'union select 1',
        'or 1=1 union', 'and 1=1 union', 'or 1=1 select',
        'and 1=1 select', 'or 1=1 from', 'and 1=1 from',
        'or 1=1 where', 'and 1=1 where', 'or 1=1 order',
        'and 1=1 order', 'or 1=1 group', 'and 1=1 group',
        'or 1=1 having', 'and 1=1 having', 'or 1=1 limit',
        'and 1=1 limit', 'or 1=1 offset', 'and 1=1 offset',
        'or 1=1 union select', 'and 1=1 union select',
        'or 1=1 union all select', 'and 1=1 union all select',
        'or 1=1 union select *', 'and 1=1 union select *',
        'or 1=1 union select 1', 'and 1=1 union select 1',
        'or 1=1 union select 1,2', 'and 1=1 union select 1,2',
        'or 1=1 union select 1,2,3', 'and 1=1 union select 1,2,3',
        'or 1=1 union select 1,2,3,4', 'and 1=1 union select 1,2,3,4',
        'or 1=1 union select 1,2,3,4,5', 'and 1=1 union select 1,2,3,4,5',
        'or 1=1 union select 1,2,3,4,5,6', 'and 1=1 union select 1,2,3,4,5,6',
        'or 1=1 union select 1,2,3,4,5,6,7', 'and 1=1 union select 1,2,3,4,5,6,7',
        'or 1=1 union select 1,2,3,4,5,6,7,8', 'and 1=1 union select 1,2,3,4,5,6,7,8',
        'or 1=1 union select 1,2,3,4,5,6,7,8,9', 'and 1=1 union select 1,2,3,4,5,6,7,8,9',
        'or 1=1 union select 1,2,3,4,5,6,7,8,9,10', 'and 1=1 union select 1,2,3,4,5,6,7,8,9,10',
        # Extended patterns
        'sqlmap', 'injection',
        # Obfuscated variants
        'uni0n', 's3lect', 'sl33p', 'dr0p', 'tabl3'
    ]
    
    print("Checking for SQLi patterns...")
    print("=" * 50)
    
    found_patterns = []
    for keyword in sqli_keywords:
        if keyword in text_content:
            found_patterns.append(keyword)
            print(f"Found: '{keyword}'")
    
    print(f"\nTotal patterns found: {len(found_patterns)}")
    if found_patterns:
        print(f"Patterns: {found_patterns}")
    else:
        print("No patterns found!")
    
    # Test specific patterns from the log
    print("\nTesting specific patterns from log:")
    test_patterns = ['benchmark(', 'or', 'union', 'select', 'sleep(', 'waitfor']
    for pattern in test_patterns:
        if pattern in text_content:
            print(f"'{pattern}' found in text")
        else:
            print(f"'{pattern}' NOT found in text")

if __name__ == "__main__":
    debug_pattern_detection()

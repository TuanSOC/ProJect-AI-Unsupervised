#!/usr/bin/env python3
"""
Fix Apache JSON logging issues - Handle line breaks in JSON logs
"""

import json
import re
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def fix_json_line_breaks(line):
    """Fix JSON line breaks by reconstructing complete JSON objects"""
    try:
        # Try to parse as-is first
        return json.loads(line.strip())
    except json.JSONDecodeError:
        # If parsing fails, try to fix common issues
        fixed_line = line.strip()
        
        # Remove any trailing incomplete JSON
        if not fixed_line.endswith('}'):
            # Find the last complete JSON object
            brace_count = 0
            last_complete_pos = -1
            
            for i, char in enumerate(fixed_line):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        last_complete_pos = i + 1
            
            if last_complete_pos > 0:
                fixed_line = fixed_line[:last_complete_pos]
        
        # Try to parse the fixed line
        try:
            return json.loads(fixed_line)
        except json.JSONDecodeError:
            # If still failing, return None to skip this line
            return None

def test_json_parsing():
    """Test JSON parsing with problematic lines"""
    
    logger.info("=" * 80)
    logger.info("TESTING JSON PARSING FIXES")
    logger.info("=" * 80)
    
    # Test cases from the problematic logs
    test_cases = [
        # Case 1: Unterminated string
        '{ 	"time": "2025-10-23T15:01:01+0700", 	"remote_ip": "192.168.205.2", 	"method": "GET", 	"uri": "/DVWA/vulnerabilities/sqli/index.php", 	"query_string": "?id=1234+%27+AND+1%3D0+UNION+ALL+SELECT+%27admin%27%2C+%2781dc9bdb52d04dc20036dbd8313ed055&Submit=Submit", 	"status": 200, 	"bytes_sent": 1532, 	"response_time_ms": 10419, 	"referer": "http://localhost/DVWA/vulnerabilities/sqli/?id=MScgQU5EIChTRUxFQ1QgMSBGUk9NIChTRUxFQ1QgQ09VTlQoKiksIENPTkNBVCh1c2VyKCksIEZMT09SKFJBTkQoKSoyKSkgeCBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgR1JPVVAgQlkgeCkgYSkgLS0g%23&Submit=Submit", 	"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", "request_length": 2083, 	"response_length": 1884, 	"cookie": "wz-user=admin; wz-api=default; wz-token=eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzU4Nzg3NTMxLCJleHAiOjE3NTg3ODg0MzEsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AesxoYn2Mswm57ZVr629sOm17LOZ9CZsYHZrBA9iJD0VIX6dhKYvdmliAam4Bz0t0ESzWhJBxRzWDcp0mbTaQfp7AItpDAA7FYRdttfxSzWRRQDQfJqdn92jw7mKWhVmfNdVi0LIuX3v5NBuEDo5DxQg4qOl0dVw4fWMVRpXkmTVqSQv; security_authentication=Fe26.2**0b0867848a70274f49c818e99c198bd4102ceb8974cd525082ce5776fb8e8c36*bt1d6pcVRjEu19un5Jvw7w*-L2I70BJALAVmDIMBIOAJY-ZFN5GxhzRtvaSxo9KyRnR-g5ePzgQBIEQmtMOZHl48IaTEjb2udup33PDNAu-e_qD5nrt_08mQGGCFRaLb_-q3U1iU-Y6N-XhdsE2tVOujUq9N-HUlJpOlgWd2KAHYy4WoTUnFVZZHvh6ZZttfNlIYgZKwzcjvafOHJlFV_ZdE1OO74rBvBuAXloTx5YJiA**d1dd55bddb24a94e17b8b9b692a4de94376a478cdb5705ea0410b2b452176ccc*yIBWZjhJtUNQOSbGOXUq-Ycj4CRKFUdKWCbHwIapAwY; security=low; __next_hmr_refresh_hash__=eaef24bda92b27543c11ee4808b99ea8633457081244afec; PHPSESSID=e16qs57nkd675aj4u44nv78r6s", 	"payload": "id=1234+%27+AND+1%3D0+UNION+ALL+SELECT+%27admin%27%2C+%2781dc9bdb52d04dc20036dbd8313ed055&Submit=Submit", 	"session_token": "e16qs57nkd675aj4u44nv78r6s" 	}',
        
        # Case 2: Extra data
        '10-23T15:01:01+0700", 	"remote_ip": "192.168.205.2", 	"method": "GET", 	"uri": "/DVWA/vulnerabilities/sqli/index.php", 	"query_string": "?id=1234+%27+AND+1%3D0+UNION+ALL+SELECT+%27admin%27%2C+%2781dc9bdb52d04dc20036dbd8313ed055&Submit=Submit", 	"status": 200, 	"bytes_sent": 1532, 	"response_time_ms": 10419, 	"referer": "http://localhost/DVWA/vulnerabilities/sqli/?id=MScgQU5EIChTRUxFQ1QgMSBGUk9NIChTRUxFQ1QgQ09VTlQoKiksIENPTkNBVCh1c2VyKCksIEZMT09SKFJBTkQoKSoyKSkgeCBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgR1JPVVAgQlkgeCkgYSkgLS0g%23&Submit=Submit", 	"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", "request_length": 2083, 	"response_length": 1884, 	"cookie": "wz-user=admin; wz-api=default; wz-token=eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzU4Nzg3NTMxLCJleHAiOjE3NTg3ODg0MzEsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AesxoYn2Mswm57ZVr629sOm17LOZ9CZsYHZrBA9iJD0VIX6dhKYvdmliAam4Bz0t0ESzWhJBxRzWDcp0mbTaQfp7AItpDAA7FYRdttfxSzWRRQDQfJqdn92jw7mKWhVmfNdVi0LIuX3v5NBuEDo5DxQg4qOl0dVw4fWMVRpXkmTVqSQv; security_authentication=Fe26.2**0b0867848a70274f49c818e99c198bd4102ceb8974cd525082ce5776fb8e8c36*bt1d6pcVRjEu19un5Jvw7w*-L2I70BJALAVmDIMBIOAJY-ZFN5GxhzRtvaSxo9KyRnR-g5ePzgQBIEQmtMOZHl48IaTEjb2udup33PDNAu-e_qD5nrt_08mQGGCFRaLb_-q3U1iU-Y6N-XhdsE2tVOujUq9N-HUlJpOlgWd2KAHYy4WoTUnFVZZHvh6ZZttfNlIYgZKwzcjvafOHJlFV_ZdE1OO74rBvBuAXloTx5YJiA**d1dd55bddb24a94e17b8b9b692a4de94376a478cdb5705ea0410b2b452176ccc*yIBWZjhJtUNQOSbGOXUq-Ycj4CRKFUdKWCbHwIapAwY; security=low; __next_hmr_refresh_hash__=eaef24bda92b27543c11ee4808b99ea8633457081244afec; PHPSESSID=e16qs57nkd675aj4u44nv78r6s", 	"payload": "id=1234+%27+AND+1%3D0+UNION+ALL+SELECT+%27admin%27%2C+%2781dc9bdb52d04dc20036dbd8313ed055&Submit=Submit", 	"session_token": "e16qs57nkd675aj4u44nv78r6s" 	}',
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        logger.info(f"\nTest Case {i}:")
        logger.info(f"Input: {test_case[:100]}...")
        
        result = fix_json_line_breaks(test_case)
        
        if result:
            logger.info(f"✅ Successfully parsed JSON!")
            logger.info(f"   Time: {result.get('time', 'N/A')}")
            logger.info(f"   URI: {result.get('uri', 'N/A')}")
            logger.info(f"   Query: {result.get('query_string', 'N/A')[:50]}...")
        else:
            logger.info(f"❌ Failed to parse JSON")
    
    logger.info("\n" + "="*80)
    logger.info("RECOMMENDATIONS:")
    logger.info("="*80)
    logger.info("1. **Apache Configuration**: Configure Apache to use single-line JSON logging")
    logger.info("2. **Log Format**: Use a simpler log format that doesn't break across lines")
    logger.info("3. **Buffer Size**: Increase Apache's log buffer size")
    logger.info("4. **Alternative**: Use syslog or structured logging instead of JSON")

if __name__ == "__main__":
    test_json_parsing()

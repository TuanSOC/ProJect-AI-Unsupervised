#!/usr/bin/env python3
"""
Fix JSON parsing issues in realtime_log_collector.py
"""

import json
import re

def fix_json_parsing():
    """Fix common JSON parsing issues"""
    
    print("=" * 80)
    print("FIX JSON PARSING ISSUES")
    print("=" * 80)
    
    # Common JSON parsing issues and fixes
    fixes = [
        {
            "issue": "Unterminated string",
            "pattern": r'"([^"]*?)(?=\s*[,}\]])',
            "fix": "Add missing quotes"
        },
        {
            "issue": "Expecting ',' delimiter",
            "pattern": r'([^,}\]])\s*([}\]])',
            "fix": "Add missing comma"
        },
        {
            "issue": "Expecting value",
            "pattern": r':\s*([,}\]])',
            "fix": "Add null value"
        }
    ]
    
    print("Common JSON parsing issues:")
    for fix in fixes:
        print(f"  - {fix['issue']}: {fix['fix']}")
    
    print("\n" + "="*80)
    print("RECOMMENDATIONS:")
    print("="*80)
    
    print("1. **Apache Log Format**: Ensure Apache is configured for proper JSON logging")
    print("2. **Log Rotation**: Check if log files are being rotated during writes")
    print("3. **Buffer Issues**: Large log entries might be split across lines")
    print("4. **Character Encoding**: Ensure UTF-8 encoding for special characters")
    
    print("\n" + "="*80)
    print("IMMEDIATE FIXES:")
    print("="*80)
    
    print("1. **Restart Apache**: sudo systemctl restart apache2")
    print("2. **Check Log Format**: Verify Apache JSON log format configuration")
    print("3. **Monitor Log File**: tail -f /var/log/apache2/access_full_json.log")
    print("4. **Test JSON**: python3 -c \"import json; print(json.loads('your_log_line'))\"")
    
    print("\n" + "="*80)
    print("REALTIME COLLECTOR IMPROVEMENTS:")
    print("="*80)
    
    print("✅ Already implemented:")
    print("  - Better JSON error handling")
    print("  - Continue processing on malformed JSON")
    print("  - Log malformed JSON for debugging")
    
    print("\n🔧 Additional improvements needed:")
    print("  - Buffer incomplete log lines")
    print("  - Retry parsing with fixes")
    print("  - Skip malformed entries gracefully")

if __name__ == "__main__":
    fix_json_parsing()

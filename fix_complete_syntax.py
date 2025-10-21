#!/usr/bin/env python3
"""
Script để fix hoàn toàn syntax error trong realtime_log_collector.py
"""

import os
import shutil
from datetime import datetime

def fix_complete_syntax():
    """Fix hoàn toàn syntax error"""
    
    print("🔧 Complete Syntax Fix for realtime_log_collector.py")
    print("=" * 50)
    
    # Backup current file
    backup_file = f"realtime_log_collector.py.broken.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        # Backup
        shutil.copy('realtime_log_collector.py', backup_file)
        print(f"✅ Backup created: {backup_file}")
        
        # Read file
        with open('realtime_log_collector.py', 'r') as f:
            content = f.read()
        
        # Fix the __init__ method signature
        # Find the broken __init__ method
        old_init = '''    def __init__(self, log_path="/var/log/apache2/access_full_json.log", 
                 webhook_url="http://localhost:5000/api/realtime-detect",
                 detection_):'''
        
        new_init = '''    def __init__(self, log_path="/var/log/apache2/access_full_json.log", 
                 webhook_url="http://localhost:5000/api/realtime-detect",
                 detection_threshold=0.85):'''
        
        if old_init in content:
            content = content.replace(old_init, new_init)
            print("✅ Fixed __init__ method signature")
        else:
            # Try to find and fix the broken line
            import re
            # Look for the broken line
            pattern = r'def __init__\(self, log_path="/var/log/apache2/access_full_json\.log",\s*webhook_url="http://localhost:5000/api/realtime-detect",\s*detection_\):'
            if re.search(pattern, content):
                content = re.sub(pattern, 
                    'def __init__(self, log_path="/var/log/apache2/access_full_json.log", \n                 webhook_url="http://localhost:5000/api/realtime-detect",\n                 detection_threshold=0.85):', 
                    content)
                print("✅ Fixed __init__ method via regex")
        
        # Also ensure main() function has correct threshold
        main_pattern = r'collector = RealtimeLogCollector\(\s*log_path="/var/log/apache2/access_full_json\.log",\s*webhook_url="http://localhost:5000/api/realtime-detect",\s*detection_threshold=0\.7\s*\)'
        if re.search(main_pattern, content):
            content = re.sub(main_pattern, 
                'collector = RealtimeLogCollector(\n        log_path="/var/log/apache2/access_full_json.log",\n        webhook_url="http://localhost:5000/api/realtime-detect",\n        detection_threshold=0.85\n    )', 
                content)
            print("✅ Fixed main() function threshold to 0.85")
        
        # Write fixed file
        with open('realtime_log_collector.py', 'w') as f:
            f.write(content)
        
        print("✅ Complete syntax fix applied!")
        print("   - __init__ method signature fixed")
        print("   - Threshold set to 0.85")
        print("   - Ready to restart")
        
    except Exception as e:
        print(f"❌ Error fixing syntax: {e}")
        
        # Try to restore from original backup
        try:
            if os.path.exists('realtime_log_collector.py.backup.20251022_003554'):
                shutil.copy('realtime_log_collector.py.backup.20251022_003554', 'realtime_log_collector.py')
                print("✅ Restored from original backup")
            else:
                print("❌ No original backup found")
        except Exception as restore_error:
            print(f"❌ Error restoring from backup: {restore_error}")

def verify_syntax():
    """Verify syntax is correct"""
    
    print(f"\n🔍 Verifying Syntax")
    print("=" * 30)
    
    try:
        # Try to compile the file
        with open('realtime_log_collector.py', 'r') as f:
            content = f.read()
        
        compile(content, 'realtime_log_collector.py', 'exec')
        print("✅ Syntax is valid - file compiles successfully")
        
        # Check for threshold
        if 'detection_threshold=0.85' in content:
            print("✅ Threshold set to 0.85")
        else:
            print("❌ Threshold not found")
            
    except SyntaxError as e:
        print(f"❌ Syntax error still exists: {e}")
    except Exception as e:
        print(f"❌ Error verifying: {e}")

if __name__ == "__main__":
    fix_complete_syntax()
    verify_syntax()

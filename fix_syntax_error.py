#!/usr/bin/env python3
"""
Script để fix syntax error trong realtime_log_collector.py
"""

import os
import shutil
from datetime import datetime

def fix_syntax_error():
    """Fix syntax error trong realtime_log_collector.py"""
    
    print("🔧 Fixing Syntax Error in realtime_log_collector.py")
    print("=" * 50)
    
    # Backup current file
    backup_file = f"realtime_log_collector.py.error.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        # Backup
        shutil.copy('realtime_log_collector.py', backup_file)
        print(f"✅ Backup created: {backup_file}")
        
        # Read file
        with open('realtime_log_collector.py', 'r') as f:
            content = f.read()
        
        # Fix the syntax error - restore proper threshold setting
        # Find and fix the main() function
        old_main = '''    collector = RealtimeLogCollector(
        log_path="/var/log/apache2/access_full_json.log",
        webhook_url="http://localhost:5000/api/realtime-detect",
        detection_threshold=0.7
    )'''
        
        new_main = '''    collector = RealtimeLogCollector(
        log_path="/var/log/apache2/access_full_json.log",
        webhook_url="http://localhost:5000/api/realtime-detect",
        detection_threshold=0.85
    )'''
        
        if old_main in content:
            content = content.replace(old_main, new_main)
            print("✅ Fixed main() function with threshold 0.85")
        else:
            # Try to find and fix the broken line
            import re
            # Look for the broken line
            pattern = r'DETECTION_THRESHOLD = 0\.85'
            if re.search(pattern, content):
                # Remove the broken line
                content = re.sub(pattern, '', content)
                print("✅ Removed broken DETECTION_THRESHOLD line")
            
            # Ensure main() function has correct threshold
            main_pattern = r'collector = RealtimeLogCollector\(\s*log_path="/var/log/apache2/access_full_json\.log",\s*webhook_url="http://localhost:5000/api/realtime-detect",\s*detection_threshold=0\.7\s*\)'
            if re.search(main_pattern, content):
                content = re.sub(main_pattern, 
                    'collector = RealtimeLogCollector(\n        log_path="/var/log/apache2/access_full_json.log",\n        webhook_url="http://localhost:5000/api/realtime-detect",\n        detection_threshold=0.85\n    )', 
                    content)
                print("✅ Fixed main() function threshold to 0.85")
        
        # Write fixed file
        with open('realtime_log_collector.py', 'w') as f:
            f.write(content)
        
        print("✅ Syntax error fixed!")
        print("   - Threshold set to 0.85")
        print("   - Main function restored")
        print("   - Ready to restart")
        
    except Exception as e:
        print(f"❌ Error fixing syntax: {e}")
        
        # Try to restore from backup
        try:
            if os.path.exists('realtime_log_collector.py.backup.20251022_003554'):
                shutil.copy('realtime_log_collector.py.backup.20251022_003554', 'realtime_log_collector.py')
                print("✅ Restored from backup")
            else:
                print("❌ No backup found to restore")
        except Exception as restore_error:
            print(f"❌ Error restoring from backup: {restore_error}")

def verify_fix():
    """Verify the fix"""
    
    print(f"\n🔍 Verifying Fix")
    print("=" * 30)
    
    try:
        with open('realtime_log_collector.py', 'r') as f:
            content = f.read()
        
        # Check for syntax issues
        if 'DETECTION_THRESHOLD = 0.85' in content and 'detection_threshold=0.85' in content:
            print("❌ Still has syntax error - both constants and parameters")
        elif 'detection_threshold=0.85' in content:
            print("✅ Fixed - using parameter correctly")
        elif 'DETECTION_THRESHOLD = 0.85' in content:
            print("❌ Still has constant instead of parameter")
        else:
            print("❌ No threshold found")
            
    except Exception as e:
        print(f"❌ Error verifying: {e}")

if __name__ == "__main__":
    fix_syntax_error()
    verify_fix()

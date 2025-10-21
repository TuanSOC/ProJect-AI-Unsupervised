#!/usr/bin/env python3
"""
Script để tăng threshold ngay lập tức và fix false positive
"""

import os
import shutil
from datetime import datetime

def quick_fix_threshold():
    """Tăng threshold ngay lập tức"""
    
    print("🚀 Quick Fix: Increasing Detection Threshold")
    print("=" * 50)
    
    # Backup original file
    backup_file = f"realtime_log_collector.py.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        # Backup
        shutil.copy('realtime_log_collector.py', backup_file)
        print(f"✅ Backup created: {backup_file}")
        
        # Read file
        with open('realtime_log_collector.py', 'r') as f:
            content = f.read()
        
        # Update threshold
        old_thresholds = [
            "DETECTION_THRESHOLD = 0.7",
            "threshold=0.7",
            "threshold = 0.7"
        ]
        
        new_threshold = "DETECTION_THRESHOLD = 0.85"  # Tăng lên 0.85 để giảm false positive
        
        updated = False
        for old_threshold in old_thresholds:
            if old_threshold in content:
                content = content.replace(old_threshold, new_threshold)
                updated = True
                print(f"✅ Updated: {old_threshold} -> {new_threshold}")
        
        if not updated:
            # Tìm và thay thế threshold trong code
            import re
            pattern = r'DETECTION_THRESHOLD\s*=\s*0\.\d+'
            if re.search(pattern, content):
                content = re.sub(pattern, new_threshold, content)
                updated = True
                print(f"✅ Updated threshold via regex")
        
        if updated:
            # Write file
            with open('realtime_log_collector.py', 'w') as f:
                f.write(content)
            
            print(f"\n🎯 Threshold updated to 0.85")
            print(f"   This should significantly reduce false positives")
            print(f"   Restart realtime_log_collector.py to apply changes")
        else:
            print("❌ Could not find threshold setting to update")
            
    except Exception as e:
        print(f"❌ Error updating threshold: {e}")

def update_app_threshold():
    """Update threshold trong app.py"""
    
    print(f"\n🔧 Updating App.py Threshold")
    print("=" * 30)
    
    try:
        with open('app.py', 'r') as f:
            content = f.read()
        
        # Tìm và thay thế threshold trong app.py
        old_thresholds = [
            "threshold=0.7",
            "threshold = 0.7"
        ]
        
        new_threshold = "threshold=0.85"
        
        updated = False
        for old_threshold in old_thresholds:
            if old_threshold in content:
                content = content.replace(old_threshold, new_threshold)
                updated = True
                print(f"✅ Updated app.py: {old_threshold} -> {new_threshold}")
        
        if updated:
            with open('app.py', 'w') as f:
                f.write(content)
            print("✅ App.py threshold updated")
        else:
            print("ℹ️  No threshold found in app.py")
            
    except Exception as e:
        print(f"❌ Error updating app.py: {e}")

def show_restart_instructions():
    """Hiển thị hướng dẫn restart"""
    
    print(f"\n📋 Restart Instructions")
    print("=" * 30)
    print("1. Stop current realtime_log_collector.py (Ctrl+C)")
    print("2. Restart with new threshold:")
    print("   python3 realtime_log_collector.py")
    print("3. Test with normal requests")
    print("4. Check if false positives are reduced")

if __name__ == "__main__":
    quick_fix_threshold()
    update_app_threshold()
    show_restart_instructions()

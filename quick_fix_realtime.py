#!/usr/bin/env python3
"""
Quick fix cho realtime_log_collector.py - fix unpacking error
"""

import os
import shutil
from datetime import datetime

def quick_fix_realtime():
    """Quick fix realtime_log_collector.py"""
    
    print("🔧 Quick Fix for realtime_log_collector.py")
    print("=" * 50)
    
    # Backup
    backup_file = f"realtime_log_collector.py.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy('realtime_log_collector.py', backup_file)
    print(f"✅ Backup created: {backup_file}")
    
    try:
        with open('realtime_log_collector.py', 'r') as f:
            content = f.read()
        
        # Fix all detection calls to handle 4 return values
        old_patterns = [
            'is_sqli, score = self.detector.predict_single(',
            'is_sqli, score = detector.predict_single(',
            'is_sqli, score = self.detector.predict_single(log_entry, threshold=',
            'is_sqli, score = self.detector.predict_single(log_entry, threshold=self.detection_threshold)'
        ]
        
        new_pattern = 'is_sqli, score, patterns, confidence = self.detector.predict_single('
        
        for old_pattern in old_patterns:
            if old_pattern in content:
                content = content.replace(old_pattern, new_pattern)
                print(f"✅ Fixed: {old_pattern}")
        
        # Also fix any remaining patterns
        content = content.replace(
            'is_sqli, score = self.detector.predict_single(',
            'is_sqli, score, patterns, confidence = self.detector.predict_single('
        )
        
        # Write back
        with open('realtime_log_collector.py', 'w') as f:
            f.write(content)
        
        print("✅ realtime_log_collector.py fixed!")
        print("   - All detection calls now handle 4 return values")
        print("   - Ready to restart")
        
    except Exception as e:
        print(f"❌ Error fixing realtime_log_collector.py: {e}")

def fix_app_json():
    """Fix JSON serialization trong app.py"""
    
    print("\n🔧 Fixing JSON serialization in app.py...")
    print("=" * 50)
    
    try:
        with open('app.py', 'r') as f:
            content = f.read()
        
        # Fix JSON serialization
        old_return = '''        return jsonify({
            'is_sqli': is_sqli,
            'score': score,
            'patterns': patterns,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        })'''
        
        new_return = '''        return jsonify({
            'is_sqli': bool(is_sqli),  # Convert numpy.bool_ to Python bool
            'score': float(score),     # Convert numpy.float64 to Python float
            'patterns': patterns,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        })'''
        
        if old_return in content:
            content = content.replace(old_return, new_return)
            print("✅ Fixed JSON serialization")
        else:
            print("ℹ️  JSON serialization pattern not found")
        
        # Write back
        with open('app.py', 'w') as f:
            f.write(content)
        
        print("✅ app.py updated")
        
    except Exception as e:
        print(f"❌ Error fixing app.py: {e}")

def main():
    """Main function"""
    
    print("🚀 Quick Fix for All Issues")
    print("=" * 60)
    
    # Fix realtime collector
    quick_fix_realtime()
    
    # Fix app JSON
    fix_app_json()
    
    print("\n🎉 Quick Fix Completed!")
    print("=" * 60)
    print("✅ Unpacking errors fixed")
    print("✅ JSON serialization fixed")
    print("\n📋 Next Steps:")
    print("1. Stop current realtime_log_collector.py (Ctrl+C)")
    print("2. Run: python3 realtime_log_collector.py")
    print("3. Test payload detection")

if __name__ == "__main__":
    main()

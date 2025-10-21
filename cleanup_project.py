#!/usr/bin/env python3
"""
Script để dọn dẹp project và chỉ giữ lại những file cần thiết
"""

import os
import shutil

def cleanup_project():
    """Dọn dẹp project"""
    
    print("🧹 Cleaning up project...")
    print("=" * 40)
    
    # Files to keep (essential)
    essential_files = [
        'app.py',
        'optimized_sqli_detector.py', 
        'realtime_log_collector.py',
        'README.md',
        'requirements.txt',
        'models/optimized_sqli_detector.pkl',
        'templates/index.html',
        'sqli_logs_clean_100k.jsonl',
        'fix_detection_threshold.py',
        'retrain_model_balanced.py'
    ]
    
    # Files to remove (temporary/debug)
    files_to_remove = [
        'debug_imports.py',
        'run_direct.py',
        'test_detection.py',
        'fix_sklearn_version.py',
        'quick_start.sh',
        'setup_user.sh',
        'setup_realtime_detection.sh',
        'install_deps.sh',
        'test_payload_capture.py',
        'inspect_model.py',
        'test_system.py',
        'start.py',
        'requirements_web.txt',
        'dvwa_sqli_logs.jsonl',
        'logs.jsonl',
        'sqli_logs_clean_100k.filtered.jsonl',
        'CODEBASE_OPTIMIZATION_SUMMARY.md',
        'UNSUPERVISED_AI_SYSTEM.md'
    ]
    
    # Directories to remove
    dirs_to_remove = [
        '__pycache__',
        'tests'
    ]
    
    # Remove files
    removed_files = []
    for file in files_to_remove:
        if os.path.exists(file):
            try:
                os.remove(file)
                removed_files.append(file)
                print(f"✅ Removed: {file}")
            except Exception as e:
                print(f"❌ Error removing {file}: {e}")
    
    # Remove directories
    removed_dirs = []
    for dir_name in dirs_to_remove:
        if os.path.exists(dir_name):
            try:
                shutil.rmtree(dir_name)
                removed_dirs.append(dir_name)
                print(f"✅ Removed directory: {dir_name}")
            except Exception as e:
                print(f"❌ Error removing directory {dir_name}: {e}")
    
    print(f"\n📊 Cleanup Summary:")
    print(f"   - Files removed: {len(removed_files)}")
    print(f"   - Directories removed: {len(removed_dirs)}")
    
    # List remaining files
    print(f"\n📁 Remaining essential files:")
    for file in essential_files:
        if os.path.exists(file):
            print(f"   ✅ {file}")
        else:
            print(f"   ❌ {file} (missing)")
    
    print(f"\n🎯 Project cleaned up!")
    print(f"   Essential files preserved")
    print(f"   Temporary/debug files removed")

if __name__ == "__main__":
    cleanup_project()

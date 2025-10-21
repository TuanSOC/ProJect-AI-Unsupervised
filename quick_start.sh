#!/bin/bash
# Quick start script - Chỉ cần thiết để chạy hệ thống

echo "🚀 Quick Start - SQLi Detection System"
echo "======================================"

# Kiểm tra log file
LOG_FILE="/var/log/apache2/access_full_json.log"
if [ ! -f "$LOG_FILE" ]; then
    echo "⚠️ Apache log file not found: $LOG_FILE"
    echo "Please ensure Apache is running and the log file exists"
    exit 1
else
    echo "✅ Apache log file found: $LOG_FILE"
fi

# Kiểm tra AI model
if [ ! -f "models/optimized_sqli_detector.pkl" ]; then
    echo "❌ AI model not found. Please run setup first:"
    echo "   ./setup_user.sh"
    exit 1
else
    echo "✅ AI model found"
fi

# Kiểm tra dependencies cơ bản
echo "📦 Checking basic dependencies..."
python3 -c "
import sys
import os

# Add system paths
sys.path.insert(0, '/usr/local/lib/python3.10/dist-packages')
sys.path.insert(0, '/usr/lib/python3/dist-packages')

required = ['flask', 'pandas', 'scikit-learn', 'joblib']
missing = []
for pkg in required:
    try:
        __import__(pkg.replace('-', '_'))
    except ImportError:
        missing.append(pkg)

if missing:
    print(f'❌ Missing packages: {missing}')
    print('Please install with: pip install --user ' + ' '.join(missing))
    print('Or run: ./setup_user.sh')
    sys.exit(1)
else:
    print('✅ All dependencies available')
"

if [ $? -ne 0 ]; then
    echo "❌ Missing dependencies. Please install them first."
    exit 1
fi

echo ""
echo "🎯 System ready! Choose what to run:"
echo ""
echo "1. Web Dashboard:"
echo "   python3 app.py"
echo ""
echo "2. Real-time Detection:"
echo "   python3 realtime_log_collector.py"
echo ""
echo "3. Test Payload Capture:"
echo "   python3 test_payload_capture.py"
echo ""
echo "4. Fix sklearn version:"
echo "   python3 fix_sklearn_version.py"
echo ""
echo "🌐 Web Dashboard: http://localhost:5000"
echo "📊 Real-time threats: tail -f realtime_threats.jsonl"

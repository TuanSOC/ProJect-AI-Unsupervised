#!/bin/bash
# Setup script cho hệ thống realtime SQLi detection (User mode)

echo "🔍 Setting up Realtime SQLi Detection System (User Mode)"
echo "========================================================"

# Kiểm tra Python dependencies
echo "📦 Checking Python dependencies..."
python3 -c "
import sys
required = ['flask', 'requests', 'pandas', 'scikit-learn', 'joblib']
missing = []
for pkg in required:
    try:
        __import__(pkg.replace('-', '_'))
    except ImportError:
        missing.append(pkg)

if missing:
    print(f'❌ Missing packages: {missing}')
    print('Please install with: pip install ' + ' '.join(missing))
    sys.exit(1)
else:
    print('✅ All dependencies available')
"

if [ $? -ne 0 ]; then
    echo "❌ Missing dependencies. Please install them first."
    exit 1
fi

# Tạo thư mục models nếu chưa có
if [ ! -d "models" ]; then
    echo "📁 Creating models directory..."
    mkdir -p models
fi

# Kiểm tra AI model
if [ ! -f "models/optimized_sqli_detector.pkl" ]; then
    echo "🤖 Training AI model..."
    python3 -c "
from optimized_sqli_detector import OptimizedSQLIDetector
import json

# Load sample data
with open('sqli_logs_clean_100k.jsonl', 'r') as f:
    clean_logs = [json.loads(line.strip()) for line in f if line.strip()]

# Train model
detector = OptimizedSQLIDetector()
detector.train(clean_logs[:10000])  # Use first 10k logs for training
detector.save_model('models/optimized_sqli_detector.pkl')
print('✅ AI model trained and saved')
"
    if [ $? -ne 0 ]; then
        echo "❌ Failed to train AI model"
        exit 1
    fi
fi

# Tạo log directory
mkdir -p logs

# Set permissions cho log files
chmod 644 logs/*.log 2>/dev/null || true

echo "✅ Setup completed successfully!"
echo ""
echo "🚀 To start web application:"
echo "   python3 app.py"
echo ""
echo "🌐 Web Dashboard: http://localhost:5000"
echo ""
echo "🚀 To start real-time monitoring:"
echo "   python3 realtime_log_collector.py"
echo ""
echo "📊 To view realtime threats:"
echo "   tail -f realtime_threats.jsonl"
echo ""
echo "📝 To test the system:"
echo "   python3 -c \"from optimized_sqli_detector import OptimizedSQLIDetector; print('✅ System ready')\""

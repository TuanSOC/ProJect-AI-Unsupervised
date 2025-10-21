#!/bin/bash
# Setup script cho hệ thống realtime SQLi detection

echo "🔍 Setting up Realtime SQLi Detection System"
echo "============================================="

# Kiểm tra quyền sudo (optional)
if [ "$EUID" -eq 0 ]; then
    echo "⚠️ Running as root. Consider running as regular user for better security."
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

# Kiểm tra Apache log file (đã được cấu hình sẵn)
LOG_FILE="/var/log/apache2/access_full_json.log"
if [ ! -f "$LOG_FILE" ]; then
    echo "⚠️ Apache log file not found: $LOG_FILE"
    echo "Please ensure Apache is running and the log file exists"
else
    echo "✅ Apache log file found: $LOG_FILE"
fi

# Tạo log directory
mkdir -p logs

# Set permissions cho log files
chmod 644 logs/*.log 2>/dev/null || true

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

# Tạo systemd service file (optional - only if running as root)
if [ "$EUID" -eq 0 ]; then
    echo "🔧 Creating systemd service file..."
    cat > /etc/systemd/system/sqli-detection.service << EOF
[Unit]
Description=SQLi Detection Monitoring System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/python3 $(pwd)/realtime_log_collector.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    echo "✅ Systemd service file created"
else
    echo "ℹ️ Skipping systemd service creation (run as root to enable)"
fi

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
if [ "$EUID" -eq 0 ]; then
    echo "🔧 To enable as system service:"
    echo "   sudo systemctl enable sqli-detection"
    echo "   sudo systemctl start sqli-detection"
    echo ""
    echo "📝 To view service logs:"
    echo "   sudo journalctl -u sqli-detection -f"
fi

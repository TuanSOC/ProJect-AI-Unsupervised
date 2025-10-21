#!/bin/bash
# Setup script cho hệ thống realtime SQLi detection

echo "🔍 Setting up Realtime SQLi Detection System"
echo "============================================="

# Kiểm tra quyền sudo
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run with sudo for log file access"
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
    python3 optimized_sqli_detector.py
    if [ $? -ne 0 ]; then
        echo "❌ Failed to train AI model"
        exit 1
    fi
fi

# Kiểm tra Apache log file
LOG_FILE="/var/log/apache2/access_full_json.log"
if [ ! -f "$LOG_FILE" ]; then
    echo "⚠️ Apache log file not found: $LOG_FILE"
    echo "Please ensure Apache is running and logging to this file"
    echo "You may need to configure Apache to log in JSON format"
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

# Tạo systemd service file (optional)
echo "🔧 Creating systemd service file..."
cat > /etc/systemd/system/sqli-detection.service << EOF
[Unit]
Description=SQLi Detection Monitoring System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/python3 $(pwd)/start_realtime_monitoring.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo "✅ Setup completed successfully!"
echo ""
echo "🚀 To start monitoring:"
echo "   python3 start_realtime_monitoring.py"
echo ""
echo "🌐 Web Dashboard: http://localhost:5000"
echo ""
echo "📊 To view realtime threats:"
echo "   tail -f realtime_threats.jsonl"
echo ""
echo "🔧 To enable as system service:"
echo "   sudo systemctl enable sqli-detection"
echo "   sudo systemctl start sqli-detection"
echo ""
echo "📝 To view service logs:"
echo "   sudo journalctl -u sqli-detection -f"

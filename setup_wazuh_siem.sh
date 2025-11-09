#!/bin/bash

set -e

echo "=========================================="
echo "WAZUH SIEM SQLI DETECTOR SETUP"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[HEADER]${NC} $1"
}

# Check if we're running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run as root (use sudo)"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "optimized_sqli_detector.py" ]; then
    print_error "Please run this script from the project root directory"
    exit 1
fi

print_header "Starting Wazuh SIEM SQLi Detector setup..."

# Step 1: Install system dependencies
print_status "Installing system dependencies..."
apt update
apt install -y python3-pip python3-venv python3-dev build-essential

# Step 2: Install Python dependencies
print_status "Installing Python dependencies..."
pip3 install -r requirements.txt

# Step 3: Create necessary directories
print_status "Creating necessary directories..."
mkdir -p /opt/ai
mkdir -p /opt/ai/models
mkdir -p /opt/ai/logs
mkdir -p /var/ossec/logs
mkdir -p /var/log

# Step 4: Copy project files to /opt/ai
print_status "Copying project files to /opt/ai..."
cp optimized_sqli_detector.py /opt/ai/
cp wazuh_siem_realtime_detector.py /opt/ai/
cp -r models/* /opt/ai/models/ 2>/dev/null || true

# Step 5: Set permissions
print_status "Setting permissions..."
chmod +x /opt/ai/wazuh_siem_realtime_detector.py
chown -R root:root /opt/ai
chmod -R 755 /opt/ai
chmod 755 /var/ossec/logs
chmod 755 /var/log

# Step 6: Check if model exists, if not train it
print_status "Checking AI model..."
if [ ! -f "/opt/ai/models/optimized_sqli_detector.pkl" ]; then
    print_warning "Model file not found, training model..."
    
    # Check if training data exists
    if [ -f "sqli_logs_clean_100k.jsonl" ]; then
        print_status "Training model from sqli_logs_clean_100k.jsonl..."
        python3 -c "
import sys
sys.path.append('.')
from optimized_sqli_detector import OptimizedSQLIDetector
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    logger.info('Loading detector...')
    detector = OptimizedSQLIDetector()
    
    logger.info('Training from sqli_logs_clean_100k.jsonl...')
    detector.train_from_path('sqli_logs_clean_100k.jsonl')
    
    logger.info('Saving model...')
    detector.save_model('/opt/ai/models/optimized_sqli_detector.pkl')
    
    logger.info('Testing model loading...')
    detector2 = OptimizedSQLIDetector()
    detector2.load_model('/opt/ai/models/optimized_sqli_detector.pkl')
    
    print('✅ Model trained and tested successfully!')
    
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"
    else
        print_error "Training data not found: sqli_logs_clean_100k.jsonl"
        print_error "Please ensure training data is available"
        exit 1
    fi
else
    print_status "✅ Model file exists: /opt/ai/models/optimized_sqli_detector.pkl"
fi

# Step 7: Test model
print_status "Testing AI model..."
python3 -c "
import sys
sys.path.append('/opt/ai')
from optimized_sqli_detector import OptimizedSQLIDetector
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    detector = OptimizedSQLIDetector()
    detector.load_model('/opt/ai/models/optimized_sqli_detector.pkl')
    
    # Test with a simple SQLi payload
    test_log = {
        'time': '2025-10-23T14:30:19+0700',
        'remote_ip': '192.168.205.2',
        'method': 'GET',
        'uri': '/DVWA/vulnerabilities/sqli/index.php',
        'query_string': '?id=admin%27%29+or+%28%271%27%3D%271%27%23&Submit=Submit',
        'status': 500,
        'bytes_sent': 0,
        'response_time_ms': 16685,
        'referer': 'http://localhost/DVWA/vulnerabilities/sqli/',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'request_length': 2244,
        'response_length': 295,
        'cookie': 'PHPSESSID=e16qs57nkd675aj4u44nv78r6s',
        'payload': 'id=admin%27%29+or+%28%271%27%3D%271%27%23&Submit=Submit',
        'session_token': 'e16qs57nkd675aj4u44nv78r6s'
    }
    
    result = detector.predict_single(test_log)
    
    if isinstance(result, tuple) and len(result) == 4:
        is_sqli, score, patterns, confidence = result
        if is_sqli:
            print('✅ Model is working correctly!')
            print(f'   Score: {score:.4f}')
            print(f'   Patterns: {patterns}')
            print(f'   Confidence: {confidence}')
        else:
            print('❌ Model is not detecting SQLi properly')
            sys.exit(1)
    else:
        print(f'❌ Unexpected result type: {type(result)}')
        sys.exit(1)
        
except Exception as e:
    print(f'❌ Error testing model: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"

# Step 8: Test Wazuh SIEM detector
print_status "Testing Wazuh SIEM detector..."
python3 -c "
import sys
sys.path.append('/opt/ai')
from wazuh_siem_realtime_detector import WazuhSIEMRealtimeDetector
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    detector = WazuhSIEMRealtimeDetector()
    
    if detector.detector:
        print('✅ WazuhSIEMRealtimeDetector initialized successfully')
        
        # Test with the same SQLi payload
        test_log = {
            'time': '2025-10-23T14:30:19+0700',
            'remote_ip': '192.168.205.2',
            'method': 'GET',
            'uri': '/DVWA/vulnerabilities/sqli/index.php',
            'query_string': '?id=admin%27%29+or+%28%271%27%3D%271%27%23&Submit=Submit',
            'status': 500,
            'bytes_sent': 0,
            'response_time_ms': 16685,
            'referer': 'http://localhost/DVWA/vulnerabilities/sqli/',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'request_length': 2244,
            'response_length': 295,
            'cookie': 'PHPSESSID=e16qs57nkd675aj4u44nv78r6s',
            'payload': 'id=admin%27%29+or+%28%271%27%3D%271%27%23&Submit=Submit',
            'session_token': 'e16qs57nkd675aj4u44nv78r6s'
        }
        
        result = detector.detect_sqli_realtime(test_log)
        
        if result and result.get('is_sqli'):
            print('✅ WazuhSIEMRealtimeDetector is working correctly!')
            print(f'   Score: {result.get(\"score\", 0):.4f}')
            print(f'   Threat Level: {result.get(\"threat_level\", \"UNKNOWN\")}')
            print(f'   Patterns: {result.get(\"detected_patterns\", [])}')
        else:
            print('❌ WazuhSIEMRealtimeDetector is not detecting SQLi properly')
            print(f'   Result: {result}')
            sys.exit(1)
    else:
        print('❌ Failed to initialize detector in WazuhSIEMRealtimeDetector')
        sys.exit(1)
        
except Exception as e:
    print(f'❌ Error testing Wazuh SIEM detector: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"

# Step 9: Check Wazuh log file
print_status "Checking Wazuh log file..."
WAZUH_LOG="/opt/ai/apache_access.log"
if [ -f "$WAZUH_LOG" ]; then
    print_status "✅ Wazuh log file exists: $WAZUH_LOG"
    
    # Check permissions
    if [ -r "$WAZUH_LOG" ]; then
        print_status "✅ Wazuh log file is readable"
    else
        print_warning "⚠️ Wazuh log file is not readable"
        print_warning "Setting permissions..."
        chmod 644 "$WAZUH_LOG"
    fi
else
    print_warning "⚠️ Wazuh log file not found: $WAZUH_LOG"
    print_warning "Creating empty log file (will be populated by Wazuh)..."
    touch "$WAZUH_LOG"
    chmod 644 "$WAZUH_LOG"
fi

# Step 10: Create systemd service
print_status "Creating systemd service..."
cat > /etc/systemd/system/wazuh-siem-sqli-detector.service << 'EOF'
[Unit]
Description=Wazuh SIEM Realtime SQLi Detector
After=network.target wazuh-manager.service
Requires=wazuh-manager.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ai
ExecStart=/usr/bin/python3 /opt/ai/wazuh_siem_realtime_detector.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Environment variables
Environment="WAZUH_SIEM_LOG_PATH=/opt/ai/apache_access.log"
Environment="WAZUH_SIEM_SQLI_LOG=/var/ossec/logs/ai-engine-sqli"

# Security
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Step 11: Enable and start service
print_status "Enabling and starting service..."
systemctl enable wazuh-siem-sqli-detector.service
systemctl start wazuh-siem-sqli-detector.service

# Step 12: Check service status
print_status "Checking service status..."
sleep 2
if systemctl is-active --quiet wazuh-siem-sqli-detector.service; then
    print_status "✅ Service is running"
else
    print_error "❌ Service failed to start"
    print_error "Check logs with: journalctl -u wazuh-siem-sqli-detector.service -f"
    systemctl status wazuh-siem-sqli-detector.service
    exit 1
fi

# Step 13: Show service info
print_header "=========================================="
print_header "SETUP COMPLETED SUCCESSFULLY!"
print_header "=========================================="
print_status "Service Information:"
print_status "  Service Name: wazuh-siem-sqli-detector"
print_status "  Status: $(systemctl is-active wazuh-siem-sqli-detector.service)"
print_status "  Log Input: /opt/ai/apache_access.log"
print_status "  Log Output: /var/ossec/logs/ai-engine-sqli"
print_status ""
print_status "Useful Commands:"
print_status "  Start service:   systemctl start wazuh-siem-sqli-detector"
print_status "  Stop service:    systemctl stop wazuh-siem-sqli-detector"
print_status "  Restart service: systemctl restart wazuh-siem-sqli-detector"
print_status "  View logs:       journalctl -u wazuh-siem-sqli-detector.service -f"
print_status "  Check status:    systemctl status wazuh-siem-sqli-detector.service"
print_status ""
print_status "Detection Logs:"
print_status "  Wazuh SIEM log: /var/ossec/logs/ai-engine-sqli"
print_status "  Service log:    /var/log/wazuh_siem_sqli_detector.log"
print_status "  System log:     journalctl -u wazuh-siem-sqli-detector.service"
print_header "=========================================="
print_status "🎉 Wazuh SIEM SQLi Detector is ready!"
print_header "=========================================="


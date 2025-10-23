#!/bin/bash
set -e

echo "=========================================="
echo "UBUNTU COMPLETE SETUP SCRIPT"
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

# Check if we're in the right directory
if [ ! -f "optimized_sqli_detector.py" ]; then
    print_error "Please run this script from the project root directory"
    exit 1
fi

print_header "Starting Ubuntu setup for AI SQLi Detection System..."

# Step 1: Install system dependencies
print_status "Installing system dependencies..."
sudo apt update
sudo apt install -y python3-pip python3-venv

# Step 2: Install Python dependencies
print_status "Installing Python dependencies..."
pip3 install -r requirements.txt

# Step 3: Create models directory if it doesn't exist
print_status "Creating models directory..."
mkdir -p models

# Step 4: Retrain model with current scikit-learn version
print_status "Retraining AI model..."
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
    detector.save_model('models/optimized_sqli_detector.pkl')
    
    logger.info('Testing model loading...')
    detector2 = OptimizedSQLIDetector()
    detector2.load_model('models/optimized_sqli_detector.pkl')
    
    print('✅ Model retrained and tested successfully!')
    
except Exception as e:
    print(f'❌ Error: {e}')
    sys.exit(1)
"

# Step 5: Test model with sample SQLi
print_status "Testing model with sample SQLi payload..."
python3 -c "
import sys
sys.path.append('.')
from optimized_sqli_detector import OptimizedSQLIDetector
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    detector = OptimizedSQLIDetector()
    detector.load_model('models/optimized_sqli_detector.pkl')
    
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
    
    # Handle both tuple and dict return types
    if isinstance(result, tuple):
        is_sqli, score, patterns = result
        if is_sqli:
            print('✅ Model is working correctly!')
            print(f'   Score: {score:.4f}')
            print(f'   Patterns: {patterns}')
        else:
            print('❌ Model is not detecting SQLi properly')
            sys.exit(1)
    elif isinstance(result, dict):
        if result.get('is_sqli'):
            print('✅ Model is working correctly!')
            print(f'   Score: {result.get(\"score\", 0):.4f}')
            print(f'   Patterns: {result.get(\"detected_patterns\", [])}')
        else:
            print('❌ Model is not detecting SQLi properly')
            sys.exit(1)
    else:
        print('❌ Unexpected result type from predict_single')
        sys.exit(1)
        
except Exception as e:
    print(f'❌ Error testing model: {e}')
    sys.exit(1)
"

# Step 6: Test realtime collector
print_status "Testing realtime collector..."
python3 -c "
import sys
sys.path.append('.')
from realtime_log_collector import RealtimeLogCollector
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    # Test collector initialization
    collector = RealtimeLogCollector(log_path='/dev/null', webhook_url=None)
    
    if collector.detector:
        print('✅ RealtimeLogCollector initialized successfully')
        
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
        
        result = collector.detect_sqli_realtime(test_log)
        
        if result and result.get('is_sqli'):
            print('✅ RealtimeLogCollector is working correctly!')
            print(f'   Score: {result.get(\"score\", 0):.4f}')
            print(f'   Patterns: {result.get(\"detected_patterns\", [])}')
        else:
            print('❌ RealtimeLogCollector is not detecting SQLi properly')
            print(f'   Result: {result}')
            sys.exit(1)
    else:
        print('❌ Failed to initialize detector in RealtimeLogCollector')
        sys.exit(1)
        
except Exception as e:
    print(f'❌ Error testing realtime collector: {e}')
    sys.exit(1)
"

# Step 7: Check Apache log file
print_status "Checking Apache log file..."
APACHE_LOG="/var/log/apache2/access_full_json.log"
if [ -f "$APACHE_LOG" ]; then
    print_status "✅ Apache log file exists: $APACHE_LOG"
    
    # Check permissions
    if [ -r "$APACHE_LOG" ]; then
        print_status "✅ Apache log file is readable"
    else
        print_warning "❌ Apache log file is not readable"
        print_warning "Try: sudo chmod 644 $APACHE_LOG"
    fi
else
    print_warning "❌ Apache log file not found: $APACHE_LOG"
    print_warning "Please check Apache configuration for JSON logging"
fi

# Step 8: Create start scripts
print_status "Creating start scripts..."

# Create start_app.sh
cat > start_app.sh << 'EOF'
#!/bin/bash
echo "Starting AI SQLi Detection Web App..."
python3 app.py
EOF

# Create start_realtime.sh
cat > start_realtime.sh << 'EOF'
#!/bin/bash
echo "Starting AI SQLi Detection Realtime Monitor..."
python3 realtime_log_collector.py
EOF

# Make scripts executable
chmod +x start_app.sh start_realtime.sh

print_header "=========================================="
print_header "SETUP COMPLETED SUCCESSFULLY!"
print_header "=========================================="
print_status "Next steps:"
print_status "1. Start web app:     ./start_app.sh"
print_status "2. Start realtime:    ./start_realtime.sh"
print_status "3. Open browser:      http://localhost:5000"
print_status "4. Test SQLi detection with various payloads"
print_header "=========================================="
print_status "🎉 AI SQLi Detection System is ready!"
print_header "=========================================="

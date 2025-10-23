#!/bin/bash
set -e

echo "=========================================="
echo "FIX APACHE JSON LOGGING CONFIGURATION"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

print_header "Fixing Apache JSON logging configuration..."

# Check if Apache is running
if ! systemctl is-active --quiet apache2; then
    print_warning "Apache2 is not running. Starting Apache2..."
    sudo systemctl start apache2
fi

# Backup current Apache configuration
print_status "Backing up current Apache configuration..."
sudo cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.backup.$(date +%Y%m%d_%H%M%S)

# Create a new log format that doesn't break across lines
print_status "Creating new Apache log format..."
sudo tee /etc/apache2/conf-available/json-logging.conf > /dev/null << 'EOF'
# JSON Logging Configuration for AI SQLi Detection
# This format ensures single-line JSON logs without line breaks

LogFormat "{ \"time\": \"%{%Y-%m-%dT%H:%M:%S%z}t\", \"remote_ip\": \"%a\", \"method\": \"%m\", \"uri\": \"%U\", \"query_string\": \"%q\", \"status\": %s, \"bytes_sent\": %b, \"response_time_ms\": %D, \"referer\": \"%{Referer}i\", \"user_agent\": \"%{User-Agent}i\", \"request_length\": %I, \"response_length\": %O, \"cookie\": \"%{Cookie}i\", \"payload\": \"%q\", \"session_token\": \"%{PHPSESSID}C\" }" json_single_line

# Alternative simpler format if the above is too complex
LogFormat "{ \"time\": \"%{%Y-%m-%dT%H:%M:%S%z}t\", \"ip\": \"%a\", \"method\": \"%m\", \"uri\": \"%U\", \"query\": \"%q\", \"status\": %s, \"size\": %b, \"time_ms\": %D, \"user_agent\": \"%{User-Agent}i\" }" json_simple
EOF

# Enable the new configuration
print_status "Enabling new JSON logging configuration..."
sudo a2enconf json-logging

# Update VirtualHost to use the new log format
print_status "Updating VirtualHost configuration..."
sudo tee /etc/apache2/sites-available/000-default.conf > /dev/null << 'EOF'
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html

    # Use single-line JSON logging
    CustomLog /var/log/apache2/access_full_json.log json_single_line
    
    # Keep the original access log as backup
    CustomLog /var/log/apache2/access.log combined

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF

# Test Apache configuration
print_status "Testing Apache configuration..."
if sudo apache2ctl configtest; then
    print_status "✅ Apache configuration is valid"
else
    print_error "❌ Apache configuration has errors"
    exit 1
fi

# Restart Apache
print_status "Restarting Apache..."
sudo systemctl restart apache2

# Check if Apache is running
if systemctl is-active --quiet apache2; then
    print_status "✅ Apache2 is running successfully"
else
    print_error "❌ Apache2 failed to start"
    exit 1
fi

# Test the new log format
print_status "Testing new log format..."
sleep 2

# Make a test request
curl -s "http://localhost/DVWA/vulnerabilities/sqli/index.php?id=test" > /dev/null

# Check if the log file is being written correctly
if [ -f "/var/log/apache2/access_full_json.log" ]; then
    print_status "✅ JSON log file exists"
    
    # Check the last few lines
    print_status "Last 3 log entries:"
    tail -3 /var/log/apache2/access_full_json.log | while read line; do
        echo "  $line"
    done
    
    # Test JSON parsing
    print_status "Testing JSON parsing..."
    if tail -1 /var/log/apache2/access_full_json.log | python3 -c "import json, sys; json.loads(sys.stdin.read().strip()); print('✅ JSON is valid')" 2>/dev/null; then
        print_status "✅ JSON logs are properly formatted"
    else
        print_warning "⚠️  JSON logs may still have formatting issues"
    fi
else
    print_warning "⚠️  JSON log file not found"
fi

print_header "=========================================="
print_header "APACHE CONFIGURATION FIX COMPLETED!"
print_header "=========================================="
print_status "Next steps:"
print_status "1. Test the realtime collector: ./start_realtime.sh"
print_status "2. Make some SQLi requests to test detection"
print_status "3. Check the logs for proper JSON formatting"
print_header "=========================================="

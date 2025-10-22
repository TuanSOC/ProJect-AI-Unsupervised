#!/bin/bash
# Setup script cho Ubuntu - Realtime SQLi Detection

echo "Setting up Realtime SQLi Detection on Ubuntu"
echo "============================================="

# Update system
echo "Updating system packages..."
sudo apt update

# Install Python dependencies
echo "Installing Python dependencies..."
sudo apt install -y python3 python3-pip python3-venv

# Install required Python packages
echo "Installing Python packages..."
pip3 install --user flask pandas scikit-learn joblib numpy requests

# Create directories
echo "Creating directories..."
mkdir -p models
mkdir -p templates
mkdir -p logs

# Set permissions
echo "Setting permissions..."
chmod +x realtime_log_collector.py
chmod +x app.py

# Check if model exists
if [ ! -f "models/optimized_sqli_detector.pkl" ]; then
    echo "Training model..."
    python3 optimized_sqli_detector.py
fi

echo "Setup completed!"
echo ""
echo "To start the system:"
echo "1. Start web interface: python3 app.py"
echo "2. Start realtime detection: python3 realtime_log_collector.py"
echo ""
echo "Web interface: http://localhost:5000"
echo "Realtime detection: Monitors /var/log/apache2/access_full_json.log"

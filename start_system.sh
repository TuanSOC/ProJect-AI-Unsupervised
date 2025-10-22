#!/bin/bash
# Start Realtime SQLi Detection System

echo "Starting Realtime SQLi Detection System"
echo "======================================="

# Check if model exists
if [ ! -f "models/optimized_sqli_detector.pkl" ]; then
    echo "Model not found. Training model..."
    python3 optimized_sqli_detector.py
fi

# Start web interface in background
echo "Starting web interface..."
python3 app.py &
WEB_PID=$!

# Wait a moment for web interface to start
sleep 3

# Start realtime detection
echo "Starting realtime detection..."
python3 realtime_log_collector.py &
DETECTOR_PID=$!

echo ""
echo "System started successfully!"
echo "Web interface: http://localhost:5000"
echo "Realtime detection: Monitoring Apache logs"
echo ""
echo "Press Ctrl+C to stop the system"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Stopping system..."
    kill $WEB_PID 2>/dev/null
    kill $DETECTOR_PID 2>/dev/null
    echo "System stopped."
    exit 0
}

# Trap Ctrl+C
trap cleanup SIGINT

# Wait for processes
wait

#!/bin/bash

# Ubuntu Simple Setup Script
# Clone và chạy ngay

echo "=========================================="
echo "UBUNTU SIMPLE SETUP"
echo "=========================================="

# Cài đặt dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Retrain model với scikit-learn hiện tại
echo "Retraining model with current scikit-learn version..."
python3 -c "
from optimized_sqli_detector import OptimizedSQLIDetector
detector = OptimizedSQLIDetector()
detector.train_from_path('sqli_logs_clean_100k.jsonl')
print('Model retrained successfully!')
"

# Test model
echo "Testing model..."
python3 -c "
from optimized_sqli_detector import OptimizedSQLIDetector
detector = OptimizedSQLIDetector()
detector.load_model('models/optimized_sqli_detector.pkl')
print('Model loaded successfully!')
"

echo "=========================================="
echo "SETUP COMPLETED!"
echo "=========================================="
echo "You can now run:"
echo "  python3 app.py"
echo "  python3 realtime_log_collector.py"
echo "=========================================="

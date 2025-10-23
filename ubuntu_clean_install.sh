#!/bin/bash

# Ubuntu Clean Install Script
# Xóa cài đặt cũ và cài đặt đúng requirements của project

echo "=========================================="
echo "UBUNTU CLEAN INSTALL SCRIPT"
echo "=========================================="

# Kiểm tra Python version
echo "Checking Python version..."
python3 --version

# Xóa các package cũ có thể gây conflict
echo "Removing old packages that might cause conflicts..."
pip uninstall -y scikit-learn numpy pandas flask werkzeug joblib requests psutil ipaddress 2>/dev/null || true

# Xóa cache pip
echo "Clearing pip cache..."
pip cache purge 2>/dev/null || true

# Cài đặt requirements mới
echo "Installing project requirements..."
pip install -r requirements.txt

# Kiểm tra cài đặt
echo "Verifying installation..."
python3 -c "
import sys
print('Python version:', sys.version)

try:
    import sklearn
    print('scikit-learn version:', sklearn.__version__)
except ImportError as e:
    print('scikit-learn import error:', e)

try:
    import numpy
    print('numpy version:', numpy.__version__)
except ImportError as e:
    print('numpy import error:', e)

try:
    import pandas
    print('pandas version:', pandas.__version__)
except ImportError as e:
    print('pandas import error:', e)

try:
    import flask
    print('flask version:', flask.__version__)
except ImportError as e:
    print('flask import error:', e)
"

# Retrain model với version mới
echo "Retraining model with new scikit-learn version..."
python3 -c "
from optimized_sqli_detector import OptimizedSQLIDetector
detector = OptimizedSQLIDetector()
detector.train('sqli_logs_clean_100k.jsonl')
print('Model retrained successfully!')
"

# Test model loading
echo "Testing model loading..."
python3 -c "
from optimized_sqli_detector import OptimizedSQLIDetector
detector = OptimizedSQLIDetector()
detector.load_model('models/optimized_sqli_detector.pkl')
print('Model loaded successfully!')
"

echo "=========================================="
echo "CLEAN INSTALL COMPLETED!"
echo "=========================================="
echo "You can now run:"
echo "  python3 app.py"
echo "  python3 realtime_log_collector.py"
echo "=========================================="

#!/bin/bash
# Script để cài đặt dependencies cho user

echo "🔧 Installing Python dependencies for user..."
echo "=============================================="

# Cài đặt cho user (không cần sudo)
echo "📦 Installing scikit-learn for user..."
pip install --user scikit-learn

echo "📦 Installing other dependencies for user..."
pip install --user flask pandas joblib requests

echo "✅ Installation completed!"
echo ""
echo "🚀 Now you can run:"
echo "   python3 test_dependencies.py"
echo "   ./setup_user.sh"
echo "   python3 app.py"

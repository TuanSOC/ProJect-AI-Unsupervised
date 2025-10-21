#!/bin/bash
# Simple dependency installer

echo "📦 Installing Python dependencies..."
echo "===================================="

# Install for user (no sudo required)
echo "Installing scikit-learn..."
pip install --user scikit-learn

echo "Installing other dependencies..."
pip install --user flask pandas joblib requests

echo ""
echo "✅ Dependencies installed!"
echo "Now you can run: ./quick_start.sh"

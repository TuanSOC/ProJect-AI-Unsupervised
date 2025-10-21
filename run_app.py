#!/usr/bin/env python3
"""
Script để chạy app trực tiếp với path fix
"""

import sys
import os

# Add system paths
sys.path.insert(0, '/usr/local/lib/python3.10/dist-packages')
sys.path.insert(0, '/usr/lib/python3/dist-packages')

print("🚀 Starting SQLi Detection App...")
print("=" * 40)

try:
    # Test imports
    import flask
    import pandas
    import sklearn
    import joblib
    print("✅ All dependencies available")
    
    # Import and run app
    from app import app
    print("✅ App imported successfully")
    
    print("\n🌐 Starting web server...")
    print("Access: http://localhost:5000")
    print("Press Ctrl+C to stop")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("\nTry installing missing packages:")
    print("pip install --user scikit-learn flask pandas joblib")
    
except Exception as e:
    print(f"❌ Error: {e}")

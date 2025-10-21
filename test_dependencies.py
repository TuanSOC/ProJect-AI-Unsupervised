#!/usr/bin/env python3
"""
Test script để kiểm tra dependencies
"""

import sys
import os

# Add system paths
sys.path.insert(0, '/usr/local/lib/python3.10/dist-packages')
sys.path.insert(0, '/usr/lib/python3/dist-packages')

print("🔍 Testing Python Dependencies")
print("=" * 40)

required = ['flask', 'requests', 'pandas', 'scikit-learn', 'joblib']
missing = []
available = []

for pkg in required:
    try:
        module = __import__(pkg.replace('-', '_'))
        available.append(pkg)
        print(f"✅ {pkg} - {module.__version__ if hasattr(module, '__version__') else 'available'}")
    except ImportError as e:
        missing.append(pkg)
        print(f"❌ {pkg} - {e}")

print("\n" + "=" * 40)
if missing:
    print(f"❌ Missing packages: {missing}")
    print("\nTo install missing packages:")
    print(f"sudo pip install {' '.join(missing)}")
    print(f"# OR")
    print(f"pip install --user {' '.join(missing)}")
    sys.exit(1)
else:
    print("✅ All dependencies available!")
    print("\n🚀 You can now run:")
    print("   python3 app.py")
    print("   python3 realtime_log_collector.py")

#!/usr/bin/env python3
"""
Test script để kiểm tra scikit-learn
"""

import sys
import os

print("🔍 Testing scikit-learn specifically")
print("=" * 40)

# Add system paths
sys.path.insert(0, '/usr/local/lib/python3.10/dist-packages')
sys.path.insert(0, '/usr/lib/python3/dist-packages')

# Check if sklearn directory exists
sklearn_path = '/usr/local/lib/python3.10/dist-packages/sklearn'
if os.path.exists(sklearn_path):
    print(f"✅ Found sklearn directory at: {sklearn_path}")
    
    # List contents
    try:
        contents = os.listdir(sklearn_path)
        print(f"Contents: {contents[:5]}...")  # Show first 5 items
    except:
        print("Cannot list contents")
    
    # Try to import
    try:
        import sklearn
        print(f"✅ Successfully imported sklearn version: {sklearn.__version__}")
        
        # Test specific modules
        from sklearn.ensemble import IsolationForest
        print("✅ IsolationForest imported successfully")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        
else:
    print(f"❌ sklearn directory not found at: {sklearn_path}")
    
    # Check other possible locations
    other_paths = [
        '/usr/local/lib/python3/dist-packages/sklearn',
        '/usr/lib/python3/dist-packages/sklearn',
        '/home/dvwa/.local/lib/python3.10/site-packages/sklearn'
    ]
    
    for path in other_paths:
        if os.path.exists(path):
            print(f"✅ Found sklearn at: {path}")
            sys.path.insert(0, os.path.dirname(path))
            break
    else:
        print("❌ sklearn not found in any standard location")

print("\n" + "=" * 40)
print("Current Python paths:")
for p in sys.path[:10]:  # Show first 10 paths
    print(f"  {p}")

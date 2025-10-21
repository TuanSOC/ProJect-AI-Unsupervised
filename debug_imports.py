#!/usr/bin/env python3
"""
Debug script để kiểm tra imports
"""

import sys
import os

print("🔍 Debug Python Imports")
print("=" * 40)

# Show current user
import getpass
print(f"Current user: {getpass.getuser()}")

# Show Python executable
print(f"Python executable: {sys.executable}")

# Show all paths
print(f"\nPython paths:")
for i, path in enumerate(sys.path):
    print(f"  {i}: {path}")

# Check specific paths
paths_to_check = [
    '/usr/local/lib/python3.10/dist-packages',
    '/usr/lib/python3/dist-packages', 
    '/home/dvwa/.local/lib/python3.10/site-packages'
]

print(f"\nChecking specific paths:")
for path in paths_to_check:
    exists = os.path.exists(path)
    print(f"  {path}: {'✅ EXISTS' if exists else '❌ NOT FOUND'}")
    if exists:
        try:
            contents = os.listdir(path)
            sklearn_found = any('sklearn' in item for item in contents)
            print(f"    sklearn: {'✅ FOUND' if sklearn_found else '❌ NOT FOUND'}")
        except:
            print(f"    (cannot list contents)")

# Try to import sklearn
print(f"\nTesting sklearn import:")
try:
    import sklearn
    print(f"✅ sklearn imported successfully")
    print(f"   Version: {sklearn.__version__}")
    print(f"   Location: {sklearn.__file__}")
except ImportError as e:
    print(f"❌ sklearn import failed: {e}")

# Try other packages
packages = ['flask', 'pandas', 'joblib']
for pkg in packages:
    try:
        module = __import__(pkg)
        print(f"✅ {pkg}: {module.__version__ if hasattr(module, '__version__') else 'available'}")
    except ImportError as e:
        print(f"❌ {pkg}: {e}")

print(f"\n" + "=" * 40)
print("Debug completed!")

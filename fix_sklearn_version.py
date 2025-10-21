#!/usr/bin/env python3
"""
Script để fix scikit-learn version mismatch
"""

import sys
import os
import subprocess

print("🔧 Fixing scikit-learn version mismatch")
print("=" * 40)

# Check current versions
try:
    import sklearn
    print(f"Current scikit-learn version: {sklearn.__version__}")
except ImportError:
    print("❌ scikit-learn not found")
    sys.exit(1)

# Check if model exists
model_path = "models/optimized_sqli_detector.pkl"
if not os.path.exists(model_path):
    print(f"❌ Model file not found: {model_path}")
    sys.exit(1)

print(f"✅ Model file found: {model_path}")

# Option 1: Retrain model with current version
print("\n🔄 Option 1: Retrain model with current scikit-learn version")
print("This will create a new model compatible with your current version.")

response = input("Retrain model? (y/n): ").lower().strip()
if response == 'y':
    try:
        print("📚 Loading training data...")
        import json
        
        with open('sqli_logs_clean_100k.jsonl', 'r') as f:
            clean_logs = [json.loads(line.strip()) for line in f if line.strip()]
        
        if not clean_logs:
            print("❌ No training data found")
            sys.exit(1)
        
        print(f"✅ Loaded {len(clean_logs)} training samples")
        
        # Import and train
        from optimized_sqli_detector import OptimizedSQLIDetector
        
        print("🤖 Training new model...")
        detector = OptimizedSQLIDetector()
        
        # Use subset for faster training
        train_data = clean_logs[:10000] if len(clean_logs) > 10000 else clean_logs
        detector.train(train_data)
        
        # Backup old model
        if os.path.exists(model_path):
            backup_path = model_path + ".backup"
            os.rename(model_path, backup_path)
            print(f"✅ Old model backed up to: {backup_path}")
        
        # Save new model
        detector.save_model(model_path)
        print(f"✅ New model saved to: {model_path}")
        print("✅ Model retrained successfully!")
        
    except Exception as e:
        print(f"❌ Error retraining model: {e}")
        sys.exit(1)

# Option 2: Upgrade scikit-learn
print("\n🔄 Option 2: Upgrade scikit-learn to match model version")
print("This will upgrade scikit-learn to version 1.7.2")

response = input("Upgrade scikit-learn? (y/n): ").lower().strip()
if response == 'y':
    try:
        print("📦 Upgrading scikit-learn...")
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "scikit-learn==1.7.2"], check=True)
        print("✅ scikit-learn upgraded successfully!")
        print("🔄 Please restart your applications")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error upgrading scikit-learn: {e}")
        sys.exit(1)

print("\n✅ Version fix completed!")
print("🚀 You can now run:")
print("   python3 app.py")
print("   python3 realtime_log_collector.py")

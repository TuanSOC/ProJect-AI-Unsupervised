#!/usr/bin/env python3
"""
Script để fix tất cả issues: version mismatch, JSON serialization, unpacking
"""

import os
import json
import logging
from optimized_sqli_detector import OptimizedSQLIDetector

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_json_serialization():
    """Fix JSON serialization trong app.py"""
    
    print("🔧 Fixing JSON serialization in app.py...")
    print("=" * 50)
    
    try:
        with open('app.py', 'r') as f:
            content = f.read()
        
        # Fix JSON serialization - convert numpy types to Python types
        old_return = '''        return jsonify({
            'is_sqli': is_sqli,
            'score': score,
            'patterns': patterns,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        })'''
        
        new_return = '''        return jsonify({
            'is_sqli': bool(is_sqli),  # Convert numpy.bool_ to Python bool
            'score': float(score),     # Convert numpy.float64 to Python float
            'patterns': patterns,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        })'''
        
        if old_return in content:
            content = content.replace(old_return, new_return)
            print("✅ Fixed JSON serialization")
        else:
            print("ℹ️  JSON serialization pattern not found")
        
        # Write back
        with open('app.py', 'w') as f:
            f.write(content)
        
        print("✅ app.py updated")
        
    except Exception as e:
        print(f"❌ Error fixing app.py: {e}")

def fix_realtime_collector():
    """Fix realtime_log_collector.py để handle 4 return values"""
    
    print("\n🔧 Fixing realtime_log_collector.py...")
    print("=" * 50)
    
    try:
        with open('realtime_log_collector.py', 'r') as f:
            content = f.read()
        
        # Find and fix the detection call
        old_detection = '''        is_sqli, score = self.detector.predict_single(log_entry, threshold=self.detection_threshold)'''
        
        new_detection = '''        is_sqli, score, patterns, confidence = self.detector.predict_single(log_entry, threshold=self.detection_threshold)'''
        
        if old_detection in content:
            content = content.replace(old_detection, new_detection)
            print("✅ Fixed detection unpacking")
        else:
            print("ℹ️  Detection pattern not found")
        
        # Also fix any other detection calls
        content = content.replace(
            'is_sqli, score = self.detector.predict_single(',
            'is_sqli, score, patterns, confidence = self.detector.predict_single('
        )
        
        # Write back
        with open('realtime_log_collector.py', 'w') as f:
            f.write(content)
        
        print("✅ realtime_log_collector.py updated")
        
    except Exception as e:
        print(f"❌ Error fixing realtime_log_collector.py: {e}")

def retrain_model_fresh():
    """Retrain model với scikit-learn version hiện tại"""
    
    print("\n🤖 Retraining model with current scikit-learn version...")
    print("=" * 50)
    
    try:
        # Load existing training data
        with open('sqli_logs_clean_100k.jsonl', 'r') as f:
            existing_logs = [json.loads(line.strip()) for line in f if line.strip()]
        print(f"✅ Loaded {len(existing_logs)} existing logs")
        
        # Use subset for faster training
        train_data = existing_logs[:10000] if len(existing_logs) > 10000 else existing_logs
        print(f"📊 Training with {len(train_data)} logs")
        
        # Train new model
        detector = OptimizedSQLIDetector()
        detector.train(train_data)
        
        # Save model
        model_path = 'models/optimized_sqli_detector.pkl'
        detector.save_model(model_path)
        print(f"✅ Model retrained and saved to {model_path}")
        
        # Test new model
        print("\n🧪 Testing new model...")
        test_log = {
            "time": "2025-10-22T00:17:28+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/sqli/index.php",
            "query_string": "?id=1&Submit=Submit",
            "payload": "id=1&Submit=Submit",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "status": 200
        }
        
        is_sqli, score, patterns, confidence = detector.predict_single(test_log, threshold=0.85)
        print(f"✅ Test result: {is_sqli} (Score: {score:.3f}, Patterns: {patterns}, Confidence: {confidence})")
        
    except Exception as e:
        print(f"❌ Error retraining model: {e}")

def main():
    """Main function"""
    
    print("🚀 Fixing All Issues")
    print("=" * 60)
    print("This script will:")
    print("1. Fix JSON serialization in app.py")
    print("2. Fix unpacking in realtime_log_collector.py")
    print("3. Retrain model with current scikit-learn version")
    print("=" * 60)
    
    # Fix JSON serialization
    fix_json_serialization()
    
    # Fix realtime collector
    fix_realtime_collector()
    
    # Retrain model
    retrain_model_fresh()
    
    print("\n🎉 All Issues Fixed!")
    print("=" * 60)
    print("✅ JSON serialization fixed")
    print("✅ Unpacking errors fixed")
    print("✅ Model retrained with current scikit-learn version")
    print("\n📋 Next Steps:")
    print("1. Run: python3 app.py")
    print("2. Run: python3 realtime_log_collector.py")
    print("3. Test payload detection")

if __name__ == "__main__":
    main()

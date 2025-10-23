#!/usr/bin/env python3
"""
Fix version compatibility - Retrain model with current scikit-learn version
"""

import sys
import subprocess
import importlib

def check_scikit_learn_version():
    """Check current scikit-learn version"""
    try:
        import sklearn
        version = sklearn.__version__
        print(f"Current scikit-learn version: {version}")
        return version
    except ImportError:
        print("scikit-learn not installed")
        return None

def retrain_model():
    """Retrain model with current scikit-learn version"""
    print("Retraining model with current scikit-learn version...")
    
    try:
        from optimized_sqli_detector import OptimizedSQLIDetector
        
        # Create new detector
        detector = OptimizedSQLIDetector()
        
        # Train with current scikit-learn version
        detector.train('sqli_logs_clean_100k.jsonl')
        
        print("Model retrained successfully with current scikit-learn version!")
        return True
        
    except Exception as e:
        print(f"Error retraining model: {e}")
        return False

def main():
    """Main function"""
    print("=" * 60)
    print("FIX VERSION COMPATIBILITY")
    print("=" * 60)
    
    # Check current version
    current_version = check_scikit_learn_version()
    if not current_version:
        print("Please install scikit-learn first")
        return
    
    print(f"Using scikit-learn version: {current_version}")
    
    # Retrain model
    if retrain_model():
        print("\n" + "=" * 60)
        print("VERSION COMPATIBILITY FIXED!")
        print("=" * 60)
        print("Model has been retrained with current scikit-learn version.")
        print("Version mismatch warnings should be resolved.")
    else:
        print("\nFailed to retrain model. Please check the error messages above.")

if __name__ == "__main__":
    main()

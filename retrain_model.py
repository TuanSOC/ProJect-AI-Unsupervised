#!/usr/bin/env python3
"""
Retrain model với code mới
"""

import json
import logging
from optimized_sqli_detector import OptimizedSQLIDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def iter_jsonl(path):
    """Iterate through JSONL file"""
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue

def main():
    print("=" * 80)
    print("Retraining Isolation Forest Model")
    print("=" * 80)
    
    # Load clean logs
    clean_logs_path = 'sqli_logs_clean_100k.jsonl'
    print(f"\nLoading clean logs from {clean_logs_path}...")
    
    clean_logs = []
    for i, log in enumerate(iter_jsonl(clean_logs_path)):
        clean_logs.append(log)
        if (i + 1) % 10000 == 0:
            print(f"  Loaded {i + 1} logs...")
    
    print(f"[OK] Loaded {len(clean_logs)} clean logs")
    
    # Initialize detector
    print("\nInitializing detector...")
    detector = OptimizedSQLIDetector(
        n_estimators=300,
        max_features=1.0,
        contamination='auto',
        random_state=42
    )
    
    # Train model
    print("\nTraining model...")
    print("  This may take a few minutes...")
    X_scaled, feature_names = detector.train(clean_logs)
    
    # Save model
    print("\nSaving model...")
    detector.save_model('models/optimized_sqli_detector.pkl')
    
    print("\n" + "=" * 80)
    print("[OK] Model retrained successfully!")
    print("=" * 80)
    print(f"  - Model saved to: models/optimized_sqli_detector.pkl")
    print(f"  - Features: {len(feature_names)}")
    print(f"  - Training samples: {len(clean_logs)}")

if __name__ == '__main__':
    main()


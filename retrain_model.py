#!/usr/bin/env python3
"""
Retrain model on Ubuntu with current scikit-learn version
"""

from optimized_sqli_detector import OptimizedSQLIDetector
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def retrain_model():
    """Retrain model with current scikit-learn version"""
    
    logger.info("=" * 80)
    logger.info("RETRAINING MODEL FOR UBUNTU COMPATIBILITY")
    logger.info("=" * 80)
    
    try:
        # Create detector
        detector = OptimizedSQLIDetector()
        
        # Train from file
        logger.info("Training model from sqli_logs_clean_100k.jsonl...")
        detector.train_from_path('sqli_logs_clean_100k.jsonl')
        
        logger.info("✅ Model successfully retrained and saved to models/optimized_sqli_detector.pkl")
        
        # Test loading
        logger.info("Testing model loading...")
        test_detector = OptimizedSQLIDetector()
        test_detector.load_model('models/optimized_sqli_detector.pkl')
        logger.info("✅ Model loaded successfully!")
        
        logger.info("=" * 80)
        logger.info("RETRAINING COMPLETED!")
        logger.info("Please restart realtime_log_collector.py and app.py to use the new model.")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"❌ Error during model retraining: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    retrain_model()

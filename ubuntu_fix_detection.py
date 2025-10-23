#!/usr/bin/env python3
"""
Ubuntu Fix Detection - Ensure realtime collector works properly
"""

import json
import logging
import subprocess
import sys
import os

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_command(cmd, description):
    """Run command and log result"""
    logger.info(f"🔧 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            logger.info(f"✅ {description} - SUCCESS")
            if result.stdout.strip():
                logger.info(f"Output: {result.stdout.strip()}")
        else:
            logger.error(f"❌ {description} - FAILED")
            logger.error(f"Error: {result.stderr.strip()}")
        return result.returncode == 0
    except Exception as e:
        logger.error(f"❌ {description} - EXCEPTION: {e}")
        return False

def fix_ubuntu_detection():
    """Fix detection issues on Ubuntu"""
    
    logger.info("=" * 80)
    logger.info("UBUNTU DETECTION FIX")
    logger.info("=" * 80)
    
    # Step 1: Check current directory and files
    logger.info("📁 Checking current directory...")
    current_dir = os.getcwd()
    logger.info(f"Current directory: {current_dir}")
    
    files_to_check = [
        "optimized_sqli_detector.py",
        "realtime_log_collector.py", 
        "app.py",
        "requirements.txt",
        "sqli_logs_clean_100k.jsonl"
    ]
    
    for file in files_to_check:
        if os.path.exists(file):
            logger.info(f"✅ {file} - EXISTS")
        else:
            logger.error(f"❌ {file} - MISSING")
    
    # Step 2: Install/update requirements
    logger.info("\n📦 Installing requirements...")
    if not run_command("pip3 install -r requirements.txt", "Install requirements"):
        logger.error("Failed to install requirements")
        return False
    
    # Step 3: Retrain model with current scikit-learn version
    logger.info("\n🤖 Retraining model...")
    retrain_script = """
import sys
sys.path.append('.')
from optimized_sqli_detector import OptimizedSQLIDetector
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    logger.info("Loading detector...")
    detector = OptimizedSQLIDetector()
    
    logger.info("Training from sqli_logs_clean_100k.jsonl...")
    detector.train_from_path('sqli_logs_clean_100k.jsonl')
    
    logger.info("Saving model...")
    detector.save_model('models/optimized_sqli_detector.pkl')
    
    logger.info("Testing model loading...")
    detector2 = OptimizedSQLIDetector()
    detector2.load_model('models/optimized_sqli_detector.pkl')
    
    logger.info("Model retrained and tested successfully!")
    
except Exception as e:
    logger.error(f"Error: {e}")
    sys.exit(1)
"""
    
    with open("temp_retrain.py", "w") as f:
        f.write(retrain_script)
    
    if not run_command("python3 temp_retrain.py", "Retrain model"):
        logger.error("Failed to retrain model")
        return False
    
    # Clean up temp file
    if os.path.exists("temp_retrain.py"):
        os.remove("temp_retrain.py")
    
    # Step 4: Test model loading
    logger.info("\n🧪 Testing model...")
    test_script = """
import sys
sys.path.append('.')
from optimized_sqli_detector import OptimizedSQLIDetector
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    detector = OptimizedSQLIDetector()
    detector.load_model('models/optimized_sqli_detector.pkl')
    
    # Test with a simple SQLi payload
    test_log = {
        "time": "2025-10-23T14:30:19+0700",
        "remote_ip": "192.168.205.2",
        "method": "GET",
        "uri": "/DVWA/vulnerabilities/sqli/index.php",
        "query_string": "?id=admin%27%29+or+%28%271%27%3D%271%27%23&Submit=Submit",
        "status": 500,
        "bytes_sent": 0,
        "response_time_ms": 16685,
        "referer": "http://localhost/DVWA/vulnerabilities/sqli/",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "request_length": 2244,
        "response_length": 295,
        "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s",
        "payload": "id=admin%27%29+or+%28%271%27%3D%271%27%23&Submit=Submit",
        "session_token": "e16qs57nkd675aj4u44nv78r6s"
    }
    
    result = detector.predict_single(test_log)
    logger.info(f"Test result: {result}")
    
    if result and result.get('is_sqli'):
        logger.info("✅ Model is working correctly!")
    else:
        logger.error("❌ Model is not detecting SQLi properly")
        
except Exception as e:
    logger.error(f"Error testing model: {e}")
    sys.exit(1)
"""
    
    with open("temp_test.py", "w") as f:
        f.write(test_script)
    
    if not run_command("python3 temp_test.py", "Test model"):
        logger.error("Failed to test model")
        return False
    
    # Clean up temp file
    if os.path.exists("temp_test.py"):
        os.remove("temp_test.py")
    
    # Step 5: Test realtime collector
    logger.info("\n📡 Testing realtime collector...")
    test_collector_script = """
import sys
sys.path.append('.')
from realtime_log_collector import RealtimeLogCollector
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    # Test collector initialization
    collector = RealtimeLogCollector(log_path="/dev/null", webhook_url=None)
    
    if collector.detector:
        logger.info("✅ RealtimeLogCollector initialized successfully")
        
        # Test with the same SQLi payload
        test_log = {
            "time": "2025-10-23T14:30:19+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/sqli/index.php",
            "query_string": "?id=admin%27%29+or+%28%271%27%3D%271%27%23&Submit=Submit",
            "status": 500,
            "bytes_sent": 0,
            "response_time_ms": 16685,
            "referer": "http://localhost/DVWA/vulnerabilities/sqli/",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "request_length": 2244,
            "response_length": 295,
            "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s",
            "payload": "id=admin%27%29+or+%28%271%27%3D%271%27%23&Submit=Submit",
            "session_token": "e16qs57nkd675aj4u44nv78r6s"
        }
        
        result = collector.detect_sqli_realtime(test_log)
        logger.info(f"Realtime detection result: {result}")
        
        if result and result.get('is_sqli'):
            logger.info("✅ RealtimeLogCollector is working correctly!")
        else:
            logger.error("❌ RealtimeLogCollector is not detecting SQLi properly")
    else:
        logger.error("❌ Failed to initialize detector in RealtimeLogCollector")
        
except Exception as e:
    logger.error(f"Error testing realtime collector: {e}")
    sys.exit(1)
"""
    
    with open("temp_test_collector.py", "w") as f:
        f.write(test_collector_script)
    
    if not run_command("python3 temp_test_collector.py", "Test realtime collector"):
        logger.error("Failed to test realtime collector")
        return False
    
    # Clean up temp file
    if os.path.exists("temp_test_collector.py"):
        os.remove("temp_test_collector.py")
    
    # Step 6: Check Apache log file
    logger.info("\n📋 Checking Apache log file...")
    apache_log = "/var/log/apache2/access_full_json.log"
    if os.path.exists(apache_log):
        logger.info(f"✅ Apache log file exists: {apache_log}")
        
        # Check permissions
        if os.access(apache_log, os.R_OK):
            logger.info("✅ Apache log file is readable")
        else:
            logger.error("❌ Apache log file is not readable")
            logger.info("Try: sudo chmod 644 /var/log/apache2/access_full_json.log")
    else:
        logger.error(f"❌ Apache log file not found: {apache_log}")
        logger.info("Please check Apache configuration for JSON logging")
    
    logger.info("\n" + "="*80)
    logger.info("UBUNTU DETECTION FIX COMPLETED!")
    logger.info("="*80)
    logger.info("Next steps:")
    logger.info("1. Run: python3 app.py")
    logger.info("2. Run: python3 realtime_log_collector.py")
    logger.info("3. Test with SQLi payloads")
    logger.info("="*80)

if __name__ == "__main__":
    fix_ubuntu_detection()

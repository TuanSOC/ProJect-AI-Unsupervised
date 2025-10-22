#!/usr/bin/env python3
"""
Realtime Log Collector cho Apache - Tối ưu hóa
Thu thập và phân tích log realtime từ Apache access logs
"""

import json
import subprocess
import time
import logging
import requests
import threading
from datetime import datetime
from optimized_sqli_detector import OptimizedSQLIDetector
import queue
import signal
import sys

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('realtime_sqli_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RealtimeLogCollector:
    """Thu thập và phân tích log realtime từ Apache"""
    
    def __init__(self, log_path="/var/log/apache2/access_full_json.log", 
                 webhook_url="http://localhost:5000/api/realtime-detect",
                 detection_threshold=0.85):
        self.log_path = log_path
        self.webhook_url = webhook_url
        self.detection_threshold = detection_threshold
        self.detector = None
        self.log_queue = queue.Queue(maxsize=1000)
        self.running = False
        self.process = None
        
        # Statistics
        self.stats = {
            'total_logs': 0,
            'sqli_detected': 0,
            'errors': 0,
            'start_time': datetime.now()
        }
        
        # Load AI model
        self.load_detector()
        
    def load_detector(self):
        """Load AI model để phát hiện SQLi"""
        try:
            self.detector = OptimizedSQLIDetector()
            self.detector.load_model('models/optimized_sqli_detector.pkl')
            logger.info("✅ AI Model loaded successfully for realtime detection!")
        except Exception as e:
            logger.error(f"❌ Error loading AI model: {e}")
            self.detector = None
    
    def parse_log_line(self, line):
        """Parse một dòng log JSON đã được format sẵn"""
        try:
            # Loại bỏ whitespace và parse JSON
            line = line.strip()
            if not line:
                return None
                
            # Parse JSON log
            log_entry = json.loads(line)
            
            # Validate required fields
            required_fields = ['time', 'remote_ip', 'method', 'uri']
            if not all(field in log_entry for field in required_fields):
                return None
            
            # Xử lý query string và payload từ log đã format sẵn
            self._process_formatted_log(log_entry)
                
            return log_entry
            
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON log line: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing log line: {e}")
            return None
    
    def _process_formatted_log(self, log_entry):
        """Xử lý log đã được format sẵn với query_string và payload"""
        try:
            # Đảm bảo các field luôn tồn tại
            log_entry.setdefault('query_string', '')
            log_entry.setdefault('payload', '')
            
            # Parse query parameters từ query_string
            query_string = log_entry.get('query_string', '')
            if query_string:
                query_params = {}
                for param in query_string.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        query_params[key] = value
                log_entry['query_params'] = query_params
            else:
                log_entry['query_params'] = {}
            
            # Parse payload parameters
            payload = log_entry.get('payload', '')
            if payload:
                payload_params = {}
                for param in payload.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        payload_params[key] = value
                log_entry['payload_params'] = payload_params
            else:
                log_entry['payload_params'] = {}
            
            # Xử lý POST requests - payload thường rỗng trong Apache logs
            method = log_entry.get('method', '').upper()
            if method == 'POST' and not payload:
                # Thử lấy từ referer nếu có
                referer = log_entry.get('referer', '')
                if referer and '?' in referer:
                    referer_query = referer.split('?', 1)[1]
                    log_entry['payload'] = referer_query
                    log_entry['payload_source'] = 'referer'
                    
                    # Parse referer payload
                    if referer_query:
                        referer_params = {}
                        for param in referer_query.split('&'):
                            if '=' in param:
                                key, value = param.split('=', 1)
                                referer_params[key] = value
                        log_entry['payload_params'] = referer_params
            
            # Tạo combined payload cho detection
            combined_payload = payload or query_string
            log_entry['combined_payload'] = combined_payload
            
            # Log debug info
            if combined_payload:
                logger.debug(f"Captured payload: {combined_payload[:100]}...")
            
        except Exception as e:
            logger.warning(f"Error processing formatted log: {e}")
            # Đảm bảo các field luôn tồn tại
            log_entry.setdefault('query_params', {})
            log_entry.setdefault('payload_params', {})
            log_entry.setdefault('combined_payload', '')
    
    def detect_sqli_realtime(self, log_entry):
        """Phát hiện SQLi trong log entry realtime - Tối ưu hóa"""
        if not self.detector:
            return None
            
        try:
            # Sử dụng AI model để phát hiện
            is_anomaly, score, patterns, confidence = self.detector.predict_single(log_entry, threshold=self.detection_threshold)
            
            return {
                'is_sqli': bool(is_anomaly),
                'score': float(score),
                'confidence': 'High' if abs(score) > 0.8 else 'Medium' if abs(score) > 0.6 else 'Low',
                'timestamp': datetime.now().isoformat(),
                'threat_level': 'CRITICAL' if is_anomaly else 'NONE'
            }
            
        except Exception as e:
            logger.error(f"Error in SQLi detection: {e}")
            self.stats['errors'] += 1
            return None
    
    def _is_real_threat(self, detection_result, log_entry):
        """Filter false positives - only detect real threats"""
        try:
            score = detection_result.get('score', 0)
            query_string = log_entry.get('query_string', '')
            payload = log_entry.get('payload', '')
            uri = log_entry.get('uri', '')
            
            # Skip if no suspicious content
            if not query_string and not payload:
                return False
            
            # Skip if score is too low
            if score < 0.6:
                return False
            
            # Skip common false positive patterns
            false_positive_patterns = [
                '/css/', '/js/', '/images/', '/favicon.ico',
                '/robots.txt', '/sitemap.xml', '/.well-known/',
                '/api/health', '/ping', '/status'
            ]
            
            for pattern in false_positive_patterns:
                if pattern in uri.lower():
                    return False
            
            # Only detect if has SQLi-like content
            suspicious_content = query_string + ' ' + payload
            sql_keywords = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'exec', 'script']
            
            has_sql_content = any(keyword in suspicious_content.lower() for keyword in sql_keywords)
            
            return has_sql_content
            
        except Exception as e:
            logger.error(f"Error in threat filtering: {e}")
            return True  # Default to detect if error
    
    def send_to_webhook(self, log_entry, detection_result):
        """Gửi kết quả phát hiện đến webhook"""
        try:
            if not self.webhook_url:
                logger.warning("Webhook URL not configured")
                return False
                
            payload = {
                'log': log_entry,
                'detection': detection_result,
                'timestamp': datetime.now().isoformat()
            }
            
            response = requests.post(
                self.webhook_url, 
                json=payload, 
                timeout=5,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                logger.info(f"✅ Detection result sent to webhook")
            else:
                logger.warning(f"⚠️ Webhook response: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"⚠️ Failed to send to webhook: {e}")
        except Exception as e:
            logger.error(f"❌ Error sending to webhook: {e}")
    
    def process_log_line(self, log_entry):
        """Xử lý một dòng log"""
        if not log_entry:
            return
            
        # Phát hiện SQLi
        detection_result = self.detect_sqli_realtime(log_entry)
        
        # Filter false positives: only detect if score > threshold AND has suspicious content
        if detection_result and detection_result['is_sqli'] and self._is_real_threat(detection_result, log_entry):
            # Log threat
            logger.warning(f"🚨 SQLi DETECTED!")
            logger.warning(f"   IP: {log_entry.get('remote_ip', 'Unknown')}")
            logger.warning(f"   URI: {log_entry.get('uri', 'Unknown')}")
            logger.warning(f"   Query: {log_entry.get('query_string', 'None')}")
            logger.warning(f"   Payload: {log_entry.get('payload', 'None')}")
            logger.warning(f"   Score: {detection_result['score']:.3f}")
            logger.warning(f"   Patterns: {detection_result.get('detected_patterns', 'N/A')}")
            logger.warning(f"   Confidence: {detection_result['confidence']}")
            logger.warning(f"   Threat Level: {detection_result['threat_level']}")
            logger.warning("-" * 80)
            
            # Gửi đến webhook
            self.send_to_webhook(log_entry, detection_result)
            
            # Lưu vào file threat log
            self.save_threat_log(log_entry, detection_result)
        else:
            # Log normal traffic (optional)
            logger.debug(f"Normal traffic from {log_entry.get('remote_ip', 'Unknown')} - {log_entry.get('uri', 'Unknown')}")
    
    def save_threat_log(self, log_entry, detection_result):
        """Lưu threat log vào file"""
        try:
            threat_data = {
                'timestamp': datetime.now().isoformat(),
                'log': log_entry,
                'detection': detection_result
            }
            
            with open('realtime_threats.jsonl', 'a', encoding='utf-8') as f:
                f.write(json.dumps(threat_data, ensure_ascii=False) + '\n')
                
        except Exception as e:
            logger.error(f"Error saving threat log: {e}")
    
    def start_monitoring(self):
        """Bắt đầu monitoring log realtime"""
        logger.info(f"🚀 Starting realtime log monitoring from {self.log_path}")
        logger.info(f"🎯 Detection threshold: {self.detection_threshold}")
        logger.info(f"🔗 Webhook URL: {self.webhook_url}")
        
        try:
            # Sử dụng tail -f để theo dõi log realtime
            self.process = subprocess.Popen(
                ['tail', '-f', self.log_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            self.running = True
            logger.info("✅ Log monitoring started successfully!")
            
            # Đọc log lines realtime
            while self.running:
                try:
                    line = self.process.stdout.readline()
                    if not line:
                        time.sleep(0.1)  # Small delay to avoid busy waiting
                        continue
                    
                    # Parse và xử lý log line
                    log_entry = self.parse_log_line(line)
                    if log_entry:
                        self.process_log_line(log_entry)
                        
                except Exception as e:
                    logger.warning(f"Error reading log line: {e}")
                    time.sleep(0.1)
                    
        except FileNotFoundError:
            logger.error(f"❌ Log file not found: {self.log_path}")
            logger.error("Please check if Apache is running and log file exists")
        except PermissionError:
            logger.error(f"❌ Permission denied accessing log file: {self.log_path}")
            logger.error("Please run with sudo or check file permissions")
        except Exception as e:
            logger.error(f"❌ Error in log monitoring: {e}")
        finally:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Dừng monitoring"""
        logger.info("🛑 Stopping log monitoring...")
        self.running = False
        
        if self.process:
            self.process.terminate()
            self.process.wait()
            
        logger.info("✅ Log monitoring stopped")
    
    def signal_handler(self, signum, frame):
        """Xử lý signal để dừng gracefully"""
        logger.info(f"Received signal {signum}, stopping...")
        self.stop_monitoring()
        sys.exit(0)

def main():
    """Main function"""
    print("🔍 Realtime SQLi Detection System")
    print("=" * 50)
    
    # Tạo collector
    collector = RealtimeLogCollector(
        log_path="/var/log/apache2/access_full_json.log",
        webhook_url="http://localhost:5000/api/realtime-detect",
        detection_threshold=0.7
    )
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, collector.signal_handler)
    signal.signal(signal.SIGTERM, collector.signal_handler)
    
    try:
        # Bắt đầu monitoring
        collector.start_monitoring()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, stopping...")
        collector.stop_monitoring()
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        collector.stop_monitoring()

if __name__ == "__main__":
    main()

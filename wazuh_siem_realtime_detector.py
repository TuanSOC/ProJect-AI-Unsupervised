#!/usr/bin/env python3
"""
Wazuh SIEM Realtime SQLi Detector
Đọc log từ Wazuh SIEM server và detect SQLi realtime bằng AI
Lưu kết quả vào /var/ossec/logs/ai-engine-sqli dạng JSON
"""

import json
import time
import logging
import threading
import os
import sys
from datetime import datetime
from optimized_sqli_detector import OptimizedSQLIDetector
import signal
import re

# Setup logging
import platform
_log_file = '/var/log/wazuh_siem_sqli_detector.log' if platform.system() != 'Windows' else 'wazuh_siem_sqli_detector.log'
_log_handlers = [logging.StreamHandler()]
try:
    _log_handlers.append(logging.FileHandler(_log_file))
except Exception:
    pass  # Skip file logging if can't create file

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=_log_handlers
)
logger = logging.getLogger(__name__)

# File log phát hiện SQLi cho Wazuh SIEM (JSONL format)
_wazuh_siem_log_lock = threading.Lock()
_wazuh_siem_log_path = os.environ.get(
    'WAZUH_SIEM_SQLI_LOG', 
    '/var/ossec/logs/ai-engine-sqli'
)

def _ensure_wazuh_siem_log_dir():
    """Đảm bảo thư mục logs tồn tại"""
    try:
        dirn = os.path.dirname(_wazuh_siem_log_path)
        if dirn:
            os.makedirs(dirn, exist_ok=True, mode=0o755)
    except Exception as e:
        logger.warning(f"Khong the tao thu muc log: {e}")

def _rotate_wazuh_siem_log_if_needed(max_bytes: int = 10 * 1024 * 1024, backups: int = 3):
    """Rotate file log khi quá 10MB"""
    try:
        if not os.path.exists(_wazuh_siem_log_path):
            return
        size = os.path.getsize(_wazuh_siem_log_path)
        if size < max_bytes:
            return
        # Rotate: ai-engine-sqli -> ai-engine-sqli.1 -> ... up to backups
        for i in range(backups, 0, -1):
            src = f"{_wazuh_siem_log_path}.{i}" if i > 0 else _wazuh_siem_log_path
            dst = f"{_wazuh_siem_log_path}.{i+1}"
            if os.path.exists(src):
                if i == backups:
                    try:
                        os.remove(src)
                    except Exception:
                        pass
                else:
                    try:
                        os.replace(src, dst)
                    except Exception:
                        pass
        # Finally rotate current to .1
        try:
            os.replace(_wazuh_siem_log_path, f"{_wazuh_siem_log_path}.1")
        except Exception:
            pass
    except Exception:
        pass

def _append_wazuh_siem_detection_jsonl(entry: dict) -> None:
    """Ghi 1 dòng JSONL về phát hiện SQLi cho Wazuh SIEM (thread-safe, best-effort)."""
    try:
        _ensure_wazuh_siem_log_dir()
        line = json.dumps(entry, ensure_ascii=False)
        with _wazuh_siem_log_lock:
            _rotate_wazuh_siem_log_if_needed()
            with open(_wazuh_siem_log_path, 'a', encoding='utf-8') as f:
                f.write(line + "\n")
    except Exception as e:
        logger.error(f"Loi khi ghi log Wazuh SIEM: {e}")

class WazuhSIEMRealtimeDetector:
    """Detect SQLi realtime từ log Wazuh SIEM"""
    
    def __init__(self, log_path="/opt/ai/apache_access.log", 
                 detection_threshold=None,
                 wazuh_log_path=None):
        self.log_path = log_path
        self.detection_threshold = detection_threshold
        self.detector = None
        self.running = False
        
        # Wazuh log path (có thể override)
        if wazuh_log_path:
            global _wazuh_siem_log_path
            _wazuh_siem_log_path = wazuh_log_path
        
        # Statistics
        self.stats = {
            'total_logs': 0,
            'sqli_detected': 0,
            'errors': 0,
            'start_time': datetime.now()
        }
        
        # Load AI model
        self._load_ai_model()
    
    def _load_ai_model(self):
        """Load AI model"""
        try:
            # Tìm model path (có thể ở nhiều vị trí)
            model_paths = [
                'models/optimized_sqli_detector.pkl',
                '/opt/ai/models/optimized_sqli_detector.pkl',
                os.path.join(os.path.dirname(__file__), 'models', 'optimized_sqli_detector.pkl')
            ]
            
            model_path = None
            for path in model_paths:
                if os.path.exists(path):
                    model_path = path
                    break
            
            if not model_path:
                logger.error("Khong tim thay model file!")
                self.detector = None
                return
            
            self.detector = OptimizedSQLIDetector()
            self.detector.load_model(model_path)
            logger.info(f"AI Model loaded successfully from {model_path}!")
        except Exception as e:
            logger.error(f"Failed to load AI model: {e}")
            self.detector = None
    
    def _parse_wazuh_log(self, line):
        """Parse log line từ Wazuh format JSON"""
        try:
            # Parse JSON
            wazuh_log = json.loads(line.strip())
            
            # Extract log entry từ full_log (nested JSON string) hoặc data
            log_entry = None
            
            # Thử parse từ full_log (nested JSON string)
            if 'full_log' in wazuh_log:
                try:
                    full_log_str = wazuh_log['full_log']
                    if isinstance(full_log_str, str):
                        full_log_data = json.loads(full_log_str)
                        log_entry = self._extract_log_entry_from_wazuh(full_log_data, wazuh_log)
                    elif isinstance(full_log_str, dict):
                        log_entry = self._extract_log_entry_from_wazuh(full_log_str, wazuh_log)
                except Exception as e:
                    logger.debug(f"Khong the parse full_log: {e}")
            
            # Nếu không có full_log, thử dùng data field
            if not log_entry and 'data' in wazuh_log:
                log_entry = self._extract_log_entry_from_wazuh(wazuh_log['data'], wazuh_log)
            
            # Thêm metadata từ Wazuh
            if log_entry:
                log_entry['wazuh_timestamp'] = wazuh_log.get('timestamp', '')
                log_entry['wazuh_agent_id'] = wazuh_log.get('agent', {}).get('id', '')
                log_entry['wazuh_agent_name'] = wazuh_log.get('agent', {}).get('name', '')
                log_entry['wazuh_agent_ip'] = wazuh_log.get('agent', {}).get('ip', '')
                log_entry['wazuh_manager'] = wazuh_log.get('manager', {}).get('name', '')
                log_entry['wazuh_location'] = wazuh_log.get('location', '')
            
            return log_entry
            
        except json.JSONDecodeError as e:
            logger.debug(f"JSON decode error: {e}")
            return None
        except Exception as e:
            logger.debug(f"Parse error: {e}")
            return None
    
    def _extract_log_entry_from_wazuh(self, data, wazuh_log):
        """Extract log entry từ Wazuh data structure"""
        try:
            log_entry = {
                'time': data.get('time', wazuh_log.get('timestamp', datetime.now().isoformat())),
                'remote_ip': data.get('remote_ip', wazuh_log.get('agent', {}).get('ip', '')),
                'method': data.get('method', 'GET'),
                'uri': data.get('uri', ''),
                'query_string': data.get('query_string', ''),
                'status': int(data.get('status', 0) or 0),
                'bytes_sent': int(data.get('bytes_sent', 0) or 0),
                'response_time_ms': int(data.get('response_time_ms', 0) or 0),
                'referer': data.get('referer', ''),
                'user_agent': data.get('user_agent', ''),
                'request_length': int(data.get('request_length', 0) or 0),
                'response_length': int(data.get('response_length', 0) or 0),
                'cookie': data.get('cookie', ''),
                'payload': data.get('payload', ''),
                'body': data.get('body', data.get('payload', '')),
                'session_token': data.get('session_token', '')
            }
            
            # Clean up time field (remove %f placeholder)
            if log_entry['time'] and '%f' in str(log_entry['time']):
                log_entry['time'] = log_entry['time'].replace('%f', '000')
            
            return log_entry
            
        except Exception as e:
            logger.debug(f"Extract error: {e}")
            return None
    
    def detect_sqli_realtime(self, log_entry):
        """Phát hiện SQLi trong log entry realtime với detailed analysis"""
        if not self.detector:
            return None
            
        try:
            # Extract features for detailed analysis
            features = self.detector.extract_optimized_features(log_entry)
            
            # Sử dụng AI model để phát hiện
            is_anomaly, score, patterns, confidence = self.detector.predict_single(log_entry)
            
            # Calculate detailed scores
            detailed_scores = self._calculate_detailed_scores(features)
            
            # Risk assessment
            risk_assessment = self._assess_risk(features, score)
            
            # Final assessment
            final_assessment = self._final_assessment(
                is_anomaly, score, detailed_scores, risk_assessment
            )
            
            # Threat level dựa trên overall_risk từ final_assessment
            overall_risk = final_assessment.get('overall_risk', 'LOW')
            if not is_anomaly:
                threat_level = 'NONE'
            elif overall_risk == 'CRITICAL':
                threat_level = 'CRITICAL'
            elif overall_risk == 'HIGH':
                threat_level = 'HIGH'
            elif overall_risk == 'MEDIUM':
                threat_level = 'MEDIUM'
            else:
                threat_level = 'LOW'
            
            # Build detection result
            detection_result = {
                'is_sqli': is_anomaly,
                'score': float(score),
                'detected_patterns': patterns if isinstance(patterns, list) else [patterns] if patterns else [],
                'confidence': confidence,
                'threat_level': threat_level,
                'detailed_analysis': {
                    'detailed_scores': detailed_scores,
                    'risk_assessment': risk_assessment,
                    'final_assessment': final_assessment
                }
            }
            
            return detection_result
            
        except Exception as e:
            logger.error(f"Error in detect_sqli_realtime: {e}")
            return None
    
    def _calculate_detailed_scores(self, features):
        """Calculate detailed scores từ features"""
        try:
            return {
                'base_scores': {
                    'sqli_patterns': features.get('sqli_patterns', 0),
                    'special_chars': features.get('special_chars', 0),
                    'sql_keywords': features.get('sql_keywords', 0),
                    'quotes': features.get('quotes', 0),
                    'operators': features.get('operators', 0)
                },
                'advanced_scores': {
                    'has_union_select': features.get('has_union_select', 0),
                    'has_information_schema': features.get('has_information_schema', 0),
                    'has_mysql_functions': features.get('has_mysql_functions', 0),
                    'has_boolean_blind': features.get('has_boolean_blind', 0),
                    'has_time_based': features.get('has_time_based', 0),
                    'has_comment_injection': features.get('has_comment_injection', 0)
                },
                'base64_scores': {
                    'base64_sqli_patterns': features.get('base64_sqli_patterns', 0),
                    'has_base64_payload': features.get('has_base64_payload', 0),
                    'has_base64_query': features.get('has_base64_query', 0)
                },
                'nosql_scores': {
                    'has_nosql_patterns': features.get('has_nosql_patterns', 0),
                    'has_nosql_operators': features.get('has_nosql_operators', 0),
                    'has_json_injection': features.get('has_json_injection', 0)
                },
                'cookie_scores': {
                    'cookie_sqli_patterns': features.get('cookie_sqli_patterns', 0),
                    'cookie_special_chars': features.get('cookie_special_chars', 0),
                    'cookie_sql_keywords': features.get('cookie_sql_keywords', 0)
                },
                'total_weighted_score': features.get('sqli_risk_score', 0)
            }
        except Exception:
            return {}
    
    def _assess_risk(self, features, ai_score):
        """Assess risk level từ features và AI score"""
        try:
            risk_score = features.get('sqli_risk_score', 0)
            
            if risk_score >= 100:
                risk_level = 'CRITICAL'
            elif risk_score >= 50:
                risk_level = 'HIGH'
            elif risk_score >= 20:
                risk_level = 'MEDIUM'
            elif risk_score >= 5:
                risk_level = 'LOW'
            else:
                risk_level = 'MINIMAL'
            
            return {
                'risk_score': float(risk_score),
                'risk_level': risk_level,
                'ai_score': float(ai_score)
            }
        except Exception:
            return {'risk_score': 0, 'risk_level': 'MINIMAL', 'ai_score': 0.0}
    
    def _final_assessment(self, is_sqli, ai_score, detailed_scores, risk_assessment):
        """Final assessment dựa trên tất cả thông tin"""
        try:
            risk_level = risk_assessment.get('risk_level', 'MINIMAL')
            
            if is_sqli:
                if risk_level == 'CRITICAL':
                    overall_risk = 'CRITICAL'
                    recommendation = 'IMMEDIATE_BLOCK'
                elif risk_level == 'HIGH':
                    overall_risk = 'HIGH'
                    recommendation = 'BLOCK_AND_INVESTIGATE'
                elif risk_level == 'MEDIUM':
                    overall_risk = 'MEDIUM'
                    recommendation = 'INVESTIGATE'
                else:
                    overall_risk = 'LOW'
                    recommendation = 'MONITOR'
            else:
                overall_risk = 'NONE'
                recommendation = 'ALLOW'
            
            return {
                'overall_risk': overall_risk,
                'recommendation': recommendation
            }
        except Exception:
            return {'overall_risk': 'NONE', 'recommendation': 'ALLOW'}
    
    def save_wazuh_siem_log(self, log_entry, detection_result):
        """Lưu detection log cho Wazuh SIEM (format JSON)"""
        try:
            # Format tương thích với Wazuh SIEM: JSON event
            wazuh_event = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'sqli_detection',
                'source': 'ai_sqli_detector',
                'wazuh_agent': {
                    'id': log_entry.get('wazuh_agent_id', ''),
                    'name': log_entry.get('wazuh_agent_name', ''),
                    'ip': log_entry.get('wazuh_agent_ip', '')
                },
                'wazuh_manager': log_entry.get('wazuh_manager', ''),
                'wazuh_location': log_entry.get('wazuh_location', ''),
                'remote_ip': log_entry.get('remote_ip', 'unknown'),
                'method': log_entry.get('method', ''),
                'uri': log_entry.get('uri', ''),
                'query_string': log_entry.get('query_string', ''),
                'payload': log_entry.get('payload', ''),
                'body': log_entry.get('body', ''),
                'cookie': log_entry.get('cookie', ''),
                'user_agent': log_entry.get('user_agent', ''),
                'status': log_entry.get('status', 0),
                'detected': True,
                'score': float(detection_result.get('score', 0.0)),
                'patterns': detection_result.get('detected_patterns', []) if isinstance(detection_result.get('detected_patterns'), list) else [detection_result.get('detected_patterns', 'N/A')],
                'confidence': detection_result.get('confidence', 'Unknown'),
                'threat_level': detection_result.get('threat_level', 'UNKNOWN'),
                # Thêm thông tin chi tiết cho Wazuh analysis
                'risk_score': detection_result.get('detailed_analysis', {}).get('risk_assessment', {}).get('risk_score', 0),
                'risk_level': detection_result.get('detailed_analysis', {}).get('risk_assessment', {}).get('risk_level', 'UNKNOWN'),
                'recommendation': detection_result.get('detailed_analysis', {}).get('final_assessment', {}).get('recommendation', 'UNKNOWN')
            }
            
            # Ghi vào file Wazuh SIEM log (thread-safe, có rotation)
            _append_wazuh_siem_detection_jsonl(wazuh_event)
            
            logger.info(f"SQLi detected va da luu vao Wazuh SIEM log: {_wazuh_siem_log_path}")
                
        except Exception as e:
            logger.error(f"Error saving Wazuh SIEM log: {e}")
    
    def process_log_line(self, line):
        """Process một dòng log từ Wazuh"""
        try:
            self.stats['total_logs'] += 1
            
            # Parse Wazuh log format
            log_entry = self._parse_wazuh_log(line)
            if not log_entry:
                return
            
            # Skip static resources
            uri_l = str(log_entry.get('uri', '')).lower()
            if any(p in uri_l for p in ['/css/', '/js/', '/images/', '/favicon.ico', '/sitemap.xml']):
                return
            if re.search(r"\.(css|js|png|jpg|jpeg|gif|ico|svg|map|woff2?)$", uri_l):
                return
            
            # Detect SQLi
            detection_result = self.detect_sqli_realtime(log_entry)
            
            # Nếu detect SQLi, lưu vào Wazuh SIEM log
            if detection_result and detection_result['is_sqli']:
                self.stats['sqli_detected'] += 1
                
                # Lưu vào file Wazuh SIEM log
                self.save_wazuh_siem_log(log_entry, detection_result)
                
                # Log chi tiết
                logger.warning(f"SQLi DETECTED!")
                logger.warning(f"   IP: {log_entry.get('remote_ip', 'Unknown')}")
                logger.warning(f"   URI: {log_entry.get('uri', 'Unknown')}")
                logger.warning(f"   Query: {log_entry.get('query_string', 'None')[:100]}")
                logger.warning(f"   Score: {detection_result['score']:.3f}")
                logger.warning(f"   Threat Level: {detection_result['threat_level']}")
                logger.warning(f"   Confidence: {detection_result['confidence']}")
                
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Error processing log line: {e}")
    
    def start_monitoring(self):
        """Bắt đầu monitoring"""
        logger.info("Starting Wazuh SIEM realtime SQLi monitoring...")
        logger.info(f"Monitoring log file: {self.log_path}")
        logger.info(f"Wazuh SIEM detection log: {_wazuh_siem_log_path}")
        logger.info(f"Set WAZUH_SIEM_SQLI_LOG env var to customize log path")
        
        if not self.detector:
            logger.error("AI Model khong duoc load! Khong the tiep tuc.")
            return
        
        if not os.path.exists(self.log_path):
            logger.error(f"Log file khong ton tai: {self.log_path}")
            return
        
        self.running = True
        
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Go to end of file
                f.seek(0, 2)
                
                while self.running:
                    line = f.readline()
                    if line:
                        try:
                            line = line.strip()
                            if line:
                                self.process_log_line(line)
                        except Exception as e:
                            logger.debug(f"Error processing line: {e}")
                    else:
                        time.sleep(0.1)  # Sleep khi không có dòng mới
                        
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, stopping...")
            self.running = False
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            self.running = False
        finally:
            self._print_stats()
    
    def stop_monitoring(self):
        """Dừng monitoring"""
        logger.info("Stopping log monitoring...")
        self.running = False
    
    def _print_stats(self):
        """Print statistics"""
        runtime = (datetime.now() - self.stats['start_time']).total_seconds()
        logger.info("=" * 80)
        logger.info("STATISTICS:")
        logger.info(f"   Total logs processed: {self.stats['total_logs']}")
        logger.info(f"   SQLi detected: {self.stats['sqli_detected']}")
        logger.info(f"   Errors: {self.stats['errors']}")
        logger.info(f"   Runtime: {runtime:.1f} seconds")
        logger.info(f"   Detection rate: {(self.stats['sqli_detected'] / max(1, self.stats['total_logs']) * 100):.2f}%")
        logger.info("=" * 80)

def signal_handler(sig, frame):
    """Handle interrupt signal"""
    logger.info("Received interrupt signal, stopping...")
    sys.exit(0)

def main():
    """Main function"""
    try:
        # Setup signal handler
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Get log path from env or use default
        log_path = os.environ.get('WAZUH_SIEM_LOG_PATH', '/opt/ai/apache_access.log')
        wazuh_log_path = os.environ.get('WAZUH_SIEM_SQLI_LOG', '/var/ossec/logs/ai-engine-sqli')
        
        # Create detector
        detector = WazuhSIEMRealtimeDetector(
            log_path=log_path,
            wazuh_log_path=wazuh_log_path
        )
        
        # Start monitoring
        detector.start_monitoring()
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()


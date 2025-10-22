#!/usr/bin/env python3
"""
Script cải tiến hệ thống dựa trên review
"""

import os
import json
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor
import queue
import logging

class ImprovedSystem:
    """Hệ thống cải tiến với thread-safety và caching"""
    
    def __init__(self):
        self.model_cache = {}
        self.thread_lock = threading.RLock()
        self.detection_queue = queue.Queue(maxsize=1000)
        self.stats_lock = threading.Lock()
        self.performance_stats = {
            'total_logs': 0,
            'sqli_detected': 0,
            'clean_logs': 0,
            'false_positives': 0,
            'detection_rate': 0.0,
            'false_positive_rate': 0.0,
            'avg_processing_time': 0.0
        }
        self.recent_logs = []
        self.recent_all_logs = []
        self.max_recent_logs = 100
        self.max_all_logs = 1000
        
        # Thread pool for concurrent processing
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Setup logging
        self.setup_logging()
    
    def setup_logging(self):
        """Setup improved logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ai_sqli_detection.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_model_cached(self, model_path: str):
        """Load model with caching"""
        with self.thread_lock:
            if model_path in self.model_cache:
                self.logger.info(f"Model loaded from cache: {model_path}")
                return self.model_cache[model_path]
            
            try:
                from optimized_sqli_detector import OptimizedSQLIDetector
                detector = OptimizedSQLIDetector()
                detector.load_model(model_path)
                
                # Cache the model
                self.model_cache[model_path] = detector
                self.logger.info(f"Model loaded and cached: {model_path}")
                return detector
                
            except Exception as e:
                self.logger.error(f"Error loading model: {e}")
                raise
    
    def update_stats_thread_safe(self, is_sqli: bool, processing_time: float):
        """Thread-safe stats update"""
        with self.stats_lock:
            self.performance_stats['total_logs'] += 1
            if is_sqli:
                self.performance_stats['sqli_detected'] += 1
            else:
                self.performance_stats['clean_logs'] += 1
            
            # Update rates
            if self.performance_stats['total_logs'] > 0:
                self.performance_stats['detection_rate'] = (
                    self.performance_stats['sqli_detected'] / 
                    self.performance_stats['total_logs']
                )
                self.performance_stats['false_positive_rate'] = (
                    self.performance_stats['false_positives'] / 
                    self.performance_stats['total_logs']
                )
            
            # Update average processing time
            current_avg = self.performance_stats['avg_processing_time']
            total_logs = self.performance_stats['total_logs']
            self.performance_stats['avg_processing_time'] = (
                (current_avg * (total_logs - 1) + processing_time) / total_logs
            )
    
    def add_log_thread_safe(self, log_entry: Dict[str, Any]):
        """Thread-safe log addition"""
        with self.thread_lock:
            # Add to recent logs
            self.recent_logs.append(log_entry)
            if len(self.recent_logs) > self.max_recent_logs:
                self.recent_logs.pop(0)
            
            # Add to all logs
            self.recent_all_logs.append(log_entry)
            if len(self.recent_all_logs) > self.max_all_logs:
                self.recent_all_logs.pop(0)
    
    def detect_sqli_async(self, log_entry: Dict[str, Any], model_path: str = 'models/optimized_sqli_detector.pkl'):
        """Async SQLi detection"""
        start_time = time.time()
        
        try:
            # Load model (cached)
            detector = self.load_model_cached(model_path)
            
            # Detect SQLi
            is_sqli, score, patterns, confidence = detector.predict_single(log_entry, threshold=0.85)
            
            processing_time = time.time() - start_time
            
            # Update stats
            self.update_stats_thread_safe(is_sqli, processing_time)
            
            # Create result
            result = {
                'timestamp': datetime.now().isoformat(),
                'log': log_entry,
                'detection': {
                    'is_sqli': is_sqli,
                    'score': score,
                    'patterns': patterns,
                    'confidence': confidence,
                    'processing_time': processing_time
                }
            }
            
            # Add to logs
            self.add_log_thread_safe(result)
            
            # Log detection
            if is_sqli:
                self.logger.warning("🚨 SQLi DETECTED!")
                self.logger.warning(f"   IP: {log_entry.get('remote_ip', 'unknown')}")
                self.logger.warning(f"   URI: {log_entry.get('uri', 'unknown')}")
                self.logger.warning(f"   Score: {score:.3f}")
                self.logger.warning(f"   Patterns: {patterns}")
                self.logger.warning(f"   Processing time: {processing_time:.3f}s")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in detection: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'log': log_entry,
                'detection': {
                    'is_sqli': False,
                    'score': 0.0,
                    'patterns': [],
                    'confidence': 'Error',
                    'processing_time': time.time() - start_time,
                    'error': str(e)
                }
            }
    
    def batch_detect_async(self, log_entries: List[Dict[str, Any]], model_path: str = 'models/optimized_sqli_detector.pkl'):
        """Batch async detection"""
        futures = []
        
        for log_entry in log_entries:
            future = self.executor.submit(self.detect_sqli_async, log_entry, model_path)
            futures.append(future)
        
        results = []
        for future in futures:
            try:
                result = future.result(timeout=30)  # 30s timeout
                results.append(result)
            except Exception as e:
                self.logger.error(f"Batch detection error: {e}")
                results.append({
                    'timestamp': datetime.now().isoformat(),
                    'log': {},
                    'detection': {'error': str(e)}
                })
        
        return results
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get thread-safe performance stats"""
        with self.stats_lock:
            return self.performance_stats.copy()
    
    def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent logs thread-safe"""
        with self.thread_lock:
            return self.recent_logs[-limit:] if self.recent_logs else []
    
    def get_recent_all_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all recent logs thread-safe"""
        with self.thread_lock:
            return self.recent_all_logs[-limit:] if self.recent_all_logs else []
    
    def clear_cache(self):
        """Clear model cache"""
        with self.thread_lock:
            self.model_cache.clear()
            self.logger.info("Model cache cleared")
    
    def shutdown(self):
        """Graceful shutdown"""
        self.logger.info("Shutting down improved system...")
        self.executor.shutdown(wait=True)
        self.logger.info("System shutdown complete")

def create_improved_app():
    """Create improved Flask app"""
    from flask import Flask, request, jsonify, render_template
    import threading
    
    app = Flask(__name__)
    improved_system = ImprovedSystem()
    
    @app.route('/')
    def index():
        """Improved dashboard"""
        return render_template('index.html')
    
    @app.route('/api/detect', methods=['POST'])
    def detect_sqli():
        """Improved single detection"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            result = improved_system.detect_sqli_async(data)
            
            return jsonify({
                'is_sqli': result['detection']['is_sqli'],
                'score': result['detection']['score'],
                'patterns': result['detection']['patterns'],
                'confidence': result['detection']['confidence'],
                'processing_time': result['detection']['processing_time'],
                'timestamp': result['timestamp']
            })
            
        except Exception as e:
            improved_system.logger.error(f"Error in detection: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/batch-detect', methods=['POST'])
    def batch_detect():
        """Improved batch detection"""
        try:
            data = request.get_json()
            if not data or 'logs' not in data:
                return jsonify({'error': 'No logs provided'}), 400
            
            results = improved_system.batch_detect_async(data['logs'])
            
            return jsonify({
                'results': results,
                'total_processed': len(results),
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            improved_system.logger.error(f"Error in batch detection: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/performance')
    def get_performance():
        """Get performance stats"""
        try:
            stats = improved_system.get_performance_stats()
            return jsonify(stats)
        except Exception as e:
            improved_system.logger.error(f"Error getting performance: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/logs')
    def get_logs():
        """Get recent logs"""
        try:
            limit = request.args.get('limit', 50, type=int)
            logs = improved_system.get_recent_logs(limit)
            return jsonify(logs)
        except Exception as e:
            improved_system.logger.error(f"Error getting logs: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/clear-cache', methods=['POST'])
    def clear_cache():
        """Clear cache"""
        try:
            improved_system.clear_cache()
            return jsonify({'message': 'Cache cleared successfully'})
        except Exception as e:
            improved_system.logger.error(f"Error clearing cache: {e}")
            return jsonify({'error': str(e)}), 500
    
    return app, improved_system

def main():
    """Main function to test improved system"""
    print("Testing Improved System")
    print("=" * 50)
    
    # Test improved system
    system = ImprovedSystem()
    
    # Test data
    test_logs = [
        {
            "time": "2025-10-22T08:47:41+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/sqli/index.php",
            "query_string": "?id=%27+or+benchmark%2810000000%2CMD5%281%29%29%23&Submit=Submit",
            "status": 200,
            "payload": "id=%27+or+benchmark%2810000000%2CMD5%281%29%29%23&Submit=Submit",
            "user_agent": "Mozilla/5.0",
            "cookie": "PHPSESSID=test"
        },
        {
            "time": "2025-10-22T08:47:41+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/csrf/index.php",
            "query_string": "?id=1&Submit=Submit",
            "status": 200,
            "payload": "id=1&Submit=Submit",
            "user_agent": "Mozilla/5.0",
            "cookie": "PHPSESSID=test"
        }
    ]
    
    print("Testing single detection...")
    result1 = system.detect_sqli_async(test_logs[0])
    print(f"Result 1: {result1['detection']['is_sqli']} (Score: {result1['detection']['score']:.3f})")
    
    print("Testing batch detection...")
    results = system.batch_detect_async(test_logs)
    print(f"Batch results: {len(results)} processed")
    
    print("Testing performance stats...")
    stats = system.get_performance_stats()
    print(f"Stats: {stats}")
    
    print("Testing thread safety...")
    import threading
    import time
    
    def worker():
        for i in range(10):
            log = test_logs[0].copy()
            log['query_string'] = f"?id={i}&test=value"
            result = system.detect_sqli_async(log)
            time.sleep(0.1)
    
    threads = []
    for i in range(5):
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    final_stats = system.get_performance_stats()
    print(f"Final stats: {final_stats}")
    
    system.shutdown()
    print("Improved system test completed!")

if __name__ == "__main__":
    main()

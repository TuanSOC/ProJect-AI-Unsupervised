#!/usr/bin/env python3
"""
Improved AI SQLi Detection Web App
- Thread-safe state management
- Model caching
- Concurrent processing
- Better error handling
- Performance monitoring
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

from flask import Flask, request, jsonify, render_template
from optimized_sqli_detector import OptimizedSQLIDetector

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ai_sqli_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global variables with thread safety
detector = None
model_cache = {}
thread_lock = threading.RLock()
stats_lock = threading.Lock()
performance_stats = {
    'total_logs': 0,
    'sqli_detected': 0,
    'clean_logs': 0,
    'false_positives': 0,
    'detection_rate': 0.0,
    'false_positive_rate': 0.0,
    'avg_processing_time': 0.0
}
recent_logs = []
recent_all_logs = []
max_recent_logs = 100
max_all_logs = 1000

# Thread pool for concurrent processing
executor = ThreadPoolExecutor(max_workers=4)

app = Flask(__name__)

# JSON sanitization for numpy/scalar types
try:
    import numpy as _np  # optional
except Exception:  # pragma: no cover
    _np = None

def _to_serializable(obj):
    """Recursively convert objects to JSON-serializable python natives.
    Handles numpy scalars/arrays, sets/tuples, and nested dict/list structures.
    """
    # Numpy scalars
    if _np is not None:
        if isinstance(obj, (_np.generic,)):
            return obj.item()
        if isinstance(obj, (_np.ndarray,)):
            return obj.tolist()
    # Basic scalars
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    # Dict
    if isinstance(obj, dict):
        return {str(k): _to_serializable(v) for k, v in obj.items()}
    # List/Tuple/Set
    if isinstance(obj, (list, tuple, set)):
        return [_to_serializable(v) for v in obj]
    # Fallback to string
    return str(obj)

def load_model_cached(model_path: str = 'models/optimized_sqli_detector.pkl'):
    """Load model with caching and thread safety"""
    global detector, model_cache
    
    with thread_lock:
        if model_path in model_cache:
            logger.info(f"Model loaded from cache: {model_path}")
            return model_cache[model_path]
        
        try:
            # Check if model file exists
            if not os.path.exists(model_path):
                logger.error(f"Model file not found: {model_path}")
                raise FileNotFoundError(f"Model file not found: {model_path}")
            
            detector = OptimizedSQLIDetector()
            detector.load_model(model_path)
            
            # Cache the model
            model_cache[model_path] = detector
            logger.info(f"Model loaded and cached: {model_path}")
            return detector
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise

def update_stats_thread_safe(is_sqli: bool, processing_time: float):
    """Thread-safe stats update"""
    global performance_stats
    
    with stats_lock:
        performance_stats['total_logs'] += 1
        if is_sqli:
            performance_stats['sqli_detected'] += 1
        else:
            performance_stats['clean_logs'] += 1
        
        # Update rates
        if performance_stats['total_logs'] > 0:
            performance_stats['detection_rate'] = (
                performance_stats['sqli_detected'] / 
                performance_stats['total_logs']
            )
            performance_stats['false_positive_rate'] = (
                performance_stats['false_positives'] / 
                performance_stats['total_logs']
            )
        
        # Update average processing time
        current_avg = performance_stats['avg_processing_time']
        total_logs = performance_stats['total_logs']
        performance_stats['avg_processing_time'] = (
            (current_avg * (total_logs - 1) + processing_time) / total_logs
        )

def add_log_thread_safe(log_entry: Dict[str, Any]):
    """Thread-safe log addition"""
    global recent_logs, recent_all_logs
    
    with thread_lock:
        # Add to recent logs
        recent_logs.append(log_entry)
        if len(recent_logs) > max_recent_logs:
            recent_logs.pop(0)
        
        # Add to all logs
        recent_all_logs.append(log_entry)
        if len(recent_all_logs) > max_all_logs:
            recent_all_logs.pop(0)

def detect_sqli_async(log_entry: Dict[str, Any], model_path: str = 'models/optimized_sqli_detector.pkl'):
    """Async SQLi detection with performance monitoring"""
    start_time = time.time()
    
    try:
        # Load model (cached)
        detector = load_model_cached(model_path)
        
        # Detect SQLi
        is_sqli, score, patterns, confidence = detector.predict_single(log_entry)
        
        processing_time = time.time() - start_time
        
        # Update stats
        update_stats_thread_safe(is_sqli, processing_time)
        
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

        # Sanitize result for JSON/log storage
        safe_result = _to_serializable(result)

        # Add to logs
        add_log_thread_safe(safe_result)
        
        # Log detection
        if is_sqli:
            logger.warning("🚨 SQLi DETECTED!")
            logger.warning(f"   IP: {log_entry.get('remote_ip', 'unknown')}")
            logger.warning(f"   URI: {log_entry.get('uri', 'unknown')}")
            logger.warning(f"   Score: {score:.3f}")
            logger.warning(f"   Patterns: {patterns}")
            logger.warning(f"   Processing time: {processing_time:.3f}s")
        
        return safe_result
        
    except Exception as e:
        logger.error(f"Error in detection: {e}")
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

@app.route('/')
def index():
    """Main dashboard"""
    try:
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error loading template: {e}")
        return f"""
        <html>
        <head><title>AI SQLi Detection</title></head>
        <body>
            <h1>AI SQLi Detection System</h1>
            <p>Template not found. Please check templates/index.html</p>
            <p>Error: {e}</p>
            <h2>API Endpoints:</h2>
            <ul>
                <li>POST /api/detect - Test SQLi detection</li>
                <li>GET /api/performance - Get performance stats</li>
                <li>GET /api/logs - Get recent logs</li>
                <li>GET /api/patterns - Get pattern analysis</li>
            </ul>
        </body>
        </html>
        """, 200

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Check if model is loaded
        model_status = "loaded" if detector is not None else "not loaded"
        
        return jsonify({
            'status': 'healthy',
            'model_status': model_status,
            'timestamp': datetime.now().isoformat(),
            'version': '2.0'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/detect', methods=['POST'])
def detect_sqli():
    """Improved single detection with async processing"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Ensure detector is loaded
        if detector is None:
            load_model_cached()
        
        # Process detection
        result = detect_sqli_async(data)
        
        return jsonify({
            'is_sqli': result['detection']['is_sqli'],
            'score': result['detection']['score'],
            'patterns': result['detection']['patterns'],
            'confidence': result['detection']['confidence'],
            'processing_time': result['detection']['processing_time'],
            'timestamp': result['timestamp']
        })
        
    except Exception as e:
        logger.error(f"Error in detection: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/batch-detect', methods=['POST'])
def batch_detect():
    """Improved batch detection with concurrent processing"""
    try:
        data = request.get_json()
        if not data or 'logs' not in data:
            return jsonify({'error': 'No logs provided'}), 400
        
        # Process batch detection
        futures = []
        for log_entry in data['logs']:
            future = executor.submit(detect_sqli_async, log_entry)
            futures.append(future)
        
        results = []
        for future in futures:
            try:
                result = future.result(timeout=30)  # 30s timeout
                results.append(result)
            except Exception as e:
                logger.error(f"Batch detection error: {e}")
                results.append({
                    'timestamp': datetime.now().isoformat(),
                    'log': {},
                    'detection': {'error': str(e)}
                })
        
        return jsonify({
            'results': results,
            'total_processed': len(results),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in batch detection: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/performance')
def get_performance():
    """Get performance statistics with thread safety"""
    try:
        with stats_lock:
            return jsonify(_to_serializable(performance_stats.copy()))
    except Exception as e:
        logger.error(f"Error getting performance: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def get_logs():
    """Get recent threat logs with thread safety"""
    try:
        limit = request.args.get('limit', 50, type=int)
        with thread_lock:
            logs = recent_logs[-limit:] if recent_logs else []
        return jsonify(_to_serializable(logs))
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/patterns')
def get_patterns():
    """Get pattern analysis with improved performance"""
    try:
        with thread_lock:
            if not recent_all_logs:
                return jsonify({'patterns': [], 'message': 'No data available'})
            
            # Analyze patterns from recent logs
            patterns = {}
            for log_entry in recent_all_logs[-100:]:  # Last 100 entries
                detection = log_entry.get('detection', {})
                if detection.get('is_sqli', False):
                    pattern = detection.get('patterns', 'Unknown')
                    if pattern in patterns:
                        patterns[pattern] += 1
                    else:
                        patterns[pattern] = 1
            
            # Sort by frequency
            sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
            
            return jsonify({
                'patterns': sorted_patterns,
                'total_threats': len([log for log in recent_all_logs if log.get('detection', {}).get('is_sqli', False)])
            })
        
    except Exception as e:
        logger.error(f"Error getting patterns: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/clear-cache', methods=['POST'])
def clear_cache():
    """Clear cache and reset statistics"""
    try:
        global model_cache, performance_stats, recent_logs, recent_all_logs
        
        with thread_lock:
            model_cache.clear()
            recent_logs.clear()
            recent_all_logs.clear()
        
        with stats_lock:
            performance_stats = {
                'total_logs': 0,
                'sqli_detected': 0,
                'clean_logs': 0,
                'false_positives': 0,
                'detection_rate': 0.0,
                'false_positive_rate': 0.0,
                'avg_processing_time': 0.0
            }
        
        logger.info("Cache cleared and statistics reset")
        return jsonify({'message': 'Cache cleared successfully'})
        
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/realtime-detect', methods=['GET', 'POST'])
def realtime_detect():
    """Realtime detection endpoint with improved handling"""
    if request.method == 'GET':
        return jsonify({'status': 'Realtime detection endpoint active'})
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract log and detection data
        log_entry = data.get('log', {})
        detection = data.get('detection', {})
        
        # Process detection
        result = detect_sqli_async(log_entry)
        
        return jsonify({
            'status': 'success',
            'message': 'Detection processed',
            'is_sqli': result['detection']['is_sqli'],
            'score': result['detection']['score'],
            'patterns': result['detection']['patterns'],
            'confidence': result['detection']['confidence']
        })
        
    except Exception as e:
        logger.error(f"Error in realtime detection: {e}")
        return jsonify({'error': str(e)}), 500

def shutdown_handler():
    """Graceful shutdown handler"""
    logger.info("Shutting down application...")
    executor.shutdown(wait=True)
    logger.info("Application shutdown complete")

if __name__ == '__main__':
    try:
        # Load AI model
        load_model_cached()
        
        # Start Flask app
        logger.info("🚀 Starting Improved AI SQLi Detection Web App...")
        logger.info("🌐 Access: http://localhost:5000")
        logger.info("📊 Features: Thread-safe, Cached, Concurrent processing")
        
        app.run(debug=False, host='0.0.0.0', port=5000)
        
    except Exception as e:
        logger.error(f"❌ Failed to start app: {e}")
    finally:
        shutdown_handler()

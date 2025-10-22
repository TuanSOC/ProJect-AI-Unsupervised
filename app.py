#!/usr/bin/env python3
"""
AI SQL Injection Detection Web Application - Simplified Version
"""

from flask import Flask, render_template, request, jsonify
import json
import logging
from datetime import datetime
from optimized_sqli_detector import OptimizedSQLIDetector

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)

# Global variables
detector = None
performance_stats = {
    'total_logs': 0,
    'sqli_detected': 0,
    'clean_logs': 0,
    'false_positives': 0,
    'detection_rate': 0.0,
    'false_positive_rate': 0.0
}
recent_logs = []  # Store recent analyzed SQLi logs (threats only)
recent_all_logs = []  # Store recent analyzed ALL logs (for dashboard/patterns)

def clear_cache():
    """Clear all cached data"""
    global recent_logs, recent_all_logs, performance_stats
    
    # Clear recent logs completely
    if 'recent_logs' in globals() and recent_logs:
        recent_logs.clear()
    if 'recent_all_logs' in globals() and recent_all_logs:
        recent_all_logs.clear()
    
    # Reset performance_stats completely
    performance_stats.update({
        'total_logs': 0,
        'sqli_detected': 0,
        'clean_logs': 0,
        'false_positives': 0,
        'detection_rate': 0.0,
        'false_positive_rate': 0.0
    })
    
    logger.info("Cache cleared completely - fresh session")

def load_detector():
    """Load AI detector"""
    global detector
    try:
        detector = OptimizedSQLIDetector()
        detector.load_model('models/optimized_sqli_detector.pkl')
        logger.info("✅ AI Model loaded successfully!")
    except Exception as e:
        logger.error(f"❌ Error loading AI model: {e}")
        raise

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/clear-cache', methods=['POST'])
def clear_cache_endpoint():
    """Clear cache endpoint"""
    try:
        clear_cache()
        return jsonify({'message': 'Cache cleared successfully'})
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/detect', methods=['POST'])
def detect_sqli():
    """Detect SQLi in single log entry"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Ensure detector is loaded
        if detector is None:
            load_detector()
        
        # Analyze log entry
        is_sqli, score, patterns, confidence = detector.predict_single(data, threshold=0.85)
        
        # Update statistics
        performance_stats['total_logs'] += 1
        if is_sqli:
            performance_stats['sqli_detected'] += 1
            # Add to recent logs
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'log': data,
                'detection': {
                    'is_sqli': is_sqli,
                    'score': score,
                    'confidence': confidence,
                    'patterns': patterns
                }
            }
            recent_logs.append(log_entry)
            # Keep only last 100 entries
            if len(recent_logs) > 100:
                recent_logs.pop(0)
        else:
            performance_stats['clean_logs'] += 1
        
        # Calculate rates
        if performance_stats['total_logs'] > 0:
            performance_stats['detection_rate'] = performance_stats['sqli_detected'] / performance_stats['total_logs']
            performance_stats['false_positive_rate'] = performance_stats['false_positives'] / performance_stats['total_logs']
        
        # Add to recent all logs
        all_log_entry = {
            'timestamp': datetime.now().isoformat(),
            'log': data,
            'detection': {
                'is_sqli': is_sqli,
                'score': score,
                'confidence': confidence,
                'patterns': patterns
            }
        }
        recent_all_logs.append(all_log_entry)
        if len(recent_all_logs) > 1000:
            recent_all_logs.pop(0)
        
        return jsonify({
            'is_sqli': is_sqli,
            'score': score,
            'patterns': patterns,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in detection: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/realtime-detect', methods=['GET', 'POST'])
def realtime_detect():
    """Realtime detection endpoint"""
    global recent_logs, recent_all_logs, performance_stats
    
    if request.method == 'GET':
        return jsonify({'status': 'Realtime detection endpoint active'})
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract log and detection data
        log_entry = data.get('log', {})
        detection = data.get('detection', {})
        
        # Add to recent logs
        recent_logs.append(data)
        recent_all_logs.append(data)
        
        # Keep only last 100 entries
        if len(recent_logs) > 100:
            recent_logs.pop(0)
        if len(recent_all_logs) > 1000:
            recent_all_logs.pop(0)
        
        # Update statistics
        performance_stats['total_logs'] += 1
        if detection.get('is_sqli', False):
            performance_stats['sqli_detected'] += 1
        else:
            performance_stats['clean_logs'] += 1
        
        # Calculate rates
        if performance_stats['total_logs'] > 0:
            performance_stats['detection_rate'] = performance_stats['sqli_detected'] / performance_stats['total_logs']
            performance_stats['false_positive_rate'] = performance_stats['false_positives'] / performance_stats['total_logs']
        
        logger.warning("🚨 REALTIME SQLi DETECTED!")
        logger.warning(f"   IP: {log_entry.get('remote_ip', 'unknown')}")
        logger.warning(f"   URI: {log_entry.get('uri', 'unknown')}")
        logger.warning(f"   Score: {detection.get('score', 0):.3f}")
        logger.warning(f"   Patterns: {detection.get('patterns', 'N/A')}")
        
        return jsonify({'status': 'success', 'message': 'Detection logged'})
        
    except Exception as e:
        logger.error(f"Error in realtime detection: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/performance')
def get_performance():
    """Get performance statistics"""
    try:
        return jsonify(performance_stats)
    except Exception as e:
        logger.error(f"Error getting performance: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def get_logs():
    """Get recent threat logs"""
    try:
        return jsonify(recent_logs[-50:])  # Return last 50 entries
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/patterns')
def get_patterns():
    """Get pattern analysis"""
    try:
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

if __name__ == '__main__':
    try:
        # Load AI model
        load_detector()
        
        # Start Flask app
        logger.info("🚀 Starting AI SQLi Detection Web App...")
        logger.info("🌐 Access: http://localhost:5000")
        app.run(debug=False, host='0.0.0.0', port=5000)
        
    except Exception as e:
        logger.error(f"❌ Failed to start app: {e}")
        raise
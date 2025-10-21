#!/usr/bin/env python3
"""
AI SQL Injection Detection Web Application
"""

from flask import Flask, render_template, request, jsonify
import json
import os
import logging
from datetime import datetime
from optimized_sqli_detector import OptimizedSQLIDetector
import pandas as pd
from werkzeug.utils import secure_filename
import tempfile
import time

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

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
    
    # Clear recent logs completely (giữ cùng tham chiếu tránh lỗi ngoài ý muốn)
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
    
    # Force garbage collection
    import gc
    gc.collect()
    
    logger.info("Cache cleared completely - fresh session")

# Detection threshold
DETECTION_THRESHOLD = 0.7

def load_detector():
    """Load AI model"""
    global detector
    try:
        if 'OptimizedSQLIDetector' in globals():
            detector = OptimizedSQLIDetector()
            detector.load_model('models/optimized_sqli_detector.pkl')
            logger.info("✅ AI Model loaded successfully!")
            return True
        else:
            logger.error("❌ OptimizedSQLIDetector not available")
            return False
    except Exception as e:
        logger.error(f"❌ Error loading model: {e}")
        return False

def get_text_content(log):
    """Extract text content from log for pattern analysis"""
    return f"{log.get('uri', '')} {log.get('query_string', '')} {log.get('payload', '')} {log.get('user_agent', '')} {log.get('cookie', '')}".lower()

# Function removed - using simplified pattern detection in API endpoints

# Function removed - using inline confidence calculation for consistency

def analyze_single_log(log):
    """Analyze single log entry"""
    try:
        if detector:
            is_anomaly, score = detector.predict_single(log, threshold=0.85)  # Use default threshold
        else:
            # Fallback if detector not available
            is_anomaly, score = False, 0.0
        
        return {
            'is_sqli': bool(is_anomaly),
            'score': float(score),
            'confidence': 'High' if abs(score) > 0.8 else 'Medium' if abs(score) > 0.6 else 'Low',
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        logger.warning(f"Error analyzing log: {e}")
        return {
            'is_sqli': False,
            'score': 0.0,
            'confidence': 'Unknown',
            'detected_patterns': [],
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }

def analyze_logs():
    """Analyze logs and update performance stats"""
    global performance_stats
    
    try:
        if not detector:
            return performance_stats
        
        # Use recent_all_logs if available; otherwise show empty metrics (no implicit fallback)
        if 'recent_all_logs' in globals() and recent_all_logs:
            logs = [log_data['log'] for log_data in recent_all_logs]
            logger.info(f"Using recent_all_logs for dashboard: {len(logs)} logs")
        else:
            logger.info("No recent logs available for dashboard; returning empty metrics")
            return performance_stats
        
        if not logs:
            return performance_stats
        
        # Analyze logs with AI model (unsupervised learning) - SAME LOGIC AS FILE ANALYSIS
        detected = 0
        false_positives = 0
        
        for i, log in enumerate(logs):
            try:
                # Use AI Isolation Forest for detection
                is_anomaly, score = detector.predict_single(log, threshold=DETECTION_THRESHOLD)
                
                if bool(is_anomaly):
                    detected += 1
                    # FP chỉ tính khi có ground truth 'label' trong log
                    # Ví dụ: label in {'clean', 0}
                    label = log.get('label')
                    if label is not None:
                        if str(label).lower() in {'clean', '0', 'false', 'normal'} or label == 0:
                            false_positives += 1
                        
            except Exception as e:
                logger.warning(f"Error processing log {i}: {e}")
                continue
        
        # Update performance stats
        performance_stats = {
            'total_logs': len(logs),
            'sqli_detected': detected,
            'clean_logs': len(logs) - detected,
            'false_positives': false_positives,
            'detection_rate': (detected / len(logs)) * 100 if len(logs) > 0 else 0,
            'false_positive_rate': (false_positives / (len(logs) - detected)) * 100 if (len(logs) - detected) > 0 else 0
        }
        
        return performance_stats
        
    except Exception as e:
        logger.error(f"Error analyzing logs: {e}")
        return performance_stats

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    return jsonify({'error': 'File too large. Maximum size is 100MB.'}), 413

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/performance')
def get_performance():
    """Get performance statistics"""
    try:
        stats = analyze_logs()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting performance stats: {e}")
        # Return default performance stats if error occurs
        default_stats = {
            'total_logs': 0,
            'sqli_detected': 0,
            'clean_logs': 0,
            'false_positives': 0,
            'detection_rate': 0.0,
            'false_positive_rate': 0.0
        }
        return jsonify(default_stats)

@app.route('/api/detect', methods=['POST'])
def detect_sqli():
    """Detect SQLi in single log entry"""
    try:
        if not detector:
            return jsonify({'error': 'Model not loaded'}), 500
        
        log_entry = request.json
        if not log_entry:
            return jsonify({'error': 'No log data provided'}), 400
        
        # Use detector directly for consistency
        if detector:
            is_anomaly, score = detector.predict_single(log_entry, threshold=0.85)
        else:
            # Fallback if detector not available
            is_anomaly, score = False, 0.0
        result = {
            'log': log_entry,
            'timestamp': log_entry.get('time', datetime.now().isoformat()),
            'is_sqli': bool(is_anomaly),
            'score': float(score),
            'confidence': 'High' if abs(score) > 0.8 else 'Medium' if abs(score) > 0.6 else 'Low',
            'threat_level': 'CRITICAL' if is_anomaly else 'NONE',
            'detection_method': 'AI Isolation Forest'
        }
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in detection: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def get_logs():
    """Get recent logs with detection results"""
    try:
        if not detector:
            return jsonify({'error': 'Model not loaded'}), 500
        
        # Return recent SQLi logs if available, otherwise return empty
        if 'recent_logs' in globals() and recent_logs:
            return jsonify(recent_logs)
        
        # No logs available - return empty array
        return jsonify([])
        
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/patterns')
def get_patterns():
    """Get SQLi pattern statistics"""
    try:
        # Prefer recently analyzed ALL logs; if none, return zeros (do not read local sample)
        if 'recent_all_logs' in globals() and recent_all_logs:
            logs = [log_data['log'] for log_data in recent_all_logs]
        else:
            return jsonify({
                'Union-based': 0,
                'Boolean-based': 0,
                'Time-based': 0,
                'Information Schema': 0,
                'Comment Injection': 0
            })
        
        pattern_stats = {
            'Union-based': 0,
            'Boolean-based': 0,
            'Time-based': 0,
            'Information Schema': 0,
            'Comment Injection': 0
        }
        
        for log in logs:
            try:
                text_content = get_text_content(log)
                # Count each pattern type only once per log
                if 'union' in text_content and 'select' in text_content:
                    pattern_stats['Union-based'] += 1
                elif any(pattern in text_content for pattern in ['or 1=1', 'and 1=1']):
                    pattern_stats['Boolean-based'] += 1
                elif any(func in text_content for func in ['sleep(', 'waitfor', 'benchmark']):
                    pattern_stats['Time-based'] += 1
                elif 'information_schema' in text_content:
                    pattern_stats['Information Schema'] += 1
                elif any(comment in text_content for comment in ['--', '/*', '*/']):
                    pattern_stats['Comment Injection'] += 1
            except Exception as e:
                logger.warning(f"Error processing log for patterns: {e}")
                continue
        
        return jsonify(pattern_stats)
        
    except Exception as e:
        logger.error(f"Error getting patterns: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload and analyze log file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not detector:
            return jsonify({'error': 'Model not loaded'}), 500
        
        # Save uploaded file
        filename = secure_filename(file.filename) if file.filename else 'uploaded_file'
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analyze file
        try:
            results = analyze_uploaded_file(filepath)
        except Exception as e:
            logger.error(f"Error analyzing uploaded file: {e}")
            results = {'error': str(e)}
        
        # Clean up uploaded file
        os.remove(filepath)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/batch-detect', methods=['POST'])
def batch_detect():
    """Batch detect SQLi in multiple log entries"""
    try:
        if not detector:
            return jsonify({'error': 'Model not loaded'}), 500
        
        data = request.json
        logs = data.get('logs', [])
        
        if not logs:
            return jsonify({'error': 'No logs provided'}), 400
        
        results = []
        sqli_count = 0
        
        for i, log in enumerate(logs):
            try:
                # Use detector directly for consistency
                if detector:
                    try:
                        is_anomaly, score = detector.predict_single(log, threshold=0.85)
                    except Exception as e:
                        logger.warning(f"Error in detector prediction for log {i}: {e}")
                        is_anomaly, score = False, 0.0
                else:
                    # Fallback if detector not available
                    is_anomaly, score = False, 0.0
                result = {
                    'log': log,
                    'timestamp': log.get('time', datetime.now().isoformat()),
                    'is_sqli': bool(is_anomaly),
                    'score': float(score),
                    'confidence': 'High' if abs(score) > 0.8 else 'Medium' if abs(score) > 0.6 else 'Low',
                    'threat_level': 'CRITICAL' if is_anomaly else 'NONE',
                    'detection_method': 'AI Isolation Forest'
                }
                result['index'] = i
                
                if result['is_sqli']:
                    sqli_count += 1
                
                results.append(result)
            except Exception as e:
                logger.error(f"Error analyzing log {i}: {e}")
                results.append({
                    'index': i,
                    'log': log,
                    'is_sqli': False,
                    'score': 0.0,
                    'confidence': 'Unknown',
                    'threat_level': 'NONE',
                    'detection_method': 'Error Fallback'
                })
        
        return jsonify({
            'total_logs': len(logs),
            'sqli_detected': sqli_count,
            'detection_rate': (sqli_count / len(logs)) * 100,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error in batch detection: {e}")
        return jsonify({'error': str(e)}), 500


def analyze_uploaded_file(filepath):
    """Analyze uploaded log file - Ultra-optimized with streaming processing"""
    try:
        import time
        start_time = time.time()
        
        # Load all logs for AI analysis (SAME LOGIC AS DASHBOARD)
        logs = []
        total_logs = 0
        
        logger.info("Loading logs for AI analysis...")
        
        # Try to read as JSONL first
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if line.strip():
                        try:
                            log = json.loads(line.strip())
                            if isinstance(log, dict):  # Ensure it's a valid log object
                                logs.append(log)
                                total_logs += 1
                                
                                # Progress update every 1000 logs
                                if total_logs % 1000 == 0:
                                    logger.info(f"Loaded {total_logs} logs...")
                            else:
                                logger.warning(f"Invalid log format at line {line_num}: {log}")
                                
                        except json.JSONDecodeError as e:
                            logger.warning(f"JSON decode error at line {line_num}: {e}")
                            continue
        except:
            # If not JSONL, try CSV
            try:
                import pandas as pd
                df = pd.read_csv(filepath)
                logs = df.to_dict('records')
                total_logs = len(logs)
                logger.info(f"Loaded {total_logs} logs from CSV")
            except Exception as e:
                logger.error(f"Error reading CSV file: {e}")
                return {'error': 'Unsupported file format'}
        
        if total_logs == 0:
            return {'error': 'No valid logs found'}
        
        logger.info(f"Loaded {total_logs} logs for AI analysis")
        
        # Process SQLi logs with AI Isolation Forest (unsupervised learning)
        results = []
        sqli_count = 0
        
        # Ensure results is initialized
        if not results:
            results = []
        
        # Process ALL logs with AI model (SAME LOGIC AS DASHBOARD)
        logger.info(f"Processing {total_logs} logs with AI Isolation Forest...")
        for i, log in enumerate(logs):
            try:
                # AI Isolation Forest analysis
                if detector:
                    is_anomaly, score = detector.predict_single(log, threshold=0.85)  # Use default threshold
                else:
                    # Fallback if detector not available
                    is_anomaly, score = False, 0.0
                
                result = {
                    'index': i,
                    'log': log,
                    'timestamp': log.get('time', datetime.now().isoformat()),
                    'is_sqli': bool(is_anomaly),
                    'score': float(score),
                    'confidence': 'High' if abs(score) > 0.8 else 'Medium' if abs(score) > 0.6 else 'Low',
                    'threat_level': 'CRITICAL' if is_anomaly else 'NONE',
                    'detection_method': 'AI Isolation Forest'
                }
                
                if result['is_sqli']:
                    sqli_count += 1
                
                results.append(result)
            except Exception as e:
                logger.warning(f"Error in AI analysis for log {i}: {e}")
                # Fallback to safe default if AI fails
                result = {
                    'index': i,
                    'log': log,
                    'timestamp': log.get('time', datetime.now().isoformat()),
                    'is_sqli': False,  # Safe default - no false positives
                    'score': 0.0,
                    'confidence': 'Unknown',
                    'threat_level': 'NONE',
                    'detection_method': 'Error Fallback'
                }
                results.append(result)
        
        # Sort results by index to maintain order
        results.sort(key=lambda x: x['index'])
        
        # Store results globally for UI
        global recent_logs, recent_all_logs
        
        # Initialize variables if not exists
        if 'recent_logs' not in globals():
            recent_logs = []
        if 'recent_all_logs' not in globals():
            recent_all_logs = []
        
        sqli_results = [result for result in results if result.get('is_sqli', False)]
        recent_logs = sqli_results[:50]  # Keep only first 50 SQLi threats for quick view
        # Giữ toàn bộ kết quả để dashboard phản ánh đúng tổng số (an toàn cho quy mô vài nghìn bản ghi)
        # Nếu cần giới hạn, có thể cắt ở 2000.
        recent_all_logs = results  # không cắt để đồng bộ với phần Upload
        
        processing_time = time.time() - start_time
        logger.info(f"Analysis complete: {sqli_count} SQLi detected out of {total_logs} logs in {processing_time:.2f}s")
        
        return {
            'total_logs': total_logs,
            'sqli_detected': sqli_count,
            'detection_rate': (sqli_count / total_logs) * 100,
            'processing_time': processing_time,
            'results': results
        }
        
    except Exception as e:
        logger.error(f"Error analyzing uploaded file: {e}")
        return {'error': str(e)}

@app.route('/api/clear-cache', methods=['POST'])
def clear_cache_api():
    """Clear all cached data"""
    try:
        clear_cache()
        return jsonify({'success': True, 'message': 'Cache cleared successfully'})
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/realtime-detect', methods=['POST'])
def realtime_detect():
    """Endpoint để nhận log realtime và phát hiện SQLi"""
    try:
        if not detector:
            return jsonify({'error': 'AI Model not loaded'}), 500
        
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        log_entry = data.get('log')
        detection_result = data.get('detection')
        
        if not log_entry:
            return jsonify({'error': 'No log data provided'}), 400
        
        # Lưu vào recent logs để dashboard hiển thị
        global recent_logs, recent_all_logs
        
        # Initialize variables if not exists
        if 'recent_logs' not in globals():
            recent_logs = []
        if 'recent_all_logs' not in globals():
            recent_all_logs = []
        
        if detection_result and detection_result.get('is_sqli', False):
            # Thêm vào recent SQLi logs
            threat_data = {
                'log': log_entry,
                'timestamp': detection_result.get('timestamp', datetime.now().isoformat()),
                'is_sqli': True,
                'score': detection_result.get('score', 0.0),
                'confidence': detection_result.get('confidence', 'Unknown'),
                'detected_patterns': detection_result.get('detected_patterns', []),
                'threat_level': detection_result.get('threat_level', 'CRITICAL')
            }
            
            # Initialize recent_logs if not exists
            if 'recent_logs' not in globals():
                recent_logs = []
            
            recent_logs.insert(0, threat_data)  # Thêm vào đầu
            recent_logs = recent_logs[:50]  # Giữ tối đa 50 threats
            
            # Initialize recent_all_logs if not exists
            if 'recent_all_logs' not in globals():
                recent_all_logs = []
            
            # Thêm vào recent_all_logs
            all_log_data = {
                'log': log_entry,
                'timestamp': detection_result.get('timestamp', datetime.now().isoformat()),
                'is_sqli': True,
                'score': detection_result.get('score', 0.0),
                'confidence': detection_result.get('confidence', 'Unknown'),
                'detected_patterns': detection_result.get('detected_patterns', []),
                'threat_level': detection_result.get('threat_level', 'CRITICAL')
            }
            # Ensure recent_all_logs is initialized
            if 'recent_all_logs' not in globals():
                recent_all_logs = []
            
            recent_all_logs.insert(0, all_log_data)
            recent_all_logs = recent_all_logs[:200]  # Giữ tối đa 200 logs
            
            logger.warning(f"🚨 REALTIME SQLi DETECTED!")
            logger.warning(f"   IP: {log_entry.get('remote_ip', 'Unknown')}")
            logger.warning(f"   URI: {log_entry.get('uri', 'Unknown')}")
            logger.warning(f"   Score: {detection_result.get('score', 0.0):.3f}")
            logger.warning(f"   Patterns: {detection_result.get('detected_patterns', 'N/A')}")
        
        return jsonify({
            'success': True,
            'message': 'Realtime detection processed',
            'is_sqli': detection_result.get('is_sqli', False) if detection_result else False
        })
        
    except Exception as e:
        logger.error(f"Error in realtime detection: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/realtime-stats')
def realtime_stats():
    """Get realtime detection statistics"""
    try:
        # Initialize variables if not exists
        global recent_all_logs, recent_logs
        if 'recent_all_logs' not in globals():
            recent_all_logs = []
        if 'recent_logs' not in globals():
            recent_logs = []
        
        stats = {
            'total_realtime_logs': len(recent_all_logs) if recent_all_logs else 0,
            'realtime_sqli_detected': len(recent_logs) if recent_logs else 0,
            'recent_threats': recent_logs[:10] if recent_logs else [],  # 10 threats gần nhất
            'last_update': datetime.now().isoformat()
        }
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting realtime stats: {e}")
        return jsonify({'error': str(e)}), 500


# Ensure API responses are not cached by browsers/proxies
@app.after_request
def add_no_cache_headers(response):
    try:
        if request.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
    except Exception:
        pass
    return response

if __name__ == '__main__':
    # Clear cache on startup
    try:
        clear_cache()
    except Exception as e:
        logger.error(f"Error clearing cache on startup: {e}")
    
    # Load AI model
    if load_detector():
        logger.info("🚀 Starting Web Application...")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        logger.error("❌ Failed to load AI model. Exiting...")
else:
    # Load model when imported
    try:
        if 'OptimizedSQLIDetector' in globals():
            load_detector()
        else:
            logger.warning("OptimizedSQLIDetector not available, skipping model load")
    except Exception as e:
        logger.error(f"Error loading detector on import: {e}")

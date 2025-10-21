#!/usr/bin/env python3
"""
Production Robustness Module - Tối ưu hóa
Cải thiện security robustness và system architecture cho production
"""

import logging
import time
import threading
import queue
import hashlib
import hmac
import secrets
import json
import os
from datetime import datetime, timedelta
from collections import deque
import psutil
import gc
import signal
import sys
from typing import Dict, List, Optional, Tuple, Any
import re

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ProductionRobustness:
    """Production robustness và security enhancements - Tối ưu hóa"""
    
    def __init__(self, 
                 max_memory_mb=1024,
                 max_cpu_percent=80,
                 rate_limit_per_minute=1000,
                 max_concurrent_requests=100,
                 security_key=None):
        
        self.max_memory_mb = max_memory_mb
        self.max_cpu_percent = max_cpu_percent
        self.rate_limit_per_minute = rate_limit_per_minute
        self.max_concurrent_requests = max_concurrent_requests
        
        # Security
        self.security_key = security_key or secrets.token_hex(32)
        self.rate_limiter = RateLimiter(rate_limit_per_minute)
        self.security_validator = SecurityValidator()
        
        # Performance monitoring
        self.performance_monitor = PerformanceMonitor()
        self.health_checker = HealthChecker()
        
        # Circuit breaker
        self.circuit_breaker = CircuitBreaker()
        
        # Request queue
        self.request_queue = queue.Queue(maxsize=max_concurrent_requests)
        self.response_queue = queue.Queue(maxsize=max_concurrent_requests)
        
        # Metrics
        self.metrics = {
            'requests_processed': 0,
            'requests_failed': 0,
            'avg_response_time': 0.0,
            'memory_usage': 0.0,
            'cpu_usage': 0.0,
            'error_rate': 0.0
        }
        
        # Error handling
        self.error_handler = ErrorHandler()
        
        # Logging
        self.audit_logger = AuditLogger()
        
    def process_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Xử lý request với production robustness"""
        try:
            # Rate limiting
            if not self.rate_limiter.allow_request():
                return self._create_error_response("Rate limit exceeded", 429)
            
            # Security validation
            if not self.security_validator.validate_request(request_data):
                return self._create_error_response("Security validation failed", 403)
            
            # Circuit breaker check
            if not self.circuit_breaker.allow_request():
                return self._create_error_response("Service temporarily unavailable", 503)
            
            # Performance monitoring
            start_time = time.time()
            
            # Process request - this should be implemented by the calling class
            # For now, return a placeholder result
            result = {'status': 'processed', 'data': request_data}
            
            # Update metrics
            response_time = time.time() - start_time
            self._update_metrics(response_time, success=True)
            
            # Audit logging
            self.audit_logger.log_request(request_data, result, response_time)
            
            return result
            
        except Exception as e:
            # Error handling
            self.error_handler.handle_error(e, request_data)
            self._update_metrics(0, success=False)
            
            return self._create_error_response("Internal server error", 500)
    
    def _process_core_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Core request processing logic"""
        # Implement your core business logic here
        # This is a placeholder
        return {
            'status': 'success',
            'data': request_data,
            'timestamp': datetime.now().isoformat()
        }
    
    def _create_error_response(self, message: str, status_code: int) -> Dict[str, Any]:
        """Tạo error response"""
        return {
            'status': 'error',
            'message': message,
            'status_code': status_code,
            'timestamp': datetime.now().isoformat()
        }
    
    def _update_metrics(self, response_time: float, success: bool):
        """Cập nhật metrics"""
        self.metrics['requests_processed'] += 1
        if not success:
            self.metrics['requests_failed'] += 1
        
        # Update average response time
        total_requests = self.metrics['requests_processed']
        current_avg = self.metrics['avg_response_time']
        self.metrics['avg_response_time'] = (
            (current_avg * (total_requests - 1) + response_time) / total_requests
        )
        
        # Update error rate
        self.metrics['error_rate'] = (
            self.metrics['requests_failed'] / self.metrics['requests_processed']
        )
    
    def get_health_status(self) -> Dict[str, Any]:
        """Lấy health status"""
        try:
            # System metrics
            memory_usage = psutil.virtual_memory().percent
            cpu_usage = psutil.cpu_percent()
            disk_usage = psutil.disk_usage('/').percent
            
            # Application metrics
            app_metrics = self.metrics.copy()
            
            # Health status
            health_status = {
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'system': {
                    'memory_usage': memory_usage,
                    'cpu_usage': cpu_usage,
                    'disk_usage': disk_usage
                },
                'application': app_metrics,
                'circuit_breaker': self.circuit_breaker.get_status(),
                'rate_limiter': self.rate_limiter.get_status()
            }
            
            # Check if unhealthy
            if (memory_usage > self.max_memory_mb or 
                cpu_usage > self.max_cpu_percent or
                app_metrics['error_rate'] > 0.1):
                health_status['status'] = 'unhealthy'
            
            return health_status
            
        except Exception as e:
            logger.error(f"Error getting health status: {e}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def cleanup_resources(self):
        """Cleanup resources"""
        try:
            # Force garbage collection
            gc.collect()
            
            # Clear queues
            while not self.request_queue.empty():
                self.request_queue.get_nowait()
            while not self.response_queue.empty():
                self.response_queue.get_nowait()
            
            logger.info("✅ Resources cleaned up")
            
        except Exception as e:
            logger.error(f"Error cleaning up resources: {e}")

class RateLimiter:
    """Rate limiter để kiểm soát request rate"""
    
    def __init__(self, max_requests_per_minute: int = 1000):
        self.max_requests = max_requests_per_minute
        # Use a reasonable maxlen to avoid memory issues
        self.requests = deque(maxlen=min(max_requests_per_minute, 10000))
        self.lock = threading.Lock()
    
    def allow_request(self) -> bool:
        """Kiểm tra xem có cho phép request không"""
        with self.lock:
            now = time.time()
            
            # Remove old requests
            while self.requests and now - self.requests[0] > 60:
                self.requests.popleft()
            
            # Check if under limit
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Lấy status của rate limiter"""
        with self.lock:
            now = time.time()
            recent_requests = [r for r in self.requests if now - r < 60]
            
            return {
                'current_requests': len(recent_requests),
                'max_requests': self.max_requests,
                'remaining': self.max_requests - len(recent_requests)
            }

class SecurityValidator:
    """Security validator để kiểm tra request security"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.suspicious_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'data:text/html',
            r'<iframe.*?>',
            r'<object.*?>',
            r'<embed.*?>'
        ]
    
    def validate_request(self, request_data: Dict[str, Any]) -> bool:
        """Validate request security"""
        try:
            # Check for suspicious patterns
            for key, value in request_data.items():
                if isinstance(value, str):
                    for pattern in self.suspicious_patterns:
                        if re.search(pattern, value, re.IGNORECASE):
                            logger.warning(f"Suspicious pattern detected in {key}: {pattern}")
                            return False
            
            # Check for SQL injection patterns
            sql_patterns = [
                r'union\s+select',
                r'or\s+1\s*=\s*1',
                r'and\s+1\s*=\s*1',
                r'drop\s+table',
                r'delete\s+from',
                r'insert\s+into',
                r'update\s+set'
            ]
            
            for key, value in request_data.items():
                if isinstance(value, str):
                    for pattern in sql_patterns:
                        if re.search(pattern, value, re.IGNORECASE):
                            logger.warning(f"SQL injection pattern detected in {key}: {pattern}")
                            return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating request: {e}")
            return False

class CircuitBreaker:
    """Circuit breaker để bảo vệ hệ thống"""
    
    def __init__(self, 
                 failure_threshold: int = 5,
                 recovery_timeout: int = 60,
                 success_threshold: int = 3):
        
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold
        
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
    
    def allow_request(self) -> bool:
        """Kiểm tra xem có cho phép request không"""
        if self.state == 'CLOSED':
            return True
        elif self.state == 'OPEN':
            if (self.last_failure_time is not None and 
                time.time() - self.last_failure_time > self.recovery_timeout):
                self.state = 'HALF_OPEN'
                return True
            return False
        elif self.state == 'HALF_OPEN':
            return True
        
        return False
    
    def record_success(self):
        """Ghi nhận success"""
        if self.state == 'HALF_OPEN':
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                self.state = 'CLOSED'
                self.failure_count = 0
                self.success_count = 0
    
    def record_failure(self):
        """Ghi nhận failure"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = 'OPEN'
    
    def get_status(self) -> Dict[str, Any]:
        """Lấy status của circuit breaker"""
        return {
            'state': self.state,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'last_failure_time': self.last_failure_time
        }

class PerformanceMonitor:
    """Performance monitor để theo dõi hiệu suất"""
    
    def __init__(self):
        self.metrics_history = deque(maxlen=1000)
        self.alert_thresholds = {
            'memory_usage': 80.0,
            'cpu_usage': 80.0,
            'response_time': 5.0,
            'error_rate': 0.1
        }
    
    def monitor_metrics(self):
        """Monitor system metrics"""
        try:
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'memory_usage': psutil.virtual_memory().percent,
                'cpu_usage': psutil.cpu_percent(),
                'disk_usage': psutil.disk_usage('/').percent
            }
            
            self.metrics_history.append(metrics)
            
            # Check for alerts
            self._check_alerts(metrics)
            
        except Exception as e:
            logger.error(f"Error monitoring metrics: {e}")
    
    def _check_alerts(self, metrics: Dict[str, Any]):
        """Kiểm tra alerts"""
        for metric, threshold in self.alert_thresholds.items():
            if metric in metrics and metrics[metric] > threshold:
                logger.warning(f"ALERT: {metric} exceeded threshold ({metrics[metric]} > {threshold})")

class HealthChecker:
    """Health checker để kiểm tra health của hệ thống"""
    
    def __init__(self):
        self.health_checks = []
        self.last_check_time = None
    
    def add_health_check(self, name: str, check_func):
        """Thêm health check"""
        self.health_checks.append({
            'name': name,
            'function': check_func
        })
    
    def run_health_checks(self) -> Dict[str, Any]:
        """Chạy health checks"""
        results = {}
        
        for check in self.health_checks:
            try:
                result = check['function']()
                results[check['name']] = {
                    'status': 'healthy' if result else 'unhealthy',
                    'result': result
                }
            except Exception as e:
                results[check['name']] = {
                    'status': 'error',
                    'error': str(e)
                }
        
        self.last_check_time = datetime.now()
        return results

class ErrorHandler:
    """Error handler để xử lý errors"""
    
    def __init__(self):
        self.error_counts = {}
        self.error_history = deque(maxlen=1000)
    
    def handle_error(self, error: Exception, context: Dict[str, Any] = None):
        """Xử lý error"""
        try:
            error_type = type(error).__name__
            error_message = str(error)
            
            # Count errors
            self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
            
            # Log error
            error_record = {
                'timestamp': datetime.now().isoformat(),
                'error_type': error_type,
                'error_message': error_message,
                'context': context
            }
            self.error_history.append(error_record)
            
            # Log to file
            logger.error(f"Error: {error_type} - {error_message}")
            
        except Exception as e:
            logger.error(f"Error handling error: {e}")

class AuditLogger:
    """Audit logger để ghi log audit"""
    
    def __init__(self, log_file: str = 'audit.log'):
        self.log_file = log_file
        self.audit_entries = deque(maxlen=10000)
    
    def log_request(self, request: Dict[str, Any], response: Dict[str, Any], response_time: float):
        """Log request và response"""
        try:
            audit_entry = {
                'timestamp': datetime.now().isoformat(),
                'request': request,
                'response': response,
                'response_time': response_time,
                'user_ip': request.get('remote_ip', 'unknown'),
                'user_agent': request.get('user_agent', 'unknown')
            }
            
            self.audit_entries.append(audit_entry)
            
            # Write to file
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(audit_entry) + '\n')
                
        except Exception as e:
            logger.error(f"Error logging audit: {e}")

def test_production_robustness():
    """Test production robustness"""
    print("🧪 Testing Production Robustness")
    print("=" * 50)
    
    # Tạo production robustness
    robustness = ProductionRobustness(
        max_memory_mb=512,
        max_cpu_percent=70,
        rate_limit_per_minute=100,
        max_concurrent_requests=50
    )
    
    # Test normal request
    print("\n📊 Testing normal request")
    request_data = {
        'uri': '/test',
        'method': 'GET',
        'remote_ip': '192.168.1.100',
        'user_agent': 'Mozilla/5.0...'
    }
    
    response = robustness.process_request(request_data)
    print(f"   Response: {response['status']}")
    
    # Test rate limiting
    print("\n📊 Testing rate limiting")
    for i in range(105):  # Exceed rate limit
        response = robustness.process_request(request_data)
        if response['status'] == 'error':
            print(f"   Rate limited at request {i+1}")
            break
    
    # Test health status
    print("\n📊 Testing health status")
    health = robustness.get_health_status()
    print(f"   Status: {health['status']}")
    print(f"   Memory: {health['system']['memory_usage']:.1f}%")
    print(f"   CPU: {health['system']['cpu_usage']:.1f}%")
    
    # Test circuit breaker
    print("\n📊 Testing circuit breaker")
    for i in range(10):
        robustness.circuit_breaker.record_failure()
    
    response = robustness.process_request(request_data)
    print(f"   Circuit breaker response: {response['status']}")
    
    print("\n✅ Production robustness test completed!")

if __name__ == "__main__":
    test_production_robustness()

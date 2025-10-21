#!/usr/bin/env python3
"""
Model Drift Detection Module - Tối ưu hóa
Phát hiện drift trong dữ liệu và model performance theo thời gian
"""

import numpy as np
import logging
from datetime import datetime, timedelta
from collections import deque

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ModelDriftDetector:
    """Phát hiện drift trong model và dữ liệu - Tối ưu hóa"""
    
    def __init__(self, window_size=1000, drift_threshold=0.1, min_samples=100):
        self.window_size = window_size
        self.drift_threshold = drift_threshold
        self.min_samples = min_samples
        
        # Baseline data
        self.baseline_features = None
        self.baseline_scores = None
        
        # Rolling window
        self.feature_window = deque(maxlen=window_size)
        self.score_window = deque(maxlen=window_size)
        
        # Drift history
        self.drift_history = []
        
    def set_baseline(self, features, scores):
        """Thiết lập baseline cho drift detection"""
        try:
            self.baseline_features = np.array(features)
            self.baseline_scores = np.array(scores)
            logger.info(f"✅ Baseline established with {len(features)} samples")
            return True
        except Exception as e:
            logger.error(f"❌ Error setting baseline: {e}")
            return False
    
    def calculate_kl_divergence(self, p, q, bins=50):
        """Tính KL Divergence giữa hai phân phối"""
        try:
            if len(p) == 0 or len(q) == 0:
                return 0.0
            
            min_val = min(np.min(p), np.min(q))
            max_val = max(np.max(p), np.max(q))
            
            if min_val == max_val:
                return 0.0
            
            bin_edges = np.linspace(min_val, max_val, bins + 1)
            
            # Tính histogram
            p_hist, _ = np.histogram(p, bins=bin_edges, density=True)
            q_hist, _ = np.histogram(q, bins=bin_edges, density=True)
            
            # Thêm epsilon để tránh log(0)
            epsilon = 1e-10
            p_hist = p_hist + epsilon
            q_hist = q_hist + epsilon
            
            # Normalize
            p_hist = p_hist / np.sum(p_hist)
            q_hist = q_hist / np.sum(q_hist)
            
            # Tính KL divergence
            kl_div = np.sum(p_hist * np.log(p_hist / q_hist))
            return kl_div
            
        except Exception as e:
            logger.warning(f"KL divergence calculation error: {e}")
            return 0.0
    
    def calculate_psi(self, expected, actual, bins=10):
        """Tính Population Stability Index (PSI)"""
        try:
            if len(expected) == 0 or len(actual) == 0:
                return 0.0
            
            min_val = min(np.min(expected), np.min(actual))
            max_val = max(np.max(expected), np.max(actual))
            
            if min_val == max_val:
                return 0.0
            
            bin_edges = np.linspace(min_val, max_val, bins + 1)
            
            # Tính histogram
            expected_hist, _ = np.histogram(expected, bins=bin_edges)
            actual_hist, _ = np.histogram(actual, bins=bin_edges)
            
            # Normalize
            expected_hist = expected_hist / np.sum(expected_hist)
            actual_hist = actual_hist / np.sum(actual_hist)
            
            # Thêm epsilon để tránh log(0)
            epsilon = 1e-10
            expected_hist = expected_hist + epsilon
            actual_hist = actual_hist + epsilon
            
            # Tính PSI với numerical stability
            # Avoid log(0) by using np.log1p and np.expm1
            ratio = actual_hist / expected_hist
            psi = np.sum((actual_hist - expected_hist) * np.log(ratio + 1e-10))
            return psi
            
        except Exception as e:
            logger.warning(f"PSI calculation error: {e}")
            return 0.0
    
    def detect_drift(self, new_features, new_scores):
        """Phát hiện drift tổng thể"""
        try:
            if self.baseline_features is None or self.baseline_scores is None:
                logger.warning("No baseline set for drift detection")
                return {'drift_detected': False, 'reason': 'No baseline set'}
            
            # Cập nhật window - ensure consistent data types
            if isinstance(new_features, np.ndarray) and new_features.ndim > 1:
                # If features is 2D, flatten it
                self.feature_window.append(new_features.flatten())
            else:
                self.feature_window.append(new_features)
            
            if isinstance(new_scores, np.ndarray) and new_scores.ndim > 1:
                # If scores is 2D, flatten it
                self.score_window.append(new_scores.flatten())
            else:
                self.score_window.append(new_scores)
            
            # Kiểm tra đủ samples
            if len(self.feature_window) < self.min_samples:
                return {
                    'drift_detected': False,
                    'reason': f'Insufficient samples: {len(self.feature_window)}/{self.min_samples}'
                }
            
            # Chuyển đổi window thành arrays
            window_features = np.array(list(self.feature_window))
            window_scores = np.array(list(self.score_window))
            
            # Sử dụng baseline scores nếu có, nếu không thì sử dụng window scores đầu tiên
            if self.baseline_scores is not None and len(self.baseline_scores) > 0:
                baseline = self.baseline_scores
            else:
                # Sử dụng một phần của window scores làm baseline
                baseline = window_scores[:min(len(window_scores)//2, 50)]
            
            # Phát hiện score drift
            kl_div = self.calculate_kl_divergence(baseline, window_scores)
            psi = self.calculate_psi(baseline, window_scores)
            
            drift_detected = kl_div > self.drift_threshold or psi > 0.2
            
            # Lưu drift record
            drift_record = {
                'timestamp': datetime.now().isoformat(),
                'drift_detected': drift_detected,
                'kl_divergence': kl_div,
                'psi': psi,
                'window_size': len(self.feature_window)
            }
            
            self.drift_history.append(drift_record)
            
            if drift_detected:
                logger.warning(f"🚨 DRIFT DETECTED! KL: {kl_div:.4f}, PSI: {psi:.4f}")
            else:
                logger.info(f"✅ No drift detected (window: {len(self.feature_window)})")
            
            return drift_record
            
        except Exception as e:
            logger.error(f"Error in drift detection: {e}")
            return {'drift_detected': False, 'error': str(e)}
    
    def get_drift_summary(self, days=7):
        """Lấy tóm tắt drift trong N ngày gần nhất"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            recent_drifts = [
                drift for drift in self.drift_history
                if datetime.fromisoformat(drift['timestamp']) > cutoff_date
            ]
            
            if not recent_drifts:
                return {
                    'total_checks': 0,
                    'drift_detected': 0,
                    'drift_rate': 0.0
                }
            
            drift_count = sum(1 for drift in recent_drifts if drift['drift_detected'])
            drift_rate = drift_count / len(recent_drifts)
            
            return {
                'total_checks': len(recent_drifts),
                'drift_detected': drift_count,
                'drift_rate': drift_rate,
                'period_days': days
            }
            
        except Exception as e:
            logger.error(f"Error getting drift summary: {e}")
            return None

def test_drift_detector():
    """Test drift detector"""
    print("🧪 Testing Model Drift Detector")
    print("=" * 40)
    
    # Tạo drift detector
    detector = ModelDriftDetector(window_size=100, min_samples=50)
    
    # Tạo baseline data
    np.random.seed(42)
    baseline_features = np.random.normal(0, 1, (200, 10))
    baseline_scores = np.random.normal(-0.1, 0.2, 200)  # Isolation Forest scores are typically negative
    
    # Set baseline
    detector.set_baseline(baseline_features, baseline_scores)
    
    # Test 1: No drift
    print("\n📊 Test 1: No drift")
    new_features = np.random.normal(0, 1, (50, 10))
    new_scores = np.random.normal(-0.1, 0.2, 50)  # Isolation Forest scores are typically negative
    
    result1 = detector.detect_drift(new_features, new_scores)
    print(f"Drift detected: {result1['drift_detected']}")
    
    # Test 2: Score drift
    print("\n📊 Test 2: Score drift")
    new_scores = np.random.normal(-0.5, 0.3, 50)  # Different distribution - more negative (more anomalous)
    
    result2 = detector.detect_drift(new_features, new_scores)
    print(f"Drift detected: {result2['drift_detected']}")
    if result2['drift_detected']:
        print(f"KL Divergence: {result2['kl_divergence']:.4f}")
        print(f"PSI: {result2['psi']:.4f}")
    
    # Get summary
    summary = detector.get_drift_summary()
    print(f"\n📈 Drift Summary:")
    print(f"   Total checks: {summary['total_checks']}")
    print(f"   Drift detected: {summary['drift_detected']}")
    print(f"   Drift rate: {summary['drift_rate']:.2%}")
    
    print("\n✅ Drift detector test completed!")

if __name__ == "__main__":
    test_drift_detector()

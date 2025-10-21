#!/usr/bin/env python3
"""
Adaptive Threshold Calibration Module - Tối ưu hóa
Tự động điều chỉnh threshold dựa trên performance metrics
"""

import numpy as np
import logging
from datetime import datetime, timedelta
from sklearn.metrics import roc_curve, precision_recall_curve
from collections import deque

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AdaptiveThresholdCalibrator:
    """Tự động điều chỉnh threshold cho anomaly detection - Tối ưu hóa"""
    
    def __init__(self, 
                 target_fpr=0.01,
                 target_precision=0.95,
                 min_threshold=0.1,
                 max_threshold=0.9,
                 calibration_window=1000,
                 update_frequency=100):
        
        self.target_fpr = target_fpr
        self.target_precision = target_precision
        self.min_threshold = min_threshold
        self.max_threshold = max_threshold
        self.calibration_window = calibration_window
        self.update_frequency = update_frequency
        
        # Current threshold
        self.current_threshold = 0.5
        self.optimal_threshold = 0.5
        
        # Calibration data
        self.scores_window = deque(maxlen=calibration_window)
        self.labels_window = deque(maxlen=calibration_window)
        
        # Performance tracking
        self.performance_history = deque(maxlen=1000)
        
    def add_prediction(self, score, label, timestamp=None):
        """Thêm prediction để calibration"""
        if timestamp is None:
            timestamp = datetime.now()
        
        self.scores_window.append(score)
        self.labels_window.append(label)
        
        # Kiểm tra xem có cần update threshold không
        if len(self.scores_window) >= self.update_frequency:
            self._update_threshold()
    
    def _calibrate_fpr_based(self, scores, labels):
        """Calibration dựa trên False Positive Rate"""
        try:
            if len(np.unique(labels)) < 2:
                return self.current_threshold
            
            # Tính ROC curve
            fpr, tpr, thresholds = roc_curve(labels, scores)
            
            # Tìm threshold gần nhất với target FPR
            target_idx = np.argmin(np.abs(fpr - self.target_fpr))
            optimal_threshold = thresholds[target_idx]
            
            # Đảm bảo threshold trong range
            optimal_threshold = np.clip(optimal_threshold, self.min_threshold, self.max_threshold)
            
            return optimal_threshold
            
        except Exception as e:
            logger.warning(f"FPR-based calibration error: {e}")
            return self.current_threshold
    
    def _calibrate_precision_based(self, scores, labels):
        """Calibration dựa trên Precision"""
        try:
            if len(np.unique(labels)) < 2:
                return self.current_threshold
            
            # Chuyển đổi Isolation Forest scores thành probabilities
            # Isolation Forest scores: âm = normal, dương = anomaly
            # Chuyển thành probabilities: 0 = normal, 1 = anomaly
            probabilities = 1 / (1 + np.exp(-scores))  # Sigmoid transformation
            
            # Tính Precision-Recall curve
            precision, recall, thresholds = precision_recall_curve(labels, probabilities)
            
            # Tìm threshold gần nhất với target precision
            target_idx = np.argmin(np.abs(precision - self.target_precision))
            optimal_threshold = thresholds[target_idx] if target_idx < len(thresholds) else thresholds[-1]
            
            # Đảm bảo threshold trong range
            optimal_threshold = np.clip(optimal_threshold, self.min_threshold, self.max_threshold)
            
            return optimal_threshold
            
        except Exception as e:
            logger.warning(f"Precision-based calibration error: {e}")
            return self.current_threshold
    
    def _update_threshold(self):
        """Cập nhật threshold dựa trên dữ liệu hiện tại"""
        try:
            if len(self.scores_window) < 10:  # Cần ít nhất 10 samples
                return
            
            scores = np.array(list(self.scores_window))
            labels = np.array(list(self.labels_window))
            
            # Sử dụng FPR-based calibration
            new_threshold = self._calibrate_fpr_based(scores, labels)
            
            # Smooth threshold update để tránh thay đổi đột ngột
            alpha = 0.3  # Smoothing factor - increased for more responsive updates
            self.optimal_threshold = alpha * new_threshold + (1 - alpha) * self.optimal_threshold
            
            # Cập nhật current threshold
            self.current_threshold = self.optimal_threshold
            
            # Tính metrics với threshold mới
            metrics = self._calculate_metrics(scores, labels, self.current_threshold)
            
            # Lưu vào history
            self.performance_history.append({
                'timestamp': datetime.now().isoformat(),
                'threshold': self.current_threshold,
                'metrics': metrics
            })
            
            logger.info(f"🎯 Threshold updated: {self.current_threshold:.4f}")
            logger.info(f"   Precision: {metrics.get('precision', 0):.3f}, Recall: {metrics.get('recall', 0):.3f}")
            
        except Exception as e:
            logger.error(f"Error updating threshold: {e}")
    
    def _calculate_metrics(self, scores, labels, threshold):
        """Tính các metrics với threshold cho trước"""
        try:
            if len(np.unique(labels)) < 2:
                return {
                    'precision': 0.0,
                    'recall': 0.0,
                    'f1_score': 0.0,
                    'fpr': 0.0,
                    'tpr': 0.0
                }
            
            # Predictions với threshold
            predictions = (scores >= threshold).astype(int)
            
            # Confusion matrix
            from sklearn.metrics import confusion_matrix
            cm = confusion_matrix(labels, predictions)
            if cm.size == 4:
                tn, fp, fn, tp = cm.ravel()
            elif cm.size == 1:
                # Only one class present
                if labels[0] == 0:
                    tn, fp, fn, tp = cm[0, 0], 0, 0, 0
                else:
                    tn, fp, fn, tp = 0, 0, 0, cm[0, 0]
            else:
                # Fallback
                tn, fp, fn, tp = 0, 0, 0, 0
            
            # Metrics
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            
            return {
                'precision': precision,
                'recall': recall,
                'f1_score': f1_score,
                'fpr': fpr,
                'tpr': tpr
            }
            
        except Exception as e:
            logger.warning(f"Error calculating metrics: {e}")
            return {
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0,
                'fpr': 0.0,
                'tpr': 0.0
            }
    
    def get_current_threshold(self):
        """Lấy threshold hiện tại"""
        return self.current_threshold
    
    def get_performance_summary(self, days=7):
        """Lấy tóm tắt performance"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            recent_history = [
                record for record in self.performance_history
                if datetime.fromisoformat(record['timestamp']) > cutoff_date
            ]
            
            if not recent_history:
                return {
                    'total_updates': 0,
                    'current_threshold': self.current_threshold,
                    'avg_precision': 0.0,
                    'avg_recall': 0.0,
                    'avg_f1': 0.0
                }
            
            # Tính average metrics
            avg_precision = np.mean([record['metrics'].get('precision', 0) for record in recent_history])
            avg_recall = np.mean([record['metrics'].get('recall', 0) for record in recent_history])
            avg_f1 = np.mean([record['metrics'].get('f1_score', 0) for record in recent_history])
            
            return {
                'total_updates': len(recent_history),
                'current_threshold': self.current_threshold,
                'avg_precision': avg_precision,
                'avg_recall': avg_recall,
                'avg_f1': avg_f1,
                'period_days': days
            }
            
        except Exception as e:
            logger.error(f"Error getting performance summary: {e}")
            return None

def test_adaptive_threshold():
    """Test adaptive threshold calibrator"""
    print("🧪 Testing Adaptive Threshold Calibrator")
    print("=" * 50)
    
    # Tạo calibrator
    calibrator = AdaptiveThresholdCalibrator(
        target_fpr=0.01,
        target_precision=0.95,
        calibration_window=100,
        update_frequency=20
    )
    
    # Test với dữ liệu giả
    np.random.seed(42)
    
    # Normal data (label=0)
    normal_scores = np.random.normal(-0.1, 0.1, 200)  # Isolation Forest scores are typically negative
    normal_labels = np.zeros(200)
    
    # Anomaly data (label=1)
    anomaly_scores = np.random.normal(-0.5, 0.1, 50)  # More negative scores indicate higher anomaly
    anomaly_labels = np.ones(50)
    
    # Combine data
    all_scores = np.concatenate([normal_scores, anomaly_scores])
    all_labels = np.concatenate([normal_labels, anomaly_labels])
    
    # Shuffle
    indices = np.random.permutation(len(all_scores))
    all_scores = all_scores[indices]
    all_labels = all_labels[indices]
    
    print(f"📊 Test data: {len(all_scores)} samples ({np.sum(all_labels)} anomalies)")
    
    # Add predictions
    for score, label in zip(all_scores, all_labels):
        calibrator.add_prediction(score, label)
    
    threshold = calibrator.get_current_threshold()
    summary = calibrator.get_performance_summary()
    
    print(f"   Final threshold: {threshold:.4f}")
    print(f"   Avg precision: {summary['avg_precision']:.3f}")
    print(f"   Avg recall: {summary['avg_recall']:.3f}")
    print(f"   Avg F1: {summary['avg_f1']:.3f}")
    
    print("\n✅ Adaptive threshold calibrator test completed!")

if __name__ == "__main__":
    test_adaptive_threshold()

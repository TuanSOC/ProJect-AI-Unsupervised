#!/usr/bin/env python3
"""
Enhanced SQLi Detector - Production-Grade System - Tối ưu hóa
Tích hợp tất cả các cải tiến: drift detection, adaptive threshold, explainability, 
data augmentation, semi-supervised learning, và production robustness
"""

import numpy as np
import logging
from datetime import datetime
import json
import os
from typing import Dict, List, Optional, Tuple, Any

# Import các modules đã tạo
from model_drift_detector import ModelDriftDetector
from adaptive_threshold_calibrator import AdaptiveThresholdCalibrator
from explainability_engine import ExplainabilityEngine
from data_augmentation_engine import DataAugmentationEngine
from semi_supervised_learning import SemiSupervisedLearning
from production_robustness import ProductionRobustness

# Import original detector
from optimized_sqli_detector import OptimizedSQLIDetector

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnhancedSQLIDetector:
    """Enhanced SQLi Detector với tất cả production-grade features - Tối ưu hóa"""
    
    def __init__(self, 
                 model_path: str = 'models/optimized_sqli_detector.pkl',
                 config: Dict[str, Any] = None):
        
        # Default config
        self.config = config or {
            'drift_detection': {
                'window_size': 1000,
                'drift_threshold': 0.1,
                'min_samples': 100
            },
            'adaptive_threshold': {
                'target_fpr': 0.01,
                'target_precision': 0.95,
                'calibration_window': 1000,
                'update_frequency': 100
            },
            'explainability': {
                'use_shap': True,
                'use_lime': True,
                'max_features': 10
            },
            'data_augmentation': {
                'synthetic_attacks': 1000,
                'mutation_rate': 0.1,
                'adversarial_examples': 500
            },
            'semi_supervised': {
                'confidence_threshold': 0.8,
                'max_iterations': 10,
                'feedback_window': 1000,
                'retrain_frequency': 100
            },
            'production': {
                'max_memory_mb': 1024,
                'max_cpu_percent': 80,
                'rate_limit_per_minute': 1000,
                'max_concurrent_requests': 100
            }
        }
        
        # Initialize components
        self.base_detector = None
        self.drift_detector = None
        self.threshold_calibrator = None
        self.explainability_engine = None
        self.data_augmentation = None
        self.semi_supervised = None
        self.production_robustness = None
        
        # State
        self.is_initialized = False
        self.model_path = model_path
        
        # Initialize system
        self._initialize_system()
    
    def _initialize_system(self):
        """Khởi tạo toàn bộ hệ thống"""
        try:
            logger.info("🚀 Initializing Enhanced SQLi Detection System")
            
            # Load base detector
            self.base_detector = OptimizedSQLIDetector()
            if os.path.exists(self.model_path):
                self.base_detector.load_model(self.model_path)
                logger.info("✅ Base detector loaded")
            else:
                logger.warning("⚠️ Base model not found, will need training")
            
            # Initialize drift detector
            drift_config = self.config['drift_detection']
            self.drift_detector = ModelDriftDetector(
                window_size=drift_config['window_size'],
                drift_threshold=drift_config['drift_threshold'],
                min_samples=drift_config['min_samples']
            )
            logger.info("✅ Drift detector initialized")
            
            # Initialize threshold calibrator
            threshold_config = self.config['adaptive_threshold']
            self.threshold_calibrator = AdaptiveThresholdCalibrator(
                target_fpr=threshold_config['target_fpr'],
                target_precision=threshold_config['target_precision'],
                calibration_window=threshold_config['calibration_window'],
                update_frequency=threshold_config['update_frequency']
            )
            logger.info("✅ Threshold calibrator initialized")
            
            # Initialize explainability engine
            explainability_config = self.config['explainability']
            self.explainability_engine = ExplainabilityEngine(
                model=self.base_detector,
                feature_names=self.base_detector.feature_names if self.base_detector else []
            )
            logger.info("✅ Explainability engine initialized")
            
            # Initialize data augmentation
            self.data_augmentation = DataAugmentationEngine()
            logger.info("✅ Data augmentation engine initialized")
            
            # Initialize semi-supervised learning
            ssl_config = self.config['semi_supervised']
            self.semi_supervised = SemiSupervisedLearning(
                confidence_threshold=ssl_config['confidence_threshold'],
                max_iterations=ssl_config['max_iterations'],
                feedback_window=ssl_config['feedback_window'],
                retrain_frequency=ssl_config['retrain_frequency']
            )
            logger.info("✅ Semi-supervised learning initialized")
            
            # Initialize production robustness
            production_config = self.config['production']
            self.production_robustness = ProductionRobustness(
                max_memory_mb=production_config['max_memory_mb'],
                max_cpu_percent=production_config['max_cpu_percent'],
                rate_limit_per_minute=production_config['rate_limit_per_minute'],
                max_concurrent_requests=production_config['max_concurrent_requests']
            )
            logger.info("✅ Production robustness initialized")
            
            self.is_initialized = True
            logger.info("🎉 Enhanced SQLi Detection System initialized successfully!")
            
        except Exception as e:
            logger.error(f"❌ Error initializing system: {e}")
            self.is_initialized = False
    
    def predict_single(self, log_entry: Dict[str, Any], 
                      include_explanation: bool = True) -> Dict[str, Any]:
        """Dự đoán SQLi cho một log entry"""
        try:
            if not self.is_initialized:
                return {'error': 'System not initialized'}
            
            # Extract features
            features = self.base_detector.extract_optimized_features(log_entry)
            features_array = np.array(list(features.values())).reshape(1, -1)
            
            # Get prediction
            is_anomaly, score = self.base_detector.predict_single(log_entry)
            
            # Get current threshold
            current_threshold = self.threshold_calibrator.get_current_threshold()
            
            # Use the original prediction from base detector
            # The base detector already applies its own threshold
            adjusted_prediction = is_anomaly
            
            # Create result
            result = {
                'is_sqli': bool(adjusted_prediction),
                'score': float(score),
                'threshold': current_threshold,
                'confidence': self._calculate_confidence(score, current_threshold),
                'timestamp': datetime.now().isoformat(),
                'log_entry': log_entry
            }
            
            # Add explanation if requested
            if include_explanation:
                explanation = self.explainability_engine.explain_anomaly_detection(
                    log_entry, features_array, score
                )
                if explanation:
                    result['explanation'] = explanation
            
            # Add drift detection
            # Ensure features_array is 1D for drift detection
            features_1d = features_array.flatten() if features_array.ndim > 1 else features_array
            drift_result = self.drift_detector.detect_drift(features_1d, np.array([score]))
            if drift_result:
                result['drift_detected'] = drift_result.get('drift_detected', False)
                result['drift_reasons'] = drift_result.get('reasons', [])
            
            return result
            
        except Exception as e:
            logger.error(f"Error in prediction: {e}")
            return {
                'is_sqli': False,
                'score': 0.0,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def predict_batch(self, log_entries: List[Dict[str, Any]], 
                     include_explanation: bool = False) -> List[Dict[str, Any]]:
        """Dự đoán SQLi cho nhiều log entries"""
        try:
            results = []
            
            for log_entry in log_entries:
                result = self.predict_single(log_entry, include_explanation)
                results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Error in batch prediction: {e}")
            return []
    
    def add_feedback(self, log_entry: Dict[str, Any], 
                    is_sqli: bool, confidence: float = 1.0, 
                    source: str = 'human'):
        """Thêm feedback để cải thiện model"""
        try:
            # Add to semi-supervised learning
            features = self.base_detector.extract_optimized_features(log_entry)
            features_array = np.array(list(features.values()))
            
            label = 1 if is_sqli else 0
            self.semi_supervised.add_feedback(features_array, label, confidence, source)
            
            # Add to threshold calibrator
            score = self.base_detector.predict_single(log_entry)[1]
            self.threshold_calibrator.add_prediction(score, label)
            
            logger.info(f"✅ Feedback added from {source}")
            
        except Exception as e:
            logger.error(f"Error adding feedback: {e}")
    
    def generate_synthetic_data(self, count: int = 1000) -> List[Dict[str, Any]]:
        """Tạo synthetic data để cải thiện model"""
        try:
            synthetic_attacks = self.data_augmentation.generate_synthetic_attacks(count)
            
            # Convert to log entries
            log_entries = [attack['log_entry'] for attack in synthetic_attacks]
            
            logger.info(f"✅ Generated {len(log_entries)} synthetic log entries")
            return log_entries
            
        except Exception as e:
            logger.error(f"Error generating synthetic data: {e}")
            return []
    
    def retrain_model(self, new_data: List[Dict[str, Any]] = None):
        """Retrain model với dữ liệu mới"""
        try:
            if new_data is None:
                new_data = self.generate_synthetic_data(1000)
            
            # Extract features
            features_list = []
            for log_entry in new_data:
                features = self.base_detector.extract_optimized_features(log_entry)
                features_list.append(features)
            
            features_array = np.array(features_list)
            
            # Retrain base model
            self.base_detector.train(features_list)
            
            # Update explainability engine
            self.explainability_engine.model = self.base_detector
            
            # Update semi-supervised model
            self.semi_supervised.update_model_with_feedback()
            
            logger.info("✅ Model retrained successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error retraining model: {e}")
            return False
    
    def get_system_status(self) -> Dict[str, Any]:
        """Lấy status của toàn bộ hệ thống"""
        try:
            status = {
                'system': {
                    'initialized': self.is_initialized,
                    'timestamp': datetime.now().isoformat()
                },
                'drift_detection': self.drift_detector.get_drift_summary() if self.drift_detector else None,
                'threshold_calibration': self.threshold_calibrator.get_performance_summary() if self.threshold_calibrator else None,
                'semi_supervised': self.semi_supervised.get_learning_summary() if self.semi_supervised else None,
                'data_augmentation': self.data_augmentation.get_augmentation_summary() if self.data_augmentation else None,
                'production_health': self.production_robustness.get_health_status() if self.production_robustness else None
            }
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {'error': str(e)}
    
    def _calculate_confidence(self, score: float, threshold: float) -> str:
        """Tính confidence level"""
        try:
            # For Isolation Forest, lower scores indicate higher anomaly
            # So we use absolute values and compare against threshold
            abs_score = abs(score)
            if abs_score > threshold * 1.5:
                return 'High'
            elif abs_score > threshold * 1.2:
                return 'Medium'
            else:
                return 'Low'
        except:
            return 'Unknown'
    
    def save_system_state(self, filepath: str = 'enhanced_system_state.json'):
        """Lưu system state"""
        try:
            state = {
                'config': self.config,
                'is_initialized': self.is_initialized,
                'model_path': self.model_path,
                'timestamp': datetime.now().isoformat()
            }
            
            with open(filepath, 'w') as f:
                json.dump(state, f, indent=2, default=str)
            
            logger.info(f"✅ System state saved to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving system state: {e}")
            return False
    
    def load_system_state(self, filepath: str = 'enhanced_system_state.json'):
        """Load system state"""
        try:
            if not os.path.exists(filepath):
                logger.info("No existing system state found")
                return False
            
            with open(filepath, 'r') as f:
                state = json.load(f)
            
            self.config = state.get('config', self.config)
            self.is_initialized = state.get('is_initialized', False)
            self.model_path = state.get('model_path', self.model_path)
            
            logger.info(f"✅ System state loaded from {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading system state: {e}")
            return False

def test_enhanced_system():
    """Test enhanced system"""
    print("🧪 Testing Enhanced SQLi Detection System")
    print("=" * 60)
    
    # Tạo enhanced detector
    detector = EnhancedSQLIDetector()
    
    # Test prediction
    print("\n📊 Testing prediction")
    test_log = {
        'uri': '/login.php',
        'query_string': '?id=1 OR 1=1',
        'payload': 'id=1 OR 1=1',
        'user_agent': 'Mozilla/5.0...',
        'cookie': 'session=abc123'
    }
    
    result = detector.predict_single(test_log)
    print(f"   Prediction: {result.get('is_sqli', False)}")
    print(f"   Score: {result.get('score', 0.0):.3f}")
    print(f"   Confidence: {result.get('confidence', 'Unknown')}")
    
    # Test feedback
    print("\n📊 Testing feedback")
    detector.add_feedback(test_log, True, 0.9, 'human')
    
    # Test synthetic data generation
    print("\n📊 Testing synthetic data generation")
    synthetic_data = detector.generate_synthetic_data(10)
    print(f"   Generated {len(synthetic_data)} synthetic log entries")
    
    # Test system status
    print("\n📊 Testing system status")
    status = detector.get_system_status()
    print(f"   System initialized: {status['system']['initialized']}")
    print(f"   Drift detection: {status['drift_detection'] is not None}")
    print(f"   Threshold calibration: {status['threshold_calibration'] is not None}")
    
    print("\n✅ Enhanced system test completed!")

if __name__ == "__main__":
    test_enhanced_system()

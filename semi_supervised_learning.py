#!/usr/bin/env python3
"""
Semi-Supervised Learning Module - Tối ưu hóa
Implement feedback loop và semi-supervised learning cho SQLi detection
"""

import numpy as np
import logging
from datetime import datetime, timedelta
from collections import deque
from sklearn.ensemble import IsolationForest
from sklearn.semi_supervised import SelfTrainingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SemiSupervisedLearning:
    """Semi-supervised learning với feedback loop - Tối ưu hóa"""
    
    def __init__(self, 
                 confidence_threshold=0.8,
                 max_iterations=10,
                 feedback_window=1000,
                 retrain_frequency=100):
        
        self.confidence_threshold = confidence_threshold
        self.max_iterations = max_iterations
        self.feedback_window = feedback_window
        self.retrain_frequency = retrain_frequency
        
        # Models
        self.base_model = None
        self.semi_supervised_model = None
        
        # Feedback data
        self.feedback_data = deque(maxlen=feedback_window)
        self.pseudo_labels = deque(maxlen=feedback_window)
        
        # Performance tracking
        self.performance_history = deque(maxlen=1000)
        self.retrain_history = deque(maxlen=100)
        
        # Learning state
        self.is_training = False
        self.last_retrain = None
        self.total_feedback = 0
        
    def initialize_base_model(self, X, y=None):
        """Khởi tạo base model"""
        try:
            if y is not None:
                # Supervised learning
                self.base_model = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_estimators=100
                )
                self.base_model.fit(X, y)
                logger.info("✅ Base model initialized with supervised learning")
            else:
                # Unsupervised learning
                self.base_model = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_estimators=100
                )
                self.base_model.fit(X)
                logger.info("✅ Base model initialized with unsupervised learning")
            
            return True
            
        except Exception as e:
            logger.error(f"Error initializing base model: {e}")
            return False
    
    def add_feedback(self, X, y, confidence=None, source='human'):
        """Thêm feedback từ human hoặc system"""
        try:
            feedback_entry = {
                'X': X,
                'y': y,
                'confidence': confidence or 1.0,
                'source': source,
                'timestamp': datetime.now().isoformat()
            }
            
            self.feedback_data.append(feedback_entry)
            self.total_feedback += 1
            
            logger.info(f"✅ Feedback added from {source} (total: {self.total_feedback})")
            return True
            
        except Exception as e:
            logger.error(f"Error adding feedback: {e}")
            return False
    
    def generate_pseudo_labels(self, X_unlabeled, confidence_threshold=None):
        """Tạo pseudo labels từ unlabeled data"""
        if confidence_threshold is None:
            confidence_threshold = self.confidence_threshold
        
        try:
            if self.base_model is None:
                logger.warning("Base model not initialized")
                return None
            
            # Dự đoán với base model
            predictions = self.base_model.predict(X_unlabeled)
            scores = self.base_model.decision_function(X_unlabeled)
            
            # Tính confidence scores - for Isolation Forest, use distance from decision boundary
            # Isolation Forest: scores < 0 = normal, scores > 0 = anomaly
            # Confidence = distance from decision boundary (0)
            confidence_scores = np.abs(scores)
            
            # Chọn samples có confidence cao
            high_confidence_mask = confidence_scores >= confidence_threshold
            high_confidence_X = X_unlabeled[high_confidence_mask]
            high_confidence_y = predictions[high_confidence_mask]
            high_confidence_scores = confidence_scores[high_confidence_mask]
            
            # Tạo pseudo labels
            pseudo_labels = []
            for i, (x, y, score) in enumerate(zip(high_confidence_X, high_confidence_y, high_confidence_scores)):
                pseudo_label = {
                    'X': x,
                    'y': y,
                    'confidence': score,
                    'source': 'pseudo',
                    'timestamp': datetime.now().isoformat()
                }
                pseudo_labels.append(pseudo_label)
            
            # Thêm vào feedback data
            for pseudo_label in pseudo_labels:
                self.feedback_data.append(pseudo_label)
                self.pseudo_labels.append(pseudo_label)
            
            logger.info(f"✅ Generated {len(pseudo_labels)} pseudo labels")
            return pseudo_labels
            
        except Exception as e:
            logger.error(f"Error generating pseudo labels: {e}")
            return None
    
    def train_semi_supervised_model(self, X_labeled, y_labeled, X_unlabeled=None):
        """Train semi-supervised model"""
        try:
            if len(self.feedback_data) < 10:
                logger.warning("Insufficient feedback data for semi-supervised learning")
                return False
            
            # Chuẩn bị data
            X_feedback = []
            y_feedback = []
            
            for feedback in self.feedback_data:
                X_feedback.append(feedback['X'])
                y_feedback.append(feedback['y'])
            
            X_feedback = np.array(X_feedback)
            y_feedback = np.array(y_feedback)
            
            # Combine labeled và feedback data
            if X_labeled is not None and y_labeled is not None:
                X_combined = np.vstack([X_labeled, X_feedback])
                y_combined = np.hstack([y_labeled, y_feedback])
            else:
                X_combined = X_feedback
                y_combined = y_feedback
            
            # Train semi-supervised model
            base_classifier = LogisticRegression(random_state=42)
            self.semi_supervised_model = SelfTrainingClassifier(
                base_classifier,
                threshold=self.confidence_threshold,
                max_iter=self.max_iterations
            )
            
            # Tạo initial labels (một số unlabeled)
            y_initial = y_combined.copy()
            unlabeled_mask = np.random.choice(
                [True, False], 
                size=len(y_initial), 
                p=[0.3, 0.7]  # 30% unlabeled
            )
            y_initial[unlabeled_mask] = -1  # -1 cho unlabeled
            
            # Train
            self.semi_supervised_model.fit(X_combined, y_initial)
            
            logger.info("✅ Semi-supervised model trained successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error training semi-supervised model: {e}")
            return False
    
    def update_model_with_feedback(self):
        """Cập nhật model với feedback mới"""
        try:
            if len(self.feedback_data) < self.retrain_frequency:
                return False
            
            # Kiểm tra xem có cần retrain không
            if self.last_retrain and (datetime.now() - self.last_retrain).total_seconds() < 3600:  # 1 hour
                return False
            
            # Chuẩn bị data cho retraining
            X_feedback = []
            y_feedback = []
            
            for feedback in self.feedback_data:
                X_feedback.append(feedback['X'])
                y_feedback.append(feedback['y'])
            
            X_feedback = np.array(X_feedback)
            y_feedback = np.array(y_feedback)
            
            # Retrain base model với feedback
            if self.base_model is not None:
                # Tạo new model với updated data
                new_model = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_estimators=100
                )
                new_model.fit(X_feedback)
                
                # So sánh performance
                old_score = self._evaluate_model(self.base_model, X_feedback, y_feedback)
                new_score = self._evaluate_model(new_model, X_feedback, y_feedback)
                
                if new_score > old_score:
                    self.base_model = new_model
                    logger.info(f"✅ Model updated (old: {old_score:.3f}, new: {new_score:.3f})")
                else:
                    logger.info(f"Model not updated (old: {old_score:.3f}, new: {new_score:.3f})")
            
            # Retrain semi-supervised model
            if self.semi_supervised_model is not None:
                self.train_semi_supervised_model(X_feedback, y_feedback)
            
            # Lưu retrain history
            retrain_record = {
                'timestamp': datetime.now().isoformat(),
                'feedback_count': len(self.feedback_data),
                'pseudo_labels_count': len(self.pseudo_labels),
                'total_feedback': self.total_feedback
            }
            self.retrain_history.append(retrain_record)
            
            self.last_retrain = datetime.now()
            logger.info("✅ Model updated with feedback")
            return True
            
        except Exception as e:
            logger.error(f"Error updating model with feedback: {e}")
            return False
    
    def _evaluate_model(self, model, X, y):
        """Đánh giá model performance"""
        try:
            predictions = model.predict(X)
            scores = model.decision_function(X)
            
            # Tính accuracy
            accuracy = accuracy_score(y, predictions)
            
            # Tính F1 score
            f1 = f1_score(y, predictions, average='weighted')
            
            # Combined score
            combined_score = 0.7 * accuracy + 0.3 * f1
            
            return combined_score
            
        except Exception as e:
            logger.warning(f"Error evaluating model: {e}")
            return 0.0
    
    def predict_with_confidence(self, X):
        """Dự đoán với confidence score"""
        try:
            if self.base_model is None:
                logger.warning("Base model not initialized")
                return None, None
            
            # Dự đoán với base model
            predictions = self.base_model.predict(X)
            scores = self.base_model.decision_function(X)
            
            # Tính confidence scores
            confidence_scores = np.abs(scores)
            
            # Nếu có semi-supervised model, sử dụng nó
            if self.semi_supervised_model is not None:
                try:
                    semi_predictions = self.semi_supervised_model.predict(X)
                    # Check if decision_function is available
                    if hasattr(self.semi_supervised_model, 'decision_function'):
                        semi_scores = self.semi_supervised_model.decision_function(X)
                    else:
                        # Fallback to prediction probabilities
                        semi_scores = self.semi_supervised_model.predict_proba(X)[:, 1] if hasattr(self.semi_supervised_model, 'predict_proba') else semi_predictions
                    
                    # Combine predictions
                    combined_predictions = []
                    combined_confidences = []
                    
                    for i in range(len(X)):
                        # Weighted combination
                        weight_base = 0.6
                        weight_semi = 0.4
                        
                        combined_pred = (weight_base * predictions[i] + 
                                       weight_semi * semi_predictions[i])
                        combined_conf = (weight_base * confidence_scores[i] + 
                                        weight_semi * abs(semi_scores[i]))
                        
                        combined_predictions.append(combined_pred)
                        combined_confidences.append(combined_conf)
                    
                    return np.array(combined_predictions), np.array(combined_confidences)
                    
                except Exception as e:
                    logger.warning(f"Semi-supervised prediction failed: {e}")
                    # Fallback to base model
                    pass
            
            return predictions, confidence_scores
            
        except Exception as e:
            logger.error(f"Error in prediction: {e}")
            return None, None
    
    def get_learning_summary(self, days=7):
        """Lấy tóm tắt learning process"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            # Recent feedback
            recent_feedback = [
                f for f in self.feedback_data
                if datetime.fromisoformat(f['timestamp']) > cutoff_date
            ]
            
            # Recent retrains
            recent_retrains = [
                r for r in self.retrain_history
                if datetime.fromisoformat(r['timestamp']) > cutoff_date
            ]
            
            # Feedback by source
            feedback_by_source = {}
            for feedback in recent_feedback:
                source = feedback['source']
                feedback_by_source[source] = feedback_by_source.get(source, 0) + 1
            
            # Pseudo labels
            pseudo_labels_count = len(self.pseudo_labels)
            
            return {
                'total_feedback': self.total_feedback,
                'recent_feedback': len(recent_feedback),
                'feedback_by_source': feedback_by_source,
                'pseudo_labels_count': pseudo_labels_count,
                'recent_retrains': len(recent_retrains),
                'last_retrain': self.last_retrain.isoformat() if self.last_retrain else None,
                'period_days': days
            }
            
        except Exception as e:
            logger.error(f"Error getting learning summary: {e}")
            return None

def test_semi_supervised_learning():
    """Test semi-supervised learning"""
    print("🧪 Testing Semi-Supervised Learning")
    print("=" * 50)
    
    # Tạo dummy data
    np.random.seed(42)
    X_labeled = np.random.normal(0, 1, (100, 10))
    y_labeled = np.random.choice([-1, 1], 100)
    
    X_unlabeled = np.random.normal(0, 1, (200, 10))
    
    # Tạo semi-supervised learning
    ssl = SemiSupervisedLearning(
        confidence_threshold=0.7,
        max_iterations=5,
        feedback_window=100,
        retrain_frequency=20
    )
    
    # Initialize base model
    print("\n📊 Initializing base model")
    ssl.initialize_base_model(X_labeled, y_labeled)
    
    # Add feedback
    print("\n📊 Adding feedback")
    for i in range(10):
        X_feedback = np.random.normal(0, 1, (1, 10))
        y_feedback = np.random.choice([-1, 1], 1)
        ssl.add_feedback(X_feedback, y_feedback, confidence=0.8, source='human')
    
    # Generate pseudo labels
    print("\n📊 Generating pseudo labels")
    pseudo_labels = ssl.generate_pseudo_labels(X_unlabeled)
    print(f"   Generated {len(pseudo_labels)} pseudo labels")
    
    # Train semi-supervised model
    print("\n📊 Training semi-supervised model")
    ssl.train_semi_supervised_model(X_labeled, y_labeled, X_unlabeled)
    
    # Test prediction
    print("\n📊 Testing prediction")
    X_test = np.random.normal(0, 1, (10, 10))
    predictions, confidences = ssl.predict_with_confidence(X_test)
    
    if predictions is not None:
        print(f"   Predictions: {predictions}")
        print(f"   Confidences: {confidences}")
    
    # Get learning summary
    summary = ssl.get_learning_summary()
    print(f"\n📈 Learning Summary:")
    print(f"   Total feedback: {summary['total_feedback']}")
    print(f"   Recent feedback: {summary['recent_feedback']}")
    print(f"   Pseudo labels: {summary['pseudo_labels_count']}")
    print(f"   Recent retrains: {summary['recent_retrains']}")
    
    print("\n✅ Semi-supervised learning test completed!")

if __name__ == "__main__":
    test_semi_supervised_learning()

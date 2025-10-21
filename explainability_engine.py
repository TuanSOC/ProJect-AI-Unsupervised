#!/usr/bin/env python3
"""
Explainability Engine Module - Tối ưu hóa
Sử dụng SHAP và LIME để giải thích kết quả detection
"""

import numpy as np
import logging
from datetime import datetime, timedelta
import json
import os
from typing import Dict, List, Optional, Any

# Try to import SHAP and LIME
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    logging.warning("SHAP not available. Install with: pip install shap")

try:
    from lime import lime_tabular
    LIME_AVAILABLE = True
except ImportError:
    LIME_AVAILABLE = False
    logging.warning("LIME not available. Install with: pip install lime")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ExplainabilityEngine:
    """Engine để giải thích kết quả AI detection - Tối ưu hóa"""
    
    def __init__(self, model=None, feature_names=None):
        self.model = model
        self.feature_names = feature_names or []
        self.explainer = None
        self.lime_explainer = None
        self.explanation_history = []
        
        # Initialize explainers
        self._initialize_explainers()
    
    def _initialize_explainers(self):
        """Khởi tạo SHAP và LIME explainers"""
        try:
            if self.model and SHAP_AVAILABLE:
                # SHAP explainer cho Isolation Forest
                self.explainer = shap.TreeExplainer(self.model)
                logger.info("✅ SHAP explainer initialized")
            
            if LIME_AVAILABLE:
                logger.info("✅ LIME available for initialization")
                
        except Exception as e:
            logger.warning(f"Error initializing explainers: {e}")
    
    def explain_with_shap(self, X, max_samples=100):
        """Giải thích bằng SHAP"""
        if not self.explainer:
            logger.warning("SHAP explainer not available")
            return None
        
        try:
            # Giới hạn số samples để tránh memory issues
            if len(X) > max_samples:
                X = X[:max_samples]
            
            # Tính SHAP values
            shap_values = self.explainer.shap_values(X)
            
            # Tạo explanation
            explanation = {
                'method': 'SHAP',
                'shap_values': shap_values.tolist() if isinstance(shap_values, np.ndarray) else shap_values,
                'feature_names': self.feature_names,
                'base_value': self.explainer.expected_value if hasattr(self.explainer, 'expected_value') else 0,
                'timestamp': datetime.now().isoformat()
            }
            
            return explanation
            
        except Exception as e:
            logger.error(f"Error in SHAP explanation: {e}")
            return None
    
    def explain_with_lime(self, X, y=None, max_samples=100):
        """Giải thích bằng LIME"""
        if not LIME_AVAILABLE:
            logger.warning("LIME not available")
            return None
        
        try:
            # Giới hạn số samples
            if len(X) > max_samples:
                X = X[:max_samples]
                if y is not None:
                    y = y[:max_samples]
            
            # Khởi tạo LIME explainer nếu chưa có
            if self.lime_explainer is None:
                self.lime_explainer = lime_tabular.LimeTabularExplainer(
                    X,
                    feature_names=self.feature_names,
                    mode='regression' if y is None else 'classification',
                    discretize_continuous=True
                )
            
            explanations = []
            
            # Tạo explanation cho từng sample
            for i in range(min(len(X), 10)):  # Giới hạn 10 samples
                try:
                    # Create prediction function for LIME
                    def predict_fn(x):
                        if hasattr(self.model, 'decision_function'):
                            return self.model.decision_function(x)
                        elif hasattr(self.model, 'predict'):
                            return self.model.predict(x)
                        else:
                            return np.zeros(len(x))
                    
                    exp = self.lime_explainer.explain_instance(
                        X[i], 
                        predict_fn,
                        num_features=min(len(self.feature_names), 10)
                    )
                    
                    # Extract explanation data
                    explanation_data = {
                        'sample_index': i,
                        'prediction': exp.predicted_value if hasattr(exp, 'predicted_value') else None,
                        'local_prediction': exp.local_pred if hasattr(exp, 'local_pred') else None,
                        'feature_importance': dict(exp.as_list()),
                        'feature_weights': exp.as_map() if hasattr(exp, 'as_map') else {}
                    }
                    
                    explanations.append(explanation_data)
                    
                except Exception as e:
                    logger.warning(f"Error explaining sample {i}: {e}")
                    continue
            
            return {
                'method': 'LIME',
                'explanations': explanations,
                'feature_names': self.feature_names,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in LIME explanation: {e}")
            return None
    
    def explain_single_prediction(self, X_single, method='both'):
        """Giải thích một prediction đơn lẻ"""
        try:
            X_single = np.array(X_single).reshape(1, -1)
            explanations = {}
            
            if method in ['both', 'shap'] and self.explainer:
                shap_exp = self.explain_with_shap(X_single)
                if shap_exp:
                    explanations['shap'] = shap_exp
            
            if method in ['both', 'lime'] and LIME_AVAILABLE:
                lime_exp = self.explain_with_lime(X_single)
                if lime_exp:
                    explanations['lime'] = lime_exp
            
            # Lưu vào history
            if explanations:
                self.explanation_history.append({
                    'timestamp': datetime.now().isoformat(),
                    'input': X_single.flatten().tolist(),  # Flatten to 1D before converting to list
                    'explanations': explanations
                })
            
            return explanations
            
        except Exception as e:
            logger.error(f"Error explaining single prediction: {e}")
            return None
    
    def get_feature_importance_ranking(self, X, top_k=10):
        """Lấy ranking feature importance"""
        try:
            if not self.explainer:
                return None
            
            # Tính SHAP values
            shap_values = self.explain_with_shap(X)
            if not shap_values:
                return None
            
            # Tính mean absolute SHAP values
            # Tính mean importance
            if isinstance(shap_values, dict) and 'shap_values' in shap_values:
                mean_shap_values = np.mean(np.abs(shap_values['shap_values']), axis=0)
            elif isinstance(shap_values, np.ndarray):
                mean_shap_values = np.mean(np.abs(shap_values), axis=0)
            else:
                logger.warning("Invalid SHAP values format")
                return None
            
            # Tạo ranking
            feature_importance = []
            for i, importance in enumerate(mean_shap_values):
                feature_name = self.feature_names[i] if i < len(self.feature_names) else f'feature_{i}'
                feature_importance.append({
                    'feature': feature_name,
                    'importance': float(importance),
                    'rank': 0  # Sẽ được set sau
                })
            
            # Sort theo importance
            feature_importance.sort(key=lambda x: x['importance'], reverse=True)
            
            # Set rank
            for i, item in enumerate(feature_importance[:top_k]):
                item['rank'] = i + 1
            
            return feature_importance[:top_k]
            
        except Exception as e:
            logger.error(f"Error getting feature importance: {e}")
            return None
    
    def explain_anomaly_detection(self, log_entry, features, prediction_score):
        """Giải thích kết quả anomaly detection cho log entry"""
        try:
            # Tạo explanation cho log entry
            explanation = {
                'log_entry': log_entry,
                'prediction_score': float(prediction_score),
                'is_anomaly': prediction_score > 0.5,
                'timestamp': datetime.now().isoformat()
            }
            
            # Feature importance
            feature_importance = self.get_feature_importance_ranking(features.reshape(1, -1))
            if feature_importance:
                explanation['top_features'] = feature_importance[:5]
            
            # SHAP explanation
            if self.explainer:
                shap_exp = self.explain_with_shap(features.reshape(1, -1))
                if shap_exp:
                    explanation['shap_explanation'] = shap_exp
            
            # LIME explanation
            if LIME_AVAILABLE:
                lime_exp = self.explain_with_lime(features.reshape(1, -1))
                if lime_exp:
                    explanation['lime_explanation'] = lime_exp
            
            # Pattern analysis
            explanation['pattern_analysis'] = self._analyze_sqli_patterns(log_entry)
            
            return explanation
            
        except Exception as e:
            logger.error(f"Error explaining anomaly detection: {e}")
            return None
    
    def _analyze_sqli_patterns(self, log_entry):
        """Phân tích SQLi patterns trong log entry"""
        try:
            patterns = []
            
            # Extract text content
            uri = log_entry.get('uri', '')
            query_string = log_entry.get('query_string', '')
            payload = log_entry.get('payload', '')
            user_agent = log_entry.get('user_agent', '')
            cookie = log_entry.get('cookie', '')
            
            text_content = f"{uri} {query_string} {payload} {user_agent} {cookie}".lower()
            
            # SQLi pattern detection
            sqli_patterns = {
                'Union-based': ['union', 'select'],
                'Boolean-based': ['or 1=1', "or '1'='1", 'and 1=1', "and '1'='1"],
                'Time-based': ['sleep(', 'waitfor', 'benchmark'],
                'Information Schema': ['information_schema', 'mysql.user'],
                'Comment Injection': ['--', '/*', '*/']
            }
            
            detected_patterns = []
            for pattern_type, keywords in sqli_patterns.items():
                for keyword in keywords:
                    if keyword in text_content:
                        detected_patterns.append({
                            'type': pattern_type,
                            'keyword': keyword,
                            'location': self._find_keyword_location(text_content, keyword)
                        })
                        break  # Chỉ lấy pattern đầu tiên của mỗi type
            
            # Calculate suspicious score based on pattern severity
            severity_weights = {
                'union_based': 0.8,
                'boolean_based': 0.6,
                'time_based': 0.9,
                'information_schema': 0.7,
                'comment_injection': 0.5
            }
            
            suspicious_score = 0.0
            for pattern in detected_patterns:
                weight = severity_weights.get(pattern, 0.3)
                suspicious_score += weight
            
            # Normalize to 0-1 range
            suspicious_score = min(suspicious_score, 1.0)
            
            return {
                'detected_patterns': detected_patterns,
                'pattern_count': len(detected_patterns),
                'text_length': len(text_content),
                'suspicious_score': suspicious_score
            }
            
        except Exception as e:
            logger.error(f"Error analyzing SQLi patterns: {e}")
            return {'detected_patterns': [], 'pattern_count': 0, 'suspicious_score': 0.0}
    
    def _find_keyword_location(self, text, keyword):
        """Tìm vị trí của keyword trong text"""
        try:
            index = text.lower().find(keyword.lower())
            if index != -1:
                # Tìm context xung quanh keyword
                start = max(0, index - 20)
                end = min(len(text), index + len(keyword) + 20)
                context = text[start:end]
                return {
                    'index': index,
                    'context': context,
                    'start': start,
                    'end': end
                }
            return None
        except Exception:
            return None
    
    def get_explanation_summary(self, days=7):
        """Lấy tóm tắt explanations"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            recent_explanations = [
                exp for exp in self.explanation_history
                if datetime.fromisoformat(exp['timestamp']) > cutoff_date
            ]
            
            if not recent_explanations:
                return {
                    'total_explanations': 0,
                    'methods_used': [],
                    'avg_features_explained': 0
                }
            
            # Thống kê methods
            methods_used = set()
            total_features = 0
            
            for exp in recent_explanations:
                for method in exp['explanations'].keys():
                    methods_used.add(method)
                
                # Đếm features được explain
                if 'shap' in exp['explanations']:
                    total_features += len(exp['explanations']['shap'].get('feature_names', []))
                if 'lime' in exp['explanations']:
                    total_features += len(exp['explanations']['lime'].get('explanations', []))
            
            return {
                'total_explanations': len(recent_explanations),
                'methods_used': list(methods_used),
                'avg_features_explained': total_features / len(recent_explanations) if recent_explanations else 0,
                'period_days': days
            }
            
        except Exception as e:
            logger.error(f"Error getting explanation summary: {e}")
            return None

def test_explainability_engine():
    """Test explainability engine"""
    print("🧪 Testing Explainability Engine")
    print("=" * 40)
    
    # Tạo dummy model
    from sklearn.ensemble import IsolationForest
    from sklearn.datasets import make_blobs
    
    # Tạo dummy data
    X, y = make_blobs(n_samples=100, centers=2, random_state=42)
    
    # Train dummy model
    model = IsolationForest(random_state=42)
    model.fit(X)
    
    # Tạo explainability engine
    feature_names = [f'feature_{i}' for i in range(X.shape[1])]
    engine = ExplainabilityEngine(model=model, feature_names=feature_names)
    
    # Test single prediction explanation
    print("\n📊 Testing single prediction explanation")
    single_prediction = X[0]
    explanation = engine.explain_single_prediction(single_prediction)
    
    if explanation:
        print(f"   Methods available: {list(explanation.keys())}")
        if 'shap' in explanation:
            print(f"   SHAP explanation generated")
        if 'lime' in explanation:
            print(f"   LIME explanation generated")
    else:
        print("   No explanation generated")
    
    # Test feature importance
    print("\n📊 Testing feature importance")
    importance = engine.get_feature_importance_ranking(X[:10])
    if importance:
        print(f"   Top 3 features:")
        for i, feat in enumerate(importance[:3]):
            print(f"     {i+1}. {feat['feature']}: {feat['importance']:.4f}")
    else:
        print("   No feature importance available")
    
    # Test anomaly detection explanation
    print("\n📊 Testing anomaly detection explanation")
    log_entry = {
        'uri': '/login.php',
        'query_string': '?id=1 OR 1=1',
        'payload': 'id=1 OR 1=1',
        'user_agent': 'Mozilla/5.0...',
        'cookie': 'session=abc123'
    }
    
    anomaly_explanation = engine.explain_anomaly_detection(
        log_entry, 
        X[0], 
        model.decision_function(X[0].reshape(1, -1))[0]
    )
    
    if anomaly_explanation:
        print(f"   Prediction score: {anomaly_explanation['prediction_score']:.4f}")
        print(f"   Is anomaly: {anomaly_explanation['is_anomaly']}")
        if 'pattern_analysis' in anomaly_explanation:
            patterns = anomaly_explanation['pattern_analysis']
            print(f"   Detected patterns: {patterns['pattern_count']}")
            print(f"   Suspicious score: {patterns['suspicious_score']:.3f}")
    
    # Get summary
    summary = engine.get_explanation_summary()
    print(f"\n📈 Explanation Summary:")
    print(f"   Total explanations: {summary['total_explanations']}")
    print(f"   Methods used: {summary['methods_used']}")
    print(f"   Avg features explained: {summary['avg_features_explained']:.1f}")
    
    print("\n✅ Explainability engine test completed!")

if __name__ == "__main__":
    test_explainability_engine()

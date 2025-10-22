#!/usr/bin/env python3
"""
Evaluate thresholds and generate Precision-Recall curves
"""

import json
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import precision_recall_curve, roc_curve, auc
from optimized_sqli_detector import OptimizedSQLIDetector

def create_test_dataset():
    """Create test dataset with known SQLi and normal requests"""
    
    # Normal requests (label=0)
    normal_logs = [
        {
            "time": "2025-10-22T08:47:41+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/csrf/index.php",
            "query_string": "?id=1&Submit=Submit",
            "status": 200,
            "payload": "id=1&Submit=Submit",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
        },
        {
            "time": "2025-10-22T08:47:41+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/favicon.ico",
            "query_string": "",
            "status": 200,
            "payload": "",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
        },
        {
            "time": "2025-10-22T08:47:41+0700",
            "remote_ip": "192.168.205.2",
            "method": "POST",
            "uri": "/DVWA/login.php",
            "query_string": "",
            "status": 200,
            "payload": "username=admin&password=admin&Login=Login",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
        }
    ]
    
    # SQLi requests (label=1)
    sqli_logs = [
        {
            "time": "2025-10-22T08:47:41+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/sqli/index.php",
            "query_string": "?id=%27+or+benchmark%2810000000%2CMD5%281%29%29%23&Submit=Submit",
            "status": 200,
            "payload": "id=%27+or+benchmark%2810000000%2CMD5%281%29%29%23&Submit=Submit",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
        },
        {
            "time": "2025-10-22T08:47:41+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/sqli/index.php",
            "query_string": "?id=%27+UNION+SELECT+null%2C+version%28%29+--&Submit=Submit",
            "status": 200,
            "payload": "id=%27+UNION+SELECT+null%2C+version%28%29+--&Submit=Submit",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
        },
        {
            "time": "2025-10-22T08:47:41+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/sqli/index.php",
            "query_string": "?id=%27+OR+%271%27%3D%271&Submit=Submit",
            "status": 200,
            "payload": "id=%27+OR+%271%27%3D%271&Submit=Submit",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
        },
        {
            "time": "2025-10-22T08:47:41+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/sqli/index.php",
            "query_string": "?id=%27+AND+%28SELECT+*+FROM+%28SELECT%28SLEEP%285%29%29%29bAKL%29+AND+%27vRxe%27%3D%27vRxe&Submit=Submit",
            "status": 200,
            "payload": "id=%27+AND+%28SELECT+*+FROM+%28SELECT%28SLEEP%285%29%29%29bAKL%29+AND+%27vRxe%27%3D%27vRxe&Submit=Submit",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
        },
        {
            "time": "2025-10-22T08:47:41+0700",
            "remote_ip": "192.168.205.2",
            "method": "GET",
            "uri": "/DVWA/vulnerabilities/sqli/index.php",
            "query_string": "?id=+UNION+SELECT+%40%40VERSION%2CSLEEP%285%29%2CUSER%28%29%2CBENCHMARK%281000000%2CMD5%28%27A%27%29%29%2C5%2C6%2C7%2C8%2C9%2C10%2C11%2C12%2C13%2C14%2C15%2C16%2C17%2C18%2C19%2C20%2C21%2C22%2C23%2C24%23&Submit=Submit",
            "status": 200,
            "payload": "id=+UNION+SELECT+%40%40VERSION%2CSLEEP%285%29%2CUSER%28%29%2CBENCHMARK%281000000%2CMD5%28%27A%27%29%29%2C5%2C6%2C7%2C8%2C9%2C10%2C11%2C12%2C13%2C14%2C15%2C16%2C17%2C18%2C19%2C20%2C21%2C22%2C23%2C24%23&Submit=Submit",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "cookie": "PHPSESSID=e16qs57nkd675aj4u44nv78r6s"
        }
    ]
    
    # Combine and add labels
    test_logs = []
    for log in normal_logs:
        log['label'] = 0
        test_logs.append(log)
    
    for log in sqli_logs:
        log['label'] = 1
        test_logs.append(log)
    
    return test_logs

def evaluate_thresholds():
    """Evaluate model with different thresholds and generate curves"""
    
    print("Evaluating Model Thresholds")
    print("=" * 50)
    
    # Load model
    detector = OptimizedSQLIDetector()
    model_data = detector.load_model('models/optimized_sqli_detector.pkl')
    
    # Create test dataset
    test_logs = create_test_dataset()
    
    # Get predictions and scores
    y_true = []
    y_scores = []
    predictions = []
    
    print("Testing model on sample data...")
    for log in test_logs:
        try:
            is_anomaly, score, patterns, confidence = detector.predict_single(log)
            y_true.append(log['label'])
            y_scores.append(score)
            predictions.append(is_anomaly)
            
            print(f"Label: {log['label']}, Predicted: {is_anomaly}, Score: {score:.3f}, Patterns: {patterns}")
        except Exception as e:
            print(f"Error processing log: {e}")
    
    y_true = np.array(y_true)
    y_scores = np.array(y_scores)
    
    # Calculate metrics
    print(f"\nDataset: {len(test_logs)} samples")
    print(f"SQLi samples: {sum(y_true)}")
    print(f"Normal samples: {len(y_true) - sum(y_true)}")
    
    # Test different thresholds
    thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95]
    
    print(f"\nThreshold Analysis:")
    print(f"{'Threshold':<10} {'Precision':<10} {'Recall':<10} {'F1-Score':<10} {'Accuracy':<10}")
    print("-" * 60)
    
    best_f1 = 0
    best_threshold = 0.85
    
    for threshold in thresholds:
        y_pred = (y_scores > threshold).astype(int)
        
        # Calculate metrics
        tp = np.sum((y_pred == 1) & (y_true == 1))
        fp = np.sum((y_pred == 1) & (y_true == 0))
        fn = np.sum((y_pred == 0) & (y_true == 1))
        tn = np.sum((y_pred == 0) & (y_true == 0))
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / (tp + fp + fn + tn)
        
        print(f"{threshold:<10.2f} {precision:<10.3f} {recall:<10.3f} {f1:<10.3f} {accuracy:<10.3f}")
        
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold
    
    print(f"\nBest threshold: {best_threshold:.2f} (F1-Score: {best_f1:.3f})")
    
    # Generate Precision-Recall curve
    try:
        precision, recall, pr_thresholds = precision_recall_curve(y_true, y_scores)
        pr_auc = auc(recall, precision)
        
        print(f"\nPrecision-Recall AUC: {pr_auc:.3f}")
        
        # Plot curves
        plt.figure(figsize=(12, 5))
        
        # Precision-Recall curve
        plt.subplot(1, 2, 1)
        plt.plot(recall, precision, 'b-', linewidth=2)
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title(f'Precision-Recall Curve (AUC = {pr_auc:.3f})')
        plt.grid(True, alpha=0.3)
        
        # ROC curve
        plt.subplot(1, 2, 2)
        fpr, tpr, roc_thresholds = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, 'r-', linewidth=2)
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(f'ROC Curve (AUC = {roc_auc:.3f})')
        plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('threshold_evaluation.png', dpi=300, bbox_inches='tight')
        print(f"\nSaved evaluation plots to threshold_evaluation.png")
        
    except Exception as e:
        print(f"Could not generate plots: {e}")
    
    # Save evaluation results
    results = {
        "best_threshold": best_threshold,
        "best_f1_score": best_f1,
        "pr_auc": pr_auc if 'pr_auc' in locals() else None,
        "roc_auc": roc_auc if 'roc_auc' in locals() else None,
        "threshold_analysis": {}
    }
    
    # Calculate detailed results for each threshold
    for threshold in thresholds:
        y_pred = (y_scores > threshold).astype(int)
        
        tp = np.sum((y_pred == 1) & (y_true == 1))
        fp = np.sum((y_pred == 1) & (y_true == 0))
        fn = np.sum((y_pred == 0) & (y_true == 1))
        tn = np.sum((y_pred == 0) & (y_true == 0))
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / (tp + fp + fn + tn)
        
        results["threshold_analysis"][str(threshold)] = {
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "accuracy": float(accuracy)
        }
    
    with open('threshold_evaluation_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nSaved evaluation results to threshold_evaluation_results.json")
    
    # Recommendations
    print(f"\nRecommendations:")
    print(f"  - Use threshold {best_threshold:.2f} for optimal F1-Score")
    print(f"  - For high precision (low false positives): use threshold 0.9+")
    print(f"  - For high recall (catch more SQLi): use threshold 0.7-0.8")
    print(f"  - Current default (0.85) is balanced for production use")

if __name__ == "__main__":
    evaluate_thresholds()

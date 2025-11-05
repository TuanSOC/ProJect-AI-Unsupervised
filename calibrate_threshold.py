#!/usr/bin/env python3
"""
Calibrate decision_function threshold trên tập clean để đạt FPR mục tiêu.

Kết quả lưu vào models/optimized_sqli_metadata.json với khóa 'decision_threshold'.
"""

import json
import numpy as np
from optimized_sqli_detector import OptimizedSQLIDetector


def load_clean_logs(path):
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def main():
    data_path = 'sqli_logs_clean_100k.jsonl'
    target_fpr = 0.01  # 1%

    detector = OptimizedSQLIDetector()
    detector.load_model('models/optimized_sqli_detector.pkl')

    scores = []
    sample_size = 10000  # Sample để tính nhanh hơn
    for i, log in enumerate(load_clean_logs(data_path)):
        if i >= sample_size:
            break
        # Tái sử dụng pipeline: trích xuất → scale → decision_function
        feats = detector.extract_optimized_features(log)
        import pandas as pd
        df = pd.DataFrame([feats])
        X = df[detector.feature_names].fillna(0)
        Xs = detector.scaler.transform(X)
        sc = detector.isolation_forest.decision_function(Xs)[0]
        scores.append(sc)

    scores = np.array(scores)
    # anomalies khi score < threshold; để false positives ~ target_fpr trên clean,
    # chọn ngưỡng là quantile ở mức target_fpr (score âm càng sâu = càng anomalous)
    # Nhưng clean logs thường có score dương, nên cần dùng percentile cao hơn
    # Ví dụ: nếu muốn FPR 1%, dùng 1st percentile (score âm nhất của clean logs)
    decision_threshold = float(np.quantile(scores, target_fpr))
    
    # Nếu threshold quá thấp (âm sâu), có thể dùng 95th percentile để conservative hơn
    # Clean logs có score dương (0.099 trung bình), nên threshold nên là giá trị âm nhẹ hoặc dương
    # Thử dùng 95th percentile để đảm bảo chỉ detect khi score thực sự thấp
    conservative_threshold = float(np.percentile(scores, 95))  # 95% clean logs có score < này

    # Tính thêm percentiles để tham khảo
    percentiles = {p: float(np.percentile(scores, p)) for p in [50, 90, 95, 97.5, 99, 99.5]}
    
    # Chọn threshold: Isolation Forest - negative scores = anomalies
    # Clean logs có score dương (0.099 trung bình), anomalies có score âm
    # Để FPR 1%, tìm 1st percentile (score thấp nhất của 1% clean logs)
    # Nếu 1st percentile là âm, dùng nó; nếu dương, dùng 0.0 hoặc giá trị âm nhỏ
    first_percentile = float(np.percentile(scores, 1))
    
    # Nếu 1st percentile là âm, dùng nó (chỉ detect khi score < 1st percentile)
    # Nếu dương, dùng giá trị âm nhỏ để conservative hơn
    if first_percentile < 0:
        final_threshold = first_percentile
    else:
        # Nếu 1st percentile dương, dùng giá trị âm nhỏ (ví dụ -0.05)
        # Hoặc dùng 0.0 (chỉ detect khi score < 0)
        final_threshold = -0.05  # Conservative: chỉ detect khi score âm rõ ràng

    # Ghi vào JSON metadata
    meta_path = 'models/optimized_sqli_metadata.json'
    try:
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)
        except FileNotFoundError:
            meta = {}
        meta['decision_threshold'] = final_threshold
        meta['clean_score_percentiles'] = percentiles
        meta['alternative_thresholds'] = {
            'target_fpr_1pct': decision_threshold,
            'conservative_95pct': conservative_threshold,
            'final_99pct': final_threshold
        }
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        print(json.dumps({
            'decision_threshold_final': final_threshold,
            'target_fpr_1pct': decision_threshold,
            'conservative_95pct': conservative_threshold,
            'percentiles': percentiles
        }, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({'error': str(e)}))


if __name__ == '__main__':
    main()





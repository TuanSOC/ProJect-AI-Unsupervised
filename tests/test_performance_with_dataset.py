#!/usr/bin/env python3
"""
Test hiệu suất với test dataset: 1000 logs (400 SQLi + 600 clean)
"""

import json
import time
import os
from optimized_sqli_detector import OptimizedSQLIDetector
from collections import defaultdict

def iter_jsonl(path):
    """Đọc JSONL file"""
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
    print("=" * 80)
    print("AI SQLi Detection Performance Test")
    print("=" * 80)
    
    # Load model
    print("\nLoading AI model...")
    detector = OptimizedSQLIDetector()
    detector.load_model('models/optimized_sqli_detector.pkl')
    
    if hasattr(detector, 'decision_threshold') and detector.decision_threshold is not None:
        print(f"[OK] Decision threshold: {detector.decision_threshold}")
    
    # Load test dataset
    test_file = "test_dataset_5000.jsonl"
    if not os.path.exists(test_file):
        test_file = "test_dataset_1000.jsonl"  # Fallback to old dataset
    print(f"\nLoading test dataset from {test_file}...")
    
    sqli_logs = []
    clean_logs = []
    
    # Phân loại logs (dựa vào payload có chứa SQLi patterns - decode trước)
    from optimized_sqli_detector import url_decode_safe
    import base64
    import urllib.parse
    
    def decode_base64_safe(s):
        try:
            if len(s) > 4:
                # Xử lý padding và space
                s = s.strip().replace(' ', '')
                # Xử lý +NTA padding
                if '+' in s and len(s) > 10:
                    last_plus_idx = s.rfind('+')
                    if last_plus_idx > 0:
                        after_plus = s[last_plus_idx + 1:]
                        if after_plus and (after_plus.isalnum() or len(after_plus) <= 5):
                            s = s[:last_plus_idx]
                # Add padding if needed
                missing_padding = len(s) % 4
                if missing_padding:
                    s += '=' * (4 - missing_padding)
                decoded = base64.b64decode(s, validate=False)
                return decoded.decode('utf-8', errors='ignore')
        except:
            pass
        return s
    
    sqli_patterns = ['union', 'select', 'or 1=1', 'and 1=1', 'sleep', 'waitfor', 
                     'benchmark', 'drop table', 'delete from', 'insert into', 'update set',
                     'information_schema', 'exec', 'xp_cmdshell', '$where', '$ne', '$gt', '$regex',
                     'ascii', 'substring', 'select password', 'from users', 'and ascii', 'and substring']
    
    for log in iter_jsonl(test_file):
        # Ưu tiên: dùng label _is_sqli nếu có
        if '_is_sqli' in log:
            has_sqli = log['_is_sqli']
        else:
            # Decode tất cả fields trước khi check
            raw_qs = log.get('query_string', '')
            raw_payload = log.get('payload', '')
            raw_body = log.get('body', '')
            raw_cookie = log.get('cookie', '')
            
            # URL decode
            decoded_qs = url_decode_safe(raw_qs)
            decoded_payload = url_decode_safe(raw_payload)
            decoded_body = url_decode_safe(raw_body)
            decoded_cookie = url_decode_safe(raw_cookie)
            
            # Double decode
            decoded_qs = url_decode_safe(decoded_qs)
            decoded_payload = url_decode_safe(decoded_payload)
            decoded_body = url_decode_safe(decoded_body)
            
            # Base64 decode nếu có (multi-pass decode)
            # Query string
            if '=' in decoded_qs:
                parts = decoded_qs.split('=', 1)
                if len(parts) > 1:
                    base64_part = parts[1].split('&')[0]
                    if len(base64_part) > 4:
                        decoded_base64 = decode_base64_safe(base64_part)
                        if decoded_base64 != base64_part:
                            decoded_qs += ' ' + decoded_base64
                            # Check nested base64
                            if len(decoded_base64) > 4:
                                nested = decode_base64_safe(decoded_base64)
                                if nested != decoded_base64:
                                    decoded_qs += ' ' + nested
            
            # Payload
            if '=' in decoded_payload:
                parts = decoded_payload.split('=', 1)
                if len(parts) > 1:
                    base64_part = parts[1].split('&')[0]
                    # Xử lý +NTA padding
                    original_base64_part = base64_part
                    if (' ' in base64_part or '+' in base64_part) and len(base64_part) > 10:
                        last_space_idx = base64_part.rfind(' ')
                        last_plus_idx = base64_part.rfind('+')
                        last_sep_idx = max(last_space_idx, last_plus_idx)
                        if last_sep_idx > 0:
                            after_sep = base64_part[last_sep_idx + 1:].strip()
                            if after_sep and (after_sep.isalnum() or len(after_sep) <= 5):
                                base64_part = base64_part[:last_sep_idx].strip()
                    if len(base64_part) > 4:
                        decoded_base64 = decode_base64_safe(base64_part)
                        if decoded_base64 != base64_part:
                            decoded_payload += ' ' + decoded_base64
                            # Check nested base64
                            if len(decoded_base64) > 4:
                                nested = decode_base64_safe(decoded_base64)
                                if nested != decoded_base64:
                                    decoded_payload += ' ' + nested
            
            # Kiểm tra xem có SQLi không (trong decoded content)
            text_content = f"{decoded_qs} {decoded_payload} {decoded_body} {decoded_cookie}".lower()
            has_sqli = any(pattern in text_content for pattern in sqli_patterns)
        
        if has_sqli:
            sqli_logs.append(log)
        else:
            clean_logs.append(log)
    
    print(f"   - SQLi logs: {len(sqli_logs)}")
    print(f"   - Clean logs: {len(clean_logs)}")
    print(f"   - Total: {len(sqli_logs) + len(clean_logs)}")
    
    # Test SQLi detection (Recall)
    print("\n" + "=" * 80)
    print("Testing Recall on SQLi attacks...")
    print("=" * 80)
    
    detected_sqli = 0
    missed_sqli = []
    sqli_detection_details = defaultdict(int)
    
    t0 = time.time()
    for log in sqli_logs:
        is_sqli, score, patterns, confidence = detector.predict_single(log)
        if is_sqli:
            detected_sqli += 1
            sqli_detection_details[confidence] += 1
        else:
            if len(missed_sqli) < 10:
                missed_sqli.append({
                    "uri": log.get('uri', '')[:100],
                    "query": log.get('query_string', '')[:100],
                    "payload": log.get('payload', '')[:100],
                    "body": log.get('body', '')[:100],
                    "cookie": log.get('cookie', '')[:100],
                    "score": round(score, 4),
                    "confidence": confidence
                })
    
    sqli_time = time.time() - t0
    recall = (detected_sqli / len(sqli_logs)) * 100 if len(sqli_logs) > 0 else 0.0
    
    # Test Clean logs (FPR)
    print("\n" + "=" * 80)
    print("Testing FPR on clean logs...")
    print("=" * 80)
    
    false_positives = 0
    clean_detection_details = defaultdict(int)
    
    t0 = time.time()
    for log in clean_logs:
        is_sqli, score, patterns, confidence = detector.predict_single(log)
        if is_sqli:
            false_positives += 1
            clean_detection_details[confidence] += 1
    
    clean_time = time.time() - t0
    fpr = (false_positives / len(clean_logs)) * 100 if len(clean_logs) > 0 else 0.0
    
    # Calculate metrics
    total_logs = len(sqli_logs) + len(clean_logs)
    total_time = sqli_time + clean_time
    qps = total_logs / total_time if total_time > 0 else 0.0
    
    true_positives = detected_sqli
    false_negatives = len(sqli_logs) - detected_sqli
    true_negatives = len(clean_logs) - false_positives
    
    precision = (true_positives / (true_positives + false_positives)) * 100 if (true_positives + false_positives) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    # Results
    print("\n" + "=" * 80)
    print("PERFORMANCE SUMMARY")
    print("=" * 80)
    
    results = {
        "recall": {
            "total_sqli": len(sqli_logs),
            "detected": detected_sqli,
            "missed": len(sqli_logs) - detected_sqli,
            "recall_percent": round(recall, 2),
            "duration_sec": round(sqli_time, 3),
            "qps": round(len(sqli_logs) / sqli_time, 2) if sqli_time > 0 else 0.0,
            "confidence_breakdown": dict(sqli_detection_details)
        },
        "fpr": {
            "total_clean": len(clean_logs),
            "false_positives": false_positives,
            "false_positive_rate_percent": round(fpr, 2),
            "duration_sec": round(clean_time, 3),
            "qps": round(len(clean_logs) / clean_time, 2) if clean_time > 0 else 0.0,
            "confidence_breakdown": dict(clean_detection_details)
        },
        "overall": {
            "total_logs": total_logs,
            "duration_sec": round(total_time, 3),
            "qps": round(qps, 2),
            "avg_latency_ms": round((total_time / total_logs) * 1000, 3) if total_logs > 0 else 0.0,
            "precision_percent": round(precision, 2),
            "recall_percent": round(recall, 2),
            "f1_score": round(f1_score, 2)
        }
    }
    
    print("\n" + json.dumps(results, indent=2, ensure_ascii=False))
    
    # Missed cases
    if missed_sqli:
        print("\n" + "=" * 80)
        print("SAMPLE MISSED SQLi CASES (first 10)")
        print("=" * 80)
        for i, case in enumerate(missed_sqli[:10], 1):
            print(f"\n[{i}] Score: {case['score']}, Confidence: {case['confidence']}")
            print(f"    URI: {case['uri']}")
            print(f"    Query: {case['query']}")
            print(f"    Payload: {case['payload']}")
            print(f"    Body: {case['body']}")
            print(f"    Cookie: {case['cookie']}")
    
    # Final assessment
    print("\n" + "=" * 80)
    print("FINAL ASSESSMENT")
    print("=" * 80)
    
    if recall >= 99.5:
        print(f"[OK] Recall: {recall:.2f}% - EXCELLENT (>= 99.5%)")
    elif recall >= 95.0:
        print(f"[WARN] Recall: {recall:.2f}% - GOOD (>= 95%)")
    else:
        print(f"[FAIL] Recall: {recall:.2f}% - NEEDS IMPROVEMENT (< 95%)")
    
    if fpr < 1.0:
        print(f"[OK] FPR: {fpr:.2f}% - EXCELLENT (< 1%)")
    elif fpr < 5.0:
        print(f"[WARN] FPR: {fpr:.2f}% - GOOD (< 5%)")
    else:
        print(f"[FAIL] FPR: {fpr:.2f}% - NEEDS IMPROVEMENT (> 5%)")
    
    if precision >= 95.0:
        print(f"[OK] Precision: {precision:.2f}% - EXCELLENT (>= 95%)")
    elif precision >= 90.0:
        print(f"[WARN] Precision: {precision:.2f}% - GOOD (>= 90%)")
    else:
        print(f"[FAIL] Precision: {precision:.2f}% - NEEDS IMPROVEMENT (< 90%)")
    
    if f1_score >= 95.0:
        print(f"[OK] F1-Score: {f1_score:.2f}% - EXCELLENT (>= 95%)")
    elif f1_score >= 90.0:
        print(f"[WARN] F1-Score: {f1_score:.2f}% - GOOD (>= 90%)")
    else:
        print(f"[FAIL] F1-Score: {f1_score:.2f}% - NEEDS IMPROVEMENT (< 90%)")
    
    if qps >= 50:
        print(f"[OK] Throughput: {qps:.2f} QPS - EXCELLENT (>= 50 QPS)")
    elif qps >= 30:
        print(f"[WARN] Throughput: {qps:.2f} QPS - GOOD (>= 30 QPS)")
    else:
        print(f"[FAIL] Throughput: {qps:.2f} QPS - NEEDS IMPROVEMENT (< 30 QPS)")
    
    print("=" * 80)

if __name__ == '__main__':
    main()


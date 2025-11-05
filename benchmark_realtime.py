#!/usr/bin/env python3
"""
Benchmark realtime: stream logs qua predict_single và đo QPS/latency.
"""
import time
import json
import os
from statistics import mean
from optimized_sqli_detector import OptimizedSQLIDetector


def iter_jsonl(path):
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def percentile(values, p):
    if not values:
        return 0.0
    values_sorted = sorted(values)
    k = (len(values_sorted) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(values_sorted) - 1)
    if f == c:
        return values_sorted[int(k)]
    d0 = values_sorted[f] * (c - k)
    d1 = values_sorted[c] * (k - f)
    return d0 + d1


def main():
    model_path = 'models/optimized_sqli_detector.pkl'
    data_path = 'test_dataset_5000.jsonl'
    if not os.path.exists(data_path):
        data_path = 'test_dataset_1000.jsonl'

    print("=" * 80)
    print("Realtime Detection Benchmark")
    print("=" * 80)

    detector = OptimizedSQLIDetector()
    detector.load_model(model_path)

    # Warm-up
    warmup = {
        "method": "GET",
        "uri": "/",
        "query_string": "id=1",
        "payload": "",
        "body": "",
        "cookie": "session=abc",
        "status": 200,
        "bytes_sent": 0,
        "response_time_ms": 0,
        "request_length": 0,
        "response_length": 0,
        "user_agent": "UA"
    }
    for _ in range(50):
        detector.predict_single(warmup)

    latencies_ms = []
    total = 0
    detected = 0

    t0 = time.time()
    for log in iter_jsonl(data_path):
        ts = time.perf_counter()
        is_sqli, score, patterns, confidence = detector.predict_single(log)
        te = time.perf_counter()
        latencies_ms.append((te - ts) * 1000.0)
        total += 1
        if is_sqli:
            detected += 1
    t1 = time.time()

    dur = t1 - t0
    qps = total / dur if dur > 0 else 0.0

    p50 = percentile(latencies_ms, 50)
    p95 = percentile(latencies_ms, 95)
    p99 = percentile(latencies_ms, 99)
    avg = mean(latencies_ms) if latencies_ms else 0.0

    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)
    print(json.dumps({
        "dataset": os.path.basename(data_path),
        "total_logs": total,
        "qps": round(qps, 2),
        "avg_latency_ms": round(avg, 3),
        "p50_ms": round(p50, 3),
        "p95_ms": round(p95, 3),
        "p99_ms": round(p99, 3),
        "detected_ratio_percent": round((detected / total) * 100, 2) if total else 0.0
    }, indent=2))


if __name__ == '__main__':
    main()



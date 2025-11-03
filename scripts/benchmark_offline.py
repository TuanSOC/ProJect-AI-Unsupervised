#!/usr/bin/env python3
"""
Benchmark hiệu suất detect trên file log JSONL (Apache full JSON).

Ví dụ:
  python scripts/benchmark_offline.py --log /var/log/apache2/access_full_json.log --bundle deployed.joblib
"""

import argparse
import json
import re
import time
from pathlib import Path

import numpy as np

from joblib import load


def load_bundle(path: str):
    return load(path)


def is_skip(log: dict) -> bool:
    uri = str(log.get("uri", "")).lower()
    method = str(log.get("method", "")).strip()
    try:
        status = int(log.get("status", 0) or 0)
    except Exception:
        status = 0

    if method in {"", "-"}:
        return True
    if status == 408:
        return True
    # common static assets
    if any(p in uri for p in ["/css/", "/js/", "/images/", "/favicon.ico", "/sitemap.xml", "/dvwa/js", "/dvwa/images"]):
        return True
    if re.search(r"\.(css|js|png|jpg|jpeg|gif|ico|svg|map|woff2?)$", uri):
        return True
    return False


def build_row(log: dict) -> dict:
    qs = str(log.get('query_string', ''))
    payload = str(log.get('payload', ''))
    combined = f"{qs} {payload}".strip()
    request_length = int(log.get('request_length', 0) or 0)
    response_time_ms = int(log.get('response_time_ms', 0) or 0)

    def special_char_ratio(text: str) -> float:
        if not text:
            return 0.0
        specials = "%'\";#-*/()=<>&"
        total = max(len(text), 1)
        return sum(1 for ch in text if ch in specials) / total

    def num_params(qs_: str) -> int:
        if not qs_:
            return 0
        return qs_.count('&') + (1 if '=' in qs_ else 0)

    def entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(s)
        ent = 0.0
        for c in freq.values():
            p = c / n
            ent -= p * np.log2(p)
        return float(ent)

    def count_sql_keywords(text: str) -> int:
        t = (text or '').lower()
        kws = [
            'union', 'select', 'insert', 'update', 'delete', 'drop',
            'information_schema', 'load_file', 'into outfile', 'exec', 'execute',
            'version(', 'user(', 'database(', 'concat(', 'char(', 'ascii(', 'substring('
        ]
        return sum(1 for k in kws if k in t)

    return {
        'combined_text': combined,
        'request_length': request_length,
        'response_time_ms': response_time_ms,
        'special_char_ratio': special_char_ratio(combined),
        'num_sql_keywords': count_sql_keywords(combined),
        'num_params': num_params(qs),
        'entropy_query': entropy(qs),
        'entropy_payload': entropy(payload),
    }


def rule_score(text: str, strong_tokens, time_tokens) -> float:
    if not text:
        return 0.0
    t = text.lower()
    sc = 0
    if any(tok in t for tok in strong_tokens):
        sc += 1
    if any(tok in t for tok in time_tokens):
        sc += 1
    return min(sc, 2) / 2.0


def detect_one(log: dict, bundle) -> dict:
    # Build features
    row = build_row(log)
    import pandas as pd
    df = pd.DataFrame([row])
    preproc = bundle['preproc']
    clf = bundle['clf']
    p95 = float(bundle['p95']) or 1.0
    best_threshold = float(bundle['threshold'])
    X = preproc.transform(df)
    raw = -clf.score_samples(X)[0]
    norm = float(np.clip(raw / p95, 0.0, 1.0))
    combined_text = str(log.get('query_string', '')) + ' ' + str(log.get('payload', ''))
    rscore = rule_score(combined_text, bundle['rule_tokens_strong'], bundle['rule_tokens_time'])
    final_score = 0.7 * norm + 0.3 * rscore
    norm_th = float(np.clip(best_threshold / p95, 0.0, 1.0))
    final_th = max(0.5, norm_th)
    return {
        'is_sqli': bool(final_score >= final_th),
        'final_score': float(final_score)
    }


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', required=True, help='Đường dẫn file log JSONL (Apache full JSON)')
    ap.add_argument('--bundle', default='deployed.joblib', help='Đường dẫn deployed bundle')
    return ap.parse_args()


def main():
    args = parse_args()
    bundle = load_bundle(args.bundle)

    total = 0; skipped = 0; processed = 0; detected = 0
    times = []
    p = Path(args.log)
    with p.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith('{'):
                continue
            try:
                log = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            if is_skip(log):
                skipped += 1
                continue
            t0 = time.perf_counter()
            res = detect_one(log, bundle)
            dt = (time.perf_counter() - t0) * 1000.0
            times.append(dt)
            processed += 1
            if res.get('is_sqli', False):
                detected += 1

    if processed == 0:
        print(json.dumps({
            'total_lines': total,
            'skipped': skipped,
            'processed': processed,
            'error': 'no processed lines'
        }, ensure_ascii=False, indent=2))
        return

    arr = np.array(times, dtype=float)
    report = {
        'total_lines': total,
        'skipped': skipped,
        'processed': processed,
        'sqli_detected': detected,
        'detection_rate': round(detected / processed, 4),
        'avg_ms': round(arr.mean(), 3),
        'p50_ms': round(np.percentile(arr, 50), 3),
        'p90_ms': round(np.percentile(arr, 90), 3),
        'p95_ms': round(np.percentile(arr, 95), 3),
        'max_ms': round(arr.max(), 3),
        'throughput_logs_per_sec': round(1000.0 / arr.mean(), 2)
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()



#!/usr/bin/env python3
"""
Runtime detector: load deployed.joblib (preproc, IsolationForest, threshold) và
thực hiện ensemble điểm bất thường + rule-based để quyết định SQLi.

Sử dụng:
  python scripts/runtime_detector.py --log '{"uri":"/DVWA/...","query_string":"..."}'
  python scripts/runtime_detector.py --file sample_log.json
"""

import json
import sys
import math
import argparse
from typing import Dict, Any, List

import numpy as np
from joblib import load


def load_bundle(path: str = 'deployed.joblib') -> Dict[str, Any]:
    bundle = load(path)
    required = ['preproc', 'clf', 'p95', 'threshold', 'rule_tokens_strong', 'rule_tokens_time', 'text_col']
    for k in required:
        if k not in bundle:
            raise RuntimeError(f"Missing '{k}' in deployed bundle")
    return bundle


def build_row(log: Dict[str, Any]) -> Dict[str, Any]:
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
        cnt = sum(1 for ch in text if ch in specials)
        return cnt / total

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
            ent -= p * math.log2(p)
        return ent

    def count_sql_keywords(text: str) -> int:
        t = (text or '').lower()
        kws = [
            'union', 'select', 'insert', 'update', 'delete', 'drop',
            'information_schema', 'load_file', 'into outfile', 'exec', 'execute',
            'version(', 'user(', 'database(', 'concat(', 'char(', 'ascii(', 'substring('
        ]
        return sum(1 for k in kws if k in t)

    row = {
        'combined_text': combined,
        'request_length': request_length,
        'response_time_ms': response_time_ms,
        'special_char_ratio': special_char_ratio(combined),
        'num_sql_keywords': count_sql_keywords(combined),
        'num_params': num_params(qs),
        'entropy_query': entropy(qs),
        'entropy_payload': entropy(payload),
    }
    return row


def rule_score(text: str, strong_tokens: List[str], time_tokens: List[str]) -> float:
    if not text:
        return 0.0
    t = text.lower()
    score = 0
    if any(tok in t for tok in strong_tokens):
        score += 1
    if any(tok in t for tok in time_tokens):
        score += 1
    return min(score, 2) / 2.0  # 0.0, 0.5, 1.0


def detect(log: Dict[str, Any], bundle: Dict[str, Any]) -> Dict[str, Any]:
    row = build_row(log)
    preproc = bundle['preproc']
    clf = bundle['clf']
    p95 = float(bundle['p95']) or 1.0
    best_threshold = float(bundle['threshold'])
    txt_col = bundle['text_col']

    import pandas as pd
    df = pd.DataFrame([row])
    X = preproc.transform(df)

    # Raw anomaly score (higher = more anomalous)
    raw = -clf.score_samples(X)[0]
    norm = float(np.clip(raw / p95, 0.0, 1.0))

    # Rule-based support
    combined_text = str(log.get('query_string', '')) + ' ' + str(log.get('payload', ''))
    rscore = rule_score(combined_text, bundle['rule_tokens_strong'], bundle['rule_tokens_time'])

    final_score = 0.7 * norm + 0.3 * rscore
    # Convert best_threshold (raw) to normalized domain for decision reference
    norm_threshold = float(np.clip(best_threshold / p95, 0.0, 1.0))
    # Final decision threshold (slightly above calibrated raw threshold mapping)
    final_threshold = max(0.5, norm_threshold)
    is_sqli = final_score >= final_threshold

    return {
        'is_sqli': bool(is_sqli),
        'final_score': float(final_score),
        'final_threshold': float(final_threshold),
        'raw_anomaly': float(raw),
        'raw_threshold': float(best_threshold),
        'normalized_score': float(norm),
        'normalized_threshold': float(norm_threshold),
        'rule_score': float(rscore)
    }


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', type=str, help='JSON string of a single log entry')
    ap.add_argument('--file', type=str, help='Path to a JSON file containing one log object')
    ap.add_argument('--bundle', type=str, default='deployed.joblib', help='Path to deployed bundle')
    return ap.parse_args()


def main():
    args = parse_args()
    bundle = load_bundle(args.bundle)

    if not args.log and not args.file:
        print(json.dumps({'error': 'Provide --log or --file'}, ensure_ascii=False))
        sys.exit(1)

    if args.log:
        try:
            log = json.loads(args.log)
        except json.JSONDecodeError as e:
            print(json.dumps({'error': f'Invalid JSON: {e}'}))
            sys.exit(1)
    else:
        with open(args.file, 'r', encoding='utf-8') as f:
            log = json.load(f)

    result = detect(log, bundle)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()



#!/usr/bin/env python3
"""
Evaluate detector (IsolationForest + ensemble) trên clean vs synthetic attacks.

Outputs:
- F1@calibrated_threshold, Precision/Recall at several points
- TPR @ target FPR levels
- Summary JSON

Usage:
  python scripts/evaluate_detector.py --clean sqli_logs_clean_100k.jsonl --bundle deployed.joblib
"""

import os
import json
import math
import argparse
from typing import Dict, Any, List, Tuple

import numpy as np
import pandas as pd
from joblib import load
from sklearn.metrics import precision_recall_curve, f1_score, confusion_matrix


def generate_synthetic_attacks(n: int = 1000) -> pd.DataFrame:
    base_patterns = [
        "' OR '1'='1", "admin' --", "UNION SELECT NULL,NULL",
        "UNION SELECT username,password FROM users",
        "sleep(5)", "benchmark(1000000,MD5(1))",
        "LOAD_FILE('/etc/passwd')",
        "INTO OUTFILE '/var/www/html/shell.php'",
        "1; DROP TABLE users;",
        "or 1=1-- -",
        "concat(char(0x75,0x6e,0x69,0x6f,0x6e),' select')"
    ]
    rows: List[Dict] = []
    rng = np.random.default_rng(42)
    for _ in range(n):
        p = base_patterns[int(rng.integers(0, len(base_patterns)))]
        qs = f"id={rng.integers(1,999)}&q={p}"
        payload = f"id={rng.integers(1,999)}&payload={p}"
        rows.append({
            'query_string': qs,
            'payload': payload,
            'request_length': len(qs) + len(payload),
            'response_time_ms': int(rng.choice([60, 120, 200, 350, 600]))
        })
    return pd.DataFrame(rows)


def build_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for col in ['query_string', 'payload', 'request_length', 'response_time_ms']:
        if col not in out.columns:
            out[col] = 0 if col in ['request_length', 'response_time_ms'] else ''
    def special_char_ratio(text: str) -> float:
        if not text:
            return 0.0
        specials = "%'\";#-*/()=<>&"
        total = max(len(text), 1)
        return sum(1 for ch in text if ch in specials) / total
    def num_params(qs: str) -> int:
        if not qs:
            return 0
        return qs.count('&') + (1 if '=' in qs else 0)
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
    out['combined_text'] = (out['query_string'].astype(str) + ' ' + out['payload'].astype(str)).fillna('')
    out['request_length'] = pd.to_numeric(out['request_length'], errors='coerce').fillna(0)
    out['response_time_ms'] = pd.to_numeric(out['response_time_ms'], errors='coerce').fillna(0)
    out['special_char_ratio'] = out['combined_text'].apply(special_char_ratio)
    out['num_sql_keywords'] = out['combined_text'].apply(count_sql_keywords)
    out['num_params'] = out['query_string'].astype(str).apply(num_params)
    out['entropy_query'] = out['query_string'].astype(str).apply(entropy)
    out['entropy_payload'] = out['payload'].astype(str).apply(entropy)
    return out


def load_clean_jsonl(path: str, sample: int = 2000) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    with open(path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            rows.append(obj)
    if sample and len(rows) > sample:
        rng = np.random.default_rng(42)
        idx = rng.choice(len(rows), size=sample, replace=False)
        rows = [rows[i] for i in idx]
    return pd.DataFrame(rows)


def rule_score(text: str, strong_tokens: List[str], time_tokens: List[str]) -> float:
    t = (text or '').lower()
    sc = 0
    if any(tok in t for tok in strong_tokens):
        sc += 1
    if any(tok in t for tok in time_tokens):
        sc += 1
    return min(sc, 2) / 2.0


def eval_bundle(df_clean: pd.DataFrame, df_att: pd.DataFrame, bundle_path: str) -> Dict[str, Any]:
    bundle = load(bundle_path)
    preproc = bundle['preproc']
    clf = bundle['clf']
    p95 = float(bundle['p95']) or 1.0
    best_threshold = float(bundle['threshold'])

    Xc = preproc.transform(build_dataframe(df_clean))
    Xa = preproc.transform(build_dataframe(df_att))

    s_clean_raw = -clf.score_samples(Xc)
    s_att_raw = -clf.score_samples(Xa)

    # Ensemble
    norm_clean = np.clip(s_clean_raw / p95, 0.0, 1.0)
    norm_att = np.clip(s_att_raw / p95, 0.0, 1.0)

    strong = bundle['rule_tokens_strong']
    time_t = bundle['rule_tokens_time']
    txt_clean = (df_clean['query_string'].astype(str) + ' ' + df_clean['payload'].astype(str)).tolist()
    txt_att = (df_att['query_string'].astype(str) + ' ' + df_att['payload'].astype(str)).tolist()
    r_clean = np.array([rule_score(t, strong, time_t) for t in txt_clean])
    r_att = np.array([rule_score(t, strong, time_t) for t in txt_att])

    f_clean = 0.7 * norm_clean + 0.3 * r_clean
    f_att = 0.7 * norm_att + 0.3 * r_att

    # Map raw threshold to normalized and choose final
    norm_th = float(np.clip(best_threshold / p95, 0.0, 1.0))
    final_th = max(0.5, norm_th)

    y_true = np.concatenate([np.zeros_like(f_clean), np.ones_like(f_att)])
    scores = np.concatenate([f_clean, f_att])
    y_pred = (scores >= final_th).astype(int)

    # Metrics
    pr, rc, ths = precision_recall_curve(y_true, scores)
    f1s = 2 * (pr * rc) / (pr + rc + 1e-12)
    best_i = int(np.argmax(f1s))
    f1_at_final = f1_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred).tolist()

    # TPR @ FPR targets
    # Compute FPR/TPR by sweeping thresholds
    tprs = {}
    fpr_targets = [1e-3, 1e-2, 5e-2]
    for target in fpr_targets:
        best_t = None
        best_diff = 1e9
        for t in ths:
            yp = (scores >= t).astype(int)
            tn = int(((y_true == 0) & (yp == 0)).sum())
            fp = int(((y_true == 0) & (yp == 1)).sum())
            tp = int(((y_true == 1) & (yp == 1)).sum())
            fn = int(((y_true == 1) & (yp == 0)).sum())
            fpr = fp / max(fp + tn, 1)
            tpr = tp / max(tp + fn, 1)
            diff = abs(fpr - target)
            if diff < best_diff:
                best_diff = diff
                best_t = (t, tpr, fpr)
        if best_t:
            tprs[str(target)] = {'threshold': float(best_t[0]), 'tpr': float(best_t[1]), 'fpr': float(best_t[2])}

    return {
        'final_threshold': float(final_th),
        'norm_threshold': float(norm_th),
        'f1_at_final': float(f1_at_final),
        'best_f1': float(f1s[best_i]) if len(f1s) else None,
        'precision_at_best': float(pr[best_i]) if len(pr) else None,
        'recall_at_best': float(rc[best_i]) if len(rc) else None,
        'confusion_matrix': cm,
        'tpr_at_fpr': tprs,
        'sizes': {'clean': int(len(df_clean)), 'attacks': int(len(df_att))}
    }


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('--clean', type=str, default='sqli_logs_clean_100k.jsonl')
    ap.add_argument('--bundle', type=str, default='deployed.joblib')
    ap.add_argument('--sample_clean', type=int, default=2000)
    ap.add_argument('--attacks', type=int, default=1000)
    return ap.parse_args()


def main():
    args = parse_args()
    if not os.path.exists(args.clean):
        raise FileNotFoundError(args.clean)
    if not os.path.exists(args.bundle):
        raise FileNotFoundError(args.bundle)

    df_clean = load_clean_jsonl(args.clean, sample=args.sample_clean)
    df_att = generate_synthetic_attacks(n=args.attacks)

    report = eval_bundle(df_clean, df_att, args.bundle)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()



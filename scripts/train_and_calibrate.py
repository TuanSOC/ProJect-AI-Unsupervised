#!/usr/bin/env python3
"""
Train + Calibrate IsolationForest (unsupervised) on clean DVWA logs.

Chiến lược:
- Train trên 100% clean để học phân bố bình thường.
- Không dùng contamination để quyết định nhãn runtime; dùng score và calibrate threshold bằng bộ validation có inject tấn công synthetic.
- Kết hợp ensemble: IF score (normalized) + rule-based nhẹ (mạnh cho token SQLi).

Output: deployed.joblib chứa preproc, clf, p95, threshold, rule_tokens.
"""

import os
import json
import math
import random
from typing import List, Dict, Tuple

import numpy as np
import pandas as pd
from joblib import dump

from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.metrics import precision_recall_curve, f1_score


# ------------------------------
# Utilities
# ------------------------------

SQLI_TOKENS_STRONG = [
    "union select", "or 1=1", "and 1=1", "' or '", '" or "',
    "sleep(", "waitfor delay", "benchmark(", "information_schema",
    "load_file(", "into outfile", "xp_cmdshell", "sp_executesql",
    "; drop", "; delete", "--", "/*", "*/",
    # Overlong UTF-8 / evasion sequences commonly seen
    "%c0%ae", "%c1%9c", "%c0%af", "%c1%9d"
]

SQLI_TOKENS_TIME = ["sleep(", "waitfor delay", "benchmark("]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def count_sql_keywords(text: str) -> int:
    if not text:
        return 0
    t = text.lower()
    keywords = [
        "union", "select", "insert", "update", "delete", "drop",
        "information_schema", "load_file", "into outfile", "exec", "execute",
        "version(", "user(", "database(", "concat(", "char(", "ascii(", "substring("
    ]
    return sum(1 for k in keywords if k in t)


def special_char_ratio(text: str) -> float:
    if not text:
        return 0.0
    specials = "%'\";#-*/()=<>&"
    total = max(len(text), 1)
    count = sum(1 for ch in text if ch in specials)
    return count / total


def num_params(qs: str) -> int:
    if not qs:
        return 0
    return qs.count("&") + (1 if "=" in qs else 0)


def load_clean_jsonl(path: str, limit: int = None) -> pd.DataFrame:
    rows: List[Dict] = []
    with open(path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if limit is not None and i >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            rows.append(obj)
    df = pd.DataFrame(rows)
    return df


def build_dataframe_clean(df: pd.DataFrame) -> pd.DataFrame:
    df2 = df.copy()
    # Ensure required columns exist
    for col in [
        'query_string', 'payload', 'request_length', 'response_time_ms'
    ]:
        if col not in df2.columns:
            df2[col] = 0 if col in ['request_length', 'response_time_ms'] else ""

    # Derived numeric features
    df2['combined_text'] = (df2['query_string'].astype(str) + ' ' + df2['payload'].astype(str)).fillna('')
    df2['request_length'] = pd.to_numeric(df2['request_length'], errors='coerce').fillna(0)
    df2['response_time_ms'] = pd.to_numeric(df2['response_time_ms'], errors='coerce').fillna(0)
    df2['special_char_ratio'] = df2['combined_text'].astype(str).apply(special_char_ratio)
    df2['num_sql_keywords'] = df2['combined_text'].astype(str).apply(count_sql_keywords)
    df2['num_params'] = df2['query_string'].astype(str).apply(num_params)
    df2['entropy_query'] = df2['query_string'].astype(str).apply(shannon_entropy)
    df2['entropy_payload'] = df2['payload'].astype(str).apply(shannon_entropy)
    return df2


def generate_synthetic_attacks(n: int = 500) -> pd.DataFrame:
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
    for _ in range(n):
        p = random.choice(base_patterns)
        uri = "/DVWA/vulnerabilities/sqli/index.php"
        qs = f"id={random.randint(1,999)}&q={p}"
        payload = f"id={random.randint(1,999)}&payload={p}"
        rows.append({
            "query_string": qs,
            "payload": payload,
            "request_length": len(uri) + len(qs) + len(payload),
            "response_time_ms": random.choice([50, 80, 120, 200, 350, 600])
        })
    df = pd.DataFrame(rows)
    return build_dataframe_clean(df)


def build_preprocessor(text_col: str, numeric_cols: List[str]) -> ColumnTransformer:
    text_pipe = Pipeline([
        ('tfidf', TfidfVectorizer(analyzer='char', ngram_range=(3, 6), max_features=2000))
    ])
    num_pipe = Pipeline([
        ('scaler', RobustScaler())
    ])
    preproc = ColumnTransformer([
        ('txt', text_pipe, text_col),
        ('num', num_pipe, numeric_cols)
    ])
    return preproc


def select_numeric_cols() -> List[str]:
    return [
        'request_length', 'response_time_ms', 'special_char_ratio',
        'num_sql_keywords', 'num_params', 'entropy_query', 'entropy_payload'
    ]


def choose_threshold_by_f1(scores_clean: np.ndarray, scores_att: np.ndarray) -> float:
    y = np.concatenate([np.zeros_like(scores_clean), np.ones_like(scores_att)])
    scores = np.concatenate([scores_clean, scores_att])
    precision, recall, thresholds = precision_recall_curve(y, scores)
    f1_scores = 2 * (precision * recall) / (precision + recall + 1e-12)
    best_idx = int(np.argmax(f1_scores))
    best_t = float(thresholds[max(best_idx, 0)]) if thresholds.size > 0 else float(np.percentile(scores_clean, 99))
    return best_t


def main():
    random.seed(42)
    np.random.seed(42)

    data_path = 'sqli_logs_clean_100k.jsonl'
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Clean dataset not found: {data_path}")

    # Load clean data
    df_clean_raw = load_clean_jsonl(data_path)
    if df_clean_raw.empty:
        raise RuntimeError("Clean dataset is empty")

    # Build clean features
    df_clean = build_dataframe_clean(df_clean_raw)

    # Split train / val_clean
    idx = np.arange(len(df_clean))
    np.random.shuffle(idx)
    split = int(0.8 * len(idx))
    train_idx, val_idx = idx[:split], idx[split:]
    df_train_clean = df_clean.iloc[train_idx].reset_index(drop=True)
    df_val_clean = df_clean.iloc[val_idx].reset_index(drop=True)

    # Synthetic attacks for validation
    df_val_attacks = generate_synthetic_attacks(n=min(1000, max(300, len(df_val_clean)//2)))

    # Preprocessor
    numeric_cols = select_numeric_cols()
    preproc = build_preprocessor(text_col='combined_text', numeric_cols=numeric_cols)

    # Fit transform train
    X_train = preproc.fit_transform(df_train_clean)

    # IsolationForest config
    clf = IsolationForest(
        n_estimators=200,
        max_samples='auto',
        contamination='auto',  # threshold sẽ được calibrate ngoài
        max_features=1.0,
        n_jobs=-1,
        random_state=42
    )
    clf.fit(X_train)

    # Scores for validation
    X_val_clean = preproc.transform(df_val_clean)
    X_val_att = preproc.transform(df_val_attacks)

    # Trong sklearn: score_samples -> higher = more normal; ta muốn higher = more anomalous
    # Nên dùng negative của score_samples làm anomaly score
    scores_clean = -clf.score_samples(X_val_clean)
    scores_att = -clf.score_samples(X_val_att)

    # Calibration
    best_threshold = choose_threshold_by_f1(scores_clean, scores_att)
    p95 = float(np.percentile(scores_clean, 95))

    # Save deployed bundle
    deployed = {
        'preproc': preproc,
        'clf': clf,
        'p95': p95,
        'threshold': best_threshold,
        'rule_tokens_strong': SQLI_TOKENS_STRONG,
        'rule_tokens_time': SQLI_TOKENS_TIME,
        'numeric_cols': numeric_cols,
        'text_col': 'combined_text',
        'meta': {
            'train_size': int(len(df_train_clean)),
            'val_clean_size': int(len(df_val_clean)),
            'val_attacks_size': int(len(df_val_attacks)),
            'p95_clean': p95,
            'best_threshold': best_threshold,
        }
    }
    dump(deployed, 'deployed.joblib')

    # Quick report
    y = np.concatenate([np.zeros_like(scores_clean), np.ones_like(scores_att)])
    all_scores = np.concatenate([scores_clean, scores_att])
    preds = (all_scores >= best_threshold).astype(int)
    f1 = f1_score(y, preds)
    print(json.dumps({
        'status': 'ok',
        'saved': 'deployed.joblib',
        'val_sizes': {'clean': len(scores_clean), 'attacks': len(scores_att)},
        'p95_clean': p95,
        'best_threshold': best_threshold,
        'f1_val': f1
    }, indent=2))


if __name__ == '__main__':
    main()



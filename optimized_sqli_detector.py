#!/usr/bin/env python3
"""
Optimized SQLi Detector – mô-đun lõi AI không giám sát (Isolation Forest)

Chức năng chính:
- Trích xuất đặc trưng tối ưu từ log web (feature engineering hướng SQLi)
- Huấn luyện IsolationForest trên dữ liệu sạch (unsupervised)
- Dự đoán đơn lẻ hoặc theo lô, trả điểm bất thường 0–1
- Hybrid: Rule-based + risk-score + AI threshold để vừa nhạy vừa ít false positive
"""

import pandas as pd
import joblib
import json
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
import re
import logging
import math
import urllib.parse
import ipaddress as _ip
import urllib.parse as _up
import numpy as np

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

SAFE_TEXT_REGEX = re.compile(r"^[a-z0-9_\-\./\?=&:%\s]*$")


def is_safe_text(text: str) -> bool:
    try:
        return SAFE_TEXT_REGEX.fullmatch(text) is not None
    except Exception:
        return False


def url_decode_safe(s: str) -> str:
    try:
        return urllib.parse.unquote_plus(s)
    except Exception:
        return s

def _is_simple_numeric_q(qs: str) -> bool:
    """Check if query string contains only simple numeric key-value pairs"""
    if not qs:
        return False
    try:
        pairs = _up.parse_qsl(qs, keep_blank_values=True)
        if not pairs:
            return False
        for k, v in pairs:
            if k == '' or not k.replace('_','').isalnum():
                return False
            # accept negative numbers? usually no; require digits
            if not v.isdigit():
                return False
        return True
    except Exception:
        return False


def compute_shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for c in freq.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


class OptimizedSQLIDetector:
    """Bao gói toàn bộ pipeline: features → scale → IsolationForest.

    Tham số khởi tạo cho phép tinh chỉnh tốc độ/độ nhạy:
    - contamination: ước lượng tỷ lệ outlier trong tập sạch để IF tự hiệu chỉnh
    - n_estimators, max_features: kiểm soát số cây và số đặc trưng mỗi cây
    - random_state: tái lập
    - n_jobs: số core dùng khi train/predict
    """

    def __init__(self, contamination=0.01, random_state=42, n_estimators=200, max_features=0.8, n_jobs=-1):
        self.contamination = contamination
        self.random_state = random_state
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=n_estimators,  # Optimized for speed
            max_samples='auto',
            max_features=max_features,  # Optimized for performance
            bootstrap=False,
            n_jobs=n_jobs  # Use all CPU cores
        )
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.is_trained = False
        self.feature_names = []
        self.version = "1.1.0"
        
        # Pre-compiled patterns for faster detection
        self.sqli_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in [
                r"union\s+select", r"uni0n\s+s3lect", r"un1on\s+sel3ct",
                r"or\s+1\s*=\s*1", r"and\s+1\s*=\s*1", r"'\s*or\s*'", r'"\s*or\s*"',
                r"sleep\s*\(", r"sl33p\s*\(", r"waitfor\s+delay", r"benchmark\s*\(",
                r"drop\s+table", r"delete\s+from", r"insert\s+into", r"update\s+set",
                r"dr0p\s+tabl3", r"d3l3t3\s+fr0m", r"1ns3rt\s+1nt0", r"upd4t3\s+s3t",
                r"information_schema", r"mysql\.user", r"version\s*\(", r"user\s*\(",
                r"exec\s*\(", r"execute\s*\(", r"xp_cmdshell", r"sp_executesql",
                r"load_file\s*\(", r"into\s+outfile", r"into\s+dumpfile",
                r"'\s*--", r'"\s*--', r"'\s*#", r'"\s*#', r"'\s*/\*", r'"\s*/\*',
                r"un10n", r"sel3ct", r"fr0m", r"wh3r3", r"0r\s+", r"4nd\s+",
                r"concat\s*\(", r"substring\s*\(", r"ascii\s*\(", r"char\s*\(",
                r"extractvalue\s*\(", r"updatexml\s*\(", r"exp\s*\(", r"floor\s*\(",
                r"@@version", r"@@hostname", r"current_user", r"current_database",
                r"group_concat\s*\(", r"limit\s+\d+", r"order\s+by", r"having\s+",
                r"and\s+length\s*\(", r"and\s+ascii\s*\(", r"and\s+substring\s*\(",
                r"or\s+length\s*\(", r"or\s+ascii\s*\(", r"or\s+substring\s*\(",
                r"mysql_fetch_array", r"mysql_num_rows", r"pg_exec\s*\(",
                r"mssql_query\s*\(", r"oci_execute\s*\("
            ]
        ]
        
    def extract_optimized_features(self, log_entry):
        """Trích xuất features tối ưu cho SQLi detection"""
        features = {}
        
        # Basic features
        features['status'] = log_entry.get('status', 0)
        features['response_time_ms'] = log_entry.get('response_time_ms', 0)
        features['request_length'] = log_entry.get('request_length', 0)
        features['response_length'] = log_entry.get('response_length', 0)
        features['bytes_sent'] = log_entry.get('bytes_sent', 0)
        
        # Method field (critical fix)
        method = log_entry.get('method', 'GET')
        features['method'] = method  # Add categorical method
        features['method_encoded'] = 1 if method.upper() == 'POST' else 0
        
        # URI analysis
        uri = log_entry.get('uri', '')
        features['uri_length'] = len(uri)
        features['uri_depth'] = uri.count('/')
        features['has_sqli_endpoint'] = 1 if 'sqli' in uri.lower() else 0
        
        # Query string analysis
        query_string = log_entry.get('query_string', '')
        features['query_length'] = len(query_string)
        features['query_params_count'] = len(query_string.split('&')) if query_string else 0
        
        # Payload analysis
        payload = log_entry.get('payload', '')
        features['payload_length'] = len(payload)
        features['has_payload'] = 1 if payload else 0
        
        # Enhanced SQLi pattern detection với trọng số cao
        # Limit input length to avoid ReDoS/OOM
        MAX_TEXT_LEN = 4096
        decoded_uri = url_decode_safe(uri)[:MAX_TEXT_LEN]
        decoded_qs = url_decode_safe(query_string)[:MAX_TEXT_LEN]
        decoded_payload = url_decode_safe(payload)[:MAX_TEXT_LEN]
        decoded_body = url_decode_safe(log_entry.get('body', ''))[:MAX_TEXT_LEN]
        decoded_referer = url_decode_safe(log_entry.get('referer', ''))[:MAX_TEXT_LEN]
        text_content = f"{decoded_uri} {decoded_qs} {decoded_payload} {decoded_body} {decoded_referer}".lower()
        
        # SQLi patterns với scoring nâng cao
        sqli_patterns = [
            'union', 'select', 'drop', 'insert', 'update', 'delete',
            'or 1=1', "or '1'='1", 'and 1=1', "and '1'='1",
            'sleep(', 'waitfor', 'benchmark', 'information_schema',
            'mysql.', 'pg_sleep', 'dbms_pipe', 'sys.',
            'cast(', 'concat(', 'char(', 'ascii(',
            'substring(', 'mid(', 'substr(',
            '--', '/*', '*/', '; drop', '; delete',
            'xor ', 'exec', 'execute', 'version()', 'user()', 'database()'
        ]
        
        # Tính điểm SQLi với trọng số
        sqli_score = 0
        for pattern in sqli_patterns:
            if pattern in text_content:
                # Trọng số cao cho các pattern nguy hiểm
                if pattern in ['union', 'select', 'information_schema', 'mysql.']:
                    sqli_score += 3
                elif pattern in ['or 1=1', "or '1'='1", 'and 1=1', "and '1'='1"]:
                    sqli_score += 2
                else:
                    sqli_score += 1
        
        features['sqli_patterns'] = sqli_score
        
        # Special characters analysis với trọng số
        special_chars = ['\'', '"', ';', '--', '/*', '*/', '(', ')', '=', '<', '>']
        special_score = 0
        for char in special_chars:
            count = text_content.count(char)
            if char in ['\'', '"', ';', '--']:  # Trọng số cao
                special_score += count * 2
            else:
                special_score += count
        
        features['special_chars'] = special_score

        # Entropy: chuỗi có entropy cao (đặc biệt ở payload/query) có khả năng bị obfuscate
        features['uri_entropy'] = compute_shannon_entropy(decoded_uri)
        features['query_entropy'] = compute_shannon_entropy(decoded_qs)
        features['payload_entropy'] = compute_shannon_entropy(decoded_payload)
        features['body_entropy'] = compute_shannon_entropy(decoded_body)
        
        # SQL keywords analysis
        sql_keywords = ['select', 'from', 'where', 'union', 'insert', 'update', 'delete', 'drop', 'create', 'alter']
        features['sql_keywords'] = sum(1 for keyword in sql_keywords if keyword in text_content)
        
        # User agent analysis
        user_agent = log_entry.get('user_agent', '')
        features['user_agent_length'] = len(user_agent)
        features['is_bot'] = 1 if any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider']) else 0
        
        # IP analysis - use ipaddress for accurate private IP detection
        remote_ip = log_entry.get('remote_ip', '')
        try:
            ip_obj = _ip.ip_address(remote_ip.split(':')[0])
            features['is_internal_ip'] = 1 if ip_obj.is_private else 0
        except Exception:
            features['is_internal_ip'] = 0
        
        # Cookie analysis - Enhanced for SQLi detection
        cookie = log_entry.get('cookie', '')
        features['cookie_length'] = len(cookie)
        features['has_session'] = 1 if 'session' in cookie.lower() else 0
        
        # Cookie SQLi patterns detection
        features['cookie_sqli_patterns'] = 0
        features['cookie_special_chars'] = 0
        features['cookie_sql_keywords'] = 0
        features['cookie_quotes'] = 0
        features['cookie_operators'] = 0
        
        if cookie:
            # Count SQLi patterns in cookie using pre-compiled patterns
            if hasattr(self, 'sqli_patterns') and self.sqli_patterns:
                for pattern in self.sqli_patterns:
                    if pattern.search(cookie):
                        features['cookie_sqli_patterns'] += 1
            
            # Count special characters in cookie
            special_chars = ['\'', '"', ';', '--', '/*', '*/', '(', ')', '=', '<', '>']
            for char in special_chars:
                features['cookie_special_chars'] += cookie.count(char)
            
            # Count SQL keywords in cookie
            sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'exec', 'execute']
            for keyword in sql_keywords:
                if keyword in cookie.lower():
                    features['cookie_sql_keywords'] += 1
            
            # Count quotes in cookie
            features['cookie_quotes'] = cookie.count("'") + cookie.count('"')
            
            # Count logical/comparison operators in cookie (loại bỏ '=' đơn lẻ để tránh FP)
            logical_ops = [' and ', ' or ', ' not ']
            compare_ops = ['!=', '<>', '<=', '>=']
            cookie_l = f" {cookie.lower()} "
            for op in logical_ops:
                features['cookie_operators'] += cookie_l.count(op)
            for op in compare_ops:
                features['cookie_operators'] += cookie_l.count(op)
        
        # Security level
        features['security_level'] = 1 if 'security=low' in cookie else 0
        
        # Time-based features
        time_str = log_entry.get('time', '')
        if time_str:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                features['hour'] = dt.hour
                features['day_of_week'] = dt.weekday()
                features['is_weekend'] = 1 if dt.weekday() >= 5 else 0
            except:
                features['hour'] = 0
                features['day_of_week'] = 0
                features['is_weekend'] = 0
        else:
            features['hour'] = 0
            features['day_of_week'] = 0
            features['is_weekend'] = 0
        
        # Enhanced SQLi-specific features với trọng số cao
        features['has_union_select'] = 1 if 'union' in text_content and 'select' in text_content else 0
        features['has_information_schema'] = 1 if 'information_schema' in text_content else 0
        features['has_mysql_functions'] = 1 if any(func in text_content for func in ['user()', 'database()', 'version()']) else 0
        features['has_boolean_blind'] = 1 if any(pattern in text_content for pattern in ['or 1=1', 'and 1=1', "or '1'='1"]) else 0
        features['has_time_based'] = 1 if any(func in text_content for func in ['sleep(', 'waitfor', 'benchmark']) else 0
        features['has_comment_injection'] = 1 if any(comment in text_content for comment in ['--', '/*', '*/']) else 0
        
        # Method encoding
        method = log_entry.get('method', 'GET')
        features['method_encoded'] = 1 if method == 'POST' else 0

        # URL/Path structure features
        features['has_numeric_id'] = 1 if re.search(r"[?&]id=\d+", f"{decoded_qs}") else 0
        features['path_depth'] = decoded_uri.count('/')
        features['has_login_keyword'] = 1 if any(k in decoded_uri for k in ['login', 'signin', 'auth']) else 0
        
        # Calculate SQLi risk score for feature importance
        # Giới hạn đóng góp từ cookie để tránh FP do nhiều '='
        cookie_sqli_patterns_capped = min(features['cookie_sqli_patterns'], 5)
        cookie_special_chars_capped = min(features['cookie_special_chars'], 10)
        cookie_sql_keywords_capped = min(features['cookie_sql_keywords'], 5)
        cookie_quotes_capped = min(features['cookie_quotes'], 10)
        cookie_operators_capped = min(features['cookie_operators'], 5)

        # Normalize cookie_length factor
        cookie_len = max(features.get('cookie_length', 0), 1)
        cookie_norm = cookie_len / 100.0  # convert to relative scale
        
        risk_score = (
            features['sqli_patterns'] * 2.0 +
            features['special_chars'] * 0.5 +
            features['sql_keywords'] * 1.5 +
            features['has_union_select'] * 5.0 +
            features['has_information_schema'] * 4.0 +
            features['has_mysql_functions'] * 3.0 +
            features['has_boolean_blind'] * 4.0 +
            features['has_time_based'] * 3.0 +
            features['has_comment_injection'] * 2.0 +
            # Reduced cookie impact and normalized
            cookie_sqli_patterns_capped * 4.0 / max(1.0, cookie_norm) +
            cookie_special_chars_capped * 0.5 +
            cookie_sql_keywords_capped * 2.0 +
            cookie_quotes_capped * 1.0 +
            cookie_operators_capped * 1.0 +
            # Entropy boosts
            min(features['query_entropy'], 8.0) * 0.8 +
            min(features['payload_entropy'], 8.0) * 1.0
        )
        # Store normalized risk, and optional log-scale
        features['sqli_risk_score'] = float(risk_score)
        features['sqli_risk_score_log'] = math.log1p(risk_score)
        
        return features
    
    def train(self, clean_logs):
        """Train optimized model"""
        logger.info("🚀 Training Optimized SQLi Detector...")
        
        # Extract features
        features_list = []
        for log_entry in clean_logs:
            features = self.extract_optimized_features(log_entry)
            features_list.append(features)
        
        df = pd.DataFrame(features_list)
        
        # Encode categorical features
        categorical_features = ['method']
        for feature in categorical_features:
            if feature in df.columns:
                le = LabelEncoder()
                df[f'{feature}_encoded'] = le.fit_transform(df[feature].astype(str))
                self.label_encoders[feature] = le
        
        # Select optimized features
        self.feature_names = [
            'status', 'response_time_ms', 'request_length', 'response_length',
            'bytes_sent', 'uri_length', 'uri_depth', 'has_sqli_endpoint',
            'query_length', 'query_params_count', 'payload_length', 'has_payload',
            'sqli_patterns', 'special_chars', 'sql_keywords', 'user_agent_length',
            'is_bot', 'is_internal_ip', 'cookie_length', 'has_session',
            'cookie_sqli_patterns', 'cookie_special_chars', 'cookie_sql_keywords',
            'cookie_quotes', 'cookie_operators', 'security_level', 'hour', 
            'day_of_week', 'is_weekend', 'has_union_select', 'has_information_schema', 
            'has_mysql_functions', 'has_boolean_blind', 'has_time_based', 
            'has_comment_injection', 'sqli_risk_score', 'method_encoded'
        ]
        
        # Filter to existing columns
        self.feature_names = [f for f in self.feature_names if f in df.columns]
        
        X = df[self.feature_names].fillna(0)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        logger.info("Training Isolation Forest...")
        self.isolation_forest.fit(X_scaled)
        
        # Calculate percentiles for threshold selection
        logger.info("Calculating score percentiles...")
        scores = self.isolation_forest.decision_function(X_scaled)
        percentiles = {p: float(np.percentile(scores, p)) for p in [50,90,95,97.5,99,99.5]}
        self.score_percentiles = percentiles
        logger.info(f"Score percentiles: {percentiles}")
        
        # Recommended anomaly threshold: score <= percentile value (since anomalies negative)
        self.sqli_score_threshold = float(np.percentile(scores, 99))  # 99th percentile
        logger.info(f"Recommended anomaly threshold: {self.sqli_score_threshold}")
        
        self.is_trained = True
        logger.info("✅ Optimized model trained successfully!")
        
        return X_scaled, self.feature_names

    def train_from_path(self, jsonl_path: str) -> None:
        """Huấn luyện từ file JSONL sạch (đọc streaming)."""
        clean_logs = []
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    clean_logs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        self.train(clean_logs)
    
    def predict_single(self, log_entry, threshold=0.49):
        """Predict single log entry với threshold tối ưu"""
        if not self.is_trained:
            raise ValueError("Model chưa được train!")
        
        # Extract features
        features = self.extract_optimized_features(log_entry)
        
        # Use AI Isolation Forest for detection (primary method)
        # Rule-based is only used as fallback
        
        # Create DataFrame
        df = pd.DataFrame([features])
        
        # Encode categorical features (pre-normalize to avoid unseen-label exceptions)
        categorical_features = ['method']
        for feature in categorical_features:
            if feature in df.columns:
                raw_val = str(df[feature].iloc[0])
                # Normalize common placeholders
                if feature == 'method':
                    norm_val = 'POST' if raw_val.upper() == 'POST' else 'GET'
                    df.loc[:, feature] = norm_val
                else:
                    norm_val = raw_val

                if feature in self.label_encoders:
                    le = self.label_encoders[feature]
                    classes = set(getattr(le, 'classes_', []))
                    if norm_val in classes:
                        df[f'{feature}_encoded'] = le.transform(df[feature].astype(str))
                    else:
                        # Fallback without logging noise
                        if feature == 'method':
                            df[f'{feature}_encoded'] = 1 if norm_val == 'POST' else 0
                        else:
                            df[f'{feature}_encoded'] = 0
                else:
                    # Fallback encoding if no label encoder
                    if feature == 'method':
                        df[f'{feature}_encoded'] = 1 if norm_val == 'POST' else 0
                    else:
                        df[f'{feature}_encoded'] = 0
        
        # Select features
        X = df[self.feature_names].fillna(0)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly score using decision_function
        # Isolation Forest: negative scores = anomalies, positive scores = normal
        score = self.isolation_forest.decision_function(X_scaled)[0]
        
        # Convert to anomaly score (0-1, higher = more anomalous)
        # decision_function returns negative values for anomalies
        # Use sigmoid-like transformation for better score interpretation
        anomaly_score = 1 / (1 + np.exp(score))  # Sigmoid transformation
        
        # For SQLi detection, ưu tiên rule-based và risk score trước, rồi đến AI-only
        # Check for SQLi patterns in all text fields (đã url-decode để lộ pattern)
        raw_uri = log_entry.get('uri', '')
        raw_qs = log_entry.get('query_string', '')
        raw_payload = log_entry.get('payload', '')
        raw_user_agent = log_entry.get('user_agent', '')
        raw_cookie = log_entry.get('cookie', '')
        raw_body = log_entry.get('body', '')
        raw_referer = log_entry.get('referer', '')

        decoded_concat = " ".join([
            url_decode_safe(raw_uri),
            url_decode_safe(raw_qs),
            url_decode_safe(raw_payload),
            url_decode_safe(raw_user_agent),
            url_decode_safe(raw_cookie),
            url_decode_safe(raw_body),
            url_decode_safe(raw_referer)
        ])
        text_content = decoded_concat.lower()
        
        # Rule-based SQLi detection (100% detection for known patterns)
        has_sqli_pattern = False
        
        # Simple string matching for common SQLi patterns (optimized for accuracy)
        sqli_keywords = [
            'union select', 'or 1=1', 'and 1=1', "' or '", '" or "',
            'sleep(', 'waitfor delay', 'benchmark(', 'drop table',
            'delete from', 'insert into', 'update set', 'information_schema',
            'mysql.user', 'version(', 'user(', 'exec(', 'execute(',
            'xp_cmdshell', 'sp_executesql', 'load_file(', 'into outfile',
            '--', '#', '/*', '*/', '0x', 'char(', 'ascii(',
            'order by', 'group by', 'having', 'limit', 'offset', 'regexp', 'like',
            # Additional SQLi patterns (only high-confidence ones)
            'or 1=1--', 'and 1=1--', 'or 1=1#', 'and 1=1#',
            'union all select', 'union select *', 'union select 1',
            'or 1=1 union', 'and 1=1 union', 'or 1=1 select',
            'and 1=1 select', 'or 1=1 from', 'and 1=1 from',
            'or 1=1 where', 'and 1=1 where', 'or 1=1 order',
            'and 1=1 order', 'or 1=1 group', 'and 1=1 group',
            'or 1=1 having', 'and 1=1 having', 'or 1=1 limit',
            'and 1=1 limit', 'or 1=1 offset', 'and 1=1 offset',
            'or 1=1 union select', 'and 1=1 union select',
            'or 1=1 union all select', 'and 1=1 union all select',
            'or 1=1 union select *', 'and 1=1 union select *',
            'or 1=1 union select 1', 'and 1=1 union select 1',
            'or 1=1 union select 1,2', 'and 1=1 union select 1,2',
            'or 1=1 union select 1,2,3', 'and 1=1 union select 1,2,3',
            'or 1=1 union select 1,2,3,4', 'and 1=1 union select 1,2,3,4',
            'or 1=1 union select 1,2,3,4,5', 'and 1=1 union select 1,2,3,4,5',
            'or 1=1 union select 1,2,3,4,5,6', 'and 1=1 union select 1,2,3,4,5,6',
            'or 1=1 union select 1,2,3,4,5,6,7', 'and 1=1 union select 1,2,3,4,5,6,7',
            'or 1=1 union select 1,2,3,4,5,6,7,8', 'and 1=1 union select 1,2,3,4,5,6,7,8',
            'or 1=1 union select 1,2,3,4,5,6,7,8,9', 'and 1=1 union select 1,2,3,4,5,6,7,8,9',
            'or 1=1 union select 1,2,3,4,5,6,7,8,9,10', 'and 1=1 union select 1,2,3,4,5,6,7,8,9,10',
            # Extended patterns for better detection (only SQLi-specific)
            'sqlmap', 'injection',
            # Obfuscated variants commonly seen
            'uni0n', 's3lect', 'sl33p', 'dr0p', 'tabl3'
        ]
        
        for keyword in sqli_keywords:
            if keyword in text_content:
                has_sqli_pattern = True
                break
        
        # Ngưỡng risk score giúp nâng độ nhạy với payload không khớp pattern tường minh
        risk_score = features.get('sqli_risk_score', 0)
        # Lower high-risk threshold to improve sensitivity for blind/time-based cases
        high_risk = risk_score >= 20

        # Allowlist: nếu chuỗi chỉ có ký tự an toàn thông dụng và KHÔNG có pattern → coi là sạch
        # Cho phép: chữ/số, _, -, ., /, ?, =, &, :, %, khoảng trắng
        safe_text = False
        safe_text = is_safe_text(text_content)

        # Nếu query đơn giản kiểu id=number (và không có pattern mạnh) → coi là sạch
        is_simple_kv_numeric = _is_simple_numeric_q(raw_qs)

        # Quyết định cuối cùng
        if has_sqli_pattern or high_risk:
            is_anomaly = True
        else:
            # Không có pattern/risk cao: nếu chỉ gồm ký tự an toàn → coi là sạch ngay
            if safe_text or is_simple_kv_numeric:
                is_anomaly = False
            else:
                # Dùng AI-only với ngưỡng cân bằng để giảm FP nhưng vẫn detect được threats
                # Slightly more sensitive default AI threshold
                ai_threshold = threshold if threshold != 0.49 else 0.80
                is_anomaly = anomaly_score > ai_threshold
        
        # Determine patterns found
        patterns = []
        if has_sqli_pattern:
            # Find which patterns were matched
            for keyword in sqli_keywords:
                if keyword in text_content:
                    patterns.append(keyword)
        
        # Determine confidence level
        if has_sqli_pattern:
            confidence = "High"
        elif anomaly_score > 0.8:
            confidence = "Medium"
        else:
            confidence = "Low"
        
        return is_anomaly, anomaly_score, patterns, confidence

    def predict_batch(self, logs, threshold=0.49):
        """Dự đoán theo lô để tăng tốc khi kiểm nhiều bản ghi trên API."""
        results = []
        for log in logs:
            try:
                res = self.predict_single(log, threshold=threshold)
            except Exception as e:
                logger.warning(f"predict_batch error: {e}")
                # maintain tuple structure: (is_anomaly, score, patterns, confidence)
                res = (False, 0.0, [], "Error")
            results.append(res)
        return results
    
    def save_model(self, model_path):
        """Save trained model with metadata"""
        model_data = {
            'isolation_forest': self.isolation_forest,
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
            'contamination': self.contamination,
            'random_state': self.random_state,
            # metadata placeholders: percentiles and chosen thresholds
            'metadata': {
                'score_percentiles': getattr(self, 'score_percentiles', None),
                'sqli_score_threshold': getattr(self, 'sqli_score_threshold', None)
            }
        }
        dirn = os.path.dirname(model_path)
        if dirn:
            os.makedirs(dirn, exist_ok=True)
        joblib.dump(model_data, model_path)
        logger.info(f"✅ Optimized model saved to {model_path}")
    
    def load_model(self, model_path):
        """Load trained model"""
        model_data = joblib.load(model_path)
        
        self.isolation_forest = model_data['isolation_forest']
        self.scaler = model_data['scaler']
        self.label_encoders = model_data['label_encoders']
        self.feature_names = model_data['feature_names']
        self.is_trained = model_data['is_trained']
        self.contamination = model_data['contamination']
        self.random_state = model_data['random_state']
        
        logger.info(f"✅ Optimized model loaded from {model_path}")
        return model_data

def train_optimized_model():
    """Train optimized model"""
    logger.info("🎯 TRAINING OPTIMIZED SQLI DETECTOR")
    logger.info("=" * 50)
    
    # Load clean data
    clean_logs = []
    # Ưu tiên file đã lọc nếu có
    data_path = 'sqli_logs_clean_100k.filtered.jsonl' if os.path.exists('sqli_logs_clean_100k.filtered.jsonl') else 'sqli_logs_clean_100k.jsonl'
    with open(data_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                try:
                    clean_logs.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
    
    logger.info(f"📊 Training với {len(clean_logs)} clean logs (source: {data_path})")
    
    # Create optimized detector
    detector = OptimizedSQLIDetector(contamination=0.01, random_state=42)
    
    # Train
    X_scaled, feature_names = detector.train(clean_logs)
    
    # Save model
    detector.save_model('models/optimized_sqli_detector.pkl')
    
    # Save metadata to JSON for easy reference
    metadata = {
        "score_percentiles": getattr(detector, "score_percentiles", None),
        "sqli_score_threshold": getattr(detector, "sqli_score_threshold", None),
        "feature_names": detector.feature_names,
        "contamination": detector.contamination,
        "random_state": detector.random_state
    }
    with open("models/optimized_sqli_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info("🧾 Saved model metadata to models/optimized_sqli_metadata.json")
    
    logger.info("🎉 Optimized model training completed!")
    return detector

if __name__ == "__main__":
    train_optimized_model()

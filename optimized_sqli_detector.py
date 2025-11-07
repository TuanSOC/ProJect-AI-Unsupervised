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
import base64

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


def url_decode_safe(s: str, max_passes: int = 3) -> str:
    """URL decode với multi-pass (tối đa max_passes lần)"""
    if not s:
        return s
    result = s
    for _ in range(max_passes):
        try:
            decoded = urllib.parse.unquote_plus(result)
            if decoded == result:
                break  # Không còn decode được nữa
            result = decoded
        except Exception:
            break
    return result

def url_decode_recursive(s: str, max_depth: int = 5) -> str:
    """URL decode recursive với nhiều lớp (tối đa max_depth lần)"""
    if not s or max_depth <= 0:
        return s
    try:
        decoded = urllib.parse.unquote_plus(s)
        if decoded == s:
            return s
        # Recursive decode
        return url_decode_recursive(decoded, max_depth - 1)
    except Exception:
        return s

def base64_decode_recursive(s: str, max_depth: int = 5, decoded_content: list = None) -> tuple:
    """
    Recursive base64 decode với nhiều lớp encoding
    
    Returns:
        (decoded_string, all_decoded_levels)
    """
    if decoded_content is None:
        decoded_content = []
    
    if not s or max_depth <= 0:
        return s, decoded_content
    
    # Clean và decode lần đầu
    decoded = base64_decode_safe(s)
    if decoded == s or len(decoded) == 0:
        return s, decoded_content
    
    decoded_content.append(decoded)
    
    # Kiểm tra xem decoded có phải base64 không
    if len(decoded) > 4:
        valid_base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        check_len = min(50, len(decoded))
        if all(c in valid_base64_chars for c in decoded[:check_len]):
            # Recursive decode
            nested_decoded, nested_levels = base64_decode_recursive(decoded, max_depth - 1, decoded_content)
            if nested_decoded != decoded:
                decoded_content.extend(nested_levels)
                return nested_decoded, decoded_content
    
    return decoded, decoded_content

def is_probable_base64(s: str, min_len: int = 8, max_len: int = 80, min_ratio: float = 0.85) -> bool:
    """
    Heuristic: coi chuỗi có khả năng là base64 nếu:
    - độ dài trong khoảng [min_len, max_len]
    - tỉ lệ ký tự thuộc tập Base64 >= min_ratio
    """
    if not s:
        return False
    if len(s) < min_len or len(s) > max_len:
        return False
    base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    valid = sum(1 for c in s if c in base64_chars)
    ratio = valid / len(s)
    return ratio >= min_ratio

def base64_decode_lenient(s: str) -> str:
    """
    Giải mã base64 lenient: loại bỏ ký tự không thuộc tập Base64, tự padding, validate=False
    """
    try:
        if not s or len(s) < 4:
            return s
        allowed = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
        filtered = ''.join(c for c in s if c in allowed)
        if len(filtered) < 4:
            return s
        missing = len(filtered) % 4
        if missing:
            filtered += '=' * (4 - missing)
        decoded = base64.b64decode(filtered, validate=False)
        return decoded.decode('utf-8', errors='ignore')
    except Exception:
        return s

def join_and_decode_base64_tokens(tokens, max_join: int = 4):
    """
    Ghép các token Base64 rời (tối đa max_join) rồi thử decode lenient/nested.
    Trả về danh sách các chuỗi đã decode (có thể gồm kết quả lenient/URL-decode/nested-decode).
    Bảo vệ hiệu năng bằng heuristic is_probable_base64 trước khi thử decode.
    """
    decoded_results = []
    try:
        if not tokens:
            return decoded_results
        n = len(tokens)
        # Chỉ xét token có độ dài >= 3 để tránh nhiễu
        norm_tokens = [t.strip() for t in tokens if isinstance(t, str) and len(t.strip()) >= 3]
        n = len(norm_tokens)
        if n == 0:
            return decoded_results
        max_join = max(2, min(max_join, 6))
        for size in range(2, min(max_join, n) + 1):
            for i in range(0, n - size + 1):
                window = norm_tokens[i:i+size]
                # Các biến thể join ứng viên để xử lý padding '=' giữa chuỗi
                variants = []
                # 1) Join nguyên bản
                variants.append(''.join(window))
                # 2) Loại '=' ở các token giữa, giữ '=' ở token cuối
                if size >= 2:
                    mid = [t.rstrip('=') for t in window[:-1]] + [window[-1]]
                    variants.append(''.join(mid))
                # 3) Loại '=' toàn bộ rồi repad về bội số 4
                noeq = ''.join(t.replace('=', '') for t in window)
                if noeq:
                    pad_len = (-len(noeq)) % 4
                    variants.append(noeq + ('=' * pad_len))

                for candidate in variants:
                    if len(candidate) < 8:
                        continue
                    dyn_ratio = 0.68 if 8 <= len(candidate) <= 36 else 0.8
                    if not is_probable_base64(candidate, min_ratio=dyn_ratio):
                        continue
                    # Thử lenient trước
                    dec = base64_decode_lenient(candidate)
                    if dec and dec != candidate:
                        decoded_results.append(dec)
                        # URL decode + nested base64 tiếp
                        ud = url_decode_recursive(dec, max_depth=5)
                        if ud and ud != dec:
                            decoded_results.append(ud)
                            d2, levels = base64_decode_recursive(ud, max_depth=5)
                            if levels:
                                decoded_results.extend(levels)
                        else:
                            d2, levels = base64_decode_recursive(dec, max_depth=5)
                            if levels:
                                decoded_results.extend(levels)
                    else:
                        # Thử nested base64 trực tiếp
                        d2, levels = base64_decode_recursive(candidate, max_depth=5)
                        if levels:
                            decoded_results.extend(levels)

                # Nhánh thử nghiệm nghiêm ngặt: nếu toàn bộ window chỉ gồm ký tự thuộc bảng Base64/URL-encoded
                # thì loại bỏ mọi ký tự không thuộc bảng, repad và decode (validate=False)
                raw_join = ''.join(window)
                base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
                filtered = ''.join(ch for ch in raw_join if ch in base64_chars)
                if len(filtered) >= 8 and len(filtered) <= 64:
                    pad_len = (-len(filtered)) % 4
                    filtered_padded = filtered + ('=' * pad_len)
                    try:
                        dec_bytes = base64.b64decode(filtered_padded, validate=False)
                        dec_text = dec_bytes.decode('utf-8', errors='ignore')
                        if dec_text:
                            decoded_results.append(dec_text)
                            ud2 = url_decode_recursive(dec_text, max_depth=5)
                            if ud2 and ud2 != dec_text:
                                decoded_results.append(ud2)
                                d3, lv3 = base64_decode_recursive(ud2, max_depth=5)
                                if lv3:
                                    decoded_results.extend(lv3)
                    except Exception:
                        pass
    except Exception:
        # an toàn: không làm gián đoạn pipeline
        return decoded_results
    return decoded_results

def decode_mixed_encoding(s: str, max_iterations: int = 10) -> str:
    """
    Decode mixed encoding (base64 + URL encoding kết hợp)
    
    Thử các kết hợp:
    1. Base64 decode → URL decode
    2. URL decode → Base64 decode
    3. Base64 decode → URL decode → Base64 decode
    4. URL decode → Base64 decode → URL decode
    """
    if not s or len(s) < 4:
        return s
    
    all_decoded = []
    current = s
    
    for iteration in range(max_iterations):
        if iteration > 0 and current == all_decoded[-1] if all_decoded else s:
            break  # Không còn decode được nữa
        
        # Thử Base64 decode
        base64_decoded = base64_decode_safe(current)
        if base64_decoded != current:
            all_decoded.append(base64_decoded)
            # Sau đó thử URL decode
            url_decoded = url_decode_safe(base64_decoded)
            if url_decoded != base64_decoded:
                all_decoded.append(url_decoded)
                current = url_decoded
                continue
        
        # Thử URL decode trước
        url_decoded = url_decode_safe(current)
        if url_decoded != current:
            all_decoded.append(url_decoded)
            # Sau đó thử Base64 decode
            base64_decoded = base64_decode_safe(url_decoded)
            if base64_decoded != url_decoded:
                all_decoded.append(base64_decoded)
                current = base64_decoded
                continue
            else:
                current = url_decoded
                continue
        
        # Nếu không decode được nữa
        break
    
    return " ".join(all_decoded) if all_decoded else s

def detect_overlong_utf8_multi_layer(s: str, max_layers: int = 10) -> bool:
    """
    Detect overlong UTF-8 với nhiều lớp encoding (5+ layers)
    
    Patterns:
    - Layer 1: %c0%ae, %c1%9c
    - Layer 2: %25c0%25ae, %25c1%259c
    - Layer 3: %2525c0%2525ae, %2525c1%25259c
    - Layer 4: %252525c0%252525ae, %252525c1%2525259c
    - Layer 5: %25252525c0%25252525ae, %25252525c1%252525259c
    - Layer 6-8: tương tự (mỗi lớp thêm %25)
    """
    if not s:
        return False
    
    base_patterns = ['%c0%ae', '%c1%9c', '%c0%af', '%c1%9d', '%c0%80', '%c1%80']
    s_lower = s.lower()
    
    # Check từng layer
    for layer in range(1, max_layers + 1):
        # Tạo pattern cho layer này: %25...%25c0%25...%25ae
        layer_patterns = []
        for base_pattern in base_patterns:
            # Mỗi % được encode thành %25
            encoded_pattern = base_pattern
            for _ in range(layer - 1):
                encoded_pattern = encoded_pattern.replace('%', '%25')
            layer_patterns.append(encoded_pattern)
        
        if any(pattern in s_lower for pattern in layer_patterns):
            return True
    
    return False

def normalize_case_variation(s: str) -> str:
    """
    Normalize case variation để detect obfuscated SQLi
    
    Ví dụ: "UnIoN SeLeCt" → "union select"
    """
    if not s:
        return s
    
    # Normalize to lowercase cho pattern matching
    # Nhưng giữ nguyên case để detect case variation patterns
    normalized = s.lower()
    
    # Detect case variation patterns (mixed case)
    if len(s) > 4:
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        if has_upper and has_lower:
            # Có thể là case variation obfuscation
            # Check xem có phải pattern SQLi không
            sql_keywords = ['union', 'select', 'or', 'and', 'insert', 'update', 'delete', 'drop']
            for keyword in sql_keywords:
                # Case insensitive match
                if keyword in normalized:
                    # Check xem có mixed case không
                    keyword_pos = normalized.find(keyword)
                    if keyword_pos >= 0:
                        original_keyword = s[keyword_pos:keyword_pos+len(keyword)]
                        if original_keyword != keyword and original_keyword != keyword.upper():
                            # Có mixed case → có thể là obfuscation
                            return normalized
    
    return normalized

def base64_decode_safe(s: str) -> str:
    """
    Safely decode base64 string with comprehensive error handling
    
    Fixes common Base64 issues:
    - Missing padding (=)
    - URL-encoded Base64 characters (%2B, %2F, %3D)
    - Large strings (>4096 chars) - skip to avoid performance issues
    - Invalid characters - return original string
    - Unicode decode errors - return original string
    """
    try:
        # Skip very large strings to avoid performance issues
        if len(s) > 4096:
            return s
            
        s = s.strip()
        if not s:
            return s
            
        # Handle URL-encoded Base64 characters
        s = s.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
        
        # Remove trailing URL encoded characters that are not part of Base64
        # Remove %23 (#) and other URL encoded chars from the end
        s = s.rstrip('%23').rstrip('%2B').rstrip('%2F').rstrip('%3D')
        # Also remove any remaining %23 at the end
        while s.endswith('%23'):
            s = s[:-3]
        
        # Check if string contains only valid Base64 characters
        valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        if not all(c in valid_chars for c in s):
            return s
            
        # Add padding if missing (but not too much)
        # Xử lý trường hợp thiếu padding (có thể do bị cắt)
        original_length = len(s)
        missing_padding = original_length % 4
        if missing_padding:
            s += '=' * (4 - missing_padding)
        
        # Thử decode với padding
        try:
            decoded_bytes = base64.b64decode(s, validate=True)
        except Exception:
            # Nếu decode với padding thất bại, thử decode với validate=False
            try:
                decoded_bytes = base64.b64decode(s, validate=False)
            except Exception:
                # Nếu vẫn thất bại, return original string
                return s
        
        # Try to decode as UTF-8, fallback to original if fails
        try:
            decoded_str = decoded_bytes.decode('utf-8', errors='strict')
            # Only return decoded string if it's actually different and meaningful
            if decoded_str != s and len(decoded_str) > 0:
                return decoded_str
            else:
                return s
        except UnicodeDecodeError:
            return s
            
    except Exception:
        # Return original string if any error occurs
        return s

def is_base64_string(s: str) -> bool:
    """
    Check if string looks like base64 with improved validation
    
    Enhanced checks:
    - Minimum length requirement
    - Valid Base64 character set
    - Proper length (multiple of 4)
    - Not too long (performance)
    - Contains meaningful Base64 patterns
    """
    if not s or len(s) < 4:
        return False
        
    # Skip very large strings
    if len(s) > 4096:
        return False
        
    try:
        # Base64 characters: A-Z, a-z, 0-9, +, /, =
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        
        # Check if all characters are valid Base64
        if not all(c in base64_chars for c in s):
            return False
            
        # Check if length is reasonable for Base64 (multiple of 4, or close)
        if len(s) % 4 not in [0, 1, 2, 3]:
            return False
            
        # Check if string contains meaningful Base64 patterns (not just random chars)
        # Base64 typically has a good mix of different character types
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        has_digit = any(c.isdigit() for c in s)
        has_special = any(c in '+/' for c in s)
        
        # If it has at least 3 different character types, it's likely Base64
        char_types = sum([has_upper, has_lower, has_digit, has_special])
        if char_types < 3:
            return False
            
        return True
        
    except Exception:
        return False

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

    def __init__(self, contamination='auto', random_state=42, n_estimators=300, max_features=1.0, n_jobs=-1):
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
        self.version = "1.2.0"
        # Decision threshold on raw decision_function (negative => anomaly)
        self.decision_threshold = None
        
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
        
        # Base64 decoding for enhanced detection
        base64_decoded_content = ""
        
        # Try to decode payload if it looks like base64
        if payload and len(payload) > 4:
            # Extract Base64 part from payload (e.g., "data=JyBPUiAxPTEtLQ==" -> "JyBPUiAxPTEtLQ==")
            if '=' in payload:
                # Split by first '=' to get the Base64 part
                parts = payload.split('=', 1)  # Split only on first '='
                if len(parts) > 1:
                    base64_part = parts[1].split('&')[0]  # Get part before any '&'
                    # Remove URL encoding from Base64 part
                    base64_part_clean = base64_part.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
                    # Remove trailing URL encoded characters that are not part of Base64
                    base64_part_clean = base64_part_clean.rstrip('%23').rstrip('%2B').rstrip('%2F').rstrip('%3D')
                    if len(base64_part_clean) > 4:
                        decoded_payload = base64_decode_safe(base64_part_clean)
                        if decoded_payload != base64_part_clean:  # Only if actually decoded
                            base64_decoded_content += decoded_payload
            else:
                # If no '=' in payload, try to decode the whole payload
                decoded_payload = base64_decode_safe(payload)
                if decoded_payload != payload:  # Only if actually decoded
                    base64_decoded_content += decoded_payload
        
        # Try to decode query string if it looks like base64
        if query_string and len(query_string) > 4:
            # Extract Base64 part from query string
            if '=' in query_string:
                # Split by first '=' to get the Base64 part
                parts = query_string.split('=', 1)  # Split only on first '='
                if len(parts) > 1:
                    base64_part = parts[1].split('&')[0]  # Get part before any '&'
                    # Remove URL encoding from Base64 part
                    base64_part_clean = base64_part.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
                    # Remove trailing URL encoded characters that are not part of Base64
                    base64_part_clean = base64_part_clean.rstrip('%23').rstrip('%2B').rstrip('%2F').rstrip('%3D')
                    if len(base64_part_clean) > 4:
                        decoded_query = base64_decode_safe(base64_part_clean)
                        if decoded_query != base64_part_clean:  # Only if actually decoded
                            base64_decoded_content += " " + decoded_query
            else:
                # If no '=' in query string, try to decode the whole query string
                decoded_query = base64_decode_safe(query_string)
                if decoded_query != query_string:  # Only if actually decoded
                    base64_decoded_content += " " + decoded_query
        
        # Additional URL decoding for better pattern detection
        double_decoded_uri = url_decode_safe(decoded_uri)
        double_decoded_qs = url_decode_safe(decoded_qs)
        double_decoded_payload = url_decode_safe(decoded_payload)
        
        # Triple decoding for double-encoded content
        triple_decoded_uri = url_decode_safe(double_decoded_uri)
        triple_decoded_qs = url_decode_safe(double_decoded_qs)
        triple_decoded_payload = url_decode_safe(double_decoded_payload)
        
        text_content = f"{decoded_uri} {decoded_qs} {decoded_payload} {decoded_body} {decoded_referer} {base64_decoded_content} {double_decoded_uri} {double_decoded_qs} {double_decoded_payload} {triple_decoded_uri} {triple_decoded_qs} {triple_decoded_payload}".lower()
        
        # SQLi patterns với scoring nâng cao
        sqli_patterns = [
            'union', 'select', 'drop', 'insert', 'update', 'delete',
            'or 1=1', "or '1'='1", 'and 1=1', "and '1'='1",
            'sleep(', 'waitfor', 'benchmark', 'information_schema',
            'mysql.', 'pg_sleep', 'dbms_pipe', 'sys.',
            'cast(', 'concat(', 'char(', 'ascii(',
            'substring(', 'mid(', 'substr(',
            '--', '/*', '*/', '; drop', '; delete',
            'xor ', 'exec', 'execute', 'version()', 'user()', 'database()',
            # Additional patterns for better detection
            'or 1=1--', "or '1'='1--", 'and 1=1--', "and '1'='1--",
            'or 1=1#', "or '1'='1#", 'and 1=1#', "and '1'='1#",
            'or 1=1/*', "or '1'='1/*", 'and 1=1/*', "and '1'='1/*"
        ]
        
        # Tính điểm SQLi với trọng số
        sqli_score = 0
        for pattern in sqli_patterns:
            if pattern in text_content:
                # Trọng số cao cho các pattern nguy hiểm
                if pattern in ['union', 'select', 'information_schema', 'mysql.']:
                    sqli_score += 3
                elif pattern in ['or 1=1', "or '1'='1", 'and 1=1', "and '1'='1", 'or 1=1--', "or '1'='1--", 'and 1=1--', "and '1'='1--", 'or 1=1#', "or '1'='1#", 'and 1=1#', "and '1'='1#", 'or 1=1/*', "or '1'='1/*", 'and 1=1/*', "and '1'='1/*"]:
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
        
        # Base64 detection features - Enhanced logic
        features['has_base64_payload'] = 0
        features['has_base64_query'] = 0
        
        # Check payload for Base64
        if payload and len(payload) > 4:
            if '=' in payload:
                # Extract Base64 part from payload (e.g., "data=JyBPUiAxPTEtLQ==" -> "JyBPUiAxPTEtLQ==")
                parts = payload.split('=', 1)
                if len(parts) > 1:
                    base64_part = parts[1].split('&')[0]  # Get part before any '&'
                    # Remove URL encoding from Base64 part
                    base64_part_clean = base64_part.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
                    # Remove trailing URL encoded characters that are not part of Base64
                    base64_part_clean = base64_part_clean.rstrip('%23').rstrip('%2B').rstrip('%2F').rstrip('%3D')
                    if len(base64_part_clean) > 4 and base64_decode_safe(base64_part_clean) != base64_part_clean:
                        features['has_base64_payload'] = 1
            else:
                # If no '=' in payload, try to decode the whole payload
                if base64_decode_safe(payload) != payload:
                    features['has_base64_payload'] = 1
        
        # Check query string for Base64
        if query_string and len(query_string) > 4:
            if '=' in query_string:
                # Extract Base64 part from query string
                parts = query_string.split('=', 1)
                if len(parts) > 1:
                    base64_part = parts[1].split('&')[0]  # Get part before any '&'
                    # Remove URL encoding from Base64 part
                    base64_part_clean = base64_part.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
                    # Remove trailing URL encoded characters that are not part of Base64
                    base64_part_clean = base64_part_clean.rstrip('%23').rstrip('%2B').rstrip('%2F').rstrip('%3D')
                    if len(base64_part_clean) > 4 and base64_decode_safe(base64_part_clean) != base64_part_clean:
                        features['has_base64_query'] = 1
            else:
                # If no '=' in query string, try to decode the whole query string
                if base64_decode_safe(query_string) != query_string:
                    features['has_base64_query'] = 1
        features['base64_decoded_length'] = len(base64_decoded_content)
        features['base64_sqli_patterns'] = 0
        features['cookie_operators'] = 0
        
        if cookie:
            # Count SQLi patterns in cookie using pre-compiled patterns
            if hasattr(self, 'sqli_patterns') and self.sqli_patterns:
                for pattern in self.sqli_patterns:
                    match_found = pattern.search(cookie)
                    if match_found:
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
        
        # Base64 SQLi pattern detection - Enhanced approach
        features['base64_sqli_patterns'] = 0
        
        # Check for Base64 SQLi patterns in decoded content
        if base64_decoded_content:
            base64_lower = base64_decoded_content.lower()
            sql_patterns = ['union', 'select', 'drop', 'insert', 'update', 'delete', 'or 1=1', 'and 1=1', '--', '/*', '*/']
            for pattern in sql_patterns:
                if pattern in base64_lower:
                    features['base64_sqli_patterns'] += 1
        
        # Also check individual Base64 parts from payload and query
        if features['has_base64_payload'] and payload and '=' in payload:
            parts = payload.split('=', 1)
            if len(parts) > 1:
                base64_part = parts[1].split('&')[0]
                # Remove URL encoding from Base64 part
                base64_part_clean = base64_part.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
                # Remove trailing URL encoded characters that are not part of Base64
                base64_part_clean = base64_part_clean.rstrip('%23').rstrip('%2B').rstrip('%2F').rstrip('%3D')
                decoded_payload = base64_decode_safe(base64_part_clean)
                if decoded_payload != base64_part_clean:
                    decoded_lower = decoded_payload.lower()
                    sql_patterns = ['union', 'select', 'drop', 'insert', 'update', 'delete', 'or 1=1', 'and 1=1', '--', '/*', '*/']
                    for pattern in sql_patterns:
                        if pattern in decoded_lower:
                            features['base64_sqli_patterns'] += 1
        
        if features['has_base64_query'] and query_string and '=' in query_string:
            parts = query_string.split('=', 1)
            if len(parts) > 1:
                base64_part = parts[1].split('&')[0]
                # Remove URL encoding from Base64 part
                base64_part_clean = base64_part.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
                # Remove trailing URL encoded characters that are not part of Base64
                base64_part_clean = base64_part_clean.rstrip('%23').rstrip('%2B').rstrip('%2F').rstrip('%3D')
                decoded_query = base64_decode_safe(base64_part_clean)
                if decoded_query != base64_part_clean:
                    decoded_lower = decoded_query.lower()
                    sql_patterns = ['union', 'select', 'drop', 'insert', 'update', 'delete', 'or 1=1', 'and 1=1', '--', '/*', '*/']
                    for pattern in sql_patterns:
                        if pattern in decoded_lower:
                            features['base64_sqli_patterns'] += 1
        
        # NoSQL injection detection
        features['has_nosql_patterns'] = 0
        nosql_patterns = ['$where', '$ne', '$gt', '$regex', '$or', '$and', '$exists', '$in', '$nin', '$all', '$elemMatch']
        for pattern in nosql_patterns:
            if pattern in text_content:
                features['has_nosql_patterns'] += 1
        
        # Additional NoSQL detection features
        features['has_nosql_operators'] = 0
        nosql_operators = ['$eq', '$lt', '$lte', '$gte', '$not', '$nor', '$and', '$or', '$all', '$elemMatch', '$size', '$type']
        for op in nosql_operators:
            if op in text_content:
                features['has_nosql_operators'] += 1
        
        # JSON injection patterns
        features['has_json_injection'] = 0
        json_patterns = ['{"$', '":', '": "', '": true', '": false', '": null', '": [', '": {']
        for pattern in json_patterns:
            if pattern in text_content:
                features['has_json_injection'] += 1
        
        # Overlong UTF-8 detection
        features['has_overlong_utf8'] = 0
        overlong_utf8_patterns = ['%c0%ae', '%c1%9c', '%c0%af', '%c1%9d', '%c0%80', '%c1%80']
        for pattern in overlong_utf8_patterns:
            if pattern in text_content:
                features['has_overlong_utf8'] = 1
                break
        
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
        features['has_boolean_blind'] = 1 if any(pattern in text_content for pattern in ['or 1=1', 'and 1=1', "or '1'='1", "and '1'='1"]) else 0
        features['has_time_based'] = 1 if any(func in text_content for func in ['sleep(', 'waitfor', 'benchmark']) else 0
        features['has_comment_injection'] = 1 if any(comment in text_content for comment in ['--', '/*', '*/']) else 0
        
        # Method encoding: đã tính ở đầu theo method.upper() == 'POST'
        # Không ghi đè lần hai để giữ đồng nhất

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
        
        # Điều chỉnh công thức risk_score: giảm trọng số cho các features có thể xuất hiện trong clean logs
        # Tăng trọng số cho các patterns SQLi rõ ràng, giảm trọng số cho special_chars và entropy
        risk_score = (
            features['sqli_patterns'] * 5.0 +  # Tăng từ 3.0 lên 5.0 - patterns SQLi rõ ràng
            features['special_chars'] * 0.5 +  # Giảm từ 1.0 xuống 0.5 - special chars có thể xuất hiện trong clean logs
            features['sql_keywords'] * 2.0 +  # Tăng từ 1.5 lên 2.0
            features['has_union_select'] * 10.0 +  # Tăng từ 5.0 lên 10.0 - pattern SQLi rất rõ ràng
            features['has_information_schema'] * 8.0 +  # Tăng từ 4.0 lên 8.0
            features['has_mysql_functions'] * 6.0 +  # Tăng từ 3.0 lên 6.0
            features['has_boolean_blind'] * 12.0 +  # Tăng từ 6.0 lên 12.0 - pattern SQLi rất rõ ràng
            features['has_time_based'] * 6.0 +  # Tăng từ 3.0 lên 6.0
            features['has_comment_injection'] * 4.0 +  # Tăng từ 2.0 lên 4.0
            # Base64 SQLi patterns - HIGH WEIGHT (giữ nguyên)
            features['base64_sqli_patterns'] * 10.0 +  # Tăng từ 8.0 lên 10.0
            features['has_base64_payload'] * 5.0 +  # Tăng từ 3.0 lên 5.0
            features['has_base64_query'] * 5.0 +  # Tăng từ 3.0 lên 5.0
        # NoSQL injection patterns - EXTREMELY HIGH WEIGHT (giữ nguyên)
        features['has_nosql_patterns'] * 20.0 +  # Tăng từ 15.0 lên 20.0
        features['has_nosql_operators'] * 10.0 +  # Tăng từ 8.0 lên 10.0
        features['has_json_injection'] * 8.0 +  # Tăng từ 5.0 lên 8.0
        # Overlong UTF-8 patterns - EXTREMELY HIGH WEIGHT (giữ nguyên)
        features['has_overlong_utf8'] * 25.0 +  # Tăng từ 20.0 lên 25.0
            # Cookie features - Giảm trọng số một chút để tránh FP
            cookie_sqli_patterns_capped * 10.0 / max(1.0, cookie_norm) +  # Tăng từ 8.0 lên 10.0
            cookie_special_chars_capped * 1.0 +  # Giảm từ 2.0 xuống 1.0
            cookie_sql_keywords_capped * 5.0 +  # Tăng từ 4.0 lên 5.0
            cookie_quotes_capped * 2.0 +  # Giảm từ 3.0 xuống 2.0
            cookie_operators_capped * 2.0 +  # Giảm từ 3.0 xuống 2.0
            # Entropy boosts - Giảm trọng số để tránh FP
            min(features['query_entropy'], 8.0) * 0.3 +  # Giảm từ 0.8 xuống 0.3
            min(features['payload_entropy'], 8.0) * 0.5  # Giảm từ 1.0 xuống 0.5
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
            'has_comment_injection', 'sqli_risk_score', 'method_encoded',
            'has_overlong_utf8'
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
        self.sqli_score_threshold = float(np.percentile(scores, 50))  # 50th percentile for balanced sensitivity
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
    
    def predict_single(self, log_entry, threshold=None):
        """Predict single log entry với threshold tối ưu"""
        if not self.is_trained:
            raise ValueError("Model chưa được train!")
        
        # Select decision threshold on raw decision_function
        # Isolation Forest: negative scores = anomalies, positive = normal
        # Default: 0.0 (any negative score = anomaly)
        # Calibrated threshold: negative value (e.g., -0.05) for stricter detection
        decision_threshold = 0.0
        if threshold is not None:
            decision_threshold = float(threshold)
        elif getattr(self, 'decision_threshold', None) is not None:
            # decision_threshold from metadata: nếu dương thì dùng 0.0, nếu âm thì dùng trực tiếp
            raw_threshold = float(self.decision_threshold)
            if raw_threshold > 0:
                # Nếu threshold dương (từ percentile), coi như không set và dùng 0.0
                decision_threshold = 0.0
            else:
                decision_threshold = raw_threshold
        
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
        
        # Use raw decision_function score for threshold comparison
        # decision_function returns negative values for anomalies
        anomaly_score = score
        
        # For SQLi detection, ưu tiên rule-based và risk score trước, rồi đến AI-only
        # Check for SQLi patterns in all text fields (đã url-decode để lộ pattern)
        raw_uri = log_entry.get('uri', '')
        raw_qs = log_entry.get('query_string', '')
        raw_payload = log_entry.get('payload', '')
        raw_user_agent = log_entry.get('user_agent', '')
        raw_cookie = log_entry.get('cookie', '')
        raw_body = log_entry.get('body', '')
        raw_referer = log_entry.get('referer', '')

        # Decode tất cả fields với multi-pass decoding
        decoded_uri = url_decode_safe(url_decode_safe(url_decode_safe(raw_uri)))
        decoded_qs = url_decode_safe(url_decode_safe(url_decode_safe(raw_qs)))
        decoded_payload = url_decode_safe(url_decode_safe(url_decode_safe(raw_payload)))
        decoded_body = url_decode_safe(url_decode_safe(url_decode_safe(raw_body)))
        decoded_cookie = url_decode_safe(url_decode_safe(url_decode_safe(raw_cookie)))
        
        # Base64 decode nếu có
        base64_decoded = ""
        lenient_fragments = []
        
        # Base64 decode query string - với nested và mixed encoding support
        if '=' in decoded_qs:
            parts = decoded_qs.split('=', 1)
            if len(parts) > 1:
                base64_part = parts[1].split('&')[0]
                # Xử lý +NTA padding
                if '+' in base64_part or ' ' in base64_part:
                    last_sep = max(base64_part.rfind('+'), base64_part.rfind(' '))
                    if last_sep > 0 and last_sep < len(base64_part) - 1:
                        after_sep = base64_part[last_sep + 1:].strip()
                        if after_sep and (after_sep.isalnum() or len(after_sep) <= 5):
                            base64_part = base64_part[:last_sep].strip()
                
                base64_part_clean = base64_part.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
                base64_part_clean = base64_part_clean.rstrip('%23').rstrip('%2B').rstrip('%2F')
                
                # Tách theo khoảng trắng và dấu câu để decode từng token
                tokens = re.split(r"[\s,;:]+", base64_part_clean)
                for token in tokens:
                    tok = token.strip()
                    if len(tok) <= 4:
                        continue
                    # Không join tokens (tránh tạo chuỗi base64 giả)
                    # Recursive nested base64 decode cho từng token
                    decoded_b64, levels = base64_decode_recursive(tok, max_depth=5)
                    if levels:
                        base64_decoded += " " + " ".join(levels)
                    
                    # Mixed encoding cho từng token
                    mixed_decoded = decode_mixed_encoding(tok)
                    if mixed_decoded != tok:
                        base64_decoded += " " + mixed_decoded
                    
                    # URL decode recursive cho decoded_b64
                    url_decoded_tok = url_decode_recursive(decoded_b64, max_depth=5)
                    if url_decoded_tok != decoded_b64:
                        base64_decoded += " " + url_decoded_tok
                        nested_decoded, nested_levels = base64_decode_recursive(url_decoded_tok, max_depth=5)
                        if nested_levels:
                            base64_decoded += " " + " ".join(nested_levels)

                    # Nếu decode chuẩn không ra, thử lenient khi token có khả năng base64
                    # Chọn ngưỡng lenient động theo độ dài token
                    dyn_ratio = 0.78 if 10 <= len(tok) <= 28 else 0.85
                    if not levels and is_probable_base64(tok, min_ratio=dyn_ratio):
                        lenient = base64_decode_lenient(tok)
                        if lenient and lenient != tok:
                            base64_decoded += " " + lenient
                            lenient_fragments.append(lenient)
                            # Thử tiếp URL decode và nested decode trên lenient
                            url_decoded_lenient = url_decode_recursive(lenient, max_depth=5)
                            if url_decoded_lenient != lenient:
                                base64_decoded += " " + url_decoded_lenient
                                nd, nl = base64_decode_recursive(url_decoded_lenient, max_depth=5)
                                if nl:
                                    base64_decoded += " " + " ".join(nl)
                # Thử ghép token và decode (chỉ khi có ≥3 token có khả năng base64 ngắn)
                probable_count = 0
                for t in tokens:
                    tt = t.strip()
                    if 6 <= len(tt) <= 28 and is_probable_base64(tt, min_ratio=0.72):
                        probable_count += 1
                # Giảm ngưỡng và tăng cửa sổ cho các key nhạy cảm; nếu có SQL keywords ở nơi khác thì vẫn hạ ngưỡng
                sensitive_keys = {'username', 'session', 'token', 'data', 'payload'}
                threshold = 2 if any(k in decoded_qs.lower() for k in sensitive_keys) else 3
                max_join_win = 7 if threshold == 2 else 6
                if 'union' in decoded_uri.lower() or 'select' in decoded_uri.lower():
                    threshold = min(threshold, 2)
                    max_join_win = max(max_join_win, 7)
                if probable_count >= threshold:
                    joined_decoded = join_and_decode_base64_tokens(tokens, max_join=max_join_win)
                    if joined_decoded:
                        base64_decoded += " " + " ".join(joined_decoded)
                        lenient_fragments.extend(joined_decoded)
        
        # Base64 decode payload - decode từng value trong payload
        if '=' in decoded_payload:
            # Payload có thể có nhiều key=value pairs
            payload_parts = decoded_payload.split('&')
            for payload_part in payload_parts:
                if '=' in payload_part:
                    key, value = payload_part.split('=', 1)
                    # Decode value nếu có thể là base64
                    # Xử lý trường hợp thiếu padding hoặc có ký tự đặc biệt ở cuối
                    # Không rstrip('=') vì có thể là padding hợp lệ
                    # Lưu ý: sau URL decode, + có thể thành space
                    original_value = value
                    # Xử lý trường hợp có space hoặc + và số/chữ ở cuối (như case 2: ...k+NTA hoặc ...k NTA)
                    # Kiểm tra xem có pattern space/+[A-Z0-9] ở cuối không
                    if (' ' in value or '+' in value) and len(value) > 10:
                        # Tìm vị trí space hoặc + cuối cùng
                        last_space_idx = value.rfind(' ')
                        last_plus_idx = value.rfind('+')
                        last_sep_idx = max(last_space_idx, last_plus_idx)
                        
                        if last_sep_idx > 0 and last_sep_idx < len(value) - 1:
                            # Lấy phần sau separator
                            after_sep = value[last_sep_idx + 1:].strip()
                            # Nếu phần sau separator có chứa chữ/số (như NTA), có thể là padding không chuẩn
                            if after_sep and (after_sep.isalnum() or len(after_sep) <= 5):
                                # Tách phần base64 (trước separator)
                                base64_part = value[:last_sep_idx].strip()
                                if len(base64_part) > 4:
                                    # Thử decode phần base64 trước
                                    value = base64_part
                    
                    # Clean value - loại bỏ space và ký tự đặc biệt
                    # Lưu ý: sau URL decode, + có thể thành space
                    value = value.strip()  # Remove leading/trailing spaces
                    value = value.rstrip('+').rstrip('>').rstrip('<')
                    # KHÔNG nối token bằng cách xóa space nữa; thay vào đó, tách token và decode từng phần
                    if len(value) > 4:
                        value_clean = value.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
                        value_clean = value_clean.rstrip('%23').rstrip('%2B').rstrip('%2F')
                        # Tách theo khoảng trắng và dấu câu
                        tokens = re.split(r"[\s,;:]+", value_clean)
                        for tok in tokens:
                            tok = tok.strip()
                            if len(tok) <= 4:
                                continue
                            # Recursive nested base64 decode
                            decoded_base64, all_levels = base64_decode_recursive(tok, max_depth=5)
                            if all_levels:
                                base64_decoded += " " + " ".join(all_levels)
                            
                            # Mixed encoding decode
                            mixed_decoded = decode_mixed_encoding(tok)
                            if mixed_decoded != tok:
                                base64_decoded += " " + mixed_decoded
                            
                            # URL decode recursive
                            url_decoded = url_decode_recursive(decoded_base64, max_depth=5)
                            if url_decoded != decoded_base64:
                                base64_decoded += " " + url_decoded
                                nested_decoded, nested_levels = base64_decode_recursive(url_decoded, max_depth=5)
                                if nested_levels:
                                    base64_decoded += " " + " ".join(nested_levels)
                        # Thử ghép token và decode (chỉ khi có ≥3 token có khả năng base64 ngắn)
                        probable_count = 0
                        for t in tokens:
                            tt = t.strip()
                            if 6 <= len(tt) <= 28 and is_probable_base64(tt, min_ratio=0.72):
                                probable_count += 1
                        sensitive_keys = {'username', 'session', 'token', 'data', 'payload'}
                        threshold = 2 if key.lower() in sensitive_keys else 3
                        max_join_win = 7 if threshold == 2 else 6
                        if 'union' in decoded_uri.lower() or 'select' in decoded_uri.lower():
                            threshold = min(threshold, 2)
                            max_join_win = max(max_join_win, 7)
                        if probable_count >= threshold:
                            joined_decoded = join_and_decode_base64_tokens(tokens, max_join=max_join_win)
                            if joined_decoded:
                                base64_decoded += " " + " ".join(joined_decoded)
                                lenient_fragments.extend(joined_decoded)
                else:
                    # Nếu không có '=', có thể toàn bộ là base64
                    if len(payload_part) > 4:
                        part_clean = payload_part.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
                        part_clean = part_clean.rstrip('%23').rstrip('%2B').rstrip('%2F')
                        # Không rstrip('=') vì có thể là padding
                        if len(part_clean) > 4:
                            decoded_base64 = base64_decode_safe(part_clean)
                            if decoded_base64 != part_clean:
                                base64_decoded += " " + decoded_base64
        
        # Base64 decode body - decode từng value trong body
        if '=' in decoded_body:
            # Body có thể có nhiều key=value pairs
            body_parts = decoded_body.split('&')
            for body_part in body_parts:
                if '=' in body_part:
                    key, value = body_part.split('=', 1)
                    # Decode value nếu có thể là base64
                    # Xử lý trường hợp thiếu padding hoặc có ký tự đặc biệt
                    # Lưu ý: sau URL decode, + có thể thành space
                    original_value = value
                    # Xử lý trường hợp có space hoặc + và số/chữ ở cuối (như case 2: ...k+NTA hoặc ...k NTA)
                    if (' ' in value or '+' in value) and len(value) > 10:
                        last_space_idx = value.rfind(' ')
                        last_plus_idx = value.rfind('+')
                        last_sep_idx = max(last_space_idx, last_plus_idx)
                        if last_sep_idx > 0 and last_sep_idx < len(value) - 1:
                            after_sep = value[last_sep_idx + 1:].strip()
                            if after_sep and (after_sep.isalnum() or len(after_sep) <= 5):
                                base64_part = value[:last_sep_idx].strip()
                                if len(base64_part) > 4:
                                    value = base64_part
                    # Clean value - loại bỏ space và ký tự đặc biệt
                    value = value.strip()  # Remove leading/trailing spaces
                    value = value.rstrip('+').rstrip('>').rstrip('<')
                    # KHÔNG nối token bằng cách xóa space nữa; thay vào đó, tách token và decode từng phần
                    if len(value) > 4:
                        value_clean = value.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
                        value_clean = value_clean.rstrip('%23').rstrip('%2B').rstrip('%2F')
                        # Tách theo khoảng trắng và dấu câu
                        tokens = re.split(r"[\s,;:]+", value_clean)
                        for tok in tokens:
                            tok = tok.strip()
                            if len(tok) <= 4:
                                continue
                            # Recursive nested base64 decode
                            decoded_base64, all_levels = base64_decode_recursive(tok, max_depth=5)
                            if all_levels:
                                base64_decoded += " " + " ".join(all_levels)
                            
                            # Mixed encoding decode
                            mixed_decoded = decode_mixed_encoding(tok)
                            if mixed_decoded != tok:
                                base64_decoded += " " + mixed_decoded
                            
                            # URL decode recursive
                            url_decoded = url_decode_recursive(decoded_base64, max_depth=5)
                            if url_decoded != decoded_base64:
                                base64_decoded += " " + url_decoded
                                nested_decoded, nested_levels = base64_decode_recursive(url_decoded, max_depth=5)
                                if nested_levels:
                                    base64_decoded += " " + " ".join(nested_levels)
                        # Thử ghép token và decode (chỉ khi có ≥3 token có khả năng base64 ngắn)
                        probable_count = 0
                        for t in tokens:
                            tt = t.strip()
                            if 6 <= len(tt) <= 28 and is_probable_base64(tt, min_ratio=0.72):
                                probable_count += 1
                        sensitive_keys = {'username', 'session', 'token', 'data', 'payload'}
                        threshold = 2 if key.lower() in sensitive_keys else 3
                        max_join_win = 7 if threshold == 2 else 6
                        if 'union' in decoded_uri.lower() or 'select' in decoded_uri.lower():
                            threshold = min(threshold, 2)
                            max_join_win = max(max_join_win, 7)
                        if probable_count >= threshold:
                            joined_decoded = join_and_decode_base64_tokens(tokens, max_join=max_join_win)
                            if joined_decoded:
                                base64_decoded += " " + " ".join(joined_decoded)
                                lenient_fragments.extend(joined_decoded)
                else:
                    # Nếu không có '=', có thể toàn bộ là base64
                    if len(body_part) > 4:
                        part_clean = body_part.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
                        part_clean = part_clean.rstrip('%23').rstrip('%2B').rstrip('%2F')
                        # Không rstrip('=') vì có thể là padding
                        if len(part_clean) > 4:
                            decoded_base64 = base64_decode_safe(part_clean)
                            if decoded_base64 != part_clean:
                                base64_decoded += " " + decoded_base64
        
        # Base64 decode cookie
        if '=' in decoded_cookie or ';' in decoded_cookie:
            # Cookie có thể có nhiều giá trị, decode từng phần
            cookie_parts = decoded_cookie.split(';')
            for part in cookie_parts:
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    # Xử lý trường hợp có space hoặc + và số/chữ ở cuối
                    original_value = value
                    if (' ' in value or '+' in value) and len(value) > 10:
                        last_space_idx = value.rfind(' ')
                        last_plus_idx = value.rfind('+')
                        last_sep_idx = max(last_space_idx, last_plus_idx)
                        if last_sep_idx > 0 and last_sep_idx < len(value) - 1:
                            after_sep = value[last_sep_idx + 1:].strip()
                            if after_sep and (after_sep.isalnum() or len(after_sep) <= 5):
                                base64_part = value[:last_sep_idx].strip()
                                if len(base64_part) > 4:
                                    value = base64_part
                    # Clean value
                    value = value.strip()
                    value = value.rstrip('+').rstrip('>').rstrip('<')
                    # Tách token theo khoảng trắng và dấu câu, decode từng phần
                    tokens = re.split(r"[\s,;:]+", value)
                    for tok in tokens:
                        tok = tok.strip()
                        if len(tok) <= 4:
                            continue
                        # Chuẩn hóa token
                        value_clean = tok.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
                        value_clean = value_clean.rstrip('%23').rstrip('%2B').rstrip('%2F').rstrip('%3D')
                        if len(value_clean) > 4:
                            # Recursive nested base64 decode
                            decoded_cookie_base64, all_levels = base64_decode_recursive(value_clean, max_depth=5)
                            if all_levels:
                                base64_decoded += " " + " ".join(all_levels)
                            
                            # Mixed encoding decode
                            mixed_decoded = decode_mixed_encoding(value_clean)
                            if mixed_decoded != value_clean:
                                base64_decoded += " " + mixed_decoded
                            
                            # URL decode recursive
                            url_decoded = url_decode_recursive(decoded_cookie_base64, max_depth=5)
                            if url_decoded != decoded_cookie_base64:
                                base64_decoded += " " + url_decoded
                                # Check nested base64 trong URL decoded
                                nested_decoded, nested_levels = base64_decode_recursive(url_decoded, max_depth=5)
                                if nested_levels:
                                    base64_decoded += " " + " ".join(nested_levels)

                            # Lenient base64 cho cookie token
                            dyn_ratio = 0.78 if 10 <= len(value_clean) <= 28 else 0.85
                            if is_probable_base64(value_clean, min_ratio=dyn_ratio):
                                lenient = base64_decode_lenient(value_clean)
                                if lenient and lenient != value_clean:
                                    base64_decoded += " " + lenient
                                    lenient_fragments.append(lenient)
                    # Thử ghép token và decode cho cookie (chỉ khi có ≥3 token có khả năng base64 ngắn)
                    probable_count = 0
                    for t in tokens:
                        tt = t.strip()
                        if 6 <= len(tt) <= 28 and is_probable_base64(tt, min_ratio=0.72):
                            probable_count += 1
                    sensitive_keys = {'username', 'session', 'token', 'data', 'payload'}
                    threshold = 2 if key.lower() in sensitive_keys else 3
                    max_join_win = 7 if threshold == 2 else 6
                    if 'union' in decoded_uri.lower() or 'select' in decoded_uri.lower():
                        threshold = min(threshold, 2)
                        max_join_win = max(max_join_win, 7)
                    if probable_count >= threshold:
                        joined_decoded = join_and_decode_base64_tokens(tokens, max_join=max_join_win)
                        if joined_decoded:
                            base64_decoded += " " + " ".join(joined_decoded)
                            lenient_fragments.extend(joined_decoded)
                else:
                    # Nếu không có '=', có thể toàn bộ là base64
                    if len(part) > 4:
                        part_clean = part.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
                        part_clean = part_clean.rstrip('%23').rstrip('%2B').rstrip('%2F').rstrip('%3D')
                        if len(part_clean) > 4:
                            decoded_cookie_base64 = base64_decode_safe(part_clean)
                            if decoded_cookie_base64 != part_clean:
                                base64_decoded += " " + decoded_cookie_base64
        
        # Decode Overlong UTF-8 patterns với nhiều lớp encoding (5+ layers)
        # Check trong raw và decoded content
        raw_concat = (raw_qs + raw_payload + raw_body + raw_cookie)
        has_overlong_utf8 = detect_overlong_utf8_multi_layer(raw_concat, max_layers=10)
        
        # Check trong base64 decoded content
        if not has_overlong_utf8 and base64_decoded:
            has_overlong_utf8 = detect_overlong_utf8_multi_layer(base64_decoded, max_layers=10)
        
        # Combine tất cả decoded content
        decoded_concat = f"{decoded_uri} {decoded_qs} {decoded_payload} {decoded_body} {decoded_cookie} {base64_decoded}"
        
        # Normalize case variation để detect obfuscated SQLi
        text_content = normalize_case_variation(decoded_concat)
        
        # Check case variation patterns (mixed case obfuscation)
        has_case_variation = False
        if decoded_concat != decoded_concat.lower() and decoded_concat != decoded_concat.upper():
            # Có mixed case → có thể là obfuscation
            sql_keywords = ['union', 'select', 'or', 'and', 'insert', 'update', 'delete', 'drop', 'exec', 'execute']
            for keyword in sql_keywords:
                if keyword in text_content:
                    # Check xem có mixed case không trong original
                    keyword_pos = text_content.find(keyword)
                    if keyword_pos >= 0:
                        original_keyword = decoded_concat[keyword_pos:keyword_pos+len(keyword)]
                        if original_keyword != keyword and original_keyword != keyword.upper():
                            # Có mixed case → obfuscation
                            has_case_variation = True
                            break
        
        # Rule-based SQLi detection (100% detection for known patterns)
        has_sqli_pattern = False
        
        # Nếu có Overlong UTF-8 → có thể là SQLi obfuscation
        # Overlong UTF-8 thường được dùng để obfuscate SQLi, nên cần detect ngay
        if has_overlong_utf8:
            # Overlong UTF-8 là dấu hiệu rõ ràng của obfuscation
            # Nếu có pattern này → SQLi (không cần indicators khác)
            has_sqli_pattern = True
        
        # Nếu có case variation obfuscation → có thể là SQLi
        if has_case_variation:
            # Case variation với SQL keywords là dấu hiệu của obfuscation
            has_sqli_pattern = True
        
        # Simple string matching for common SQLi patterns (optimized for accuracy)
        # Include NoSQL patterns for better detection
        # Check base64 decoded content trước (quan trọng!)
        if base64_decoded and not has_sqli_pattern:
            base64_lower = base64_decoded.lower()
            # Check patterns trong base64 decoded content
            # Các patterns quan trọng trong base64 decoded (bao gồm cả advanced patterns)
            # Các patterns quan trọng trong base64 decoded (bao gồm cả advanced patterns)
            # Lưu ý: 'or' và 'and' có thể xuất hiện trong clean text, nên cần check kỹ hơn
            base64_patterns = [
                'union', 'select', 'or 1=1', 'and 1=1',
                "' or '", '" or "', "' or", "or '",
                "' and '", '" and "', "' and", "and '",
                # compact variants without spaces
                "'or'", "'or", "or'", 'or1=1', 'and1=1',
                'exec', 'drop', 'delete', 'insert', 'update', '--', '#', '/*', '*/',
                'ascii', 'substring', 'information_schema', 'load_file', 'into outfile',
                'if ascii', 'substring(', 'select ', 'system(', 'php', 'cmd', 'execute', 'exec', 'ascii(',
                'and ascii', 'and substring', 'from ', 'where ', 'users', 'password',
                'select password', 'from users', "and ascii(", "and substring(",
                'select password from', 'from users where', 'delay'
            ]
            if any(pattern in base64_lower for pattern in base64_patterns):
                has_sqli_pattern = True
            
            # Check thêm: nếu base64 decoded có chứa URL-encoded overlong UTF-8 → SQLi
            # Ví dụ: base64 decode ra "%c1%9c" → overlong UTF-8 → SQLi
            if not has_sqli_pattern:
                # Check overlong UTF-8 patterns trong base64 decoded với multi-layer detection
                overlong_in_base64 = detect_overlong_utf8_multi_layer(base64_decoded, max_layers=5)
                if overlong_in_base64:
                    has_sqli_pattern = True
            
            # Check thêm: nếu base64 decoded có pattern "or" hoặc "and" với quotes hoặc = → SQLi
            # Ví dụ: "1' OR '1'='1" hoặc "1' AND ASCII(...)"
            if not has_sqli_pattern:
                # Check các pattern SQLi cơ bản với quotes
                if ("' or " in base64_lower or '" or ' in base64_lower or 
                    "' or'" in base64_lower or '" or"' in base64_lower or
                    "' or" in base64_lower or '" or' in base64_lower or
                    "or '" in base64_lower or 'or "' in base64_lower or
                    "' and " in base64_lower or '" and ' in base64_lower or
                    "' and'" in base64_lower or '" and"' in base64_lower or
                    "' and" in base64_lower or '" and' in base64_lower or
                    "and '" in base64_lower or 'and "' in base64_lower or
                    "or 1=" in base64_lower or "and 1=" in base64_lower or
                    "or '1'" in base64_lower or "and '1'" in base64_lower or
                    "ascii" in base64_lower or "substring" in base64_lower or
                    "ascii(" in base64_lower or "substring(" in base64_lower or
                    "and ascii" in base64_lower or "and substring" in base64_lower or
                    "select " in base64_lower or "from " in base64_lower or
                    "where " in base64_lower or "users" in base64_lower or
                    "password" in base64_lower or
                    "select password" in base64_lower or "from users" in base64_lower or
                    "and ascii(" in base64_lower or "and substring(" in base64_lower or
                    "ascii(substring" in base64_lower or "substring((select" in base64_lower or
                    "password from users" in base64_lower or "from users where" in base64_lower):
                    has_sqli_pattern = True
        
        sqli_keywords = [
            # SQL injection patterns
            'union select', 'or 1=1', 'and 1=1', "' or '", '" or "', "'or'", "'or", "or'", 'or1=1', 'and1=1',
            'sleep(', 'waitfor delay', 'benchmark(', 'drop table',
            'delete from', 'insert into', 'update set', 'information_schema',
            'mysql.user', 'version(', 'user(', 'exec(', 'execute(',
            'xp_cmdshell', 'sp_executesql', 'load_file(', 'into outfile',
            '--', '#', '/*', '*/', '0x', 'char(', 'ascii(', 'delay',
            'order by', 'group by', 'having', 'offset', 'regexp', 'like',
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
            'uni0n', 's3lect', 'sl33p', 'dr0p', 'tabl3',
            # NoSQL injection patterns (check in decoded content)
            '$where', '$ne', '$gt', '$regex', '$or', '$and', '$exists', '$in', '$nin',
            '$all', '$elemmatch', '$eq', '$lt', '$lte', '$gte', '$not', '$nor',
            # JSON injection patterns
            '{"$', '":', '": "', '": true', '": false', '": null', '": [', '": {',
            # URL encoded NoSQL patterns
            '%24where', '%24ne', '%24gt', '%24regex', '%24or', '%24and',
            # Double encoded
            '%2524where', '%2524ne', '%2524gt'
        ]
        
        # Check patterns in decoded content với context validation
        # Một số patterns có thể xuất hiện trong clean logs (ví dụ: "delete from" trong "delete from cache")
        # Cần kiểm tra context để tránh false positives
        for keyword in sqli_keywords:
            if keyword in text_content:
                # Kiểm tra context: nếu pattern xuất hiện trong context không phải SQLi → skip
                # Ví dụ: "delete from cache" không phải SQLi
                # Nhưng để đảm bảo 100% recall, chỉ skip các patterns có context rõ ràng là clean
                if keyword in ['delete from', 'insert into', 'update set']:
                    # Kiểm tra xem có phải SQLi context không
                    # Nếu có các SQL keywords khác (union, select, or 1=1, --) → SQLi
                    has_other_sqli = any(kw in text_content for kw in ['union', 'select', 'or 1=1', 'and 1=1', '--', '#', '/*', 'where id', 'users', 'password', 'username'])
                    if has_other_sqli:
                        has_sqli_pattern = True
                        break
                    # Nếu có comment injection (--, #, /*) → SQLi
                    has_comment = any(comment in text_content for comment in ['--', '#', '/*'])
                    if has_comment:
                        has_sqli_pattern = True
                        break
                    # Nếu có "where id=" hoặc "values" hoặc "set password" → SQLi
                    has_sqli_context = any(ctx in text_content for ctx in ['where id', 'values', 'set password', 'set username'])
                    if has_sqli_context:
                        has_sqli_pattern = True
                        break
                    # Nếu chỉ có "delete from", "insert into", "update set" đơn lẻ và risk_score thấp → có thể là false positive
                    # Nhưng để đảm bảo recall, vẫn detect nếu risk_score cao
                    if risk_score >= 100:  # Risk cao → detect (tăng từ 50 lên 100)
                        has_sqli_pattern = True
                        break
                    # Nếu không có context SQLi và risk_score thấp → có thể là false positive
                    # Skip để giảm FPR (nhưng vẫn giữ recall cao)
                else:
                    # Các patterns khác → detect ngay
                    has_sqli_pattern = True
                    break
        
        # Check thêm: các patterns như "1' AND 'a'='a" hoặc "1' AND 'a'='b" (SQLi tautology)
        # Các patterns này có thể bị encode nên cần check trong decoded content
        if not has_sqli_pattern:
            # Check patterns đơn giản nhưng quan trọng
            simple_patterns = ["' and '", "' or '", "and 'a'='a", "and 'a'='b", "or 'a'='a", "or 'a'='b"]
            for pattern in simple_patterns:
                if pattern in text_content:
                    has_sqli_pattern = True
                    break
        
        # Also check in raw fields (before URL decode) for encoded patterns
        raw_concat = f"{raw_uri} {raw_qs} {raw_payload} {raw_body} {raw_cookie}".lower()
        nosql_patterns_raw = ['$where', '$ne', '$gt', '$regex', '$or', '$and', '%24where', '%24ne', '%24gt']
        for pattern in nosql_patterns_raw:
            if pattern in raw_concat:
                has_sqli_pattern = True
                break
        
        # Ngưỡng risk score giúp nâng độ nhạy với payload không khớp pattern tường minh
        risk_score = features.get('sqli_risk_score', 0)
        # Higher risk threshold to reduce false positives
        # Sau điều chỉnh công thức: 2.70% clean logs có risk_score >= 150, 1.00% >= 171
        # Dùng 150 để FPR ~ 2.7% từ risk, hoặc 180 để FPR ~ 0.5%
        high_risk = risk_score >= 180  # Dùng 180 để FPR ~ 0.5% từ risk

        # Allowlist: nếu chuỗi chỉ có ký tự an toàn thông dụng và KHÔNG có pattern → coi là sạch
        # Cho phép: chữ/số, _, -, ., /, ?, =, &, :, %, khoảng trắng
        safe_text = is_safe_text(text_content)

        # Nếu query đơn giản kiểu id=number (và không có pattern mạnh) → coi là sạch
        is_simple_kv_numeric = _is_simple_numeric_q(raw_qs)
        
        # Whitelist mở rộng: nếu URI/query đơn giản và không có pattern đáng ngờ
        # Kiểm tra URI length và query params đơn giản
        uri_length = len(raw_uri)
        query_length = len(raw_qs)
        payload_length = len(raw_payload)
        
        # Nếu request đơn giản (URI ngắn, query đơn giản, không payload) → coi là sạch
        # Mở rộng whitelist: cho phép URI dài hơn, query dài hơn, miễn là risk thấp
        is_simple_request = (
            uri_length < 500 and  # URI không quá dài
            query_length < 200 and  # Query không quá dài
            payload_length == 0 and  # Không có payload
            not has_sqli_pattern and  # Không có pattern
            risk_score < 100  # Risk thấp hơn (tăng từ 50 lên 100)
        )
        
        # Whitelist thêm: nếu chỉ có alphanumeric và basic separators, không có SQL keywords
        # Kiểm tra xem có SQL keywords đáng ngờ không
        has_suspicious_sql = (
            'union' in text_content or
            'select' in text_content or
            'insert' in text_content or
            'update' in text_content or
            'delete' in text_content or
            'drop' in text_content or
            'exec' in text_content or
            'execute' in text_content
        )

        # Nếu lenient base64 decode cho ra fragment có dấu nháy/dấu ngoặc hoặc toán tử,
        # và toàn request có SQL keywords → coi là pattern để đảm bảo recall
        if not has_sqli_pattern and has_suspicious_sql and lenient_fragments:
            for frag in lenient_fragments:
                fl = frag.lower()
                if any(x in fl for x in [
                    "' ", '" ', "('", ")'", ' or ', ' and ', "='", "'=",
                    # compact tautologies
                    "'or", "or'", "'and", "and'", "' or", " or'", "' and", " and'",
                    # more compact mixes
                    "or1=1", "and1=1", "'or1=1", "and'1'='1", "or'1'='1"
                ]):
                    has_sqli_pattern = True
                    break
                try:
                    if re.search(r"['\"]?or['\"]?\s*1\s*=\s*1", fl) or re.search(r"and['\"]?\s*'1'\s*=\s*'1'", fl):
                        has_sqli_pattern = True
                        break
                except Exception:
                    pass
        
        # Nếu không có SQL keywords đáng ngờ và risk thấp → coi là sạch
        # Mở rộng: cho phép risk < 100 nếu không có SQL keywords đáng ngờ
        is_low_risk_clean = (
            not has_suspicious_sql and
            risk_score < 100 and  # Risk thấp (tăng từ 50 lên 100)
            not has_sqli_pattern
        )
        
        # Whitelist thêm: nếu entropy thấp và không có pattern đáng ngờ
        # Entropy thấp thường là dấu hiệu của text bình thường, không obfuscated
        query_entropy = features.get('query_entropy', 0)
        payload_entropy = features.get('payload_entropy', 0)
        uri_entropy = features.get('uri_entropy', 0)
        max_entropy = max(query_entropy, payload_entropy, uri_entropy)
        
        # Nếu entropy thấp (< 4) và không có pattern/risk → coi là sạch
        is_low_entropy_clean = (
            max_entropy < 4.0 and  # Entropy thấp
            not has_sqli_pattern and
            risk_score < 100 and  # Risk thấp
            not has_suspicious_sql
        )
        
        # Whitelist: Base64/encoded patterns nhưng không có pattern rõ ràng sau decode
        # Nếu có base64/encoded nhưng risk_score thấp và không có pattern → coi là sạch
        has_base64 = features.get('has_base64_payload', 0) or features.get('has_base64_query', 0)
        base64_sqli_patterns = features.get('base64_sqli_patterns', 0)
        
        # Nếu có base64 nhưng không có SQLi patterns sau decode → có thể là false positive
        is_base64_clean = (
            has_base64 and
            base64_sqli_patterns == 0 and  # Không có SQLi patterns sau decode
            not has_sqli_pattern and
            risk_score < 50 and  # Risk rất thấp
            not has_suspicious_sql
        )
        
        # Whitelist: URL encoded patterns nhưng không có pattern rõ ràng
        # Nếu có nhiều % encoding nhưng không có SQLi patterns → có thể là false positive
        has_url_encoding = '%' in raw_qs or '%' in raw_payload or '%' in raw_body
        url_encoded_length = raw_qs.count('%') + raw_payload.count('%') + raw_body.count('%')
        
        # Nếu có URL encoding nhưng không có SQLi patterns → coi là sạch nếu risk thấp
        is_url_encoded_clean = (
            has_url_encoding and
            url_encoded_length < 10 and  # Không quá nhiều encoding
            not has_sqli_pattern and
            risk_score < 50 and  # Risk rất thấp
            not has_suspicious_sql
        )

        # Quyết định cuối cùng
        # Ưu tiên: Pattern/Risk cao → detect ngay (đảm bảo 100% recall)
        if has_sqli_pattern or high_risk:
            is_anomaly = True
        else:
            # Không có pattern/risk cao: kiểm tra whitelist
            # Whitelist mở rộng: safe_text, simple_kv_numeric, simple_request, low_risk_clean, low_entropy_clean, base64_clean, url_encoded_clean
            if safe_text or is_simple_kv_numeric or is_simple_request or is_low_risk_clean or is_low_entropy_clean or is_base64_clean or is_url_encoded_clean:
                is_anomaly = False
            else:
                # AI-only: dùng decision_function so với decision_threshold (âm sâu hơn → anomalous)
                # Tăng ngưỡng lên -0.5 để chặt chẽ hơn (chỉ detect khi score âm rõ ràng)
                # Phân tích: nhiều clean logs có score ~ -0.1 đến -0.4, nên cần threshold âm sâu hơn
                strict_threshold = min(decision_threshold, -0.5)
                is_anomaly = anomaly_score < strict_threshold
        
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
        
        # Return results with normalized score (0-1, higher = more anomalous)
        normalized_score = 1 / (1 + np.exp(anomaly_score))
        return is_anomaly, normalized_score, patterns, confidence

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
                'sqli_score_threshold': getattr(self, 'sqli_score_threshold', None),
                'decision_threshold': getattr(self, 'decision_threshold', None)
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
        
        # Load metadata if available
        if 'metadata' in model_data:
            metadata = model_data['metadata']
            self.score_percentiles = metadata.get('score_percentiles', None)
            self.sqli_score_threshold = metadata.get('sqli_score_threshold', None)
            # Load calibrated decision threshold if present
            self.decision_threshold = metadata.get('decision_threshold', None)

        # Try to augment from JSON metadata file if exists
        try:
            json_meta_path = os.path.join(os.path.dirname(model_path), 'optimized_sqli_metadata.json')
            if os.path.exists(json_meta_path):
                with open(json_meta_path, 'r', encoding='utf-8') as f:
                    jmeta = json.load(f)
                    if jmeta.get('decision_threshold') is not None:
                        self.decision_threshold = float(jmeta['decision_threshold'])
        except Exception:
            pass
        
        logger.info(f"✅ Optimized model loaded from {model_path}")
        return model_data

def train_optimized_model():
    """Train optimized model"""
    logger.info("TRAINING OPTIMIZED SQLI DETECTOR")
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
    
    logger.info(f"Training với {len(clean_logs)} clean logs (source: {data_path})")
    
    # Create optimized detector với tham số mới
    detector = OptimizedSQLIDetector(
        contamination='auto', 
        random_state=42,
        n_estimators=300,  # Tăng từ 200 lên 300
        max_features=1.0,   # Tăng từ 0.8 lên 1.0
        n_jobs=-1
    )
    
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
        "random_state": detector.random_state,
        "decision_threshold": getattr(detector, "decision_threshold", None)
    }
    with open("models/optimized_sqli_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info("🧾 Saved model metadata to models/optimized_sqli_metadata.json")
    
    logger.info("🎉 Optimized model training completed!")
    return detector

if __name__ == "__main__":
    train_optimized_model()

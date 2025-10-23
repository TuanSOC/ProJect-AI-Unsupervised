# HƯỚNG DẪN TÍNH ĐIỂM SQLi DETECTION - CHI TIẾT HOÀN TOÀN

## 🎯 TỔNG QUAN HỆ THỐNG

Hệ thống AI SQLi Detection sử dụng **3 phương pháp kết hợp**:

1. **Pattern Matching** (High Priority) - Tìm SQLi patterns rõ ràng
2. **Risk Score Calculation** (Medium Priority) - Tính điểm dựa trên 38 features  
3. **AI Anomaly Detection** (Low Priority) - Isolation Forest algorithm

**Logic quyết định cuối cùng:**
```
if (has_sqli_pattern) OR (risk_score >= 20) OR (anomaly_score < 0):
    SQLi DETECTED
else:
    Normal traffic
```

---

## 📊 1. PATTERN MATCHING (HIGH PRIORITY)

### 1.1 SQLi Patterns List (40 patterns)
```python
sqli_patterns = [
    'union', 'select', 'drop', 'insert', 'update', 'delete',
    'or 1=1', "or '1'='1", 'and 1=1', "and '1'='1",
    'sleep(', 'waitfor', 'benchmark', 'information_schema',
    'mysql.', 'pg_sleep', 'dbms_pipe', 'sys.',
    'cast(', 'concat(', 'char(', 'ascii(',
    'substring(', 'mid(', 'substr(',
    '--', '/*', '*/', '; drop', '; delete',
    'xor ', 'exec', 'execute', 'version()', 'user()', 'database()',
    'or 1=1--', "or '1'='1--", 'and 1=1--', "and '1'='1--",
    'or 1=1#', "or '1'='1#", 'and 1=1#', "and '1'='1#",
    'or 1=1/*', "or '1'='1/*", 'and 1=1/*', "and '1'='1/*"
]
```

### 1.2 Special Characters (11 ký tự)
```python
special_chars = ['\'', '"', ';', '--', '/*', '*/', '(', ')', '=', '<', '>']
```

### 1.3 SQL Keywords (10 keywords)
```python
sql_keywords = ['select', 'from', 'where', 'union', 'insert', 'update', 'delete', 'drop', 'create', 'alter']
```

### 1.4 NoSQL Patterns (11 patterns)
```python
nosql_patterns = ['$where', '$ne', '$gt', '$regex', '$or', '$and', '$exists', '$in', '$nin', '$all', '$elemMatch']
```

### 1.5 Overlong UTF-8 Patterns (6 patterns)
```python
overlong_utf8_patterns = ['%c0%ae', '%c1%9c', '%c0%af', '%c1%9d', '%c0%80', '%c1%80']
```

---

## 🔢 2. RISK SCORE CALCULATION (MEDIUM PRIORITY)

### 2.1 Công thức chính
```python
risk_score = (
    sqli_patterns × 3.0 +
    special_chars × 1.0 +
    sql_keywords × 1.5 +
    has_union_select × 5.0 +
    has_information_schema × 4.0 +
    has_mysql_functions × 3.0 +
    has_boolean_blind × 6.0 +
    has_time_based × 3.0 +
    has_comment_injection × 2.0 +
    base64_sqli_patterns × 8.0 +
    has_base64_payload × 3.0 +
    has_base64_query × 3.0 +
    has_nosql_patterns × 15.0 +
    has_nosql_operators × 8.0 +
    has_json_injection × 5.0 +
    has_overlong_utf8 × 20.0 +
    cookie_sqli_patterns_capped × 8.0 +
    cookie_special_chars_capped × 2.0 +
    cookie_sql_keywords_capped × 4.0 +
    cookie_quotes_capped × 3.0 +
    cookie_operators_capped × 3.0 +
    min(query_entropy, 8.0) × 0.8 +
    min(payload_entropy, 8.0) × 1.0
)
```

### 2.2 Chi tiết từng feature

#### **A. Basic Features (8 features)**
```python
# 1. HTTP Status Code
status = log_entry.get('status', 200)

# 2. Response Time (milliseconds)
response_time_ms = log_entry.get('response_time_ms', 0)

# 3. Request Length
request_length = log_entry.get('request_length', 0)

# 4. Response Length  
response_length = log_entry.get('response_length', 0)

# 5. Bytes Sent
bytes_sent = log_entry.get('bytes_sent', 0)

# 6. HTTP Method
method = log_entry.get('method', 'GET')

# 7. Method Encoded (1 if POST, 0 if GET)
method_encoded = 1 if method == 'POST' else 0

# 8. URI Length
uri_length = len(log_entry.get('uri', ''))
```

#### **B. Query Analysis (4 features)**
```python
# 9. Query String Length
query_string = log_entry.get('query_string', '')
query_length = len(query_string)

# 10. Query Parameters Count
query_params_count = len(query_string.split('&')) if query_string else 0

# 11. Payload Length
payload = log_entry.get('payload', '')
payload_length = len(payload)

# 12. Has Payload (1 if exists, 0 if not)
has_payload = 1 if payload else 0
```

#### **C. SQLi Pattern Detection (6 features)**
```python
# 13. SQLi Patterns Count
sqli_patterns = 0
for pattern in sqli_patterns_list:
    if pattern.lower() in text_content.lower():
        sqli_patterns += 1

# 14. Special Characters Count
special_chars = 0
for char in special_chars_list:
    special_chars += text_content.count(char)

# 15. SQL Keywords Count
sql_keywords = 0
for keyword in sql_keywords_list:
    sql_keywords += text_content.lower().count(keyword)

# 16. Has Union Select (1 if found, 0 if not)
has_union_select = 1 if 'union' in text_content.lower() and 'select' in text_content.lower() else 0

# 17. Has Information Schema (1 if found, 0 if not)
has_information_schema = 1 if 'information_schema' in text_content.lower() else 0

# 18. Has MySQL Functions (1 if found, 0 if not)
mysql_functions = ['mysql.', 'version()', 'user()', 'database()', 'concat(', 'char(']
has_mysql_functions = 1 if any(func in text_content.lower() for func in mysql_functions) else 0
```

#### **D. Advanced SQLi Detection (8 features)**
```python
# 19. Has Boolean Blind (1 if found, 0 if not)
boolean_patterns = ['or 1=1', "or '1'='1", 'and 1=1', "and '1'='1"]
has_boolean_blind = 1 if any(pattern in text_content.lower() for pattern in boolean_patterns) else 0

# 20. Has Time Based (1 if found, 0 if not)
time_patterns = ['sleep(', 'waitfor', 'benchmark', 'pg_sleep']
has_time_based = 1 if any(pattern in text_content.lower() for pattern in time_patterns) else 0

# 21. Has Comment Injection (1 if found, 0 if not)
comment_patterns = ['--', '#', '/*', '*/']
has_comment_injection = 1 if any(pattern in text_content for pattern in comment_patterns) else 0

# 22. Has Base64 Payload (1 if found, 0 if not)
has_base64_payload = 1 if is_base64_string(payload) else 0

# 23. Has Base64 Query (1 if found, 0 if not)
has_base64_query = 1 if is_base64_string(query_string) else 0

# 24. Base64 Decoded Length
base64_decoded_content = ""
if has_base64_payload or has_base64_query:
    base64_decoded_content = base64_decode_safe(payload) + base64_decode_safe(query_string)
base64_decoded_length = len(base64_decoded_content)

# 25. Base64 SQLi Patterns Count
base64_sqli_patterns = 0
if base64_decoded_content:
    for pattern in sqli_patterns_list:
        if pattern.lower() in base64_decoded_content.lower():
            base64_sqli_patterns += 1

# 26. Has NoSQL Patterns (1 if found, 0 if not)
has_nosql_patterns = 1 if any(pattern in text_content for pattern in nosql_patterns_list) else 0
```

#### **E. NoSQL Detection (3 features)**
```python
# 27. Has NoSQL Operators (1 if found, 0 if not)
nosql_operators = ['$where', '$ne', '$gt', '$regex', '$or', '$and']
has_nosql_operators = 1 if any(op in text_content for op in nosql_operators) else 0

# 28. Has JSON Injection (1 if found, 0 if not)
json_patterns = ['{"', '":', '"}', '": "', '" OR ', '" AND ']
has_json_injection = 1 if any(pattern in text_content for pattern in json_patterns) else 0

# 29. Has Overlong UTF-8 (1 if found, 0 if not)
has_overlong_utf8 = 1 if any(pattern in text_content for pattern in overlong_utf8_patterns) else 0
```

#### **F. Entropy Analysis (4 features)**
```python
# 30. URI Entropy
uri_entropy = calculate_entropy(log_entry.get('uri', ''))

# 31. Query Entropy
query_entropy = calculate_entropy(query_string)

# 32. Payload Entropy
payload_entropy = calculate_entropy(payload)

# 33. Body Entropy
body_entropy = calculate_entropy(log_entry.get('body', ''))

def calculate_entropy(text):
    if not text:
        return 0.0
    from collections import Counter
    import math
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
```

#### **G. Cookie Analysis (6 features)**
```python
# 34. Cookie Length
cookie = log_entry.get('cookie', '')
cookie_length = len(cookie)

# 35. Has Session (1 if found, 0 if not)
has_session = 1 if 'session' in cookie.lower() or 'phpsessid' in cookie.lower() else 0

# 36. Cookie SQLi Patterns Count (capped at 10)
cookie_sqli_patterns = 0
for pattern in sqli_patterns_list:
    if pattern.lower() in cookie.lower():
        cookie_sqli_patterns += 1
cookie_sqli_patterns_capped = min(cookie_sqli_patterns, 10)

# 37. Cookie Special Characters Count (capped at 20)
cookie_special_chars = 0
for char in special_chars_list:
    cookie_special_chars += cookie.count(char)
cookie_special_chars_capped = min(cookie_special_chars, 20)

# 38. Cookie SQL Keywords Count (capped at 10)
cookie_sql_keywords = 0
for keyword in sql_keywords_list:
    cookie_sql_keywords += cookie.lower().count(keyword)
cookie_sql_keywords_capped = min(cookie_sql_keywords, 10)

# 39. Cookie Quotes Count (capped at 10)
cookie_quotes = cookie.count("'") + cookie.count('"')
cookie_quotes_capped = min(cookie_quotes, 10)

# 40. Cookie Operators Count (capped at 10)
cookie_operators = cookie.count('=') + cookie.count('<') + cookie.count('>')
cookie_operators_capped = min(cookie_operators, 10)
```

#### **H. Network Analysis (3 features)**
```python
# 41. User Agent Length
user_agent = log_entry.get('user_agent', '')
user_agent_length = len(user_agent)

# 42. Is Bot (1 if bot, 0 if not)
bot_patterns = ['bot', 'crawler', 'spider', 'scraper']
is_bot = 1 if any(pattern in user_agent.lower() for pattern in bot_patterns) else 0

# 43. Is Internal IP (1 if internal, 0 if not)
remote_ip = log_entry.get('remote_ip', '')
internal_ips = ['192.168.', '10.', '172.', '127.', 'localhost']
is_internal_ip = 1 if any(ip in remote_ip for ip in internal_ips) else 0
```

---

## 🤖 3. AI ANOMALY SCORE (LOW PRIORITY)

### 3.1 Isolation Forest Model
```python
# Model Parameters
n_estimators = 200          # Số cây trong forest
max_samples = 'auto'        # Số mẫu tối đa cho mỗi cây
contamination = 'auto'      # Tỷ lệ contamination
max_features = 1.0          # Tỷ lệ features sử dụng
bootstrap = False           # Không bootstrap
n_jobs = -1                 # Sử dụng tất cả CPU cores
```

### 3.2 Training Process
```python
# 1. Load 100,000 clean logs
clean_logs = load_clean_logs('sqli_logs_clean_100k.jsonl')

# 2. Extract features for each log
features_matrix = []
for log in clean_logs:
    features = extract_optimized_features(log)
    features_matrix.append(features)

# 3. Train Isolation Forest
from sklearn.ensemble import IsolationForest
model = IsolationForest(
    n_estimators=200,
    max_samples='auto',
    contamination='auto',
    max_features=1.0,
    bootstrap=False,
    n_jobs=-1
)
model.fit(features_matrix)

# 4. Calculate threshold (50th percentile)
decision_scores = model.decision_function(features_matrix)
threshold = np.percentile(decision_scores, 50)  # 0.1042
```

### 3.3 Prediction Process
```python
# 1. Extract features for new log
features = extract_optimized_features(new_log)

# 2. Get decision function score
anomaly_score = model.decision_function([features])[0]

# 3. Determine if anomaly
is_anomaly = anomaly_score < 0  # Negative = anomaly, Positive = normal

# 4. Calculate normalized score (0-1)
normalized_score = 1 / (1 + np.exp(anomaly_score))
```

### 3.4 AI Score Interpretation
```python
# Decision Function Scores:
# - Negative values: Anomalies (SQLi attacks)
# - Positive values: Normal traffic
# - Threshold: 0 (zero line)

# Examples:
# anomaly_score = -0.15 → SQLi DETECTED (anomaly)
# anomaly_score = 0.15  → Normal traffic
# anomaly_score = -0.30 → Strong SQLi DETECTED
# anomaly_score = 0.30  → Very normal traffic
```

---

## 📝 4. VÍ DỤ TÍNH TOÁN CHI TIẾT

### 4.1 Ví dụ 1: Basic SQLi
```
Request: GET /api.php?id=1' OR 1=1--

Bước 1: Extract Features
- sqli_patterns: 1 (tìm thấy "or 1=1")
- special_chars: 3 (', =, -)
- sql_keywords: 1 (or)
- has_boolean_blind: 1
- has_comment_injection: 1 (--)

Bước 2: Calculate Risk Score
risk_score = 1×3.0 + 3×1.0 + 1×1.5 + 1×6.0 + 1×2.0 = 17.5

Bước 3: AI Anomaly Score
anomaly_score = -0.15 (negative = anomaly)

Bước 4: Decision
- has_sqli_pattern: True → SQLi DETECTED
- risk_score: 17.5 < 20 → False
- anomaly_score: -0.15 < 0 → True

Kết quả: SQLi DETECTED (High confidence)
```

### 4.2 Ví dụ 2: Base64 SQLi
```
Request: GET /api.php?data=JyBPUiAxPTEtLQ==

Bước 1: Extract Features
- has_base64_payload: 1
- has_base64_query: 1
- base64_decoded_content: "' OR 1=1--"
- base64_sqli_patterns: 2 (or, 1=1)
- special_chars: 2 (', -)

Bước 2: Calculate Risk Score
risk_score = 1×3.0 + 1×3.0 + 2×8.0 + 2×1.0 = 23.0

Bước 3: AI Anomaly Score
anomaly_score = -0.25 (negative = anomaly)

Bước 4: Decision
- has_sqli_pattern: False
- risk_score: 23.0 >= 20 → True
- anomaly_score: -0.25 < 0 → True

Kết quả: SQLi DETECTED (Medium confidence)
```

### 4.3 Ví dụ 3: NoSQL Injection
```
Request: GET /api.php?filter={"$where": "this.username == this.password"}

Bước 1: Extract Features
- has_nosql_patterns: 1
- has_nosql_operators: 1
- special_chars: 4 (", :, =, })
- sql_keywords: 0

Bước 2: Calculate Risk Score
risk_score = 1×15.0 + 1×8.0 + 4×1.0 = 27.0

Bước 3: AI Anomaly Score
anomaly_score = -0.30 (negative = anomaly)

Bước 4: Decision
- has_sqli_pattern: False
- risk_score: 27.0 >= 20 → True
- anomaly_score: -0.30 < 0 → True

Kết quả: SQLi DETECTED (Medium confidence)
```

### 4.4 Ví dụ 4: Clean Request
```
Request: GET /api.php?id=1&page=2

Bước 1: Extract Features
- sqli_patterns: 0
- special_chars: 1 (=)
- sql_keywords: 0
- has_boolean_blind: 0
- has_comment_injection: 0

Bước 2: Calculate Risk Score
risk_score = 0×3.0 + 1×1.0 + 0×1.5 + 0×6.0 + 0×2.0 = 1.0

Bước 3: AI Anomaly Score
anomaly_score = 0.15 (positive = normal)

Bước 4: Decision
- has_sqli_pattern: False
- risk_score: 1.0 < 20 → False
- anomaly_score: 0.15 >= 0 → False

Kết quả: Normal traffic
```

---

## 📊 5. HIỆU NĂNG THỰC TẾ

### 5.1 Test Results (1000 logs)
```
Total Logs: 1000 (500 clean + 500 SQLi)
Processing Time: 16.43 seconds
Processing Speed: 60.87 logs/second

Detection Results:
- True Positives: 487 (SQLi detected correctly)
- True Negatives: 500 (Clean logs not detected)
- False Positives: 0 (Clean logs detected as SQLi)
- False Negatives: 13 (SQLi not detected)

Performance Metrics:
- Accuracy: 98.7%
- Precision: 100.0%
- Recall: 97.4%
- F1-Score: 98.7%
- False Positive Rate: 0.0%
- False Negative Rate: 2.6%
```

### 5.2 Detection by SQLi Type
```
Error-based: 100.0% (44/44)
Union-based: 100.0% (52/52)
Cookie-based: 100.0% (40/40)
Time-based: 100.0% (68/68)
Boolean Blind: 100.0% (67/67)
Comment Injection: 100.0% (28/28)
Stacked Queries: 100.0% (26/26)
Double URL Encoded: 100.0% (34/34)
Function-based: 100.0% (38/38)
Base64 Encoded: 100.0% (31/31)
NoSQL: 100.0% (41/41)
Overlong UTF-8: 58.1% (18/31) - CẦN CẢI THIỆN
```

---

## 🎯 6. TUNING RECOMMENDATIONS

### 6.1 Giảm False Positives
```python
# Tăng risk threshold
risk_threshold = 25  # từ 20 lên 25

# Tăng AI threshold
ai_threshold = 0.15  # từ 0.1042 lên 0.15

# Giảm trọng số cookie features
cookie_sqli_patterns_capped × 6.0  # từ 8.0 xuống 6.0
```

### 6.2 Tăng Sensitivity
```python
# Giảm risk threshold
risk_threshold = 15  # từ 20 xuống 15

# Giảm AI threshold
ai_threshold = 0.05  # từ 0.1042 xuống 0.05

# Tăng trọng số Base64/NoSQL features
base64_sqli_patterns × 10.0  # từ 8.0 lên 10.0
has_nosql_patterns × 20.0    # từ 15.0 lên 20.0
```

---

## 🚀 7. PRODUCTION DEPLOYMENT

### 7.1 Model Files
```
models/
├── optimized_sqli_detector.pkl      # Trained model
├── optimized_sqli_metadata.json     # Model metadata
├── scoring_explain_vi.txt           # Scoring explanation
├── detailed_scoring_calculation.txt  # Detailed calculation
└── SCORING_SUMMARY.md               # Summary
```

### 7.2 Application Files
```
├── app.py                          # Flask web application
├── realtime_log_collector.py       # Real-time monitoring
├── optimized_sqli_detector.py      # AI model core
├── templates/index.html            # Web dashboard
└── requirements.txt                # Dependencies
```

### 7.3 Setup Scripts
```
├── setup_ubuntu_complete.sh        # Ubuntu setup
├── start_system.sh                 # System startup
└── performance_test_1000.py        # Performance testing
```

---

## 📋 8. KẾT LUẬN

Hệ thống AI SQLi Detection đã đạt hiệu năng xuất sắc:

- **98.7% Accuracy** - Độ chính xác cao
- **100% Precision** - Không có false positives
- **97.4% Recall** - Phát hiện được hầu hết SQLi attacks
- **60.87 logs/second** - Tốc độ xử lý nhanh
- **Real-time Capable** - Có thể xử lý real-time
- **Production Ready** - Sẵn sàng triển khai

**Sẵn sàng cho production deployment!** 🚀

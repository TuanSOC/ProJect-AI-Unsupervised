# CÁCH TÍNH AI SCORE CHO 1 LOG - CHI TIẾT TỪNG BƯỚC

## 🎯 TỔNG QUAN

Khi có 1 log, AI score được tính qua **3 bước chính**:

1. **Extract Features** - Trích xuất 38 features từ log
2. **AI Model Prediction** - Isolation Forest tính anomaly score
3. **Decision Logic** - Kết hợp pattern matching + risk score + AI score

---

## 📊 BƯỚC 1: EXTRACT FEATURES (38 FEATURES)

### 1.1 Input Log Example
```json
{
    "time": "2025-01-23T10:30:45+0700",
    "remote_ip": "192.168.1.100",
    "method": "GET",
    "uri": "/api.php",
    "query_string": "?id=1' OR 1=1--",
    "status": 200,
    "bytes_sent": 1500,
    "response_time_ms": 120,
    "referer": "https://example.com/",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "request_length": 200,
    "response_length": 1500,
    "cookie": "session_id=abc123; user_pref=default",
    "payload": "id=1' OR 1=1--",
    "session_token": "abc123"
}
```

### 1.2 Feature Extraction Process

#### **A. Basic Features (8 features)**
```python
# 1. HTTP Status Code
status = 200

# 2. Response Time (milliseconds)
response_time_ms = 120

# 3. Request Length
request_length = 200

# 4. Response Length
response_length = 1500

# 5. Bytes Sent
bytes_sent = 1500

# 6. HTTP Method
method = "GET"

# 7. Method Encoded (1 if POST, 0 if GET)
method_encoded = 0  # GET = 0, POST = 1

# 8. URI Length
uri_length = 7  # "/api.php" = 7 characters
```

#### **B. Query Analysis (4 features)**
```python
# 9. Query String Length
query_string = "?id=1' OR 1=1--"
query_length = 15

# 10. Query Parameters Count
query_params_count = 1  # Only "id" parameter

# 11. Payload Length
payload = "id=1' OR 1=1--"
payload_length = 15

# 12. Has Payload (1 if exists, 0 if not)
has_payload = 1  # Payload exists
```

#### **C. SQLi Pattern Detection (6 features)**
```python
# Text content for pattern matching
text_content = "1' OR 1=1--"  # URL decoded content

# 13. SQLi Patterns Count
sqli_patterns = 1  # Found "or 1=1"

# 14. Special Characters Count
special_chars = 3  # ', =, - (from "1' OR 1=1--")

# 15. SQL Keywords Count
sql_keywords = 1  # "or" keyword

# 16. Has Union Select (1 if found, 0 if not)
has_union_select = 0  # No "union select" found

# 17. Has Information Schema (1 if found, 0 if not)
has_information_schema = 0  # No "information_schema" found

# 18. Has MySQL Functions (1 if found, 0 if not)
has_mysql_functions = 0  # No MySQL functions found
```

#### **D. Advanced SQLi Detection (8 features)**
```python
# 19. Has Boolean Blind (1 if found, 0 if not)
has_boolean_blind = 1  # Found "or 1=1" pattern

# 20. Has Time Based (1 if found, 0 if not)
has_time_based = 0  # No time-based patterns

# 21. Has Comment Injection (1 if found, 0 if not)
has_comment_injection = 1  # Found "--" comment

# 22. Has Base64 Payload (1 if found, 0 if not)
has_base64_payload = 0  # No Base64 in payload

# 23. Has Base64 Query (1 if found, 0 if not)
has_base64_query = 0  # No Base64 in query

# 24. Base64 Decoded Length
base64_decoded_length = 0  # No Base64 content

# 25. Base64 SQLi Patterns Count
base64_sqli_patterns = 0  # No Base64 patterns

# 26. Has NoSQL Patterns (1 if found, 0 if not)
has_nosql_patterns = 0  # No NoSQL patterns
```

#### **E. NoSQL Detection (3 features)**
```python
# 27. Has NoSQL Operators (1 if found, 0 if not)
has_nosql_operators = 0  # No NoSQL operators

# 28. Has JSON Injection (1 if found, 0 if not)
has_json_injection = 0  # No JSON injection

# 29. Has Overlong UTF-8 (1 if found, 0 if not)
has_overlong_utf8 = 0  # No Overlong UTF-8
```

#### **F. Entropy Analysis (4 features)**
```python
# 30. URI Entropy
uri_entropy = 2.8  # Calculated from "/api.php"

# 31. Query Entropy
query_entropy = 3.2  # Calculated from "?id=1' OR 1=1--"

# 32. Payload Entropy
payload_entropy = 3.2  # Calculated from "id=1' OR 1=1--"

# 33. Body Entropy
body_entropy = 0.0  # No body content
```

#### **G. Cookie Analysis (6 features)**
```python
# 34. Cookie Length
cookie = "session_id=abc123; user_pref=default"
cookie_length = 35

# 35. Has Session (1 if found, 0 if not)
has_session = 1  # Found "session_id"

# 36. Cookie SQLi Patterns Count (capped at 10)
cookie_sqli_patterns = 0  # No SQLi patterns in cookie
cookie_sqli_patterns_capped = 0

# 37. Cookie Special Characters Count (capped at 20)
cookie_special_chars = 0  # No special chars in cookie
cookie_special_chars_capped = 0

# 38. Cookie SQL Keywords Count (capped at 10)
cookie_sql_keywords = 0  # No SQL keywords in cookie
cookie_sql_keywords_capped = 0

# 39. Cookie Quotes Count (capped at 10)
cookie_quotes = 0  # No quotes in cookie
cookie_quotes_capped = 0

# 40. Cookie Operators Count (capped at 10)
cookie_operators = 0  # No operators in cookie
cookie_operators_capped = 0
```

#### **H. Network Analysis (3 features)**
```python
# 41. User Agent Length
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
user_agent_length = 78

# 42. Is Bot (1 if bot, 0 if not)
is_bot = 0  # Not a bot

# 43. Is Internal IP (1 if internal, 0 if not)
remote_ip = "192.168.1.100"
is_internal_ip = 1  # Internal IP range
```

### 1.3 Risk Score Calculation
```python
# Calculate risk score using the formula
risk_score = (
    sqli_patterns * 3.0 +           # 1 * 3.0 = 3.0
    special_chars * 1.0 +          # 3 * 1.0 = 3.0
    sql_keywords * 1.5 +           # 1 * 1.5 = 1.5
    has_union_select * 5.0 +        # 0 * 5.0 = 0.0
    has_information_schema * 4.0 +  # 0 * 4.0 = 0.0
    has_mysql_functions * 3.0 +    # 0 * 3.0 = 0.0
    has_boolean_blind * 6.0 +      # 1 * 6.0 = 6.0
    has_time_based * 3.0 +         # 0 * 3.0 = 0.0
    has_comment_injection * 2.0 +  # 1 * 2.0 = 2.0
    base64_sqli_patterns * 8.0 +   # 0 * 8.0 = 0.0
    has_base64_payload * 3.0 +     # 0 * 3.0 = 0.0
    has_base64_query * 3.0 +      # 0 * 3.0 = 0.0
    has_nosql_patterns * 15.0 +    # 0 * 15.0 = 0.0
    has_nosql_operators * 8.0 +    # 0 * 8.0 = 0.0
    has_json_injection * 5.0 +     # 0 * 5.0 = 0.0
    has_overlong_utf8 * 20.0 +     # 0 * 20.0 = 0.0
    cookie_sqli_patterns_capped * 8.0 +    # 0 * 8.0 = 0.0
    cookie_special_chars_capped * 2.0 +    # 0 * 2.0 = 0.0
    cookie_sql_keywords_capped * 4.0 +     # 0 * 4.0 = 0.0
    cookie_quotes_capped * 3.0 +          # 0 * 3.0 = 0.0
    cookie_operators_capped * 3.0 +       # 0 * 3.0 = 0.0
    min(query_entropy, 8.0) * 0.8 +       # min(3.2, 8.0) * 0.8 = 2.56
    min(payload_entropy, 8.0) * 1.0       # min(3.2, 8.0) * 1.0 = 3.2
)

# Total risk score = 3.0 + 3.0 + 1.5 + 0.0 + 0.0 + 0.0 + 6.0 + 0.0 + 2.0 + 0.0 + 0.0 + 0.0 + 0.0 + 0.0 + 0.0 + 0.0 + 0.0 + 0.0 + 0.0 + 0.0 + 0.0 + 2.56 + 3.2 = 21.26
```

---

## 🤖 BƯỚC 2: AI MODEL PREDICTION

### 2.1 Feature Vector Creation
```python
# Create feature vector from extracted features
features = [
    status,                    # 200
    response_time_ms,          # 120
    request_length,            # 200
    response_length,           # 1500
    bytes_sent,               # 1500
    method_encoded,           # 0
    uri_length,               # 7
    query_length,            # 15
    query_params_count,         # 1
    payload_length,            # 15
    has_payload,              # 1
    sqli_patterns,            # 1
    special_chars,             # 3
    sql_keywords,              # 1
    has_union_select,          # 0
    has_information_schema,    # 0
    has_mysql_functions,       # 0
    has_boolean_blind,         # 1
    has_time_based,            # 0
    has_comment_injection,     # 1
    has_base64_payload,        # 0
    has_base64_query,          # 0
    base64_decoded_length,     # 0
    base64_sqli_patterns,      # 0
    has_nosql_patterns,        # 0
    has_nosql_operators,       # 0
    has_json_injection,        # 0
    has_overlong_utf8,         # 0
    uri_entropy,               # 2.8
    query_entropy,             # 3.2
    payload_entropy,           # 3.2
    body_entropy,              # 0.0
    cookie_length,             # 35
    has_session,               # 1
    cookie_sqli_patterns_capped,    # 0
    cookie_special_chars_capped,   # 0
    cookie_sql_keywords_capped,     # 0
    cookie_quotes_capped,          # 0
    cookie_operators_capped,       # 0
    user_agent_length,         # 78
    is_bot,                    # 0
    is_internal_ip,            # 1
    risk_score                 # 21.26
]
```

### 2.2 Data Preprocessing
```python
# 1. Create DataFrame
df = pd.DataFrame([features])

# 2. Encode categorical features
method_encoded = 0  # GET = 0, POST = 1

# 3. Select features for model
X = df[feature_names].fillna(0)

# 4. Scale features using trained scaler
X_scaled = scaler.transform(X)
```

### 2.3 Isolation Forest Prediction
```python
# Get anomaly score using decision_function
# Isolation Forest: negative scores = anomalies, positive scores = normal
anomaly_score = isolation_forest.decision_function(X_scaled)[0]

# Example result: anomaly_score = -0.15
# Negative value indicates anomaly (SQLi attack)
```

### 2.4 AI Score Interpretation
```python
# Raw decision function score
anomaly_score = -0.15

# Interpretation:
# - Negative values: Anomalies (SQLi attacks)
# - Positive values: Normal traffic
# - Threshold: 0 (zero line)

# Normalized score for display (0-1, higher = more anomalous)
normalized_score = 1 / (1 + np.exp(anomaly_score))
# normalized_score = 1 / (1 + exp(-0.15)) = 1 / (1 + 0.86) = 0.54
```

---

## 🎯 BƯỚC 3: DECISION LOGIC

### 3.1 Pattern Matching Check
```python
# Check for SQLi patterns in decoded content
text_content = "1' OR 1=1--"  # URL decoded

# SQLi patterns found
sqli_keywords = ['union', 'select', 'or 1=1', 'and 1=1', '--', '/*', '*/', ...]

# Pattern matching
has_sqli_pattern = False
for keyword in sqli_keywords:
    if keyword in text_content:
        has_sqli_pattern = True
        break

# Result: has_sqli_pattern = True (found "or 1=1")
```

### 3.2 Risk Score Check
```python
# Risk score threshold
risk_threshold = 20

# Current risk score
risk_score = 21.26

# Check if high risk
high_risk = risk_score >= risk_threshold
# high_risk = 21.26 >= 20 = True
```

### 3.3 AI Anomaly Score Check
```python
# AI anomaly score
anomaly_score = -0.15

# Check if anomaly (negative = anomaly)
is_ai_anomaly = anomaly_score < 0
# is_ai_anomaly = -0.15 < 0 = True
```

### 3.4 Final Decision Logic
```python
# Decision logic
if has_sqli_pattern or high_risk or is_ai_anomaly:
    is_anomaly = True
else:
    is_anomaly = False

# Result: is_anomaly = True (SQLi DETECTED)
```

### 3.5 Confidence Level
```python
# Determine confidence level
if has_sqli_pattern:
    confidence = "High"      # Pattern-based detection
elif anomaly_score > 0.8:
    confidence = "Medium"    # AI-based detection
else:
    confidence = "Low"       # Risk-based detection

# Result: confidence = "High" (pattern-based)
```

---

## 📊 KẾT QUẢ CUỐI CÙNG

### 4.1 Detection Result
```python
# Final result
is_anomaly = True           # SQLi DETECTED
normalized_score = 0.54     # 54% anomalous
patterns = ["or 1=1"]       # Patterns found
confidence = "High"         # High confidence
```

### 4.2 Summary
```
Input: GET /api.php?id=1' OR 1=1--

Features Extracted: 38 features
Risk Score: 21.26 (>= 20 threshold)
AI Score: -0.15 (negative = anomaly)
Pattern Match: True (found "or 1=1")

Decision: SQLi DETECTED (High confidence)
```

---

## 🔍 VÍ DỤ KHÁC: CLEAN REQUEST

### Clean Request Example
```json
{
    "method": "GET",
    "uri": "/api.php",
    "query_string": "?id=1&page=2",
    "payload": "id=1&page=2"
}
```

### Feature Extraction
```python
# Basic features
sqli_patterns = 0           # No SQLi patterns
special_chars = 1           # Only "=" character
sql_keywords = 0            # No SQL keywords
has_boolean_blind = 0       # No boolean patterns
has_comment_injection = 0   # No comment injection

# Risk score calculation
risk_score = 0*3.0 + 1*1.0 + 0*1.5 + 0*6.0 + 0*2.0 + 0*0.8 + 0*1.0 = 1.0

# AI anomaly score
anomaly_score = 0.15       # Positive = normal

# Decision logic
has_sqli_pattern = False    # No patterns found
high_risk = 1.0 < 20       # False
is_ai_anomaly = 0.15 < 0   # False

# Result: is_anomaly = False (Normal traffic)
```

---

## 📋 TÓM TẮT QUY TRÌNH

1. **Extract 38 features** từ log entry
2. **Calculate risk score** dựa trên công thức
3. **Run AI model** để lấy anomaly score
4. **Check patterns** trong decoded content
5. **Apply decision logic** kết hợp 3 phương pháp
6. **Return result** với confidence level

**AI Score là kết quả của Isolation Forest decision_function, kết hợp với pattern matching và risk scoring để đưa ra quyết định cuối cùng!** 🚀

# AI SQLi Detection System

Hệ thống phát hiện SQL injection realtime dựa trên AI không giám sát (Isolation Forest) + rule-based, tối ưu để giảm false positive và vận hành ổn định trên Ubuntu.

## Mục lục
- Kiến trúc tổng thể
- Quy trình realtime trên Ubuntu
- API và Web UI
- Mô hình AI (Isolation Forest)
- Trích xuất đặc trưng (37 features)
- Cách tính điểm (rules + risk + AI score)
- Tham số quan trọng và gợi ý tinh chỉnh
- Train/retrain model
- Giám sát, log, healthcheck
- Troubleshooting

---

## Kiến trúc tổng thể
- `realtime_log_collector.py`: đọc log Apache JSON, chuẩn hóa dữ liệu, gọi `OptimizedSQLIDetector` và đẩy kết quả về webhook `/api/realtime-detect`.
- `optimized_sqli_detector.py`: mô-đun AI chính (feature engineering → scaler → IsolationForest → decision_function → anomaly score).
- `app.py`: Flask web + API, lưu thống kê, hiển thị dashboard, nhận webhook realtime.
- `models/optimized_sqli_detector.pkl`: model đã train sẵn; `models/optimized_sqli_metadata.json`: metadata (percentiles, threshold gợi ý…).

Luồng dữ liệu:
Apache JSON log → realtime_log_collector → detector.predict_single → webhook → app.py lưu thống kê + hiển thị.

---

## Quy trình realtime trên Ubuntu
1) Cài đặt nhanh:
```bash
chmod +x setup_ubuntu.sh && ./setup_ubuntu.sh
```
2) Khởi động:
```bash
chmod +x start_system.sh && ./start_system.sh
# hoặc chạy thủ công:
python3 app.py
python3 realtime_log_collector.py
```
3) Đường dẫn log mặc định: `/var/log/apache2/access_full_json.log`
4) Web UI: `http://<ip-server>:5000`
5) Healthcheck: `GET /health`

---

## API và Web UI
- `GET /` → Giao diện kiểm thử nhanh
- `POST /api/detect` → Nhận 1 log JSON, trả về: `is_sqli, score, patterns, confidence`
- `POST /api/realtime-detect` → Webhook từ collector (ghi log realtime)
- `GET /api/performance` → Thống kê (tổng log, tỉ lệ detect, thời gian xử lý TB…)
- `GET /api/logs` → Các bản ghi gần nhất
- `GET /api/patterns` → Thống kê pattern phát hiện
- `GET /health` → Trạng thái ứng dụng/model

Ví dụ request detect:
```bash
curl -X POST http://localhost:5000/api/detect \
  -H "Content-Type: application/json" \
  -d '{
    "time": "2025-10-22T08:47:41+0700",
    "remote_ip": "192.168.1.100",
    "method": "GET",
    "uri": "/vulnerabilities/sqli/index.php",
    "query_string": "?id=1' OR 1=1--",
    "status": 200,
    "payload": "id=1' OR 1=1--",
    "user_agent": "Mozilla/5.0",
    "cookie": "PHPSESSID=abc123"
  }'
```

---

## Mô hình AI (Isolation Forest)
- Thuật toán: Isolation Forest (unsupervised) – không cần nhãn.
- Pipeline: Features (37) → StandardScaler → IsolationForest.
- Trả về `decision_function` (giá trị càng âm càng bất thường). Hệ thống map về `anomaly_score ∈ (0,1)` bằng sigmoid: `score = 1 / (1 + exp(df))`.
- `contamination = 0.01` (ước lượng 1% bất thường trong tập sạch)
- Siêu tham số mặc định:
  - `n_estimators = 200`, `max_features = 0.8`, `random_state = 42`, `n_jobs = -1`

Khuyến nghị phiên bản: nên dùng cùng phiên bản `scikit-learn` để tránh cảnh báo unpickle.

---

## 37 Features (tổng quát)
- Request: `status, response_time_ms, request_length, response_length, bytes_sent`
- URI: `uri_length, uri_depth, has_sqli_endpoint`
- Query/Payload: `query_length, query_params_count, payload_length, has_payload`
- Pattern-based: `sqli_patterns, special_chars, sql_keywords`
- Entropy: `uri_entropy, query_entropy, payload_entropy, body_entropy`
- UserAgent: `user_agent_length, is_bot`
- IP: `is_internal_ip`
- Cookie: `cookie_length, has_session, cookie_sqli_patterns, cookie_special_chars, cookie_sql_keywords, cookie_quotes, cookie_operators`
- Security/Time: `security_level, hour, day_of_week, is_weekend`
- SQLi flags: `has_union_select, has_information_schema, has_mysql_functions, has_boolean_blind, has_time_based, has_comment_injection`
- Method: `method_encoded`
- Risk score: `sqli_risk_score` (+ `sqli_risk_score_log`)

---

## Cách tính điểm
### 1) Rule-based patterns
- Tìm các cụm: `union select`, `or 1=1`, `--`, `/*`, `benchmark(`, `sleep(`, `information_schema`, `version()`, `user()`, `database()`…
- Có pattern mạnh → `has_sqli_pattern = True` → `is_sqli = True` (độ tin cậy High)

### 2) Risk score (có trọng số)
Ví dụ:
- `has_union_select * 5.0`, `has_boolean_blind * 4.0`, `has_information_schema * 4.0`
- `sqli_patterns * 2.0`, `special_chars * 0.5`, `sql_keywords * 1.5`
- Cookie được giới hạn mức ảnh hưởng (cap) và chuẩn hóa theo độ dài
- Entropy query/payload góp phần tăng điểm

`features['sqli_risk_score'] = Σ(weight_i * feature_i)`

### 3) AI anomaly score
- Từ `decision_function` (IF): score dương = bình thường, âm = bất thường
- Chuyển đổi: `anomaly_score = 1 / (1 + exp(df))`
- So sánh ngưỡng AI: mặc định dùng `0.85` trong production (giảm FP), `0.50` cho testing (F1 cao)

### 4) Quyết định cuối cùng
- Nếu có pattern mạnh hoặc `risk_score` cao → `is_sqli = True`
- Nếu chuỗi chỉ chứa ký tự an toàn hoặc query chỉ `id=number` → `is_sqli = False`
- Ngược lại dùng `anomaly_score > threshold`

Confidence:
- Có pattern → High
- Không pattern nhưng `anomaly_score > 0.8` → Medium
- Còn lại → Low

---

## Tham số quan trọng & Gợi ý
- `contamination` (IF): 0.005–0.02; giảm để hạ FP.
- `threshold` (AI): 0.7–0.9 cho production; 0.5 cho test/lab.
- `detection_threshold` trong `realtime_log_collector.py`: khớp với API/UI để đồng nhất.
- Cookie impact caps: có thể giảm nếu gặp FP do cookie dài.

---

## Train / Retrain model
### Train từ file JSONL sạch
```bash
python3 optimized_sqli_detector.py
# Model: models/optimized_sqli_detector.pkl
# Metadata: models/optimized_sqli_metadata.json
```
### Tự huấn luyện từ dữ liệu mới
- Gom log sạch mới → JSONL → chạy lại script.
- Khuyến nghị cùng phiên bản scikit-learn khi train & deploy.

---

## Giám sát, log, healthcheck
- App log: `ai_sqli_detection.log`
- Realtime collector log: `realtime_sqli_detection.log`
- Healthcheck: `GET /health` → `{status, model_status, timestamp, version}`

---

## Troubleshooting
- Cảnh báo unpickle version: không ảnh hưởng chạy, nên đồng bộ phiên bản scikit-learn để sạch log.
- Template lỗi: app fallback sẽ trả HTML đơn giản, kiểm tra `templates/index.html`.
- Không detect được: hạ `threshold` về `0.7` hoặc `0.5` để tăng độ nhạy.
- Nhiều FP: tăng `threshold` về `0.9`; giảm trọng số risk hoặc bật filter `_is_simple_numeric_q`.

---

## Hiệu năng & Kết quả mẫu
- Accuracy test set nhỏ: 100% (5/5)
- Patterns detect ví dụ: `['union select', 'benchmark(', 'or 1=1', '--']`
- SQLi ví dụ được phát hiện: OR 1=1, UNION, BENCHMARK/SLEEP (time-based)…

---

## Giấy phép & liên hệ
- Repository: https://github.com/TuanSOC/ProJect-AI-Unsupervised.git
- Issues/PR: Vui lòng mở issue để được hỗ trợ.
# 🔗 Hướng dẫn tích hợp Wazuh SIEM với AI SQLi Detection

## 📋 Tổng quan

Khi `realtime_log_collector.py` phát hiện SQLi, nó sẽ tự động ghi vào file log JSONL format để Wazuh Agent có thể đọc và gửi đến Wazuh Manager.

## 📁 File Log Location

**Mặc định**: `logs/wazuh_sqli_detections.jsonl`

**Custom path**: Set environment variable:
```bash
export WAZUH_SQLI_DETECTION_LOG=/var/log/wazuh/sqli_detections.jsonl
```

## 📊 Log Format

File log sử dụng **JSONL format** (JSON Lines), mỗi dòng là một JSON event:

```json
{
  "timestamp": "2025-11-05T18:22:29.840285",
  "event_type": "sqli_detection",
  "source": "ai_sqli_detector",
  "remote_ip": "192.168.1.100",
  "method": "GET",
  "uri": "/dvwa/vulnerabilities/sqli/",
  "query_string": "id=1' OR 1=1--",
  "payload": "",
  "body": "",
  "cookie": "session=abc123",
  "user_agent": "Mozilla/5.0...",
  "status": 200,
  "detected": true,
  "score": 0.852,
  "patterns": ["or 1=1", "--"],
  "confidence": "High",
  "threat_level": "CRITICAL",
  "risk_score": 185.5,
  "risk_level": "CRITICAL",
  "attack_vectors": ["QUERY_PARAMETER_SQLi"],
  "encoding_types": ["URL_ENCODED"],
  "database_types": ["MYSQL"],
  "evasion_techniques": ["COMMENT_INJECTION"],
  "recommendation": "IMMEDIATE_BLOCK"
}
```

## 🔧 Cấu hình Wazuh Agent

### 1. Tạo Wazuh Agent configuration

Tạo file `/var/ossec/etc/ossec.conf.d/sqli_detection.xml`:

```xml
<ossec_config>
  <!-- SQLi Detection Log Reader -->
  <localfile>
    <log_format>json</log_format>
    <location>/opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl</location>
    <!-- Hoặc đường dẫn custom của bạn -->
    <!-- <location>/var/log/wazuh/sqli_detections.jsonl</location> -->
  </localfile>
</ossec_config>
```

### 2. Restart Wazuh Agent

```bash
sudo systemctl restart wazuh-agent
```

### 3. Kiểm tra log

```bash
# Kiểm tra Wazuh Agent log
sudo tail -f /var/ossec/logs/ossec.log | grep sqli

# Kiểm tra file SQLi detection log
tail -f /opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl
```

## 📝 Cấu hình Wazuh Manager (Optional)

### 1. Tạo Decoder cho SQLi events

Tạo file `/var/ossec/etc/decoders/sqli_decoder.xml`:

```xml
<decoder name="sqli-detection">
  <type>json</type>
  <prematch>^\{</prematch>
</decoder>

<decoder name="sqli-detection-json">
  <parent>sqli-detection</parent>
  <type>json</type>
  <regex>"event_type":\s*"sqli_detection"</regex>
  <order>timestamp, event_type, source, remote_ip, method, uri, query_string, score, patterns, confidence, threat_level, risk_score, risk_level, attack_vectors, recommendation</order>
  <fts>timestamp, remote_ip, uri, patterns, threat_level</fts>
</decoder>
```

### 2. Tạo Rule cho SQLi alerts

Tạo file `/var/ossec/etc/rules/sqli_rules.xml`:

```xml
<group name="sqli_detection,">
  <!-- SQLi Detection Alert -->
  <rule id="100001" level="12">
    <decoded_as>sqli-detection-json</decoded_as>
    <match>sqli_detection</match>
    <description>SQLi Attack Detected: $(method) $(uri) from $(remote_ip)</description>
    <field name="threat_level">CRITICAL</field>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>

  <!-- High Risk SQLi -->
  <rule id="100002" level="10">
    <decoded_as>sqli-detection-json</decoded_as>
    <match>sqli_detection</match>
    <field name="risk_level">HIGH|CRITICAL</field>
    <description>High Risk SQLi: $(patterns) - Score: $(score)</description>
  </rule>

  <!-- Union-Based SQLi -->
  <rule id="100003" level="11">
    <decoded_as>sqli-detection-json</decoded_as>
    <match>sqli_detection</match>
    <field name="attack_vectors">QUERY_PARAMETER_SQLi</field>
    <regex>union|select</regex>
    <description>Union-Based SQLi Attack Detected from $(remote_ip)</description>
  </rule>

  <!-- Base64 Encoded SQLi -->
  <rule id="100004" level="10">
    <decoded_as>sqli-detection-json</decoded_as>
    <match>sqli_detection</match>
    <field name="encoding_types">BASE64</field>
    <description>Base64 Encoded SQLi Attack Detected - Obfuscated payload</description>
  </rule>

  <!-- Time-Based SQLi -->
  <rule id="100005" level="11">
    <decoded_as>sqli-detection-json</decoded_as>
    <match>sqli_detection</match>
    <regex>sleep|waitfor|benchmark</regex>
    <description>Time-Based SQLi Attack Detected from $(remote_ip)</description>
  </rule>
</group>
```

### 3. Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
```

## 🚀 Deployment trên Ubuntu với DVWA

### 1. Cài đặt và chạy AI SQLi Detector

```bash
# Clone hoặc copy project
cd /opt
sudo mkdir -p ai-sqli-detection
cd ai-sqli-detection

# Copy files
sudo cp -r /path/to/your/project/* .

# Tạo thư mục logs
sudo mkdir -p logs
sudo chmod 755 logs

# Cài đặt dependencies
sudo pip3 install -r requirements.txt

# Set environment variable cho Wazuh log path
export WAZUH_SQLI_DETECTION_LOG=/opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl

# Chạy realtime collector
python3 realtime_log_collector.py
```

### 2. Cấu hình Wazuh Agent

```bash
# Tạo config file
sudo nano /var/ossec/etc/ossec.conf.d/sqli_detection.xml
```

Paste nội dung config ở trên.

```bash
# Restart Wazuh Agent
sudo systemctl restart wazuh-agent

# Kiểm tra status
sudo systemctl status wazuh-agent
```

### 3. Tạo systemd service (Optional)

Tạo file `/etc/systemd/system/ai-sqli-detector.service`:

```ini
[Unit]
Description=AI SQLi Detection Realtime Collector
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ai-sqli-detection
Environment="WAZUH_SQLI_DETECTION_LOG=/opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl"
ExecStart=/usr/bin/python3 /opt/ai-sqli-detection/realtime_log_collector.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable và start service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable ai-sqli-detector
sudo systemctl start ai-sqli-detector
sudo systemctl status ai-sqli-detector
```

## 📊 Monitoring

### Kiểm tra log file

```bash
# Xem real-time log
tail -f /opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl

# Xem số lượng detections
wc -l /opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl

# Parse và filter
cat /opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl | jq '.threat_level, .remote_ip, .uri' | head -20
```

### Kiểm tra Wazuh integration

```bash
# Check Wazuh Agent log
sudo tail -f /var/ossec/logs/ossec.log | grep -i sqli

# Check Wazuh Manager alerts
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep -i sqli
```

## 🔍 Query trong Wazuh Dashboard

Sau khi tích hợp, bạn có thể query trong Wazuh Dashboard:

```
data.source:ai_sqli_detector AND data.threat_level:CRITICAL
```

Hoặc filter theo IP:

```
data.source:ai_sqli_detector AND data.remote_ip:192.168.1.100
```

## 📝 Log Rotation

File log tự động rotate khi đạt **10MB**:
- `wazuh_sqli_detections.jsonl` (current)
- `wazuh_sqli_detections.jsonl.1` (backup 1)
- `wazuh_sqli_detections.jsonl.2` (backup 2)
- `wazuh_sqli_detections.jsonl.3` (backup 3)

## ⚙️ Customization

### Thay đổi log path

```bash
# Trong code
export WAZUH_SQLI_DETECTION_LOG=/custom/path/to/sqli_detections.jsonl
python3 realtime_log_collector.py

# Hoặc trong systemd service
Environment="WAZUH_SQLI_DETECTION_LOG=/custom/path/to/sqli_detections.jsonl"
```

### Thay đổi rotation size

Sửa trong `realtime_log_collector.py`:

```python
_rotate_wazuh_log_if_needed(max_bytes: int = 20 * 1024 * 1024, backups: int = 5)  # 20MB, 5 backups
```

## 🔐 Permissions

Đảm bảo Wazuh Agent có quyền đọc file log:

```bash
# Nếu chạy với user khác
sudo chown root:wazuh /opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl
sudo chmod 644 /opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl

# Hoặc cho phép group đọc
sudo chmod 640 /opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl
```

## ✅ Testing

### Test manual

```bash
# Tạo test log entry
echo '{"timestamp":"2025-11-05T18:22:29","event_type":"sqli_detection","source":"ai_sqli_detector","remote_ip":"192.168.1.100","method":"GET","uri":"/test.php","query_string":"id=1 OR 1=1","score":0.85,"patterns":["or 1=1"],"confidence":"High","threat_level":"CRITICAL"}' >> /opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl

# Kiểm tra Wazuh Agent nhận được
sudo tail -f /var/ossec/logs/ossec.log | grep sqli
```

## 📚 Troubleshooting

### Wazuh Agent không đọc được file

1. **Kiểm tra file path trong config**:
   ```bash
   cat /var/ossec/etc/ossec.conf.d/sqli_detection.xml
   ```

2. **Kiểm tra permissions**:
   ```bash
   ls -la /opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl
   ```

3. **Kiểm tra Wazuh Agent log**:
   ```bash
   sudo tail -f /var/ossec/logs/ossec.log
   ```

### File log không được tạo

1. **Kiểm tra thư mục logs tồn tại**:
   ```bash
   ls -la /opt/ai-sqli-detection/logs/
   ```

2. **Kiểm tra realtime_log_collector đang chạy**:
   ```bash
   ps aux | grep realtime_log_collector
   ```

3. **Kiểm tra có detections không**:
   ```bash
   tail -f realtime_sqli_detection.log | grep "SQLi DETECTED"
   ```

---

**✅ Setup hoàn tất!** File log sẽ tự động được tạo khi có SQLi detections và Wazuh Agent sẽ gửi đến Wazuh Manager.


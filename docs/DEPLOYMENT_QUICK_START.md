# 🚀 Quick Start - Deploy AI SQLi Detection với Wazuh

## 📋 Tóm tắt

Khi `realtime_log_collector.py` detect SQLi realtime, nó sẽ **TỰ ĐỘNG** lưu vào file:
```
logs/wazuh_sqli_detections.jsonl
```

File này được format JSONL, thread-safe, có auto rotation, và sẵn sàng cho Wazuh Agent đọc.

## ✅ Logic Flow

```
Apache Log → realtime_log_collector.py
    ↓
Detect SQLi (is_sqli == True)
    ↓
✅ Lưu vào logs/wazuh_sqli_detections.jsonl (LUÔN LƯU)
    ↓
Filter real threats (để log chi tiết)
    ↓
Log chi tiết + gửi webhook (nếu real threat)
```

## 🎯 File Log Location

**Default**: `logs/wazuh_sqli_detections.jsonl`

**Custom**: Set environment variable:
```bash
export WAZUH_SQLI_DETECTION_LOG=/custom/path/to/wazuh_sqli_detections.jsonl
```

## 🔧 Cấu hình Wazuh Agent

### 1. Tạo config file

```bash
sudo nano /var/ossec/etc/ossec.conf.d/sqli_detection.xml
```

Paste:
```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl</location>
  </localfile>
</ossec_config>
```

### 2. Restart Wazuh Agent

```bash
sudo systemctl restart wazuh-agent
```

### 3. Kiểm tra

```bash
# Xem log realtime
tail -f /opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl

# Kiểm tra Wazuh Agent
sudo tail -f /var/ossec/logs/ossec.log | grep sqli
```

## 📊 Format Log

Mỗi dòng là một JSON event:

```json
{
  "timestamp": "2025-11-07T07:28:50.092201",
  "event_type": "sqli_detection",
  "source": "ai_sqli_detector",
  "remote_ip": "192.168.1.100",
  "method": "GET",
  "uri": "/dvwa/vulnerabilities/sqli/",
  "query_string": "id=1' OR 1=1--",
  "score": 0.852,
  "patterns": ["or 1=1", "--"],
  "confidence": "High",
  "threat_level": "CRITICAL",
  "risk_score": 185.5,
  "risk_level": "CRITICAL",
  "attack_vectors": ["QUERY_PARAMETER_SQLi"],
  "recommendation": "IMMEDIATE_BLOCK"
}
```

## ⚙️ Deployment trên Ubuntu

```bash
# 1. Copy project
sudo mkdir -p /opt/ai-sqli-detection
sudo cp -r * /opt/ai-sqli-detection/

# 2. Install dependencies
cd /opt/ai-sqli-detection
sudo pip3 install -r requirements.txt

# 3. Set log path
export WAZUH_SQLI_DETECTION_LOG=/opt/ai-sqli-detection/logs/wazuh_sqli_detections.jsonl

# 4. Run collector
python3 realtime_log_collector.py
```

## 📚 Chi tiết

Xem `WAZUH_INTEGRATION.md` để biết:
- Cấu hình Wazuh Manager (decoders, rules)
- Systemd service setup
- Troubleshooting
- Advanced configuration

---

**✅ Tất cả SQLi detections đều được lưu vào `logs/wazuh_sqli_detections.jsonl`**


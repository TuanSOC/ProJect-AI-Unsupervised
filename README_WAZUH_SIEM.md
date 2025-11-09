# Wazuh SIEM SQLi Detector Setup Guide

## Tổng quan

Script này tự động setup và chạy AI SQLi Detector trên Wazuh SIEM server để detect SQLi attacks realtime từ Apache access logs.

## Yêu cầu

- Ubuntu/Debian Linux
- Wazuh SIEM đã được cài đặt và chạy
- Python 3.8+
- Root/sudo access

## Cài đặt nhanh

### Bước 1: Clone repository

```bash
git clone https://github.com/TuanSOC/ProJect-AI-Unsupervised.git
cd ProJect-AI-Unsupervised
```

### Bước 2: Chạy setup script

```bash
sudo chmod +x setup_wazuh_siem.sh
sudo ./setup_wazuh_siem.sh
```

Script sẽ tự động:
- Cài đặt dependencies (Python, pip, packages)
- Tạo thư mục cần thiết (`/opt/ai`, `/var/ossec/logs`)
- Copy files đến `/opt/ai`
- Train AI model (nếu chưa có)
- Test model và detector
- Tạo systemd service
- Start service tự động

## Cấu trúc thư mục sau khi cài đặt

```
/opt/ai/
├── optimized_sqli_detector.py          # AI model core
├── wazuh_siem_realtime_detector.py     # Wazuh SIEM detector
└── models/
    └── optimized_sqli_detector.pkl     # Trained model

/var/ossec/logs/
└── ai-engine-sqli                      # Detection logs (JSONL format)

/opt/ai/apache_access.log               # Input log từ Wazuh
```

## Cấu hình

### Environment Variables

Có thể cấu hình qua systemd service file hoặc environment:

- `WAZUH_SIEM_LOG_PATH`: Path đến log file từ Wazuh (default: `/opt/ai/apache_access.log`)
- `WAZUH_SIEM_SQLI_LOG`: Path đến file log detection (default: `/var/ossec/logs/ai-engine-sqli`)

### Sửa systemd service

```bash
sudo systemctl edit wazuh-siem-sqli-detector.service
```

Thêm vào `[Service]` section:
```ini
Environment="WAZUH_SIEM_LOG_PATH=/custom/path/to/log"
Environment="WAZUH_SIEM_SQLI_LOG=/custom/path/to/output"
```

Sau đó reload và restart:
```bash
sudo systemctl daemon-reload
sudo systemctl restart wazuh-siem-sqli-detector.service
```

## Sử dụng

### ⚠️ Lưu ý quan trọng

**Sau khi chạy `setup_wazuh_siem.sh`, bạn KHÔNG cần chạy tay script `wazuh_siem_realtime_detector.py`!**

Systemd service sẽ tự động:
- ✅ Start service ngay sau khi setup
- ✅ Tự động start khi hệ thống boot
- ✅ Tự động restart nếu service crash (sau 10 giây)
- ✅ Quản lý logs qua journalctl

### Quản lý service

```bash
# Check status (service đã được start tự động)
sudo systemctl status wazuh-siem-sqli-detector

# Restart service (nếu cần)
sudo systemctl restart wazuh-siem-sqli-detector

# Stop service (nếu cần dừng)
sudo systemctl stop wazuh-siem-sqli-detector

# Start service (nếu đã stop)
sudo systemctl start wazuh-siem-sqli-detector

# Disable auto-start on boot (nếu không muốn tự động start)
sudo systemctl disable wazuh-siem-sqli-detector

# Enable auto-start on boot (mặc định đã enable)
sudo systemctl enable wazuh-siem-sqli-detector
```

### ⚠️ KHÔNG chạy tay script

**KHÔNG** chạy trực tiếp:
```bash
# ❌ KHÔNG làm như này
python3 /opt/ai/wazuh_siem_realtime_detector.py
```

**Lý do:**
- Systemd đã quản lý service
- Chạy tay sẽ conflict với systemd service
- Service sẽ tự động restart và có thể gây lỗi

### Xem logs

```bash
# Service logs (real-time)
sudo journalctl -u wazuh-siem-sqli-detector.service -f

# Detection logs (JSONL format)
sudo tail -f /var/ossec/logs/ai-engine-sqli

# Application logs
sudo tail -f /var/log/wazuh_siem_sqli_detector.log
```

### Test detection

```bash
# Test với log mẫu
cd /opt/ai
python3 test_wazuh_siem_detector.py
```

### Debug mode (chỉ khi cần)

**⚠️ Chỉ dùng khi systemd service không chạy và cần debug:**

```bash
# Stop systemd service trước
sudo systemctl stop wazuh-siem-sqli-detector

# Chạy script test (chỉ để debug)
cd /opt/ai
./start_wazuh_siem_detector.sh

# Sau khi debug xong, start lại systemd service
sudo systemctl start wazuh-siem-sqli-detector
```

**Lưu ý:** Script `start_wazuh_siem_detector.sh` sẽ tự động kiểm tra và cảnh báo nếu systemd service đang chạy.

## Format log detection

Mỗi dòng trong `/var/ossec/logs/ai-engine-sqli` là một JSON object:

```json
{
  "timestamp": "2025-11-08T01:24:00.552+0700",
  "event_type": "sqli_detection",
  "source": "ai_sqli_detector",
  "wazuh_agent": {
    "id": "001",
    "name": "web-server",
    "ip": "192.168.15.10"
  },
  "remote_ip": "192.168.15.12",
  "method": "GET",
  "uri": "/dvwa/vulnerabilities/sqli/index.php",
  "query_string": "?id=1%27%29+UNION+ALL+SELECT+NULL...",
  "payload": "1%27%29+UNION+ALL+SELECT+NULL...",
  "detected": true,
  "score": 0.9542,
  "threat_level": "HIGH",
  "confidence": "HIGH",
  "risk_score": 85.5,
  "risk_level": "HIGH",
  "patterns": ["UNION SELECT", "NULL injection"],
  "recommendation": "BLOCK_AND_INVESTIGATE"
}
```

## Tích hợp với Wazuh

### Cách 1: Wazuh đọc trực tiếp từ file log

Cấu hình Wazuh để đọc từ `/var/ossec/logs/ai-engine-sqli`:

1. Thêm vào `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/ai-engine-sqli</location>
</localfile>
```

2. Restart Wazuh manager:
```bash
sudo systemctl restart wazuh-manager
```

### Cách 2: Sử dụng Wazuh API

Có thể tích hợp qua Wazuh API để gửi alerts trực tiếp.

## Troubleshooting

### Service không start

```bash
# Check logs
sudo journalctl -u wazuh-siem-sqli-detector.service -n 50

# Check model file
ls -la /opt/ai/models/optimized_sqli_detector.pkl

# Check permissions
ls -la /opt/ai/
ls -la /var/ossec/logs/
```

### Model không load

```bash
# Test model loading
cd /opt/ai
python3 -c "from optimized_sqli_detector import OptimizedSQLIDetector; d = OptimizedSQLIDetector(); d.load_model('models/optimized_sqli_detector.pkl'); print('OK')"
```

### Log file không đọc được

```bash
# Check permissions
ls -la /opt/ai/apache_access.log

# Fix permissions if needed
sudo chmod 644 /opt/ai/apache_access.log
```

### Không detect được SQLi

```bash
# Test với payload mẫu
cd /opt/ai
python3 test_wazuh_siem_detector.py
```

## Uninstall

```bash
# Stop và disable service
sudo systemctl stop wazuh-siem-sqli-detector
sudo systemctl disable wazuh-siem-sqli-detector

# Remove service file
sudo rm /etc/systemd/system/wazuh-siem-sqli-detector.service
sudo systemctl daemon-reload

# Remove files (optional)
sudo rm -rf /opt/ai
sudo rm -rf /var/ossec/logs/ai-engine-sqli*
```

## Support

Nếu gặp vấn đề, vui lòng:
1. Check logs: `journalctl -u wazuh-siem-sqli-detector.service -f`
2. Test model: `python3 test_wazuh_siem_detector.py`
3. Check GitHub Issues: https://github.com/TuanSOC/ProJect-AI-Unsupervised/issues

## License

Xem LICENSE file trong repository.


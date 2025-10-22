# AI SQLi Detection System

Hệ thống phát hiện SQL injection realtime sử dụng AI không giám sát.

## 🚀 Quick Start

### 1. Setup trên Ubuntu
```bash
# Clone repository
git clone https://github.com/TuanSOC/ProJect-AI-Unsupervised.git
cd ProJect-AI-Unsupervised

# Setup system
chmod +x setup_ubuntu.sh
./setup_ubuntu.sh

# Start system
chmod +x start_system.sh
./start_system.sh
```

### 2. Sử dụng

#### Web Interface
- Truy cập: http://localhost:5000
- Test payload SQLi
- Xem kết quả detection
- Dashboard realtime

#### Realtime Detection
- Tự động monitor Apache logs
- Phát hiện SQLi realtime
- Gửi alert khi phát hiện

## 📁 Files quan trọng

- `app.py` - Web interface
- `realtime_log_collector.py` - Realtime detection
- `optimized_sqli_detector.py` - AI model
- `templates/index.html` - Web dashboard
- `models/optimized_sqli_detector.pkl` - Trained model

## 🔧 Cấu hình

### Apache Log Format
Đảm bảo Apache log có format JSON với các fields:
```json
{
  "time": "2025-10-22T08:47:41+0700",
  "remote_ip": "192.168.1.100",
  "method": "GET",
  "uri": "/vulnerabilities/sqli/index.php",
  "query_string": "?id=1' OR 1=1--",
  "status": 200,
  "payload": "id=1' OR 1=1--",
  "user_agent": "Mozilla/5.0...",
  "cookie": "PHPSESSID=abc123"
}
```

### Log File Path
Mặc định monitor: `/var/log/apache2/access_full_json.log`

## 🎯 Features

- ✅ AI phát hiện SQLi realtime
- ✅ Web interface test payload
- ✅ Dashboard monitoring
- ✅ Alert system
- ✅ Pattern detection
- ✅ Confidence scoring

## 📊 Model Performance

- **Accuracy:** 100% (5/5 test cases)
- **Features:** 37 engineered features
- **Algorithm:** Isolation Forest
- **Contamination:** 0.01 (1% outliers)

## 🛠️ Troubleshooting

### Model không load được
```bash
python3 optimized_sqli_detector.py
```

### Permission denied
```bash
sudo chmod +x *.sh
```

### Port 5000 đã được sử dụng
```bash
# Kill process using port 5000
sudo lsof -ti:5000 | xargs kill -9
```

## 📞 Support

Repository: https://github.com/TuanSOC/ProJect-AI-Unsupervised.git
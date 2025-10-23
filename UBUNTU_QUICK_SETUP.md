# 🚀 UBUNTU QUICK SETUP - AI SQLi Detection System

## 📋 Hướng dẫn nhanh cho Ubuntu

### 1. Xóa project cũ (nếu có)
```bash
# Xóa thư mục cũ
rm -rf ProJect-AI-Unsupervised
```

### 2. Clone project mới
```bash
# Clone từ GitHub
git clone https://github.com/TuanSOC/ProJect-AI-Unsupervised.git
cd ProJect-AI-Unsupervised
```

### 3. Chạy setup tự động
```bash
# Chạy script setup
python3 ubuntu_fix_detection.py
```

### 4. Khởi động hệ thống
```bash
# Terminal 1: Start web app
python3 app.py

# Terminal 2: Start realtime monitoring
python3 realtime_log_collector.py
```

## 🎯 Kết quả mong đợi

- ✅ **100% SQLi Detection** cho tất cả payloads
- ✅ **Real-time monitoring** Apache logs
- ✅ **Web interface** tại `http://localhost:5000`
- ✅ **Detailed analysis** với feature scores
- ✅ **Robust JSON parsing** không crash

## 🔧 Troubleshooting

### Nếu gặp lỗi dependencies:
```bash
sudo apt update
sudo apt install python3-pip python3-venv
pip3 install -r requirements.txt
```

### Nếu Apache log không tồn tại:
```bash
# Kiểm tra Apache config
sudo nano /etc/apache2/apache2.conf

# Thêm JSON logging format
LogFormat "{ \"time\": \"%{%Y-%m-%dT%H:%M:%S%z}t\", \"remote_ip\": \"%a\", \"method\": \"%m\", \"uri\": \"%U\", \"query_string\": \"%q\", \"status\": %s, \"bytes_sent\": %b, \"response_time_ms\": %D, \"referer\": \"%{Referer}i\", \"user_agent\": \"%{User-Agent}i\", \"request_length\": %I, \"response_length\": %O, \"cookie\": \"%{Cookie}i\", \"payload\": \"%q\", \"session_token\": \"%{PHPSESSID}C\" }" json_format

# Thêm vào VirtualHost
CustomLog /var/log/apache2/access_full_json.log json_format

# Restart Apache
sudo systemctl restart apache2
```

### Nếu model không load:
```bash
# Retrain model manually
python3 -c "
from optimized_sqli_detector import OptimizedSQLIDetector
detector = OptimizedSQLIDetector()
detector.train_from_path('sqli_logs_clean_100k.jsonl')
detector.save_model('models/optimized_sqli_detector.pkl')
print('Model retrained successfully!')
"
```

## 📊 Test SQLi Detection

### Test với web interface:
1. Mở `http://localhost:5000`
2. Paste SQLi payload vào form
3. Click "Detect SQLi"
4. Xem detailed analysis

### Test với realtime:
1. Chạy `python3 realtime_log_collector.py`
2. Tạo SQLi request đến Apache
3. Xem log output với detection results

## 🎉 Hoàn thành!

Sau khi setup xong, bạn sẽ có:
- **AI SQLi Detection System** hoạt động 100%
- **Real-time monitoring** Apache logs
- **Web dashboard** với detailed analysis
- **Robust error handling** không crash

**Chúc bạn thành công!** 🚀

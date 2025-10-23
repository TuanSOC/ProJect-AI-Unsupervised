# Ubuntu Manual Fix Guide

## Xóa cài đặt cũ và cài đặt đúng requirements

### Bước 1: Xóa các package cũ
```bash
# Xóa tất cả packages có thể gây conflict
pip uninstall -y scikit-learn numpy pandas flask werkzeug joblib requests psutil ipaddress

# Xóa cache pip
pip cache purge
```

### Bước 2: Cài đặt requirements mới
```bash
# Cài đặt từ requirements.txt
pip install -r requirements.txt
```

### Bước 3: Kiểm tra cài đặt
```bash
# Kiểm tra versions
python3 -c "
import sklearn
print('scikit-learn:', sklearn.__version__)
import numpy
print('numpy:', numpy.__version__)
import pandas
print('pandas:', pandas.__version__)
import flask
print('flask:', flask.__version__)
"
```

### Bước 4: Retrain model với version mới
```bash
# Retrain model để tương thích với scikit-learn hiện tại
python3 -c "
from optimized_sqli_detector import OptimizedSQLIDetector
detector = OptimizedSQLIDetector()
detector.train_from_path('sqli_logs_clean_100k.jsonl')
print('Model retrained successfully!')
"
```

### Bước 5: Test model
```bash
# Test model loading
python3 -c "
from optimized_sqli_detector import OptimizedSQLIDetector
detector = OptimizedSQLIDetector()
detector.load_model('models/optimized_sqli_detector.pkl')
print('Model loaded successfully!')
"
```

### Bước 6: Chạy ứng dụng
```bash
# Chạy web app
python3 app.py

# Chạy real-time monitoring (terminal khác)
python3 realtime_log_collector.py
```

## Troubleshooting

### Nếu vẫn có lỗi version mismatch:
```bash
# Xóa model cũ và retrain
rm models/optimized_sqli_detector.pkl
python3 optimized_sqli_detector.py
```

### Nếu có lỗi import:
```bash
# Cài đặt lại từ đầu
pip install --force-reinstall -r requirements.txt
```

### Nếu có lỗi permission:
```bash
# Sử dụng --user flag
pip install --user -r requirements.txt
```

## Kết quả mong đợi

- Không có version mismatch warnings
- Model load thành công
- App chạy bình thường
- 100% detection rate được duy trì

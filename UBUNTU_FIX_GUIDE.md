# Ubuntu Fix Guide - Version Compatibility

## Vấn đề hiện tại

1. **ipaddress version**: Ubuntu không có version 1.0, chỉ có 1.0.1+
2. **scikit-learn version mismatch**: Ubuntu dùng 1.4.2 nhưng model được train với 1.7.2

## Giải pháp

### Bước 1: Cập nhật requirements.txt
```bash
git pull origin main
```

### Bước 2: Cài đặt dependencies
```bash
pip install -r requirements.txt
```

### Bước 3: Retrain model với scikit-learn hiện tại
```bash
python3 fix_version_compatibility.py
```

### Bước 4: Test model
```bash
python3 -c "from optimized_sqli_detector import OptimizedSQLIDetector; detector = OptimizedSQLIDetector(); detector.load_model('models/optimized_sqli_detector.pkl'); print('Model loaded successfully!')"
```

### Bước 5: Chạy ứng dụng
```bash
python3 app.py
```

## Lưu ý

- Script `fix_version_compatibility.py` sẽ retrain model với scikit-learn version hiện tại
- Điều này sẽ loại bỏ version mismatch warnings
- Model sẽ hoạt động hoàn hảo với scikit-learn 1.4.2

## Troubleshooting

Nếu vẫn có lỗi:
1. Kiểm tra Python version: `python3 --version`
2. Kiểm tra scikit-learn version: `python3 -c "import sklearn; print(sklearn.__version__)"`
3. Chạy lại script retrain: `python3 fix_version_compatibility.py`

# AI Unsupervised SQLi Detection System

## 🎯 Overview
Hệ thống phát hiện SQL Injection sử dụng AI không giám sát (Unsupervised Learning) với Isolation Forest algorithm.

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Fix Detection Issues (if needed)
```bash
# Test detection accuracy
python3 fix_detection_threshold.py

# Retrain model with balanced data
python3 retrain_model_balanced.py
```

### 3. Run Web Dashboard
```bash
python3 app.py
```

### 4. Run Realtime Detection
```bash
python3 realtime_log_collector.py
```

## 📊 Features
- **Unsupervised AI**: Isolation Forest for anomaly detection
- **Real-time Monitoring**: Apache log monitoring
- **Web Dashboard**: Flask-based interface
- **Pattern Detection**: Rule-based + AI hybrid approach
- **False Positive Reduction**: Balanced training data

## 🔧 Configuration
- **Detection Threshold**: 0.8 (adjustable)
- **Log File**: `/var/log/apache2/access_full_json.log`
- **Webhook**: `http://localhost:5000/api/realtime-detect`

## 🛠️ Troubleshooting

### False Positive Issues
Nếu hệ thống báo false positive (detect normal request là SQLi):

1. **Test detection accuracy**:
   ```bash
   python3 fix_detection_threshold.py
   ```

2. **Retrain model với balanced data**:
```bash
   python3 retrain_model_balanced.py
```

3. **Restart realtime collector**:
```bash
   python3 realtime_log_collector.py
```

### Clean Up Project
```bash
python3 cleanup_project.py
```

## 📈 Performance
- **Accuracy**: High detection rate for known SQLi patterns
- **False Positives**: Reduced with balanced training
- **Real-time**: Sub-second detection latency

## 📁 Essential Files
```
├── app.py                          # Flask web application
├── optimized_sqli_detector.py      # Core AI model (Isolation Forest)
├── realtime_log_collector.py       # Real-time log monitoring
├── fix_detection_threshold.py      # Fix false positive issues
├── retrain_model_balanced.py       # Retrain with balanced data
├── cleanup_project.py              # Clean up unnecessary files
├── requirements.txt                # Python dependencies
├── templates/index.html            # Web dashboard template
└── models/                         # AI model storage
    └── optimized_sqli_detector.pkl
```

## 🎯 Usage
1. **Web Dashboard**: Monitor threats via web interface
2. **Real-time Detection**: Monitor Apache logs continuously
3. **API Endpoints**: `/api/detect`, `/api/realtime-detect`
4. **Batch Analysis**: Upload log files for analysis
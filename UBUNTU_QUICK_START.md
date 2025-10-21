# 🚀 Ubuntu Quick Start Guide

## ⚡ **Quick Setup (5 minutes)**

### **1. Clone và Setup**
```bash
# Clone repository
git clone https://github.com/TuanSOC/ProJect-AI-Unsupervised.git
cd ProJect-AI-Unsupervised

# Make scripts executable
chmod +x setup_user.sh setup_realtime_detection.sh

# Run user setup (không cần sudo)
./setup_user.sh
```

### **2. Start Web Application**
```bash
# Start web dashboard
python3 app.py

# Access dashboard: http://localhost:5000
```

### **3. Start Real-time Monitoring**
```bash
# Start real-time monitoring
python3 realtime_log_collector.py
```

---

## 🔧 **Troubleshooting**

### **❌ "Missing packages" Error**
```bash
# Install missing packages
pip install flask pandas scikit-learn joblib requests

# Or install all at once
pip install -r requirements.txt
pip install -r requirements_web.txt
```

### **❌ "Permission denied" Error**
```bash
# Don't use sudo for setup
./setup_user.sh  # ✅ Correct
sudo ./setup_realtime_detection.sh  # ❌ Wrong (causes permission issues)
```

### **❌ "Model not found" Error**
```bash
# Train model manually
python3 -c "
from optimized_sqli_detector import OptimizedSQLIDetector
import json

# Load and train
with open('sqli_logs_clean_100k.jsonl', 'r') as f:
    clean_logs = [json.loads(line.strip()) for line in f if line.strip()]

detector = OptimizedSQLIDetector()
detector.train(clean_logs[:10000])
detector.save_model('models/optimized_sqli_detector.pkl')
print('✅ Model trained')
"
```

---

## 📋 **Commands Summary**

```bash
# Setup
git clone https://github.com/TuanSOC/ProJect-AI-Unsupervised.git
cd ProJect-AI-Unsupervised
chmod +x setup_user.sh
./setup_user.sh

# Run Web App
python3 app.py

# Run Real-time Monitoring
python3 realtime_log_collector.py

# Test System
python3 -c "from optimized_sqli_detector import OptimizedSQLIDetector; print('✅ Ready')"
```

---

## 🌐 **Access Points**

- **Web Dashboard**: http://localhost:5000
- **API Endpoints**: http://localhost:5000/api/*
- **Real-time Logs**: `tail -f realtime_threats.jsonl`

---

**🎉 System ready in 5 minutes!**

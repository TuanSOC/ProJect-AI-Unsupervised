# 🐧 Ubuntu Setup Guide - AI SQL Injection Detection System

## 🚀 **Quick Setup for Ubuntu**

### **1. Clone Repository**
```bash
# Clone the repository
git clone https://github.com/TuanSOC/ProJect-AI-Unsupervised.git
cd ProJect-AI-Unsupervised

# Make setup script executable
chmod +x setup_realtime_detection.sh
```

### **2. Install Dependencies**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.8+ and pip
sudo apt install python3 python3-pip python3-venv -y

# Install system dependencies
sudo apt install curl wget git -y

# Install Apache (for log monitoring)
sudo apt install apache2 -y

# Start Apache
sudo systemctl start apache2
sudo systemctl enable apache2
```

### **3. Setup Python Environment**
```bash
# Create virtual environment
python3 -m venv ai-sqli-env

# Activate virtual environment
source ai-sqli-env/bin/activate

# Install Python dependencies
pip install -r requirements.txt
pip install -r requirements_web.txt

# Install additional dependencies for Ubuntu
pip install psutil shap lime
```

### **4. Configure Apache Logs**
```bash
# Enable JSON log format
sudo a2enmod log_config

# Create custom log format
sudo tee /etc/apache2/conf-available/json-log.conf << EOF
LogFormat "{ \"timestamp\": \"%{%Y-%m-%dT%H:%M:%S}t.%{usec_frac}t%{%z}t\", \"remote_ip\": \"%a\", \"method\": \"%m\", \"uri\": \"%U\", \"query_string\": \"%q\", \"status\": %s, \"response_time\": %D, \"user_agent\": \"%{User-Agent}i\", \"referer\": \"%{Referer}i\", \"cookie\": \"%{Cookie}i\" }" json_log
CustomLog /var/log/apache2/access_full_json.log json_log
EOF

# Enable the configuration
sudo a2enconf json-log

# Restart Apache
sudo systemctl restart apache2
```

### **5. Run the System**

#### **Option A: Web Application**
```bash
# Activate virtual environment
source ai-sqli-env/bin/activate

# Run web application
python app.py

# Access dashboard at: http://localhost:5000
```

#### **Option B: Real-time Monitoring**
```bash
# Activate virtual environment
source ai-sqli-env/bin/activate

# Run real-time monitoring
python realtime_log_collector.py

# Or use the setup script
./setup_realtime_detection.sh
```

---

## 🔧 **Advanced Configuration**

### **1. Systemd Service (Auto-start)**
```bash
# Create systemd service file
sudo tee /etc/systemd/system/ai-sqli-detector.service << EOF
[Unit]
Description=AI SQL Injection Detection System
After=network.target apache2.service

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/ProJect-AI-Unsupervised
Environment=PATH=/path/to/ProJect-AI-Unsupervised/ai-sqli-env/bin
ExecStart=/path/to/ProJect-AI-Unsupervised/ai-sqli-env/bin/python realtime_log_collector.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable ai-sqli-detector.service
sudo systemctl start ai-sqli-detector.service
```

### **2. Firewall Configuration**
```bash
# Allow web traffic
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 5000/tcp

# Enable firewall
sudo ufw enable
```

### **3. Log Rotation**
```bash
# Configure log rotation
sudo tee /etc/logrotate.d/apache2-json << EOF
/var/log/apache2/access_full_json.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
    postrotate
        systemctl reload apache2
    endscript
}
EOF
```

---

## 📊 **Monitoring & Maintenance**

### **1. Check System Status**
```bash
# Check Apache status
sudo systemctl status apache2

# Check AI detector status
sudo systemctl status ai-sqli-detector

# Check logs
tail -f /var/log/apache2/access_full_json.log
```

### **2. Performance Monitoring**
```bash
# Monitor system resources
htop

# Monitor disk usage
df -h

# Monitor network connections
netstat -tulpn
```

### **3. Log Analysis**
```bash
# View recent logs
tail -100 /var/log/apache2/access_full_json.log

# Search for SQLi patterns
grep -i "union\|select\|or 1=1" /var/log/apache2/access_full_json.log

# Monitor in real-time
tail -f /var/log/apache2/access_full_json.log | grep -i "union\|select"
```

---

## 🚨 **Troubleshooting**

### **Common Issues:**

#### **1. Permission Denied**
```bash
# Fix file permissions
sudo chown -R www-data:www-data /path/to/ProJect-AI-Unsupervised
sudo chmod -R 755 /path/to/ProJect-AI-Unsupervised
```

#### **2. Python Dependencies**
```bash
# Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall
```

#### **3. Apache Log Format**
```bash
# Check Apache configuration
sudo apache2ctl configtest

# Restart Apache
sudo systemctl restart apache2
```

#### **4. Port Already in Use**
```bash
# Find process using port 5000
sudo lsof -i :5000

# Kill process
sudo kill -9 <PID>
```

---

## 🔐 **Security Configuration**

### **1. Secure Apache**
```bash
# Disable server signature
echo "ServerTokens Prod" | sudo tee -a /etc/apache2/apache2.conf
echo "ServerSignature Off" | sudo tee -a /etc/apache2/apache2.conf

# Restart Apache
sudo systemctl restart apache2
```

### **2. Firewall Rules**
```bash
# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 5000/tcp
```

### **3. SSL Certificate (Optional)**
```bash
# Install Certbot
sudo apt install certbot python3-certbot-apache -y

# Get SSL certificate
sudo certbot --apache -d your-domain.com
```

---

## 📈 **Performance Optimization**

### **1. System Optimization**
```bash
# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize kernel parameters
echo "net.core.somaxconn = 65536" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### **2. Apache Optimization**
```bash
# Edit Apache configuration
sudo nano /etc/apache2/apache2.conf

# Add these settings:
# MaxRequestWorkers 400
# ServerLimit 16
# ThreadsPerChild 25
```

---

## 🎯 **Quick Commands Summary**

```bash
# Start system
cd ProJect-AI-Unsupervised
source ai-sqli-env/bin/activate
python app.py

# Start real-time monitoring
python realtime_log_collector.py

# Check status
sudo systemctl status apache2
sudo systemctl status ai-sqli-detector

# View logs
tail -f /var/log/apache2/access_full_json.log

# Restart services
sudo systemctl restart apache2
sudo systemctl restart ai-sqli-detector
```

---

## 📞 **Support**

### **GitHub Repository:**
- **URL**: https://github.com/TuanSOC/ProJect-AI-Unsupervised.git
- **Issues**: https://github.com/TuanSOC/ProJect-AI-Unsupervised/issues

### **Documentation:**
- **README.md**: Main documentation
- **README_DETAILED.md**: Detailed technical docs
- **UNSUPERVISED_AI_SYSTEM.md**: AI system documentation

---

**🎉 AI SQL Injection Detection System sẵn sàng chạy trên Ubuntu!**

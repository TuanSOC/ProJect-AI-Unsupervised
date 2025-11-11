#!/bin/bash
# Script để start Wazuh SIEM Realtime SQLi Detector
# 
# CANH BAO: Script nay chi dung de TEST/DEBUG
# 
# Trong production, sử dụng systemd service:
#   sudo systemctl start wazuh-siem-sqli-detector
#   sudo systemctl status wazuh-siem-sqli-detector
#
# Nếu systemd service đang chạy, KHÔNG chạy script này!
# Chạy script này sẽ conflict với systemd service.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if systemd service is running
if command -v systemctl &> /dev/null; then
    if systemctl is-active --quiet wazuh-siem-sqli-detector.service 2>/dev/null; then
        echo "WARNING: Systemd service 'wazuh-siem-sqli-detector' is already running!"
        echo "   Không nên chạy script này khi systemd service đang chạy."
        echo "   Sử dụng: sudo systemctl status wazuh-siem-sqli-detector"
        echo ""
        read -p "Bạn có muốn tiếp tục? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Da huy."
            exit 1
        fi
    fi
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Python3 khong duoc tim thay!"
    exit 1
fi

# Check model file
MODEL_PATHS=(
    "models/optimized_sqli_detector.pkl"
    "/opt/ai/models/optimized_sqli_detector.pkl"
)

MODEL_FOUND=false
for path in "${MODEL_PATHS[@]}"; do
    if [ -f "$path" ]; then
        MODEL_FOUND=true
        echo "Model found: $path"
        break
    fi
done

if [ "$MODEL_FOUND" = false ]; then
    echo "Warning: Model file khong duoc tim thay!"
    echo "   Đảm bảo model đã được train và lưu tại một trong các vị trí:"
    for path in "${MODEL_PATHS[@]}"; do
        echo "   - $path"
    done
fi

# Check log file
LOG_PATH="${WAZUH_SIEM_LOG_PATH:-/opt/ai/apache_access.log}"
if [ ! -f "$LOG_PATH" ]; then
    echo "Warning: Log file khong ton tai: $LOG_PATH"
    echo "   Tạo file nếu cần hoặc set WAZUH_SIEM_LOG_PATH env var"
fi

# Check output directory
OUTPUT_DIR="/var/ossec/logs"
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Tao thu muc output: $OUTPUT_DIR"
    sudo mkdir -p "$OUTPUT_DIR"
    sudo chmod 755 "$OUTPUT_DIR"
fi

# Start detector
echo "Starting Wazuh SIEM Realtime SQLi Detector (TEST/DEBUG MODE)..."
echo "   Log input: ${WAZUH_SIEM_LOG_PATH:-/opt/ai/apache_access.log}"
echo "   Log output: ${WAZUH_SIEM_SQLI_LOG:-/var/ossec/logs/ai-engine-sqli}"
echo ""
echo "Luu y: Day la che do test/debug."
echo "   Để chạy production, sử dụng systemd service thay vì script này."
echo ""

python3 wazuh_siem_realtime_detector.py


# Test Files

Thư mục này chứa các file test cho hệ thống AI SQLi Detection.

## Test Files

- `test_wazuh_siem_detector.py` - Test Wazuh SIEM realtime detector
- `test_wazuh_log.py` - Test Wazuh log parsing
- `test_threat_levels.py` - Test threat level classification
- `test_threat_levels_comprehensive.py` - Comprehensive threat level testing
- `test_performance_with_dataset.py` - Performance testing với dataset

## Cách chạy test

```bash
# Test Wazuh SIEM detector
python tests/test_wazuh_siem_detector.py

# Test threat levels
python tests/test_threat_levels.py

# Test comprehensive
python tests/test_threat_levels_comprehensive.py

# Test performance
python tests/test_performance_with_dataset.py
```

## Lưu ý

- Các test files này chỉ dùng để development và testing
- Không cần thiết cho production deployment
- Có thể xóa nếu không cần thiết

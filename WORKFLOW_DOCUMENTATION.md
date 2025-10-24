# Workflow Documentation

## 🔄 Hệ thống Workflow SQLi Detection

### 1. Tổng quan Workflow

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Training      │    │   Detection      │    │   Monitoring    │
│   Phase         │    │   Phase          │    │   Phase         │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Clean Logs      │    │ New Log Entry    │    │ Real-time       │
│ (100k)          │    │                  │    │ Monitoring      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Feature         │    │ Feature          │    │ Log Collector   │
│ Extraction      │    │ Extraction       │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Model Training  │    │ AI Detection     │    │ Web Dashboard   │
│ (Isolation      │    │ (Isolation       │    │                 │
│  Forest)        │    │  Forest)         │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Model Save      │    │ Decision Logic   │    │ Alert System    │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### 2. Training Phase Workflow

#### 2.1 Data Preparation
```python
def prepare_training_data():
    # Load clean logs
    clean_logs = load_clean_logs('sqli_logs_clean_100k.jsonl')
    
    # Validate data
    validate_logs(clean_logs)
    
    # Shuffle data
    random.shuffle(clean_logs)
    
    return clean_logs
```

#### 2.2 Feature Extraction
```python
def extract_features_training(clean_logs):
    features_list = []
    
    for log_entry in clean_logs:
        # Extract 38 features
        features = extract_optimized_features(log_entry)
        features_list.append(features)
    
    return features_list
```

#### 2.3 Model Training
```python
def train_model(features_list):
    # Create DataFrame
    df = pd.DataFrame(features_list)
    
    # Encode categorical features
    encode_categorical_features(df)
    
    # Select features
    X = df[feature_names].fillna(0)
    
    # Scale features
    X_scaled = scaler.fit_transform(X)
    
    # Train Isolation Forest
    isolation_forest.fit(X_scaled)
    
    # Calculate percentiles
    scores = isolation_forest.decision_function(X_scaled)
    percentiles = calculate_percentiles(scores)
    
    return isolation_forest, scaler, percentiles
```

#### 2.4 Model Persistence
```python
def save_model(model, scaler, percentiles):
    model_data = {
        'isolation_forest': model,
        'scaler': scaler,
        'percentiles': percentiles,
        'feature_names': feature_names,
        'threshold': percentiles['50']
    }
    
    joblib.dump(model_data, 'models/optimized_sqli_detector.pkl')
    save_metadata(model_data)
```

### 3. Detection Phase Workflow

#### 3.1 Log Entry Processing
```python
def process_log_entry(log_entry):
    # Extract features
    features = extract_optimized_features(log_entry)
    
    # Create DataFrame
    df = pd.DataFrame([features])
    
    # Encode categorical features
    encode_categorical_features(df)
    
    # Select features
    X = df[feature_names].fillna(0)
    
    # Scale features
    X_scaled = scaler.transform(X)
    
    return X_scaled
```

#### 3.2 AI Detection
```python
def ai_detection(X_scaled):
    # Get anomaly score
    anomaly_score = isolation_forest.decision_function(X_scaled)[0]
    
    # Determine if anomaly
    is_anomaly = anomaly_score < 0
    
    return is_anomaly, anomaly_score
```

#### 3.3 Risk Score Calculation
```python
def calculate_risk_score(features):
    risk_score = (
        features['sqli_patterns'] * 3.0 +
        features['special_chars'] * 1.0 +
        features['sql_keywords'] * 1.5 +
        # ... all formula components
    )
    
    return risk_score
```

#### 3.4 Pattern Matching
```python
def pattern_matching(log_entry):
    # Get all text content
    text_content = get_all_text_content(log_entry)
    
    # Check for SQLi patterns
    has_sqli_pattern = detect_sqli_patterns(text_content)
    
    # Check for Base64 patterns
    has_base64_sqli = detect_base64_sqli(log_entry)
    
    # Check for NoSQL patterns
    has_nosql_sqli = detect_nosql_patterns(text_content)
    
    return has_sqli_pattern or has_base64_sqli or has_nosql_sqli
```

#### 3.5 Final Decision
```python
def make_final_decision(has_sqli_pattern, risk_score, anomaly_score):
    # High confidence: Pattern matching
    if has_sqli_pattern:
        return True, "High", ["pattern_match"]
    
    # Medium confidence: Risk score
    elif risk_score >= 50:
        return True, "Medium", ["risk_score"]
    
    # Low confidence: AI anomaly
    elif anomaly_score < 0:
        return True, "Low", ["ai_anomaly"]
    
    # Normal traffic
    else:
        return False, "Normal", []
```

### 4. Real-time Monitoring Workflow

#### 4.1 Log Collection
```python
def collect_logs():
    # Monitor Apache log file
    log_file = '/var/log/apache2/access_full_json.log'
    
    # Tail log file
    for line in tail(log_file):
        try:
            log_entry = json.loads(line)
            process_log_entry(log_entry)
        except json.JSONDecodeError:
            continue
```

#### 4.2 Real-time Processing
```python
def process_realtime_log(log_entry):
    # Extract features
    features = extract_optimized_features(log_entry)
    
    # AI detection
    is_anomaly, anomaly_score = ai_detection(features)
    
    # Risk score
    risk_score = calculate_risk_score(features)
    
    # Pattern matching
    has_sqli_pattern = pattern_matching(log_entry)
    
    # Final decision
    is_sqli, confidence, patterns = make_final_decision(
        has_sqli_pattern, risk_score, anomaly_score
    )
    
    return {
        'is_sqli': is_sqli,
        'confidence': confidence,
        'patterns': patterns,
        'anomaly_score': anomaly_score,
        'risk_score': risk_score
    }
```

#### 4.3 Alert Generation
```python
def generate_alert(detection_result):
    if detection_result['is_sqli']:
        alert = {
            'timestamp': datetime.now().isoformat(),
            'ip': detection_result['ip'],
            'uri': detection_result['uri'],
            'confidence': detection_result['confidence'],
            'patterns': detection_result['patterns'],
            'anomaly_score': detection_result['anomaly_score'],
            'risk_score': detection_result['risk_score']
        }
        
        # Send to webhook
        send_webhook(alert)
        
        # Log alert
        log_alert(alert)
```

### 5. Web Dashboard Workflow

#### 5.1 API Endpoints
```python
# Detection API
@app.route('/api/detect', methods=['POST'])
def api_detect():
    log_entry = request.json
    result = process_realtime_log(log_entry)
    return jsonify(result)

# Real-time detection
@app.route('/api/realtime-detect', methods=['POST'])
def api_realtime_detect():
    log_entry = request.json
    result = process_realtime_log(log_entry)
    
    if result['is_sqli']:
        generate_alert(result)
    
    return jsonify(result)

# Performance metrics
@app.route('/api/performance', methods=['GET'])
def api_performance():
    metrics = get_performance_metrics()
    return jsonify(metrics)
```

#### 5.2 Dashboard Interface
```python
@app.route('/')
def dashboard():
    # Get recent detections
    recent_detections = get_recent_detections()
    
    # Get performance metrics
    performance = get_performance_metrics()
    
    # Get pattern statistics
    patterns = get_pattern_statistics()
    
    return render_template('index.html', 
                         detections=recent_detections,
                         performance=performance,
                         patterns=patterns)
```

### 6. Error Handling Workflow

#### 6.1 Feature Extraction Errors
```python
def handle_feature_extraction_error(log_entry, error):
    logger.error(f"Feature extraction failed: {error}")
    
    # Fallback to basic features
    basic_features = extract_basic_features(log_entry)
    
    # Use default values
    default_features = get_default_features()
    
    return merge_features(basic_features, default_features)
```

#### 6.2 Model Prediction Errors
```python
def handle_model_prediction_error(features, error):
    logger.error(f"Model prediction failed: {error}")
    
    # Fallback to rule-based detection
    has_sqli_pattern = pattern_matching(features)
    risk_score = calculate_risk_score(features)
    
    # Simple decision logic
    if has_sqli_pattern or risk_score >= 50:
        return True, "Fallback"
    else:
        return False, "Fallback"
```

#### 6.3 Label Encoding Errors
```python
def handle_label_encoding_error(feature, value, error):
    logger.error(f"Label encoding failed: {error}")
    
    # Use default encoding
    if feature == 'method':
        return 1 if value.upper() == 'POST' else 0
    else:
        return 0
```

### 7. Performance Optimization Workflow

#### 7.1 Caching Strategy
```python
# Model caching
@lru_cache(maxsize=1)
def get_cached_model():
    return load_model('models/optimized_sqli_detector.pkl')

# Feature caching
@lru_cache(maxsize=1000)
def get_cached_features(log_entry):
    return extract_optimized_features(log_entry)
```

#### 7.2 Batch Processing
```python
def process_batch_logs(logs):
    # Extract features for all logs
    features_list = [extract_optimized_features(log) for log in logs]
    
    # Create DataFrame
    df = pd.DataFrame(features_list)
    
    # Process all at once
    X_scaled = scaler.transform(df[feature_names])
    scores = isolation_forest.decision_function(X_scaled)
    
    return scores
```

#### 7.3 Memory Management
```python
def optimize_memory_usage():
    # Clear unused variables
    gc.collect()
    
    # Limit feature extraction
    MAX_TEXT_LEN = 4096
    
    # Use generators for large datasets
    def log_generator(log_file):
        for line in open(log_file):
            yield json.loads(line)
```

### 8. Monitoring & Logging Workflow

#### 8.1 Performance Monitoring
```python
def monitor_performance():
    # CPU usage
    cpu_usage = psutil.cpu_percent()
    
    # Memory usage
    memory_usage = psutil.virtual_memory().percent
    
    # Processing time
    processing_time = time.time() - start_time
    
    # Log metrics
    logger.info(f"CPU: {cpu_usage}%, Memory: {memory_usage}%, Time: {processing_time:.2f}s")
```

#### 8.2 Detection Monitoring
```python
def monitor_detections():
    # Detection rate
    detection_rate = detections / total_logs
    
    # False positive rate
    false_positive_rate = false_positives / clean_logs
    
    # Pattern distribution
    pattern_distribution = get_pattern_distribution()
    
    # Log metrics
    logger.info(f"Detection Rate: {detection_rate:.2f}%")
    logger.info(f"False Positive Rate: {false_positive_rate:.2f}%")
    logger.info(f"Pattern Distribution: {pattern_distribution}")
```

#### 8.3 Alert Monitoring
```python
def monitor_alerts():
    # Alert frequency
    alert_frequency = alerts / time_period
    
    # Alert types
    alert_types = get_alert_types()
    
    # Response time
    response_time = get_alert_response_time()
    
    # Log metrics
    logger.info(f"Alert Frequency: {alert_frequency:.2f}/min")
    logger.info(f"Alert Types: {alert_types}")
    logger.info(f"Response Time: {response_time:.2f}s")
```

### 9. Deployment Workflow

#### 9.1 Production Deployment
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train model
python train_optimized_model.py

# 3. Start web application
python app.py

# 4. Start log collector
python realtime_log_collector.py

# 5. Configure Apache
sudo a2enmod rewrite
sudo systemctl restart apache2
```

#### 9.2 Health Checks
```python
def health_check():
    # Check model loading
    model_status = check_model_loading()
    
    # Check feature extraction
    feature_status = check_feature_extraction()
    
    # Check detection
    detection_status = check_detection()
    
    # Overall health
    health = all([model_status, feature_status, detection_status])
    
    return {
        'status': 'healthy' if health else 'unhealthy',
        'model': model_status,
        'features': feature_status,
        'detection': detection_status
    }
```

### 10. Maintenance Workflow

#### 10.1 Model Retraining
```python
def retrain_model():
    # Load new clean data
    new_clean_logs = load_clean_logs('new_clean_logs.jsonl')
    
    # Retrain model
    model, scaler, percentiles = train_model(new_clean_logs)
    
    # Save new model
    save_model(model, scaler, percentiles)
    
    # Update metadata
    update_metadata(percentiles)
```

#### 10.2 Performance Tuning
```python
def tune_performance():
    # Adjust thresholds
    adjust_risk_threshold(new_threshold)
    adjust_ai_threshold(new_threshold)
    
    # Optimize features
    optimize_feature_extraction()
    
    # Update patterns
    update_sqli_patterns(new_patterns)
```

#### 10.3 Log Rotation
```python
def rotate_logs():
    # Archive old logs
    archive_old_logs()
    
    # Compress logs
    compress_logs()
    
    # Clean up
    cleanup_old_files()
```

---

**🎯 Workflow Documentation hoàn chỉnh - Tất cả quy trình từ training đến monitoring đã được mô tả chi tiết!**

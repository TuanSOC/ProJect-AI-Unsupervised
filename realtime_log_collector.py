#!/usr/bin/env python3
"""
Realtime Log Collector cho Apache - Tối ưu hóa với detailed analysis
Thu thập và phân tích log realtime từ Apache access logs
"""

import json
import subprocess
import time
import logging
import requests
import threading
from datetime import datetime
from optimized_sqli_detector import OptimizedSQLIDetector
import queue
import signal
import sys
import numpy as np

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('realtime_sqli_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RealtimeLogCollector:
    """Thu thập và phân tích log realtime từ Apache với detailed analysis"""
    
    def __init__(self, log_path="/var/log/apache2/access_full_json.log", 
                 webhook_url="http://localhost:5000/api/realtime-detect",
                 detection_threshold=None):
        self.log_path = log_path
        self.webhook_url = webhook_url
        self.detection_threshold = detection_threshold
        self.detector = None
        self.log_queue = queue.Queue(maxsize=1000)
        self.running = False
        self.process = None
        
        # Statistics
        self.stats = {
            'total_logs': 0,
            'sqli_detected': 0,
            'errors': 0,
            'start_time': datetime.now()
        }
        
        # Load AI model
        self._load_ai_model()
    
    def _load_ai_model(self):
        """Load AI model"""
        try:
            self.detector = OptimizedSQLIDetector()
            self.detector.load_model('models/optimized_sqli_detector.pkl')
            logger.info("✅ AI Model loaded successfully for realtime detection!")
        except Exception as e:
            logger.error(f"❌ Failed to load AI model: {e}")
            self.detector = None
    
    def detect_sqli_realtime(self, log_entry):
        """Phát hiện SQLi trong log entry realtime với detailed analysis"""
        if not self.detector:
            return None
            
        try:
            # Extract features for detailed analysis
            features = self.detector.extract_optimized_features(log_entry)
            
            # Sử dụng AI model để phát hiện
            is_anomaly, score, patterns, confidence = self.detector.predict_single(log_entry)
            
            # Calculate detailed scores
            detailed_scores = self._calculate_detailed_scores(features)
            
            # Risk assessment
            risk_assessment = self._assess_risk(features, score)
            
            # Attack vector analysis
            attack_vectors = self._analyze_attack_vectors(log_entry, features)
            
            # Pattern analysis
            pattern_analysis = self._analyze_patterns(log_entry, features)
            
            # Encoding analysis
            encoding_analysis = self._analyze_encoding(log_entry, features)
            
            # Database analysis
            database_analysis = self._analyze_database(log_entry, features)
            
            # Evasion analysis
            evasion_analysis = self._analyze_evasion(log_entry, features)
            
            # Time analysis
            time_analysis = self._analyze_time(log_entry, features)
            
            # Network analysis
            network_analysis = self._analyze_network(log_entry, features)
            
            # Cookie analysis
            cookie_analysis = self._analyze_cookie(log_entry, features)
            
            # Entropy analysis
            entropy_analysis = self._analyze_entropy(log_entry, features)
            
            # Final assessment
            final_assessment = self._final_assessment(
                is_anomaly, score, detailed_scores, risk_assessment
            )
            
            return {
                'is_sqli': bool(is_anomaly),
                'score': float(score),
                'detected_patterns': patterns if patterns else 'N/A',
                'confidence': confidence,
                'timestamp': datetime.now().isoformat(),
                'threat_level': 'CRITICAL' if is_anomaly else 'NONE',
                'detailed_analysis': {
                    'detailed_scores': detailed_scores,
                    'risk_assessment': risk_assessment,
                    'attack_vectors': attack_vectors,
                    'pattern_analysis': pattern_analysis,
                    'encoding_analysis': encoding_analysis,
                    'database_analysis': database_analysis,
                    'evasion_analysis': evasion_analysis,
                    'time_analysis': time_analysis,
                    'network_analysis': network_analysis,
                    'cookie_analysis': cookie_analysis,
                    'entropy_analysis': entropy_analysis,
                    'final_assessment': final_assessment,
                    'raw_features': features
                }
            }
            
        except Exception as e:
            logger.error(f"Error in SQLi detection: {e}")
            self.stats['errors'] += 1
            return None
    
    def _calculate_detailed_scores(self, features):
        """Tính toán chi tiết các scores"""
        
        # Base scores
        base_scores = {
            "sqli_patterns": features.get('sqli_patterns', 0),
            "special_chars": features.get('special_chars', 0),
            "sql_keywords": features.get('sql_keywords', 0),
            "sqli_risk_score": features.get('sqli_risk_score', 0),
            "sqli_risk_score_log": features.get('sqli_risk_score_log', 0)
        }
        
        # Advanced scores
        advanced_scores = {
            "has_union_select": features.get('has_union_select', 0),
            "has_information_schema": features.get('has_information_schema', 0),
            "has_mysql_functions": features.get('has_mysql_functions', 0),
            "has_boolean_blind": features.get('has_boolean_blind', 0),
            "has_time_based": features.get('has_time_based', 0),
            "has_comment_injection": features.get('has_comment_injection', 0)
        }
        
        # Base64 scores
        base64_scores = {
            "has_base64_payload": features.get('has_base64_payload', 0),
            "has_base64_query": features.get('has_base64_query', 0),
            "base64_sqli_patterns": features.get('base64_sqli_patterns', 0),
            "base64_decoded_length": features.get('base64_decoded_length', 0)
        }
        
        # NoSQL scores
        nosql_scores = {
            "has_nosql_patterns": features.get('has_nosql_patterns', 0),
            "has_nosql_operators": features.get('has_nosql_operators', 0),
            "has_json_injection": features.get('has_json_injection', 0)
        }
        
        # Cookie scores
        cookie_scores = {
            "cookie_sqli_patterns": features.get('cookie_sqli_patterns', 0),
            "cookie_special_chars": features.get('cookie_special_chars', 0),
            "cookie_sql_keywords": features.get('cookie_sql_keywords', 0),
            "cookie_quotes": features.get('cookie_quotes', 0),
            "cookie_operators": features.get('cookie_operators', 0)
        }
        
        # Entropy scores
        entropy_scores = {
            "uri_entropy": features.get('uri_entropy', 0),
            "query_entropy": features.get('query_entropy', 0),
            "payload_entropy": features.get('payload_entropy', 0),
            "body_entropy": features.get('body_entropy', 0)
        }
        
        # Time scores
        time_scores = {
            "hour": features.get('hour', 0),
            "day_of_week": features.get('day_of_week', 0),
            "is_weekend": features.get('is_weekend', 0)
        }
        
        # Network scores
        network_scores = {
            "is_internal_ip": features.get('is_internal_ip', 0),
            "is_bot": features.get('is_bot', 0),
            "user_agent_length": features.get('user_agent_length', 0)
        }
        
        # Calculate weighted scores
        weighted_scores = {
            "pattern_weight": base_scores["sqli_patterns"] * 3.0,
            "special_weight": base_scores["special_chars"] * 1.0,
            "keyword_weight": base_scores["sql_keywords"] * 1.5,
            "union_weight": advanced_scores["has_union_select"] * 5.0,
            "schema_weight": advanced_scores["has_information_schema"] * 4.0,
            "mysql_weight": advanced_scores["has_mysql_functions"] * 3.0,
            "blind_weight": advanced_scores["has_boolean_blind"] * 6.0,
            "time_weight": advanced_scores["has_time_based"] * 3.0,
            "comment_weight": advanced_scores["has_comment_injection"] * 2.0,
            "base64_weight": base64_scores["base64_sqli_patterns"] * 8.0,
            "nosql_weight": nosql_scores["has_nosql_patterns"] * 15.0,
            "cookie_weight": cookie_scores["cookie_sqli_patterns"] * 8.0
        }
        
        # Total weighted score
        total_weighted = sum(weighted_scores.values())
        
        return {
            "base_scores": base_scores,
            "advanced_scores": advanced_scores,
            "base64_scores": base64_scores,
            "nosql_scores": nosql_scores,
            "cookie_scores": cookie_scores,
            "entropy_scores": entropy_scores,
            "time_scores": time_scores,
            "network_scores": network_scores,
            "weighted_scores": weighted_scores,
            "total_weighted_score": total_weighted
        }
    
    def _assess_risk(self, features, ai_score):
        """Đánh giá rủi ro"""
        
        risk_score = features.get('sqli_risk_score', 0)
        high_risk = features.get('high_risk', False)
        
        # Risk levels
        if risk_score >= 50:
            risk_level = "CRITICAL"
        elif risk_score >= 30:
            risk_level = "HIGH"
        elif risk_score >= 15:
            risk_level = "MEDIUM"
        elif risk_score >= 5:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        # AI score assessment
        if ai_score >= 0.5:
            ai_risk = "HIGH"
        elif ai_score >= 0.49:
            ai_risk = "MEDIUM"
        else:
            ai_risk = "LOW"
        
        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "high_risk": high_risk,
            "ai_risk": ai_risk,
            "ai_score": ai_score,
            "threshold": self.detector.sqli_score_threshold
        }
    
    def _analyze_attack_vectors(self, log_entry, features):
        """Phân tích attack vectors"""
        
        vectors = []
        
        # URI analysis
        uri = log_entry.get('uri', '')
        if any(pattern in uri.lower() for pattern in ['union', 'select', 'or 1=1', 'and 1=1']):
            vectors.append("URI_PATH_SQLi")
        
        # Query analysis
        query = log_entry.get('query_string', '')
        if any(pattern in query.lower() for pattern in ['union', 'select', 'or 1=1', 'and 1=1']):
            vectors.append("QUERY_PARAMETER_SQLi")
        
        # Payload analysis
        payload = log_entry.get('payload', '')
        if any(pattern in payload.lower() for pattern in ['union', 'select', 'or 1=1', 'and 1=1']):
            vectors.append("PAYLOAD_SQLi")
        
        # Body analysis
        body = log_entry.get('body', '')
        if any(pattern in body.lower() for pattern in ['union', 'select', 'or 1=1', 'and 1=1']):
            vectors.append("POST_BODY_SQLi")
        
        # Cookie analysis
        cookie = log_entry.get('cookie', '')
        if any(pattern in cookie.lower() for pattern in ['union', 'select', 'or 1=1', 'and 1=1']):
            vectors.append("COOKIE_SQLi")
        
        # Base64 analysis
        if features.get('has_base64_payload', 0) or features.get('has_base64_query', 0):
            vectors.append("BASE64_ENCODED_SQLi")
        
        # NoSQL analysis
        if features.get('has_nosql_patterns', 0) or features.get('has_nosql_operators', 0):
            vectors.append("NOSQL_INJECTION")
        
        return {
            "attack_vectors": vectors,
            "vector_count": len(vectors),
            "primary_vector": vectors[0] if vectors else "NONE"
        }
    
    def _analyze_patterns(self, log_entry, features):
        """Phân tích patterns"""
        
        patterns = []
        
        # SQL patterns
        if features.get('has_union_select', 0):
            patterns.append("UNION_SELECT")
        if features.get('has_information_schema', 0):
            patterns.append("INFORMATION_SCHEMA")
        if features.get('has_mysql_functions', 0):
            patterns.append("MYSQL_FUNCTIONS")
        if features.get('has_boolean_blind', 0):
            patterns.append("BOOLEAN_BLIND")
        if features.get('has_time_based', 0):
            patterns.append("TIME_BASED")
        if features.get('has_comment_injection', 0):
            patterns.append("COMMENT_INJECTION")
        
        # Base64 patterns
        if features.get('base64_sqli_patterns', 0):
            patterns.append("BASE64_SQLi")
        
        # NoSQL patterns
        if features.get('has_nosql_patterns', 0):
            patterns.append("NOSQL_PATTERNS")
        if features.get('has_nosql_operators', 0):
            patterns.append("NOSQL_OPERATORS")
        if features.get('has_json_injection', 0):
            patterns.append("JSON_INJECTION")
        
        return {
            "detected_patterns": patterns,
            "pattern_count": len(patterns),
            "pattern_score": features.get('sqli_patterns', 0)
        }
    
    def _analyze_encoding(self, log_entry, features):
        """Phân tích encoding"""
        
        encoding_types = []
        
        # Base64 encoding
        if features.get('has_base64_payload', 0) or features.get('has_base64_query', 0):
            encoding_types.append("BASE64")
        
        # URL encoding
        query = log_entry.get('query_string', '')
        if '%' in query:
            encoding_types.append("URL_ENCODED")
        
        # Double encoding
        if '%%' in query:
            encoding_types.append("DOUBLE_ENCODED")
        
        # Hex encoding
        if '0x' in query or 'CHAR(' in query:
            encoding_types.append("HEX_ENCODED")
        
        return {
            "encoding_types": encoding_types,
            "encoding_count": len(encoding_types),
            "base64_decoded_length": features.get('base64_decoded_length', 0)
        }
    
    def _analyze_database(self, log_entry, features):
        """Phân tích database"""
        
        db_types = []
        
        # MySQL
        if any(pattern in str(log_entry).lower() for pattern in ['mysql', 'information_schema', 'load_file', 'benchmark']):
            db_types.append("MYSQL")
        
        # MSSQL
        if any(pattern in str(log_entry).lower() for pattern in ['mssql', 'sysobjects', 'xp_cmdshell', 'waitfor']):
            db_types.append("MSSQL")
        
        # PostgreSQL
        if any(pattern in str(log_entry).lower() for pattern in ['postgresql', 'pg_sleep', 'pg_user', 'pg_database']):
            db_types.append("POSTGRESQL")
        
        # Oracle
        if any(pattern in str(log_entry).lower() for pattern in ['oracle', 'all_users', 'v$version', 'all_tables']):
            db_types.append("ORACLE")
        
        # MongoDB
        if any(pattern in str(log_entry).lower() for pattern in ['$where', '$ne', '$gt', '$regex']):
            db_types.append("MONGODB")
        
        return {
            "database_types": db_types,
            "db_count": len(db_types),
            "primary_db": db_types[0] if db_types else "UNKNOWN"
        }
    
    def _analyze_evasion(self, log_entry, features):
        """Phân tích evasion techniques"""
        
        evasion_techniques = []
        
        # Case mixing
        text = str(log_entry).lower()
        if any(pattern in text for pattern in ['un1on', 'sel3ct', 'uni0n', 's3lect']):
            evasion_techniques.append("CASE_MIXING")
        
        # Comment injection
        if any(pattern in text for pattern in ['/**/', '/*comment*/', '/*']):
            evasion_techniques.append("COMMENT_INJECTION")
        
        # String concatenation
        if any(pattern in text for pattern in ['concat(', 'char(', 'substring(']):
            evasion_techniques.append("STRING_CONCATENATION")
        
        # Whitespace variants
        if any(pattern in text for pattern in ['\t', '\n', '\r', '%09', '%0A', '%0D']):
            evasion_techniques.append("WHITESPACE_VARIANTS")
        
        # Encoding
        if any(pattern in text for pattern in ['%27', '%20', '0x', 'base64']):
            evasion_techniques.append("ENCODING")
        
        return {
            "evasion_techniques": evasion_techniques,
            "evasion_count": len(evasion_techniques),
            "evasion_score": len(evasion_techniques) * 2.0
        }
    
    def _analyze_time(self, log_entry, features):
        """Phân tích thời gian"""
        
        hour = features.get('hour', 0)
        day_of_week = features.get('day_of_week', 0)
        is_weekend = features.get('is_weekend', 0)
        
        # Time-based risk
        if 2 <= hour <= 6:  # Night time
            time_risk = "HIGH"
        elif 9 <= hour <= 17:  # Business hours
            time_risk = "MEDIUM"
        else:
            time_risk = "LOW"
        
        # Weekend risk
        if is_weekend:
            weekend_risk = "HIGH"
        else:
            weekend_risk = "LOW"
        
        return {
            "hour": hour,
            "day_of_week": day_of_week,
            "is_weekend": bool(is_weekend),
            "time_risk": time_risk,
            "weekend_risk": weekend_risk
        }
    
    def _analyze_network(self, log_entry, features):
        """Phân tích network"""
        
        ip = log_entry.get('remote_ip', '')
        user_agent = log_entry.get('user_agent', '')
        
        # IP analysis
        is_internal = features.get('is_internal_ip', 0)
        if is_internal:
            ip_risk = "LOW"
        else:
            ip_risk = "MEDIUM"
        
        # Bot analysis
        is_bot = features.get('is_bot', 0)
        if is_bot:
            bot_risk = "LOW"
        else:
            bot_risk = "MEDIUM"
        
        return {
            "ip": ip,
            "is_internal": bool(is_internal),
            "is_bot": bool(is_bot),
            "ip_risk": ip_risk,
            "bot_risk": bot_risk,
            "user_agent_length": features.get('user_agent_length', 0)
        }
    
    def _analyze_cookie(self, log_entry, features):
        """Phân tích cookie"""
        
        cookie = log_entry.get('cookie', '')
        
        # Cookie analysis
        cookie_sqli = features.get('cookie_sqli_patterns', 0)
        cookie_special = features.get('cookie_special_chars', 0)
        cookie_sql = features.get('cookie_sql_keywords', 0)
        cookie_quotes = features.get('cookie_quotes', 0)
        cookie_ops = features.get('cookie_operators', 0)
        
        # Cookie risk
        cookie_score = cookie_sqli + cookie_special + cookie_sql + cookie_quotes + cookie_ops
        if cookie_score >= 10:
            cookie_risk = "HIGH"
        elif cookie_score >= 5:
            cookie_risk = "MEDIUM"
        else:
            cookie_risk = "LOW"
        
        return {
            "cookie_length": len(cookie),
            "cookie_sqli_patterns": cookie_sqli,
            "cookie_special_chars": cookie_special,
            "cookie_sql_keywords": cookie_sql,
            "cookie_quotes": cookie_quotes,
            "cookie_operators": cookie_ops,
            "cookie_score": cookie_score,
            "cookie_risk": cookie_risk
        }
    
    def _analyze_entropy(self, log_entry, features):
        """Phân tích entropy"""
        
        uri_entropy = features.get('uri_entropy', 0)
        query_entropy = features.get('query_entropy', 0)
        payload_entropy = features.get('payload_entropy', 0)
        body_entropy = features.get('body_entropy', 0)
        
        # Entropy risk
        max_entropy = max(uri_entropy, query_entropy, payload_entropy, body_entropy)
        if max_entropy >= 6:
            entropy_risk = "HIGH"
        elif max_entropy >= 4:
            entropy_risk = "MEDIUM"
        else:
            entropy_risk = "LOW"
        
        return {
            "uri_entropy": uri_entropy,
            "query_entropy": query_entropy,
            "payload_entropy": payload_entropy,
            "body_entropy": body_entropy,
            "max_entropy": max_entropy,
            "entropy_risk": entropy_risk
        }
    
    def _final_assessment(self, is_sqli, ai_score, detailed_scores, risk_assessment):
        """Đánh giá cuối cùng"""
        
        # Overall risk
        if is_sqli and risk_assessment["risk_level"] == "CRITICAL":
            overall_risk = "CRITICAL"
        elif is_sqli and risk_assessment["risk_level"] == "HIGH":
            overall_risk = "HIGH"
        elif is_sqli:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        # Confidence level
        if ai_score >= 0.5 and risk_assessment["risk_score"] >= 30:
            confidence = "VERY_HIGH"
        elif ai_score >= 0.49 and risk_assessment["risk_score"] >= 15:
            confidence = "HIGH"
        elif ai_score >= 0.48:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        
        # Recommendation
        if overall_risk == "CRITICAL":
            recommendation = "IMMEDIATE_BLOCK"
        elif overall_risk == "HIGH":
            recommendation = "BLOCK_AND_INVESTIGATE"
        elif overall_risk == "MEDIUM":
            recommendation = "MONITOR_AND_LOG"
        else:
            recommendation = "ALLOW"
        
        return {
            "overall_risk": overall_risk,
            "confidence": confidence,
            "recommendation": recommendation,
            "ai_score": ai_score,
            "risk_score": risk_assessment["risk_score"],
            "total_weighted_score": detailed_scores["total_weighted_score"]
        }
    
    def process_log_line(self, log_entry):
        """Xử lý một dòng log với detailed analysis"""
        if not log_entry:
            return
            
        # Phát hiện SQLi
        detection_result = self.detect_sqli_realtime(log_entry)
        
        # Filter false positives: only detect if score > threshold AND has suspicious content
        if detection_result and detection_result['is_sqli']:
            is_real_threat = self._is_real_threat(detection_result, log_entry)
            if is_real_threat:
                # Get detailed analysis
                detailed_analysis = detection_result.get('detailed_analysis', {})
                
                # Log threat with detailed analysis
                logger.warning(f"🚨 SQLi DETECTED!")
                logger.warning(f"   IP: {log_entry.get('remote_ip', 'Unknown')}")
                logger.warning(f"   URI: {log_entry.get('uri', 'Unknown')}")
                logger.warning(f"   Query: {log_entry.get('query_string', 'None')}")
                logger.warning(f"   Payload: {log_entry.get('payload', 'None')}")
                logger.warning(f"   Score: {detection_result['score']:.3f}")
                logger.warning(f"   Patterns: {detection_result.get('detected_patterns', 'N/A')}")
                logger.warning(f"   Confidence: {detection_result['confidence']}")
                logger.warning(f"   Threat Level: {detection_result['threat_level']}")
                
                # Detailed analysis
                if detailed_analysis:
                    risk_assessment = detailed_analysis.get('risk_assessment', {})
                    attack_vectors = detailed_analysis.get('attack_vectors', {})
                    pattern_analysis = detailed_analysis.get('pattern_analysis', {})
                    encoding_analysis = detailed_analysis.get('encoding_analysis', {})
                    database_analysis = detailed_analysis.get('database_analysis', {})
                    evasion_analysis = detailed_analysis.get('evasion_analysis', {})
                    time_analysis = detailed_analysis.get('time_analysis', {})
                    network_analysis = detailed_analysis.get('network_analysis', {})
                    cookie_analysis = detailed_analysis.get('cookie_analysis', {})
                    entropy_analysis = detailed_analysis.get('entropy_analysis', {})
                    final_assessment = detailed_analysis.get('final_assessment', {})
                    
                    logger.warning("📊 DETAILED ANALYSIS:")
                    logger.warning(f"   Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}")
                    logger.warning(f"   Risk Score: {risk_assessment.get('risk_score', 0):.2f}")
                    logger.warning(f"   Attack Vectors: {attack_vectors.get('attack_vectors', [])}")
                    logger.warning(f"   Detected Patterns: {pattern_analysis.get('detected_patterns', [])}")
                    logger.warning(f"   Encoding Types: {encoding_analysis.get('encoding_types', [])}")
                    logger.warning(f"   Database Types: {database_analysis.get('database_types', [])}")
                    logger.warning(f"   Evasion Techniques: {evasion_analysis.get('evasion_techniques', [])}")
                    logger.warning(f"   Time Risk: {time_analysis.get('time_risk', 'UNKNOWN')}")
                    logger.warning(f"   Network Risk: {network_analysis.get('ip_risk', 'UNKNOWN')}")
                    logger.warning(f"   Cookie Risk: {cookie_analysis.get('cookie_risk', 'UNKNOWN')}")
                    logger.warning(f"   Entropy Risk: {entropy_analysis.get('entropy_risk', 'UNKNOWN')}")
                    logger.warning(f"   Overall Risk: {final_assessment.get('overall_risk', 'UNKNOWN')}")
                    logger.warning(f"   Recommendation: {final_assessment.get('recommendation', 'UNKNOWN')}")
                    
                    # Feature scores
                    detailed_scores = detailed_analysis.get('detailed_scores', {})
                    if detailed_scores:
                        base_scores = detailed_scores.get('base_scores', {})
                        advanced_scores = detailed_scores.get('advanced_scores', {})
                        base64_scores = detailed_scores.get('base64_scores', {})
                        nosql_scores = detailed_scores.get('nosql_scores', {})
                        cookie_scores = detailed_scores.get('cookie_scores', {})
                        
                        logger.warning("🔍 FEATURE SCORES:")
                        logger.warning(f"   SQLi Patterns: {base_scores.get('sqli_patterns', 0)}")
                        logger.warning(f"   Special Chars: {base_scores.get('special_chars', 0)}")
                        logger.warning(f"   SQL Keywords: {base_scores.get('sql_keywords', 0)}")
                        logger.warning(f"   Union Select: {advanced_scores.get('has_union_select', 0)}")
                        logger.warning(f"   Information Schema: {advanced_scores.get('has_information_schema', 0)}")
                        logger.warning(f"   MySQL Functions: {advanced_scores.get('has_mysql_functions', 0)}")
                        logger.warning(f"   Boolean Blind: {advanced_scores.get('has_boolean_blind', 0)}")
                        logger.warning(f"   Time Based: {advanced_scores.get('has_time_based', 0)}")
                        logger.warning(f"   Comment Injection: {advanced_scores.get('has_comment_injection', 0)}")
                        logger.warning(f"   Base64 Patterns: {base64_scores.get('base64_sqli_patterns', 0)}")
                        logger.warning(f"   NoSQL Patterns: {nosql_scores.get('has_nosql_patterns', 0)}")
                        logger.warning(f"   Cookie SQLi: {cookie_scores.get('cookie_sqli_patterns', 0)}")
                        logger.warning(f"   Total Weighted Score: {detailed_scores.get('total_weighted_score', 0):.2f}")
                
                logger.warning("-" * 80)
                
                # Gửi đến webhook
                self.send_to_webhook(log_entry, detection_result)
            
            # Lưu vào file threat log
            self.save_threat_log(log_entry, detection_result)
        else:
            # Log normal traffic (optional)
            logger.debug(f"Normal traffic from {log_entry.get('remote_ip', 'Unknown')} - {log_entry.get('uri', 'Unknown')}")
    
    def _is_real_threat(self, detection_result, log_entry):
        """Filter false positives - only detect real threats"""
        try:
            score = detection_result.get('score', 0)
            query_string = log_entry.get('query_string', '')
            payload = log_entry.get('payload', '')
            uri = log_entry.get('uri', '')
            
            # Skip if no suspicious content
            if not query_string and not payload:
                return False
            
            # Skip if score is too low (but allow some flexibility)
            # Model returns normalized score (0-1, higher = more anomalous)
            # Use model's trained threshold for normalized score
            model_threshold = 0.5  # Default normalized threshold
            if hasattr(self.detector, 'sqli_score_threshold') and self.detector.sqli_score_threshold:
                # Convert raw threshold to normalized score
                raw_threshold = self.detector.sqli_score_threshold
                model_threshold = 1 / (1 + np.exp(-raw_threshold))  # Sigmoid transformation
            
            if score < model_threshold:
                return False
            
            # Skip common false positive patterns
            false_positive_patterns = [
                '/css/', '/js/', '/images/', '/favicon.ico',
                '/robots.txt', '/sitemap.xml', '/.well-known/',
                '/api/health', '/ping', '/status'
            ]
            
            for pattern in false_positive_patterns:
                if pattern in uri.lower():
                    return False
            
            # Get features to check for advanced patterns
            features = self.detector.extract_optimized_features(log_entry)
            
            # Check for advanced SQLi patterns
            has_advanced_patterns = (
                features.get('has_union_select', 0) == 1 or
                features.get('has_information_schema', 0) == 1 or
                features.get('has_mysql_functions', 0) == 1 or
                features.get('has_boolean_blind', 0) == 1 or
                features.get('has_time_based', 0) == 1 or
                features.get('has_comment_injection', 0) == 1 or
                features.get('base64_sqli_patterns', 0) > 0 or
                features.get('has_nosql_patterns', 0) == 1 or
                features.get('has_nosql_operators', 0) == 1 or
                features.get('has_json_injection', 0) == 1 or
                features.get('has_overlong_utf8', 0) == 1
            )
            
            # Check for SQLi-like content (expanded keywords)
            suspicious_content = query_string + ' ' + payload
            sql_keywords = [
                'union', 'select', 'insert', 'update', 'delete', 'drop', 'exec', 'script',
                'benchmark', 'sleep', 'waitfor', 'version', 'user', 'database', 'table',
                'information_schema', 'mysql', 'or 1=1', 'and 1=1', "' or '", '" or "',
                '--', '/*', '*/', '0x', 'char(', 'ascii(', 'substring', 'concat',
                'load_file', 'into outfile', 'xp_cmdshell', 'sp_executesql',
                # Add more patterns for better detection
                '%c0%ae', '%c1%9c', '%c0%af', '%c1%9d',  # Overlong UTF-8
                'base64', 'encoded', 'urlencoded', 'double encoded',
                'nosql', 'mongodb', '$where', '$ne', '$gt', '$regex',
                'json', 'javascript', 'eval', 'function'
            ]
            
            has_sql_content = any(keyword in suspicious_content.lower() for keyword in sql_keywords)
            
            # Also check for suspicious patterns
            suspicious_patterns = [
                'or+', 'and+', 'union+', 'select+', 'insert+', 'update+', 'delete+',
                'benchmark(', 'sleep(', 'waitfor', 'version(', 'user(', 'database(',
                'information_schema', 'mysql.user', 'load_file(', 'into outfile',
                # Add more patterns
                '%c0%ae', '%c1%9c', '%c0%af', '%c1%9d',
                'base64', 'encoded', 'urlencoded', 'double encoded'
            ]
            
            has_suspicious_patterns = any(pattern in suspicious_content.lower() for pattern in suspicious_patterns)
            
            # Check risk score
            risk_score = features.get('sqli_risk_score', 0)
            has_high_risk = risk_score >= 30  # Lowered threshold
            
            # Return True if any condition is met
            return (has_sql_content or 
                   has_suspicious_patterns or 
                   has_advanced_patterns or 
                   has_high_risk)
            
        except Exception as e:
            logger.error(f"Error in threat filtering: {e}")
            return True  # Default to detect if error
    
    def send_to_webhook(self, log_entry, detection_result):
        """Gửi kết quả phát hiện đến webhook"""
        try:
            if not self.webhook_url:
                logger.warning("Webhook URL not configured")
                return False
                
            payload = {
                'log': log_entry,
                'detection': detection_result,
                'timestamp': datetime.now().isoformat()
            }
            
            response = requests.post(
                self.webhook_url, 
                json=payload, 
                timeout=5,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                logger.info(f"✅ Detection result sent to webhook")
            else:
                logger.warning(f"⚠️ Webhook response: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"⚠️ Failed to send to webhook: {e}")
        except Exception as e:
            logger.error(f"❌ Error sending to webhook: {e}")
    
    def save_threat_log(self, log_entry, detection_result):
        """Lưu threat log vào file"""
        try:
            threat_data = {
                'timestamp': datetime.now().isoformat(),
                'log_entry': log_entry,
                'detection_result': detection_result
            }
            
            with open('threat_logs.jsonl', 'a') as f:
                f.write(json.dumps(threat_data, default=str) + '\n')
                
        except Exception as e:
            logger.error(f"Error saving threat log: {e}")
    
    def start_monitoring(self):
        """Bắt đầu monitoring"""
        logger.info("🚀 Starting realtime SQLi monitoring...")
        logger.info(f"📁 Monitoring log file: {self.log_path}")
        
        self.running = True
        
        try:
            with open(self.log_path, 'r') as f:
                # Go to end of file
                f.seek(0, 2)
                
                while self.running:
                    line = f.readline()
                    if line:
                        try:
                            # Parse log entry with better error handling
                            line = line.strip()
                            if not line:
                                continue
                                
                            # Try to parse JSON
                            log_entry = json.loads(line)
                            
                            # Process log entry
                            if log_entry:
                                self.process_log_line(log_entry)
                                
                        except json.JSONDecodeError as e:
                            # Log malformed JSON but continue processing
                            logger.warning(f"Malformed JSON in log line: {str(e)[:100]}...")
                            continue
                        except Exception as e:
                            logger.warning(f"Error reading log line: {e}")
                            time.sleep(0.1)
                            
        except FileNotFoundError:
            logger.error(f"❌ Log file not found: {self.log_path}")
            logger.error("Please check if Apache is running and log file exists")
        except PermissionError:
            logger.error(f"❌ Permission denied accessing log file: {self.log_path}")
            logger.error("Please run with sudo or check file permissions")
        except Exception as e:
            logger.error(f"❌ Error in log monitoring: {e}")
        finally:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Dừng monitoring"""
        logger.info("🛑 Stopping log monitoring...")
        self.running = False

def main():
    """Main function"""
    try:
        # Create collector
        collector = RealtimeLogCollector()
        
        # Bắt đầu monitoring
        collector.start_monitoring()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, stopping...")
        collector.stop_monitoring()
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        collector.stop_monitoring()

if __name__ == "__main__":
    main()

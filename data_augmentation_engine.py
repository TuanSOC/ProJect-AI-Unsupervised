#!/usr/bin/env python3
"""
Data Augmentation Engine Module - Tối ưu hóa
Tạo synthetic SQLi attacks và mutation-based attack generation
"""

import logging
import random
import string
from datetime import datetime
from collections import defaultdict

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DataAugmentationEngine:
    """Engine để tạo synthetic SQLi attacks và data augmentation - Tối ưu hóa"""
    
    def __init__(self):
        self.sqli_templates = self._initialize_sqli_templates()
        self.obfuscation_techniques = self._initialize_obfuscation_techniques()
        self.mutation_operators = self._initialize_mutation_operators()
        self.generated_attacks = []
        
    def _initialize_sqli_templates(self):
        """Khởi tạo SQLi attack templates"""
        return {
            'union_based': [
                "1' UNION SELECT {columns} FROM {table}--",
                "1' UNION ALL SELECT {columns} FROM {table}--",
                "1' UNION SELECT {columns} FROM {table} WHERE {condition}--"
            ],
            'boolean_based': [
                "1' OR 1=1--",
                "1' AND 1=1--",
                "1' OR '1'='1",
                "1' AND '1'='1"
            ],
            'time_based': [
                "1'; WAITFOR DELAY '00:00:{delay}'--",
                "1' OR SLEEP({delay})--",
                "1' AND SLEEP({delay})--"
            ],
            'information_schema': [
                "1' UNION SELECT table_name,column_name FROM information_schema.columns--",
                "1' UNION SELECT table_name,column_name FROM information_schema.columns WHERE table_schema='{database}'--"
            ]
        }
    
    def _initialize_obfuscation_techniques(self):
        """Khởi tạo kỹ thuật obfuscation"""
        return {
            'character_encoding': [
                lambda s: s.replace('a', '&#97;'),
                lambda s: s.replace('o', '&#111;'),
                lambda s: s.replace('e', '&#101;')
            ],
            'case_variation': [
                lambda s: s.upper(),
                lambda s: s.lower(),
                lambda s: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))
            ],
            'whitespace_manipulation': [
                lambda s: s.replace(' ', '/**/'),
                lambda s: s.replace(' ', '+'),
                lambda s: s.replace(' ', '%20')
            ],
            'character_substitution': [
                lambda s: s.replace('o', '0'),
                lambda s: s.replace('l', '1'),
                lambda s: s.replace('e', '3')
            ]
        }
    
    def _initialize_mutation_operators(self):
        """Khởi tạo mutation operators"""
        return {
            'insert_random_chars': self._insert_random_chars,
            'delete_random_chars': self._delete_random_chars,
            'substitute_chars': self._substitute_chars,
            'duplicate_chars': self._duplicate_chars
        }
    
    def generate_synthetic_attacks(self, count=100, attack_types=None):
        """Tạo synthetic SQLi attacks"""
        if attack_types is None:
            attack_types = list(self.sqli_templates.keys())
        
        generated_attacks = []
        
        for i in range(count):
            try:
                # Chọn random attack type
                attack_type = random.choice(attack_types)
                
                # Tạo attack payload
                attack_payload = self._generate_attack_payload(attack_type)
                
                # Tạo log entry
                log_entry = self._create_log_entry(attack_payload, attack_type)
                
                # Thêm obfuscation
                obfuscated_log = self._apply_obfuscation(log_entry)
                
                generated_attacks.append({
                    'attack_type': attack_type,
                    'payload': attack_payload,
                    'log_entry': obfuscated_log,
                    'timestamp': datetime.now().isoformat(),
                    'generation_method': 'synthetic'
                })
                
            except Exception as e:
                logger.warning(f"Error generating attack {i}: {e}")
                continue
        
        self.generated_attacks.extend(generated_attacks)
        logger.info(f"✅ Generated {len(generated_attacks)} synthetic attacks")
        
        return generated_attacks
    
    def _generate_attack_payload(self, attack_type):
        """Tạo attack payload cho attack type"""
        templates = self.sqli_templates.get(attack_type, [])
        if not templates:
            # Fallback to basic SQLi pattern
            return "1' OR 1=1--"
        
        template = random.choice(templates)
        
        # Thay thế placeholders
        payload = template
        
        # Thay thế {columns}
        if '{columns}' in payload:
            columns = random.choice(['*', 'id,username,password', 'user,pass', 'name,email'])
            payload = payload.replace('{columns}', columns)
        
        # Thay thế {table}
        if '{table}' in payload:
            table = random.choice(['users', 'admin', 'accounts', 'members'])
            payload = payload.replace('{table}', table)
        
        # Thay thế {database}
        if '{database}' in payload:
            database = random.choice(['information_schema', 'mysql', 'test', 'app'])
            payload = payload.replace('{database}', database)
        
        # Thay thế {condition}
        if '{condition}' in payload:
            condition = random.choice(['id=1', 'username="admin"', 'active=1'])
            payload = payload.replace('{condition}', condition)
        
        # Thay thế {delay}
        if '{delay}' in payload:
            delay = random.choice(['1', '2', '3', '5'])
            payload = payload.replace('{delay}', delay)
        
        return payload
    
    def _create_log_entry(self, payload, attack_type):
        """Tạo log entry từ payload"""
        # Tạo URI và query string
        uri = random.choice([
            '/login.php',
            '/search.php',
            '/product.php',
            '/user.php',
            '/admin.php'
        ])
        
        # Tạo query string
        if random.choice([True, False]):
            query_string = f"?id={payload}"
        else:
            query_string = f"?search={payload}"
        
        # Tạo log entry
        log_entry = {
            'time': datetime.now().isoformat(),
            'remote_ip': self._generate_random_ip(),
            'method': random.choice(['GET', 'POST']),
            'uri': uri,
            'query_string': query_string,
            'status': random.choice([200, 404, 500]),
            'bytes_sent': random.randint(100, 5000),
            'response_time_ms': random.randint(10, 1000),
            'referer': random.choice(['http://localhost/', 'http://example.com/', '-']),
            'user_agent': self._generate_random_user_agent(),
            'request_length': random.randint(100, 2000),
            'response_length': random.randint(100, 5000),
            'cookie': self._generate_random_cookie(),
            'payload': payload,
            'session_token': self._generate_random_session_token(),
            'attack_type': attack_type
        }
        
        return log_entry
    
    def _generate_random_ip(self):
        """Tạo random IP address"""
        # Avoid reserved IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x)
        while True:
            first_octet = random.randint(1, 254)
            if first_octet not in [10, 127, 172, 192]:
                break
            elif first_octet == 172:
                second_octet = random.randint(1, 255)
                if not (16 <= second_octet <= 31):
                    break
            elif first_octet == 192:
                second_octet = random.randint(1, 255)
                if second_octet != 168:
                    break
        
        return f"{first_octet}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    def _generate_random_user_agent(self):
        """Tạo random user agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        return random.choice(user_agents)
    
    def _generate_random_cookie(self):
        """Tạo random cookie"""
        cookies = [
            'PHPSESSID=abc123def456',
            'session=xyz789',
            'user=admin; role=admin',
            'auth=token123; expires=2024-12-31'
        ]
        return random.choice(cookies)
    
    def _generate_random_session_token(self):
        """Tạo random session token"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    
    def _apply_obfuscation(self, log_entry):
        """Áp dụng obfuscation techniques"""
        obfuscated_log = log_entry.copy()
        
        # Chọn random obfuscation techniques
        techniques = random.sample(
            list(self.obfuscation_techniques.keys()), 
            random.randint(1, 2)
        )
        
        for technique in techniques:
            if technique in self.obfuscation_techniques:
                obfuscation_funcs = self.obfuscation_techniques[technique]
                obfuscation_func = random.choice(obfuscation_funcs)
                
                # Áp dụng obfuscation cho query_string và payload
                if 'query_string' in obfuscated_log:
                    obfuscated_log['query_string'] = obfuscation_func(obfuscated_log['query_string'])
                
                if 'payload' in obfuscated_log:
                    obfuscated_log['payload'] = obfuscation_func(obfuscated_log['payload'])
        
        return obfuscated_log
    
    def mutate_existing_attacks(self, attacks, mutation_count=50):
        """Mutation existing attacks"""
        mutated_attacks = []
        
        for i in range(mutation_count):
            try:
                # Chọn random attack để mutate
                base_attack = random.choice(attacks)
                
                # Chọn random mutation operator
                mutation_operator = random.choice(list(self.mutation_operators.keys()))
                mutation_func = self.mutation_operators[mutation_operator]
                
                # Tạo mutated attack
                mutated_attack = base_attack.copy()
                mutated_attack['payload'] = mutation_func(base_attack['payload'])
                mutated_attack['mutation_operator'] = mutation_operator
                mutated_attack['generation_method'] = 'mutation'
                mutated_attack['timestamp'] = datetime.now().isoformat()
                
                # Cập nhật log entry
                mutated_attack['log_entry'] = self._create_log_entry(
                    mutated_attack['payload'], 
                    base_attack.get('attack_type', 'unknown')
                )
                
                mutated_attacks.append(mutated_attack)
                
            except Exception as e:
                logger.warning(f"Error mutating attack {i}: {e}")
                continue
        
        logger.info(f"✅ Generated {len(mutated_attacks)} mutated attacks")
        return mutated_attacks
    
    def _insert_random_chars(self, payload):
        """Insert random characters"""
        if len(payload) < 2:
            return payload
        
        pos = random.randint(0, len(payload))
        char = random.choice(['x', 'X', '0', '1', 'a', 'A'])
        return payload[:pos] + char + payload[pos:]
    
    def _delete_random_chars(self, payload):
        """Delete random characters"""
        if len(payload) < 3:
            return payload
        
        pos = random.randint(0, len(payload) - 1)
        return payload[:pos] + payload[pos + 1:]
    
    def _substitute_chars(self, payload):
        """Substitute characters"""
        if len(payload) < 2:
            return payload
        
        pos = random.randint(0, len(payload) - 1)
        char = random.choice(['x', 'X', '0', '1', 'a', 'A'])
        return payload[:pos] + char + payload[pos + 1:]
    
    def _duplicate_chars(self, payload):
        """Duplicate characters"""
        if len(payload) < 2:
            return payload
        
        pos = random.randint(0, len(payload) - 1)
        char = payload[pos]
        return payload[:pos] + char + char + payload[pos + 1:]
    
    def generate_adversarial_examples(self, clean_logs, count=100):
        """Tạo adversarial examples từ clean logs"""
        adversarial_examples = []
        
        for i in range(count):
            try:
                # Chọn random clean log
                base_log = random.choice(clean_logs)
                
                # Tạo adversarial log
                adversarial_log = base_log.copy()
                
                # Thêm SQLi patterns vào query_string
                if 'query_string' in adversarial_log:
                    sqli_pattern = random.choice([
                        " OR 1=1",
                        " AND 1=1",
                        " UNION SELECT *",
                        "'; DROP TABLE users--"
                    ])
                    adversarial_log['query_string'] += sqli_pattern
                
                # Thêm SQLi patterns vào payload
                if 'payload' in adversarial_log:
                    adversarial_log['payload'] += sqli_pattern
                
                adversarial_examples.append({
                    'base_log': base_log,
                    'adversarial_log': adversarial_log,
                    'added_pattern': sqli_pattern,
                    'timestamp': datetime.now().isoformat(),
                    'generation_method': 'adversarial'
                })
                
            except Exception as e:
                logger.warning(f"Error generating adversarial example {i}: {e}")
                continue
        
        logger.info(f"✅ Generated {len(adversarial_examples)} adversarial examples")
        return adversarial_examples
    
    def get_augmentation_summary(self):
        """Lấy tóm tắt data augmentation"""
        try:
            summary = {
                'total_generated': len(self.generated_attacks),
                'by_method': defaultdict(int),
                'by_attack_type': defaultdict(int),
                'by_mutation_operator': defaultdict(int)
            }
            
            for attack in self.generated_attacks:
                method = attack.get('generation_method', 'unknown')
                summary['by_method'][method] += 1
                
                attack_type = attack.get('attack_type', 'unknown')
                summary['by_attack_type'][attack_type] += 1
                
                if 'mutation_operator' in attack:
                    operator = attack['mutation_operator']
                    summary['by_mutation_operator'][operator] += 1
            
            return dict(summary)
            
        except Exception as e:
            logger.error(f"Error getting augmentation summary: {e}")
            return None

def test_data_augmentation_engine():
    """Test data augmentation engine"""
    print("🧪 Testing Data Augmentation Engine")
    print("=" * 50)
    
    # Tạo engine
    engine = DataAugmentationEngine()
    
    # Test synthetic attack generation
    print("\n📊 Testing synthetic attack generation")
    synthetic_attacks = engine.generate_synthetic_attacks(count=20)
    print(f"   Generated {len(synthetic_attacks)} synthetic attacks")
    
    # Test mutation
    print("\n📊 Testing attack mutation")
    mutated_attacks = engine.mutate_existing_attacks(synthetic_attacks, mutation_count=10)
    print(f"   Generated {len(mutated_attacks)} mutated attacks")
    
    # Test adversarial examples
    print("\n📊 Testing adversarial examples")
    clean_logs = [
        {
            'uri': '/index.php',
            'query_string': '?id=1',
            'payload': 'id=1',
            'cookie': 'session=abc123'
        },
        {
            'uri': '/search.php',
            'query_string': '?q=test',
            'payload': 'q=test',
            'cookie': 'user=admin'
        }
    ]
    
    adversarial_examples = engine.generate_adversarial_examples(clean_logs, count=5)
    print(f"   Generated {len(adversarial_examples)} adversarial examples")
    
    # Get summary
    summary = engine.get_augmentation_summary()
    print(f"\n📈 Augmentation Summary:")
    print(f"   Total generated: {summary['total_generated']}")
    print(f"   By method: {dict(summary['by_method'])}")
    print(f"   By attack type: {dict(summary['by_attack_type'])}")
    
    print("\n✅ Data augmentation engine test completed!")

if __name__ == "__main__":
    test_data_augmentation_engine()

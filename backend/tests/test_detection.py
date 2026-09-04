import pytest
from detection.rules import SecurityRules

class TestDetection:
    """Test security detection rules"""
    
    def setup_method(self):
        self.rules = SecurityRules()
    
    def test_brute_force_detection(self):
        """Test brute force detection"""
        logs = [
            "Failed login for admin from 192.168.1.10",
            "Failed login for admin from 192.168.1.10",
            "Failed login for admin from 192.168.1.10",
            "Failed login for admin from 192.168.1.10",
            "Failed login for admin from 192.168.1.10",
        ]
        
        threats = self.rules.detect_brute_force(logs)
        
        assert len(threats) > 0
        assert threats[0]['type'] == 'Brute Force Attack'
        assert threats[0]['source_ip'] == '192.168.1.10'
    
    def test_brute_force_no_detection(self):
        """Test no brute force detection with few attempts"""
        logs = [
            "Failed login for admin from 192.168.1.10",
            "Failed login for admin from 192.168.1.10",
        ]
        
        threats = self.rules.detect_brute_force(logs)
        
        # Should not detect with only 2 attempts
        assert len(threats) == 0
    
    def test_sql_injection_detection(self):
        """Test SQL injection detection"""
        logs = [
            "GET /login?id=' OR '1'='1' --",
            "GET /users?query=UNION SELECT * FROM users"
        ]
        
        threats = self.rules.detect_sql_injection(logs)
        
        assert len(threats) > 0
        assert threats[0]['type'] == 'SQL Injection Attempt'
        assert threats[0]['severity'] == 'Critical'
    
    def test_xss_detection(self):
        """Test XSS detection"""
        logs = [
            "GET /search?q=<script>alert('XSS')</script>",
            "GET /profile?name=<img src=x onerror=alert(1)>"
        ]
        
        threats = self.rules.detect_xss_attempts(logs)
        
        assert len(threats) > 0
        assert threats[0]['type'] == 'XSS Attack Attempt'
        assert threats[0]['severity'] == 'High'
    
    def test_port_scan_detection(self):
        """Test port scan detection"""
        logs = [
            "Connection to port 22 from 192.168.1.100",
            "Connection to port 23 from 192.168.1.100",
            "Connection to port 25 from 192.168.1.100",
            "Connection to port 80 from 192.168.1.100",
            "Connection to port 443 from 192.168.1.100",
        ]
        
        threats = self.rules.detect_port_scanning(logs)
        
        assert len(threats) > 0
        assert threats[0]['type'] == 'Port Scanning Activity'
        assert threats[0]['source_ip'] == '192.168.1.100'
    
    def test_ip_extraction(self):
        """Test IP extraction from logs"""
        log = "IP=192.168.1.100 user=admin status=401 Failed login attempt"
        ip = self.rules._extract_ip(log)
        assert ip == '192.168.1.100'
    
    def test_confidence_calculation(self):
        """Test confidence score calculation"""
        from services.log_processor import LogProcessor
        processor = LogProcessor()
        
        threat = {
            'type': 'Brute Force Attack',
            'details': '10 failed login attempts repeated from same IP',
            'attempt_count': 10
        }
        
        confidence = processor._calculate_confidence(threat, [])
        assert 0 <= confidence <= 1
        assert confidence > 0.7  # Should be high for 10 attempts
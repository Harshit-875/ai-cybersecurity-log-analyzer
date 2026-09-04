import re
from collections import Counter

class SecurityRules:
    """Security detection rules for identifying suspicious activities"""
    
    @staticmethod
    def detect_brute_force(logs):
        """Detect brute force attempts from login failures"""
        failed_attempts = []
        
        for log in logs:
            if 'failed' in log.lower() and 'login' in log.lower():
                # Extract IP using regex
                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log)
                if ip_match:
                    failed_attempts.append(ip_match.group())
        
        # Count attempts per IP
        ip_counts = Counter(failed_attempts)
        
        threats = []
        for ip, count in ip_counts.items():
            if count >= 5:
                threats.append({
                    'type': 'Brute Force Attack',
                    'severity': 'High',
                    'source_ip': ip,
                    'details': f'{count} failed login attempts from {ip}',
                    'recommendation': f'Block IP {ip} and investigate source'
                })
            elif count >= 3:
                threats.append({
                    'type': 'Suspicious Login Activity',
                    'severity': 'Medium',
                    'source_ip': ip,
                    'details': f'{count} failed login attempts from {ip}',
                    'recommendation': f'Monitor IP {ip} for further attempts'
                })
        
        return threats
    
    @staticmethod
    def detect_sql_injection(logs):
        """Detect potential SQL injection attempts"""
        sql_patterns = [
            r"(\bSELECT\b.*\bFROM\b)",
            r"(\bINSERT\b.*\bINTO\b)",
            r"(\bDROP\b.*\bTABLE\b)",
            r"(\bUNION\b.*\bSELECT\b)",
            r"' OR '1'='1",
            r"'.*--",
            r"'.*;.*--",
            r"admin' --"
        ]
        
        threats = []
        for log in logs:
            for pattern in sql_patterns:
                if re.search(pattern, log, re.IGNORECASE):
                    # Extract IP
                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log)
                    source_ip = ip_match.group() if ip_match else 'Unknown'
                    
                    threats.append({
                        'type': 'SQL Injection Attempt',
                        'severity': 'Critical',
                        'source_ip': source_ip,
                        'details': f'Potential SQL injection detected: {log[:100]}...',
                        'recommendation': f'Block IP {source_ip} and inspect logs for data exfiltration'
                    })
                    break
        
        return threats
    
    @staticmethod
    def detect_xss_attempts(logs):
        """Detect potential XSS attacks"""
        xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"onerror=",
            r"onload=",
            r"alert\(",
            r"<img.*?onerror=",
            r"<body.*?onload="
        ]
        
        threats = []
        for log in logs:
            for pattern in xss_patterns:
                if re.search(pattern, log, re.IGNORECASE):
                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log)
                    source_ip = ip_match.group() if ip_match else 'Unknown'
                    
                    threats.append({
                        'type': 'XSS Attack Attempt',
                        'severity': 'High',
                        'source_ip': source_ip,
                        'details': f'Potential XSS detected: {log[:100]}...',
                        'recommendation': f'Block IP {source_ip} and sanitize input'
                    })
                    break
        
        return threats
    
    @staticmethod
    def detect_port_scanning(logs):
        """Detect potential port scanning activity"""
        port_patterns = [
            r"Connection to port \d+",
            r"Scan from \d+\.\d+\.\d+\.\d+",
            r"SYN packet",
            r"Port scan"
        ]
        
        threats = []
        ip_logs = {}
        
        for log in logs:
            for pattern in port_patterns:
                if re.search(pattern, log, re.IGNORECASE):
                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log)
                    if ip_match:
                        source_ip = ip_match.group()
                        if source_ip not in ip_logs:
                            ip_logs[source_ip] = 0
                        ip_logs[source_ip] += 1
                    break
        
        for ip, count in ip_logs.items():
            if count >= 5:
                threats.append({
                    'type': 'Port Scanning Activity',
                    'severity': 'High',
                    'source_ip': ip,
                    'details': f'Port scan detected with {count} connections from {ip}',
                    'recommendation': f'Block IP {ip} and investigate for reconnaissance'
                })
        
        return threats
    
    @staticmethod
    def analyze_logs(logs):
        """Analyze logs using all detection rules"""
        all_threats = []
        
        # Apply all detection rules
        all_threats.extend(SecurityRules.detect_brute_force(logs))
        all_threats.extend(SecurityRules.detect_sql_injection(logs))
        all_threats.extend(SecurityRules.detect_xss_attempts(logs))
        all_threats.extend(SecurityRules.detect_port_scanning(logs))
        
        # Remove duplicates (same IP and type)
        unique_threats = []
        seen = set()
        for threat in all_threats:
            key = (threat['type'], threat['source_ip'])
            if key not in seen:
                seen.add(key)
                unique_threats.append(threat)
        
        return unique_threats
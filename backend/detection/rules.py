import re
from collections import defaultdict
from datetime import datetime, timedelta
from config import Config
import logging

logger = logging.getLogger(__name__)

class SecurityRules:
    """Security detection rules for identifying suspicious activities"""
    
    def __init__(self):
        self.brute_force_threshold = Config.BRUTE_FORCE_THRESHOLD
        self.brute_force_window = Config.BRUTE_FORCE_WINDOW_MINUTES
        self.port_scan_threshold = Config.PORT_SCAN_THRESHOLD
    
    def analyze_logs(self, logs):
        """Analyze logs using all detection rules"""
        all_threats = []
        
        # Apply all detection rules
        all_threats.extend(self.detect_brute_force(logs))
        all_threats.extend(self.detect_sql_injection(logs))
        all_threats.extend(self.detect_xss_attempts(logs))
        all_threats.extend(self.detect_port_scanning(logs))
        
        # Remove duplicates
        unique_threats = []
        seen = set()
        for threat in all_threats:
            key = (threat['type'], threat['source_ip'])
            if key not in seen:
                seen.add(key)
                unique_threats.append(threat)
        
        return unique_threats
    
    def detect_brute_force(self, logs):
        """Detect brute force attempts with time window"""
        # Group failed login attempts by IP with timestamps
        attempts_by_ip = defaultdict(list)
        
        for log in logs:
            if 'failed' in log.lower() and 'login' in log.lower():
                ip = self._extract_ip(log)
                if ip:
                    timestamp = self._extract_timestamp(log)
                    if timestamp:
                        attempts_by_ip[ip].append(timestamp)
        
        threats = []
        for ip, timestamps in attempts_by_ip.items():
            if len(timestamps) < self.brute_force_threshold:
                continue
            
            # Sort timestamps
            timestamps.sort()
            
            # Check time window
            window_start = datetime.now() - timedelta(minutes=self.brute_force_window)
            recent_attempts = [t for t in timestamps if t >= window_start]
            
            if len(recent_attempts) >= self.brute_force_threshold:
                # Calculate actual window
                if len(recent_attempts) > 1:
                    time_window = (recent_attempts[-1] - recent_attempts[0]).total_seconds() / 60
                else:
                    time_window = 0
                
                severity = 'Critical' if len(recent_attempts) >= 10 else 'High'
                
                threats.append({
                    'type': 'Brute Force Attack',
                    'severity': severity,
                    'source_ip': ip,
                    'details': f'{len(recent_attempts)} failed login attempts in {time_window:.1f} minutes',
                    'recommendation': f'Block IP {ip} and enable MFA for affected accounts',
                    'attempt_count': len(recent_attempts),
                    'time_window_minutes': round(time_window, 1)
                })
            elif len(timestamps) >= self.brute_force_threshold:
                # Failed attempts exist but outside window
                threats.append({
                    'type': 'Suspicious Login Activity',
                    'severity': 'Medium',
                    'source_ip': ip,
                    'details': f'{len(timestamps)} failed login attempts over extended period',
                    'recommendation': f'Monitor IP {ip} for unusual activity',
                    'attempt_count': len(timestamps),
                    'time_window_minutes': None
                })
        
        return threats
    
    def detect_sql_injection(self, logs):
        """Detect potential SQL injection attempts"""
        sql_patterns = [
            # OWASP Top 10 SQL Injection patterns
            r"(?i)(\bSELECT\b.*\bFROM\b)",
            r"(?i)(\bINSERT\b.*\bINTO\b)",
            r"(?i)(\bDROP\b.*\bTABLE\b)",
            r"(?i)(\bUNION\b.*\bSELECT\b)",
            r"(?i)(\bDELETE\b.*\bFROM\b)",
            r"(?i)(\bUPDATE\b.*\bSET\b)",
            
            # Common injection patterns
            r"(?i)'\s*OR\s*'1'\s*=\s*'1",
            r"(?i)'\s*OR\s*1\s*=\s*1",
            r"(?i)'\s*OR\s*'a'\s*=\s*'a",
            r"(?i)'\s*;.*--",
            r"(?i)'\s*--",
            r"(?i)admin'\s*--",
            r"(?i)'\s*OR\s*'x'\s*=\s*'x",
            
            # Advanced patterns
            r"(?i)\bSLEEP\s*\(",
            r"(?i)\bBENCHMARK\s*\(",
            r"(?i)\bWAITFOR\s+DELAY",
            r"(?i);\s*SHUTDOWN",
            r"(?i);\s*DROP\s+",
        ]
        
        threats = []
        for log in logs:
            for pattern in sql_patterns:
                if re.search(pattern, log, re.IGNORECASE):
                    ip = self._extract_ip(log)
                    threats.append({
                        'type': 'SQL Injection Attempt',
                        'severity': 'Critical',
                        'source_ip': ip or 'Unknown',
                        'details': f'SQL injection pattern detected: {log[:150]}...',
                        'recommendation': f'Block IP {ip if ip else "source"} and review database logs'
                    })
                    break
        
        return threats
    
    def detect_xss_attempts(self, logs):
        """Detect potential XSS attacks"""
        xss_patterns = [
            # Script injection
            r"(?i)<script.*?>.*?</script>",
            r"(?i)javascript\s*:",
            r"(?i)vbscript\s*:",
            r"(?i)onerror\s*=",
            r"(?i)onload\s*=",
            r"(?i)onclick\s*=",
            r"(?i)alert\s*\(",
            r"(?i)prompt\s*\(",
            r"(?i)confirm\s*\(",
            
            # HTML injection
            r"(?i)<img.*?onerror=",
            r"(?i)<body.*?onload=",
            r"(?i)<iframe.*?src=.*?javascript:",
            
            # Encoded variants
            r"(?i)%3Cscript%3E",
            r"(?i)%3Cimg%3E",
            r"(?i)&#60;script&#62;",
        ]
        
        threats = []
        for log in logs:
            for pattern in xss_patterns:
                if re.search(pattern, log, re.IGNORECASE):
                    ip = self._extract_ip(log)
                    threats.append({
                        'type': 'XSS Attack Attempt',
                        'severity': 'High',
                        'source_ip': ip or 'Unknown',
                        'details': f'XSS pattern detected: {log[:150]}...',
                        'recommendation': f'Block IP {ip if ip else "source"} and sanitize input'
                    })
                    break
        
        return threats
    
    def detect_port_scanning(self, logs):
        """Detect potential port scanning activity"""
        port_patterns = [
            r"(?i)connection to port \d+",
            r"(?i)scan from",
            r"(?i)port scan",
            r"(?i)SYN\s+packet",
            r"(?i)ACK\s+packet",
            r"(?i)connection attempt to port",
            r"(?i)connect from.*\s+port\s+\d+",
        ]
        
        ip_ports = defaultdict(set)
        
        for log in logs:
            for pattern in port_patterns:
                if re.search(pattern, log, re.IGNORECASE):
                    ip = self._extract_ip(log)
                    if ip:
                        # Extract port number if present
                        port_match = re.search(r'port\s+(\d+)', log, re.IGNORECASE)
                        if port_match:
                            port = port_match.group(1)
                            ip_ports[ip].add(port)
                        else:
                            ip_ports[ip].add('unknown')
                    break
        
        threats = []
        for ip, ports in ip_ports.items():
            if len(ports) >= self.port_scan_threshold:
                threats.append({
                    'type': 'Port Scanning Activity',
                    'severity': 'High',
                    'source_ip': ip,
                    'details': f'Scanning activity detected: {len(ports)} unique ports',
                    'recommendation': f'Block IP {ip} and investigate for reconnaissance activity',
                    'attempt_count': len(ports),
                    'time_window_minutes': None
                })
        
        return threats
    
    def _extract_ip(self, log):
        """Extract IP address from log line"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        match = re.search(ip_pattern, log)
        return match.group() if match else None
    
    def _extract_timestamp(self, log):
        """Extract timestamp from log line if present"""
        # Try common timestamp formats
        patterns = [
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',  # 2026-09-03 18:42:10
            r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',  # 09/03/2026 18:42:10
            r'(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})',  # 09-03-2026 18:42:10
            r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})',  # Sep 3 18:42:10
        ]
        
        for pattern in patterns:
            match = re.search(pattern, log)
            if match:
                try:
                    return datetime.strptime(match.group(1), self._get_format(pattern))
                except ValueError:
                    continue
        
        # If no timestamp found, use current time
        return datetime.now()
    
    def _get_format(self, pattern):
        """Get datetime format for pattern"""
        formats = {
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})': '%Y-%m-%d %H:%M:%S',
            r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})': '%m/%d/%Y %H:%M:%S',
            r'(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})': '%m-%d-%Y %H:%M:%S',
        }
        return formats.get(pattern, '%Y-%m-%d %H:%M:%S')
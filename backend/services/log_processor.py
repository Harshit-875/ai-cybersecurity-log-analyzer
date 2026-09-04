from detection.rules import SecurityRules
from services.ai_service import AIService
from database.repositories import ThreatRepository
from datetime import datetime
import re
import logging

logger = logging.getLogger(__name__)

class LogProcessor:
    """Process logs and detect threats"""
    
    def __init__(self):
        self.rules = SecurityRules()
        self.ai_service = AIService()
        self.repository = ThreatRepository()
    
    def process_logs(self, log_text):
        """Process raw log text and identify security threats"""
        if not log_text or not log_text.strip():
            return {'data': [], 'total': 0, 'suspicious': 0}
        
        # Split logs into individual entries
        logs = [log.strip() for log in log_text.strip().split('\n') if log.strip()]
        
        # Apply rule-based detection
        threats = self.rules.analyze_logs(logs)
        
        # Enrich threats with AI analysis and confidence
        enriched_threats = []
        for threat in threats:
            # Add confidence score
            confidence = self._calculate_confidence(threat, logs)
            threat['confidence'] = confidence
            
            # Get AI analysis
            ai_analysis = self.ai_service.analyze_threat(threat)
            summary = self.ai_service.generate_summary(threat)
            
            # Combine threat with AI analysis
            enriched = {
                'timestamp': datetime.now().isoformat(),
                'threat_type': threat.get('type', 'Unknown'),
                'severity': threat.get('severity', 'Medium'),
                'source_ip': threat.get('source_ip', 'Unknown'),
                'raw_log': threat.get('details', ''),
                'summary': summary,
                'recommendation': threat.get('recommendation', 'Investigate immediately.'),
                'confidence': confidence,
                'ai_analysis': ai_analysis,
                'detection_method': 'rule_based_and_ai' if ai_analysis else 'rule_based',
                'attempt_count': threat.get('attempt_count'),
                'time_window_minutes': threat.get('time_window_minutes')
            }
            
            # Save to database
            saved = self.repository.save_threat(enriched)
            if saved:
                enriched['_id'] = saved.get('_id')
            
            enriched_threats.append(enriched)
        
        # Add normal activity log entry
        normal_logs = self._identify_normal_logs(logs, threats)
        if normal_logs:
            normal_entry = {
                'timestamp': datetime.now().isoformat(),
                'threat_type': 'Normal Activity',
                'severity': 'Low',
                'source_ip': self._extract_ips_from_logs(normal_logs)[0] if normal_logs else 'Unknown',
                'raw_log': '\n'.join(normal_logs[:3]),
                'summary': f'{len(normal_logs)} normal log entries processed',
                'recommendation': 'Continue monitoring',
                'confidence': 1.0,
                'ai_analysis': {'explanation': 'Normal system activity detected'},
                'detection_method': 'rule_based'
            }
            self.repository.save_threat(normal_entry)
            enriched_threats.append(normal_entry)
        
        return {
            'data': enriched_threats,
            'total': len(logs),
            'suspicious': len([t for t in enriched_threats if t['threat_type'] != 'Normal Activity'])
        }
    
    def _calculate_confidence(self, threat, logs):
        """Calculate confidence score for a detection"""
        confidence = 0.5  # Base confidence
        
        threat_type = threat.get('type', '')
        details = threat.get('details', '').lower()
        
        # Adjust confidence based on evidence strength
        if 'brute force' in threat_type.lower():
            attempt_count = threat.get('attempt_count', 0)
            if attempt_count >= 10:
                confidence += 0.3
            elif attempt_count >= 5:
                confidence += 0.2
            
            # Check if multiple indicators
            if 'repeated' in details or 'multiple' in details:
                confidence += 0.1
        
        elif 'sql injection' in threat_type.lower():
            # Check for multiple SQL patterns
            sql_patterns = ['union', 'select', 'drop', 'insert', 'or 1=1']
            matches = sum(1 for p in sql_patterns if p in details)
            confidence += min(matches * 0.1, 0.3)
            confidence += 0.2  # Base confidence for SQL injection patterns
        
        elif 'xss' in threat_type.lower():
            xss_patterns = ['script', 'alert', 'onerror', 'onload']
            matches = sum(1 for p in xss_patterns if p in details)
            confidence += min(matches * 0.1, 0.3)
            confidence += 0.2
        
        elif 'port scan' in threat_type.lower():
            # Port scans with many ports = higher confidence
            import re
            port_matches = len(re.findall(r'port \d+', details))
            confidence += min(port_matches * 0.05, 0.3)
            confidence += 0.1
        
        # Cap confidence at 0.95
        return min(round(confidence, 2), 0.95)
    
    def _identify_normal_logs(self, logs, threats):
        """Identify logs that weren't flagged as threats"""
        threat_ips = set(t.get('source_ip', '') for t in threats if t.get('source_ip'))
        normal_logs = []
        
        for log in logs:
            ip = self._extract_ip_from_log(log)
            # If no suspicious pattern and IP not in threats
            if ip and ip not in threat_ips:
                normal_logs.append(log)
            elif not ip:
                # Log with no IP, check if it contains suspicious patterns
                is_suspicious = False
                for threat in threats:
                    if threat.get('details', '') in log:
                        is_suspicious = True
                        break
                if not is_suspicious:
                    normal_logs.append(log)
        
        return normal_logs
    
    def _extract_ip_from_log(self, log):
        """Extract IP address from log entry"""
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log)
        return ip_match.group() if ip_match else None
    
    def _extract_ips_from_logs(self, logs):
        """Extract all IPs from log entries"""
        ips = []
        for log in logs:
            ip = self._extract_ip_from_log(log)
            if ip:
                ips.append(ip)
        return list(set(ips))  # Unique IPs
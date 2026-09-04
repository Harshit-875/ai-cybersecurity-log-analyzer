from detection.rules import SecurityRules
from services.ai_analyzer import AIAnalyzer
from models.log_model import SecurityLog
import re
from datetime import datetime

class LogProcessor:
    def __init__(self):
        self.ai_analyzer = AIAnalyzer()
    
    def process_logs(self, log_text):
        """Process raw log text and identify security threats"""
        # Split logs into individual entries
        logs = log_text.strip().split('\n')
        logs = [log.strip() for log in logs if log.strip()]
        
        # Initial rule-based detection
        threats = SecurityRules.analyze_logs(logs)
        
        # Process each threat with AI
        enriched_threats = []
        for threat in threats:
            # Get AI analysis
            ai_analysis = self.ai_analyzer.analyze_threat(threat)
            summary = self.ai_analyzer.generate_threat_summary(threat)
            
            # Combine threat data with AI analysis
            enriched_threat = {
                'threat_type': threat['type'],
                'severity': threat['severity'],
                'source_ip': threat['source_ip'],
                'raw_log': threat.get('details', ''),
                'summary': summary,
                'recommendation': threat.get('recommendation', 'Investigate immediately.'),
                'ai_analysis': ai_analysis,
                'timestamp': datetime.now().isoformat(),
                'detection_type': 'rule_based_and_ai'
            }
            enriched_threats.append(enriched_threat)
        
        # Also check for normal logs (not threats)
        normal_logs = self._identify_normal_logs(logs, threats)
        if normal_logs:
            enriched_threats.append({
                'threat_type': 'Normal Activity',
                'severity': 'Low',
                'source_ip': self._extract_ips_from_logs(normal_logs)[0] if normal_logs else 'Unknown',
                'raw_log': '\n'.join(normal_logs[:5]),  # First 5 normal logs
                'summary': f'{len(normal_logs)} normal log entries processed',
                'recommendation': 'Continue monitoring',
                'ai_analysis': {'explanation': 'Normal system activity detected'},
                'timestamp': datetime.now().isoformat(),
                'detection_type': 'rule_based'
            })
        
        return enriched_threats
    
    def _identify_normal_logs(self, logs, threats):
        """Identify logs that weren't flagged as threats"""
        threat_ips = set(threat['source_ip'] for threat in threats)
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
        return ips
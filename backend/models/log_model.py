from datetime import datetime

class SecurityLog:
    def __init__(self, data):
        self.raw_log = data.get('raw_log', '')
        self.source_ip = data.get('source_ip', '')
        self.timestamp = data.get('timestamp', datetime.now().isoformat())
        self.threat_type = data.get('threat_type', 'Normal')
        self.severity = data.get('severity', 'Low')
        self.summary = data.get('summary', '')
        self.recommendation = data.get('recommendation', '')
        self.ai_analysis = data.get('ai_analysis', {})
        self.detection_type = data.get('detection_type', 'rule_based')

    def to_dict(self):
        return {
            'raw_log': self.raw_log,
            'source_ip': self.source_ip,
            'timestamp': self.timestamp,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'summary': self.summary,
            'recommendation': self.recommendation,
            'ai_analysis': self.ai_analysis,
            'detection_type': self.detection_type
        }
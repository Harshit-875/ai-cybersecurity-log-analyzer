from flask import Blueprint, request, jsonify
from services.log_processor import LogProcessor
from datetime import datetime

log_bp = Blueprint('log', __name__)
log_processor = LogProcessor()

@log_bp.route('/analyze', methods=['POST'])
def analyze_logs():
    """Analyze uploaded logs"""
    try:
        data = request.get_json()
        
        if not data or 'logs' not in data:
            return jsonify({'error': 'No logs provided'}), 400
        
        log_text = data['logs']
        
        # Process logs
        results = log_processor.process_logs(log_text)
        
        # Calculate statistics
        threats_found = [r for r in results if r['threat_type'] != 'Normal Activity']
        threat_types = {}
        severity_breakdown = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for r in results:
            threat_type = r['threat_type']
            severity = r['severity']
            
            if threat_type not in threat_types:
                threat_types[threat_type] = 0
            threat_types[threat_type] += 1
            
            if severity in severity_breakdown:
                severity_breakdown[severity] += 1
        
        # Return results with statistics
        return jsonify({
            'status': 'success',
            'data': results,
            'total_logs_analyzed': len(log_text.split('\n')),
            'suspicious_events': len(threats_found),
            'threat_types': threat_types,
            'severity_breakdown': severity_breakdown
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@log_bp.route('/threats', methods=['GET'])
def get_threats():
    """Get all analyzed threats (sample data)"""
    sample_threats = [
        {
            'id': '1',
            'threat_type': 'Brute Force Attack',
            'severity': 'High',
            'source_ip': '192.168.1.100',
            'timestamp': datetime.now().isoformat(),
            'summary': 'Multiple failed login attempts detected from IP 192.168.1.100',
            'recommendation': 'Block the IP and review authentication logs',
            'ai_analysis': {
                'explanation': 'This pattern indicates a potential brute force attack where an attacker is systematically trying different passwords.',
                'risk_assessment': 'High risk of unauthorized access if successful.',
                'recommendations': 'Immediately block the source IP and implement account lockout policies.'
            }
        },
        {
            'id': '2',
            'threat_type': 'SQL Injection Attempt',
            'severity': 'Critical',
            'source_ip': '10.0.0.50',
            'timestamp': datetime.now().isoformat(),
            'summary': 'SQL injection pattern detected in request parameters',
            'recommendation': 'Block IP and review database access logs',
            'ai_analysis': {
                'explanation': 'The request contains SQL commands that could manipulate database queries.',
                'risk_assessment': 'Critical risk of data exfiltration or manipulation.',
                'recommendations': 'Immediately block the IP and review input sanitization measures.'
            }
        }
    ]
    return jsonify(sample_threats)

@log_bp.route('/statistics', methods=['GET'])
def get_statistics():
    """Get statistics about analyzed logs"""
    stats = {
        'total_logs_analyzed': 1542,
        'suspicious_events': 23,
        'threat_types': {
            'Brute Force Attack': 8,
            'SQL Injection Attempt': 5,
            'XSS Attack Attempt': 4,
            'Port Scanning Activity': 6,
            'Normal Activity': 1519
        },
        'severity_breakdown': {
            'Critical': 5,
            'High': 14,
            'Medium': 4,
            'Low': 1519
        }
    }
    return jsonify(stats)
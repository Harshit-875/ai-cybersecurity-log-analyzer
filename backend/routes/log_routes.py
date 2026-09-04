from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from services.log_processor import LogProcessor
from config import Config
import logging

logger = logging.getLogger(__name__)

log_bp = Blueprint('logs', __name__)
log_processor = LogProcessor()

@log_bp.route('/analyze', methods=['POST'])
@jwt_required()
def analyze_logs():
    """Analyze uploaded logs"""
    try:
        data = request.get_json()
        
        if not data or 'logs' not in data:
            return jsonify({'error': 'No logs provided'}), 400
        
        log_text = data['logs']
        
        # Check size limit
        if len(log_text) > Config.MAX_LOG_SIZE:
            return jsonify({'error': f'Log size exceeds maximum of {Config.MAX_LOG_SIZE // (1024*1024)}MB'}), 400
        
        # Process logs
        results = log_processor.process_logs(log_text)
        
        return jsonify({
            'status': 'success',
            'data': results['data'],
            'total_logs_analyzed': results['total'],
            'suspicious_events': results['suspicious'],
            'message': f'Analysis complete. Found {results["suspicious"]} suspicious events out of {results["total"]} logs.'
        }), 200
    
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({'error': str(e)}), 500
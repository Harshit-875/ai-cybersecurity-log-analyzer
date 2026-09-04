from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from database.repositories import ThreatRepository
import logging

logger = logging.getLogger(__name__)

threat_bp = Blueprint('threats', __name__)
threat_repo = ThreatRepository()

@threat_bp.route('/', methods=['GET'])
@jwt_required()
def get_threats():
    """Get all threats with pagination"""
    try:
        limit = request.args.get('limit', 100, type=int)
        skip = request.args.get('skip', 0, type=int)
        threat_type = request.args.get('type')
        severity = request.args.get('severity')
        
        # Build filters
        filters = {}
        if threat_type:
            filters['threat_type'] = threat_type
        if severity:
            filters['severity'] = severity
        
        threats = threat_repo.get_threats(limit=limit, skip=skip, filters=filters)
        
        return jsonify({
            'data': threats,
            'count': len(threats),
            'limit': limit,
            'skip': skip
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting threats: {e}")
        return jsonify({'error': str(e)}), 500

@threat_bp.route('/<threat_id>', methods=['GET'])
@jwt_required()
def get_threat_by_id(threat_id):
    """Get a specific threat by ID"""
    try:
        threat = threat_repo.get_threat_by_id(threat_id)
        
        if not threat:
            return jsonify({'error': 'Threat not found'}), 404
        
        return jsonify(threat), 200
    
    except Exception as e:
        logger.error(f"Error getting threat: {e}")
        return jsonify({'error': str(e)}), 500
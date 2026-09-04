from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from database.repositories import ThreatRepository
import logging

logger = logging.getLogger(__name__)

stats_bp = Blueprint('stats', __name__)
threat_repo = ThreatRepository()

@stats_bp.route('/', methods=['GET'])
@jwt_required()
def get_statistics():
    """Get dynamic statistics from database"""
    try:
        stats = threat_repo.get_statistics()
        return jsonify(stats), 200
    
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({'error': str(e)}), 500
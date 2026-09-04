from database.mongo_db import MongoDB
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ThreatRepository:
    """Repository for threat operations"""
    
    def __init__(self):
        self.mongo = MongoDB()
    
    def save_threat(self, threat_data):
        """Save a threat to the database"""
        if not self.mongo.is_connected():
            logger.warning("MongoDB not connected, threat not saved")
            return None
        
        collection = self.mongo.get_collection('threats')
        if collection is None:
            return None
        
        # Add timestamp if not present
        if 'timestamp' not in threat_data:
            threat_data['timestamp'] = datetime.now().isoformat()
        
        # Ensure severity is set
        if 'severity' not in threat_data:
            threat_data['severity'] = 'Low'
        
        # Set detection method if not present
        if 'detection_method' not in threat_data:
            threat_data['detection_method'] = 'rule_based'
        
        # Remove None values
        threat_data = {k: v for k, v in threat_data.items() if v is not None}
        
        try:
            result = collection.insert_one(threat_data)
            threat_data['_id'] = str(result.inserted_id)
            return threat_data
        except Exception as e:
            logger.error(f"Error saving threat: {e}")
            return None
    
    def get_threats(self, limit=100, skip=0, filters=None):
        """Get threats with optional filters"""
        if not self.mongo.is_connected():
            return []
        
        collection = self.mongo.get_collection('threats')
        if collection is None:
            return []
        
        query = filters or {}
        
        try:
            threats = list(collection.find(query)
                          .sort('timestamp', -1)
                          .skip(skip)
                          .limit(limit))
            
            # Convert ObjectId to string
            for threat in threats:
                threat['_id'] = str(threat['_id'])
            
            return threats
        except Exception as e:
            logger.error(f"Error getting threats: {e}")
            return []
    
    def get_threat_by_id(self, threat_id):
        """Get a threat by ID"""
        from bson import ObjectId
        
        if not self.mongo.is_connected():
            return None
        
        collection = self.mongo.get_collection('threats')
        if collection is None:
            return None
        
        try:
            threat = collection.find_one({'_id': ObjectId(threat_id)})
            if threat:
                threat['_id'] = str(threat['_id'])
            return threat
        except Exception as e:
            logger.error(f"Error getting threat by ID: {e}")
            return None
    
    def get_statistics(self):
        """Get threat statistics"""
        if not self.mongo.is_connected():
            return self._get_empty_statistics()
        
        collection = self.mongo.get_collection('threats')
        if collection is None:
            return self._get_empty_statistics()
        
        try:
            # Total threats
            total = collection.count_documents({})
            
            # Suspicious events (non-normal)
            suspicious = collection.count_documents({
                'threat_type': {'$ne': 'Normal Activity'}
            })
            
            # Threat type breakdown
            threat_types = list(collection.aggregate([
                {'$group': {
                    '_id': '$threat_type',
                    'count': {'$sum': 1}
                }},
                {'$sort': {'count': -1}}
            ]))
            
            threat_type_dict = {}
            for item in threat_types:
                if item['_id']:
                    threat_type_dict[item['_id']] = item['count']
            
            # Severity breakdown
            severity = list(collection.aggregate([
                {'$group': {
                    '_id': '$severity',
                    'count': {'$sum': 1}
                }},
                {'$sort': {'count': -1}}
            ]))
            
            severity_dict = {}
            for item in severity:
                if item['_id']:
                    severity_dict[item['_id']] = item['count']
            
            # Recent threats (last 5)
            recent = self.get_threats(limit=5)
            
            return {
                'total_logs_analyzed': total,
                'suspicious_events': suspicious,
                'threat_types': threat_type_dict,
                'severity_breakdown': severity_dict,
                'recent_threats': recent
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return self._get_empty_statistics()
    
    def _get_empty_statistics(self):
        """Return empty statistics"""
        return {
            'total_logs_analyzed': 0,
            'suspicious_events': 0,
            'threat_types': {},
            'severity_breakdown': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
            'recent_threats': []
        }

class UserRepository:
    """Repository for user operations"""
    
    def __init__(self):
        self.mongo = MongoDB()
    
    def create_user(self, username, email, password_hash):
        """Create a new user"""
        if not self.mongo.is_connected():
            return None
        
        collection = self.mongo.get_collection('users')
        if collection is None:
            return None
        
        user = {
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'created_at': datetime.now().isoformat(),
            'is_active': True
        }
        
        try:
            result = collection.insert_one(user)
            user['_id'] = str(result.inserted_id)
            return user
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return None
    
    def get_user_by_username(self, username):
        """Get user by username"""
        if not self.mongo.is_connected():
            return None
        
        collection = self.mongo.get_collection('users')
        if collection is None:
            return None
        
        try:
            user = collection.find_one({'username': username})
            if user:
                user['_id'] = str(user['_id'])
            return user
        except Exception as e:
            logger.error(f"Error getting user: {e}")
            return None
    
    def get_user_by_email(self, email):
        """Get user by email"""
        if not self.mongo.is_connected():
            return None
        
        collection = self.mongo.get_collection('users')
        if collection is None:
            return None
        
        try:
            user = collection.find_one({'email': email})
            if user:
                user['_id'] = str(user['_id'])
            return user
        except Exception as e:
            logger.error(f"Error getting user: {e}")
            return None
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from config import Config
import logging

logger = logging.getLogger(__name__)

class MongoDB:
    """MongoDB connection manager"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MongoDB, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.client = None
        self.db = None
        self._connect()
    
    def _connect(self):
        """Establish MongoDB connection"""
        try:
            self.client = MongoClient(
                Config.MONGO_URI,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000
            )
            # Test connection
            self.client.admin.command('ping')
            self.db = self.client[Config.MONGO_DB_NAME]
            self._ensure_indexes()
            logger.info("MongoDB connected successfully")
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.error(f"MongoDB connection failed: {e}")
            self.client = None
            self.db = None
    
    def connect(self):
        """Re-establish connection if needed"""
        if self.db is None:
            self._connect()
        return self.db is not None
    
    def _ensure_indexes(self):
        """Create necessary indexes"""
        if self.db is None:
            return
        
        try:
            # Threats collection indexes
            threats = self.db.threats
            threats.create_index('timestamp')
            threats.create_index('source_ip')
            threats.create_index('threat_type')
            threats.create_index('severity')
            
            # Users collection indexes
            users = self.db.users
            users.create_index('username', unique=True)
            users.create_index('email', unique=True)
        except Exception as e:
            logger.warning(f"Error creating indexes: {e}")
    
    def get_collection(self, name):
        """Get a collection by name"""
        if self.db is None:
            self.connect()
        return self.db[name] if self.db is not None else None
    
    def is_connected(self):
        """Check if MongoDB is connected"""
        return self.db is not None
    
    def close(self):
        """Close the MongoDB connection"""
        if self.client:
            self.client.close()
            self.client = None
            self.db = None
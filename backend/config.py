import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # AI Configuration
    AI_PROVIDER = os.getenv('AI_PROVIDER', 'ollama')
    
    # OpenAI Configuration
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-3.5-turbo')
    OPENAI_MAX_TOKENS = int(os.getenv('OPENAI_MAX_TOKENS', 500))
    OPENAI_TEMPERATURE = float(os.getenv('OPENAI_TEMPERATURE', 0.3))
    
    # Ollama Configuration
    OLLAMA_URL = os.getenv('OLLAMA_URL', 'http://localhost:11434')
    OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'llama3.2')
    
    # MongoDB Configuration
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DB_NAME = os.getenv('MONGO_DB_NAME', 'log_analyzer')
    
    # Security Detection Configuration
    BRUTE_FORCE_THRESHOLD = int(os.getenv('BRUTE_FORCE_THRESHOLD', 5))
    BRUTE_FORCE_WINDOW_MINUTES = int(os.getenv('BRUTE_FORCE_WINDOW_MINUTES', 5))
    PORT_SCAN_THRESHOLD = int(os.getenv('PORT_SCAN_THRESHOLD', 5))
    
    # JWT Configuration
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', 24))
    
    # CORS Configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000').split(',')
    
    # File Upload
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
    
    # Flask
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
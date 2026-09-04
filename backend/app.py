from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from config import Config
from routes.auth_routes import auth_bp
from routes.log_routes import log_bp
from routes.threat_routes import threat_bp
from routes.statistics_routes import stats_bp
from database.mongo_db import MongoDB
import os

app = Flask(__name__)
app.config.from_object(Config)

# Initialize CORS
CORS(app, origins=Config.CORS_ORIGINS)

# Initialize JWT
jwt = JWTManager(app)

# Initialize MongoDB
mongo = MongoDB()

@app.before_request
def before_request():
    """Ensure MongoDB connection is established before each request"""
    if mongo.db is None:
        mongo.connect()

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'mongodb': 'connected' if mongo.db else 'disconnected',
        'ai_provider': Config.AI_PROVIDER
    })

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(log_bp, url_prefix='/api')
app.register_blueprint(threat_bp, url_prefix='/api/threats')
app.register_blueprint(stats_bp, url_prefix='/api/stats')

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(debug=Config.FLASK_DEBUG, host='0.0.0.0', port=port)
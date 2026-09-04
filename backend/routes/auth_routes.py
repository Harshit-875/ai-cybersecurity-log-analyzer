from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from database.repositories import UserRepository
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from datetime import timedelta
import re
import logging

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)
user_repo = UserRepository()

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    # Validate input
    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not username or not email or not password:
        return jsonify({'error': 'Username, email, and password are required'}), 400
    
    # Validate username
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return jsonify({'error': 'Username must be 3-20 characters and contain only letters, numbers, and underscores'}), 400
    
    # Validate email
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'error': 'Invalid email address'}), 400
    
    # Validate password
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    # Check if user exists
    if user_repo.get_user_by_username(username):
        return jsonify({'error': 'Username already exists'}), 400
    
    if user_repo.get_user_by_email(email):
        return jsonify({'error': 'Email already registered'}), 400
    
    # Create user
    password_hash = generate_password_hash(password)
    user = user_repo.create_user(username, email, password_hash)
    
    if not user:
        return jsonify({'error': 'Failed to create user'}), 500
    
    return jsonify({
        'message': 'User registered successfully',
        'username': username,
        'email': email
    }), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    """Login user and return JWT token"""
    data = request.get_json()
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    # Get user
    user = user_repo.get_user_by_username(username)
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check password
    if not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Create JWT token
    access_token = create_access_token(
        identity=username,
        expires_delta=timedelta(hours=Config.JWT_EXPIRATION_HOURS)
    )
    
    return jsonify({
        'access_token': access_token,
        'username': username,
        'message': 'Login successful'
    }), 200

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user info"""
    username = get_jwt_identity()
    user = user_repo.get_user_by_username(username)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'username': user['username'],
        'email': user['email'],
        'created_at': user.get('created_at')
    }), 200

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user (client-side token discard)"""
    return jsonify({'message': 'Logout successful'}), 200
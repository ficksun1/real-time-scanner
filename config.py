import os
from datetime import timedelta
import secrets
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration for MySQL
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME', 'network_scanner'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'auth_plugin': 'mysql_native_password'
}

# Session settings
SESSION_EXPIRATION = timedelta(days=1)

# Cookie settings
COOKIE_NAME = "session_id"
COOKIE_EXPIRATION = 30  # days

# Secret key for JWT
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Make sure SECRET_KEY is properly exported
__all__ = ['DB_CONFIG', 'SECRET_KEY', 'TOKEN_EXPIRATION', 'COOKIE_NAME', 'COOKIE_EXPIRATION']


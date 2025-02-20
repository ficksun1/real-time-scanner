import mysql.connector
import hashlib
import jwt
from datetime import datetime, timedelta
from config import DB_CONFIG, SECRET_KEY

class DatabaseManager:
    def __init__(self):
        self.init_database()

    def init_database(self):
        """Initialize database and tables"""
        try:
            conn = mysql.connector.connect(
                host=DB_CONFIG['host'],
                user=DB_CONFIG['user'],
                password=DB_CONFIG['password']
            )
            cursor = conn.cursor()
            
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
            conn.close()

            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.commit()
            conn.close()

        except Exception as e:
            print(f"Database initialization error: {str(e)}")

    def verify_user(self, username: str, password: str) -> dict:
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor(dictionary=True)

            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            cursor.execute(
                "SELECT * FROM users WHERE username = %s AND password = %s",
                (username, hashed_password)
            )
            
            user = cursor.fetchone()
            conn.close()
            return user

        except Exception as e:
            print(f"Error verifying user: {str(e)}")
            return None

    def create_user(self, username: str, password: str, email: str) -> bool:
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor()

            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            cursor.execute(
                "INSERT INTO users (username, password, email) VALUES (%s, %s, %s)",
                (username, hashed_password, email)
            )

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            print(f"Error creating user: {str(e)}")
            return False

class AuthManager:
    def __init__(self):
        self.db = DatabaseManager()

    def create_token(self, user_id: int) -> str:
        payload = {
            'user_id': user_id,
            'exp': datetime.now() + timedelta(days=1)
        }
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    def verify_token(self, token: str) -> dict:
        try:
            return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except:
            return None 
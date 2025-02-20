import mysql.connector
import bcrypt
import jwt
from datetime import datetime, timedelta
from config import DB_CONFIG, SECRET_KEY

class DatabaseManager:
    def __init__(self):
        self.db_config = DB_CONFIG
        self.init_db()

    def get_connection(self):
        """Create and return a database connection"""
        return mysql.connector.connect(**self.db_config)

    def init_db(self):
        """Initialize the database with required tables"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Drop existing packet_data table if exists
            cursor.execute('DROP TABLE IF EXISTS packet_data')
            
            # Create packet_data table with correct columns
            cursor.execute('''
                CREATE TABLE packet_data (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(255) NOT NULL,
                    scan_type VARCHAR(50) NOT NULL,
                    status VARCHAR(50),
                    hostname VARCHAR(255),
                    ports TEXT,
                    services TEXT,
                    os_info VARCHAR(255),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Database initialization error: {str(e)}")

    def create_user(self, username, password, email):
        """Create a new user"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Hash the password
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            cursor.execute('INSERT INTO users (username, password, email) VALUES (%s, %s, %s)',
                         (username, hashed, email))
            
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except mysql.connector.Error as e:
            print(f"Error creating user: {str(e)}")
            return False

    def verify_user(self, username, password):
        """Verify user credentials"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute('SELECT id, password FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            
            cursor.close()
            conn.close()
            
            if result and bcrypt.checkpw(password.encode('utf-8'), result['password'].encode('utf-8')):
                return {'id': result['id'], 'username': username}
            
            return None
        except Exception as e:
            print(f"Error verifying user: {str(e)}")
            return None

    def save_scan_result(self, user_id, target, scan_type, host_info):
        """Save scan results to database"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO packet_data 
                (user_id, ip_address, scan_type, status, hostname, ports, services, os_info)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                user_id,
                host_info['IP Address'],
                scan_type,
                host_info['Status'],
                host_info['Hostname'],
                ','.join(map(str, host_info['Ports'])),
                ','.join(host_info['Services']),
                host_info['OS']
            ))
            
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            print(f"Error saving scan result: {str(e)}")
            return False

class AuthManager:
    def __init__(self):
        self.db = DatabaseManager()

    def login_user(self, username, password):
        """Login user and return user data"""
        return self.db.verify_user(username, password)

    def register_user(self, username, password, email):
        """Register a new user"""
        return self.db.create_user(username, password, email)
        
    def create_token(self, user_id):
        """Create JWT token for user"""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(days=1)
        }
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    def verify_token(self, token):
        """Verify JWT token"""
        try:
            return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except:
            return None 
import hashlib
import jwt
from datetime import datetime, timedelta
import MySQLdb

class AuthManager:
    def __init__(self, db_config, secret_key, token_expires):
        self.db_config = db_config
        self.secret_key = secret_key
        self.token_expires = token_expires
        self.roles = {
            'admin': ['view_dashboard', 'view_alerts', 'manage_rules', 'manage_config', 'manage_users'],
            'user': ['view_dashboard', 'view_alerts']
        }

    def init_db(self):
        """Initialize database with users and roles tables"""
        conn = MySQLdb.connect(**self.db_config)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(20) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create default admin user if not exists
        admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
        cursor.execute("""
            INSERT IGNORE INTO users (username, password, role)
            VALUES ('admin', %s, 'admin')
        """, (admin_password,))
        
        conn.commit()
        cursor.close()
        conn.close()

    def login(self, username, password):
        """Handle user login"""
        conn = MySQLdb.connect(**self.db_config)
        cursor = conn.cursor()
        
        # Hash password
        password = hashlib.sha256(password.encode()).hexdigest()
        
        # Check credentials
        cursor.execute("SELECT username, role FROM users WHERE username = %s AND password = %s",
                      (username, password))
        user = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if user:
            token = jwt.encode({
                'username': user[0],
                'role': user[1],
                'exp': datetime.utcnow() + self.token_expires
            }, self.secret_key)
            
            return {'token': token, 'role': user[1]}
        
        return None

    def verify_token(self, token):
        """Verify JWT token and return user info"""
        try:
            data = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return data
        except:
            return None

    def check_permission(self, role, required_permission):
        """Check if role has required permission"""
        return required_permission in self.roles.get(role, []) 
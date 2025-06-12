import hashlib
import MySQLdb

class UserManager:
    def __init__(self, db_config):
        self.db_config = db_config

    def get_users(self):
        """Get all users"""
        conn = MySQLdb.connect(**self.db_config)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, role, created_at FROM users")
        users = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return [{
            'id': user[0],
            'username': user[1],
            'role': user[2],
            'created_at': user[3].strftime('%Y-%m-%d %H:%M:%S')
        } for user in users]

    def create_user(self, username, password, role):
        """Create new user"""
        conn = MySQLdb.connect(**self.db_config)
        cursor = conn.cursor()
        
        try:
            password = hashlib.sha256(password.encode()).hexdigest()
            cursor.execute("""
                INSERT INTO users (username, password, role)
                VALUES (%s, %s, %s)
            """, (username, password, role))
            
            conn.commit()
            return True
            
        except MySQLdb.IntegrityError:
            return False
        finally:
            cursor.close()
            conn.close() 
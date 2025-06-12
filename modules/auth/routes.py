from flask import jsonify, request
from functools import wraps

def init_routes(app, auth_manager):
    def has_permission(required_permission):
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                token = None
                if 'Authorization' in request.headers:
                    token = request.headers['Authorization'].split(" ")[1]
                
                if not token:
                    return jsonify({'message': 'Token is missing!'}), 401
                
                user_data = auth_manager.verify_token(token)
                if not user_data:
                    return jsonify({'message': 'Token is invalid!'}), 401
                
                if not auth_manager.check_permission(user_data['role'], required_permission):
                    return jsonify({'message': 'Permission denied!'}), 403
                    
                return f(user_data['username'], *args, **kwargs)
            return decorated
        return decorator

    @app.route('/auth/login', methods=['POST', 'OPTIONS'])
    def login():
        if request.method == 'OPTIONS':
            return '', 200
            
        auth = request.get_json()
        if not auth or not auth.get('username') or not auth.get('password'):
            return jsonify({'message': 'Could not verify'}), 401

        result = auth_manager.login(auth.get('username'), auth.get('password'))
        if result:
            return jsonify(result)
        
        return jsonify({'message': 'Invalid credentials!'}), 401

    return has_permission 
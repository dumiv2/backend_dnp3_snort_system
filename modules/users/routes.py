from flask import jsonify, request

def init_routes(app, user_manager, has_permission):
    @app.route('/users', methods=['GET'])
    @has_permission('manage_users')
    def get_users(current_user):
        users = user_manager.get_users()
        return jsonify(users)

    @app.route('/users', methods=['POST'])
    @has_permission('manage_users')
    def create_user(current_user):
        data = request.get_json()
        if not data or not data.get('username') or not data.get('password') or not data.get('role'):
            return jsonify({'message': 'Missing required fields'}), 400
            
        if data.get('role') not in ['admin', 'user']:
            return jsonify({'message': 'Invalid role'}), 400
        
        if user_manager.create_user(data.get('username'), data.get('password'), data.get('role')):
            return jsonify({'message': 'User created successfully'}), 201
        else:
            return jsonify({'message': 'Username already exists'}), 400 
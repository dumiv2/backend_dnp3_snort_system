from flask import jsonify, request

def init_routes(app, config_manager, has_permission):
    @app.route("/config/vars", methods=["GET"])
    @has_permission('manage_config')
    def get_snort_vars(current_user):
        return jsonify(config_manager.get_vars())

    @app.route("/config/vars/<varname>", methods=["PUT"])
    @has_permission('manage_config')
    def update_snort_var(current_user, varname):
        new_value = request.json.get("value")
        if not new_value:
            return jsonify({"error": "Missing value"}), 400
        config_manager.update_var(varname, new_value)
        return jsonify({"message": f"{varname} updated successfully", "new_value": new_value})

    @app.route("/config/backup", methods=["POST"])
    @has_permission('manage_config')
    def backup_config(current_user):
        backup_name = config_manager.backup()
        return jsonify({"message": "Backup created", "backup": backup_name})

    @app.route("/config/restore", methods=["POST"])
    @has_permission('manage_config')
    def restore_config(current_user):
        data = request.get_json()
        backup_name = data.get("backup")
        if not backup_name or not config_manager.restore(backup_name):
            return jsonify({"error": "Backup file not found"}), 404
        return jsonify({"message": "Restore completed successfully"})

    @app.route("/config/backups", methods=["GET"])
    @has_permission('manage_config')
    def list_backups(current_user):
        files = config_manager.list_backups()
        return jsonify({"backups": files}), 200 
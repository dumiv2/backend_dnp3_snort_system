from flask import jsonify

def init_routes(app, snort_manager, has_permission):
    @app.route("/snort/status", methods=["GET"])
    def get_snort_status():
        result = snort_manager.check_status()
        if result.get("status") == "error":
            return jsonify(result), 500
        return jsonify(result)

    @app.route("/snort/start", methods=["POST"])
    @has_permission('manage_config')
    def start_snort(current_user):
        result = snort_manager.start_snort()
        if "error" in result:
            return jsonify(result), 500
        return jsonify(result) 
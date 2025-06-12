from flask import jsonify, request

def init_routes(app, event_manager, has_permission):
    @app.route("/events", methods=["GET"])
    @has_permission('view_alerts')
    def get_events(current_user):
        src_ip = request.args.get("src_ip")
        dst_ip = request.args.get("dst_ip")
        events = event_manager.get_events(src_ip, dst_ip)
        return jsonify(events)

    @app.route("/stats", methods=["GET"])
    def get_stats():
        stats = event_manager.get_stats()
        return jsonify(stats) 
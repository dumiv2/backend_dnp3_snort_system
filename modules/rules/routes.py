from flask import jsonify, request
import subprocess
import traceback

from .manager import RULES_FILE_PATH

def init_routes(app, rule_manager, has_permission):
    @app.route('/rules', methods=['GET'])
    @has_permission('manage_rules')
    def get_rules(current_user):
        try:
            rules = rule_manager.parse_rules_from_file()
            return jsonify(rules), 200
        except Exception as e:
            return jsonify({"error": f"Failed to retrieve rules: {str(e)}"}), 500

    @app.route('/rules/<int:line_number>', methods=['GET'])
    @has_permission('manage_rules')
    def get_rule_by_line(current_user, line_number):
        try:
            rules = rule_manager.parse_rules_from_file()
            rule = next((r for r in rules if r['id'] == line_number), None)
            if rule:
                return jsonify(rule), 200
            else:
                return jsonify({"error": f"Rule not found at line {line_number}"}), 404
        except Exception as e:
            return jsonify({"error": f"Failed to retrieve rule: {str(e)}"}), 500

    @app.route('/rules', methods=['POST'])
    @has_permission('manage_rules')
    def add_rule_to_file(current_user):
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing request body"}), 400
        required_fields = ['action', 'protocol', 'msg', 'sid']
        missing_fields = [f for f in required_fields if f not in data or not data[f]]
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {missing_fields}"}), 400
        try:
            sid = int(data['sid'])
            rev = int(data.get('rev', '1'))
        except ValueError:
            return jsonify({"error": "'sid' and 'rev' (if provided) must be integers"}), 400
        rule_dict = {
            'action': data['action'],
            'protocol': data['protocol'],
            'source_ip': data.get('source_ip', 'any'),
            'source_port': data.get('source_port', 'any'),
            'direction': data.get('direction', '->'),
            'destination_ip': data.get('destination_ip', 'any'),
            'destination_port': data.get('destination_port', 'any'),
        }
        options_list = []
        msg_val = data['msg']
        if not (msg_val.startswith('"') and msg_val.endswith('"')):
            msg_val = f'"{msg_val.replace('"', '\\"')}"'
        options_list.append(f"msg:{msg_val}")
        options_list.append(f"sid:{sid}")
        options_list.append(f"rev:{rev}")
        if 'classtype' in data and data['classtype']:
            options_list.append(f"classtype:{data['classtype']}")
        if 'metadata' in data and data['metadata']:
            options_list.append(f"metadata:{data['metadata']}")
        rule_dict['options'] = "; ".join(options_list) + ";"
        try:
            new_rule_str = rule_manager.format_rule_to_string(rule_dict)
        except ValueError as e:
            return jsonify({"error": f"Internal error formatting rule: {str(e)}"}), 500
        try:
            try:
                with open(RULES_FILE_PATH, 'r') as f:
                    lines = f.read().splitlines()
            except FileNotFoundError:
                lines = []
            lines.append(new_rule_str)
            rule_manager.write_rules_to_file(lines)
            new_line_number = len(lines)
            return jsonify({
                "message": "Rule added successfully",
                "id": new_line_number,
                "rule": new_rule_str
            }), 201
        except Exception as e:
            return jsonify({"error": f"Failed to write rule to file: {str(e)}"}), 500

    @app.route('/rules/<int:line_number>', methods=['PUT'])
    @has_permission('manage_rules')
    def update_rule_in_file(current_user, line_number):
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing request body"}), 400
        if line_number <= 0:
            return jsonify({"error": "Invalid line number"}), 400
        try:
            updated_rule_str = rule_manager.format_rule_to_string(data)
        except ValueError as e:
            return jsonify({"error": f"Invalid rule format: {str(e)}"}), 400
        try:
            try:
                with open(RULES_FILE_PATH, 'r') as f:
                    lines = f.read().splitlines()
            except FileNotFoundError:
                return jsonify({"error": f"Rules file not found, cannot update line {line_number}"}), 404
            if line_number > len(lines):
                return jsonify({"error": f"Line number {line_number} exceeds file length ({len(lines)})"}), 404
            lines[line_number - 1] = updated_rule_str
            rule_manager.write_rules_to_file(lines)
            return jsonify({"message": f"Rule at line {line_number} updated successfully", "rule": updated_rule_str}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to update rule: {str(e)}"}), 500

    @app.route('/rules/<int:line_number>', methods=['DELETE'])
    @has_permission('manage_rules')
    def delete_rule_from_file(current_user, line_number):
        if line_number <= 0:
            return jsonify({"error": "Invalid line number"}), 400
        try:
            try:
                with open(RULES_FILE_PATH, 'r') as f:
                    lines = f.read().splitlines()
            except FileNotFoundError:
                return jsonify({"error": "Rules file not found, cannot delete line"}), 404
            if line_number > len(lines):
                return jsonify({"error": f"Line number {line_number} exceeds file length ({len(lines)})"}), 404
            deleted_line = lines.pop(line_number - 1)
            rule_manager.write_rules_to_file(lines)
            return jsonify({"message": f"Rule at line {line_number} deleted successfully", "deleted_rule": deleted_line}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to delete rule: {str(e)}"}), 500

    @app.route('/rules/apply', methods=['POST'])
    @has_permission('manage_rules')
    def apply_rules_and_restart(current_user):
        try:
            pgrep_process = subprocess.run(["pgrep", "-f", "snort -c /etc/snort/snort.conf"], capture_output=True, text=True)
            snort_pids = pgrep_process.stdout.strip().split()
            if snort_pids:
                kill_cmd = ["sudo", "pkill", "-f", "snort -c /etc/snort/snort.conf -Q -i ens37:ens38 -A fast"]
                subprocess.run(kill_cmd, check=False, capture_output=True, text=True)
            start_cmd = ["sudo", "snort", "-c", "/etc/snort/snort.conf", "-Q", "-i", "ens37:ens38", "-A", "fast"]
            subprocess.Popen(start_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return jsonify({"message": "Rules applied and Snort restart initiated."}), 200
        except Exception as e:
            traceback.print_exc()
            return jsonify({"error": f"Failed during Snort restart process: {str(e)}"}), 500

    @app.route('/rules/reorder', methods=['POST'])
    @has_permission('manage_rules')
    def reorder_rules(current_user):
        data = request.get_json()
        if not data or 'rule_ids' not in data:
            return jsonify({"error": "Missing 'rule_ids' in request body"}), 400
        rule_ids = data['rule_ids']
        if not isinstance(rule_ids, list):
            return jsonify({"error": "'rule_ids' must be a list"}), 400
        try:
            with open(RULES_FILE_PATH, 'r') as f:
                lines = f.read().splitlines()
            rule_map = {i + 1: line for i, line in enumerate(lines) if line.strip() and not line.strip().startswith('#')}
            if not all(rule_id in rule_map for rule_id in rule_ids):
                return jsonify({"error": "One or more rule IDs are invalid"}), 400
            reordered_lines = [rule_map[rule_id] for rule_id in rule_ids]
            with open(RULES_FILE_PATH, 'w') as f:
                f.write("\n".join(reordered_lines) + "\n")
            return jsonify({"message": "Rules reordered successfully"}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to reorder rules: {str(e)}"}), 500 
import os
import re
import traceback

RULES_FILE_PATH = '/etc/snort/rules/local.rules'

RULE_PATTERN = re.compile(
    r'^\s*'                  # Optional leading whitespace
    r'(?P<action>\w+)'      # Action (e.g., alert, log, pass)
    r'\s+'
    r'(?P<protocol>\w+)'    # Protocol (e.g., tcp, udp, icmp)
    r'\s+'
    r'(?P<source_ip>[\w\./\$\!\,\[\]]+)'  # Source IP/var
    r'\s+'
    r'(?P<source_port>[\w\$\!\,\[\]:]+)' # Source Port/var
    r'\s+'
    r'(?P<direction>[-<>]+)' # Direction indicator
    r'\s+'
    r'(?P<destination_ip>[\w\./\$\!\,\[\]]+)' # Dest IP/var
    r'\s+'
    r'(?P<destination_port>[\w\$\!\,\[\]:]+)' # Dest Port/var
    r'\s*'
    r'(?:\((?P<options>.*)\))?' # Optional options in parentheses
    r'\s*$'                 # Optional trailing whitespace
)

class RuleManager:
    def __init__(self, rules_file=RULES_FILE_PATH):
        self.rules_file = rules_file

    def parse_rules_from_file(self):
        rules = []
        try:
            with open(self.rules_file, 'r') as f:
                for i, line in enumerate(f):
                    line_content = line.strip()
                    if not line_content or line_content.startswith('#'):
                        continue
                    match = RULE_PATTERN.match(line_content)
                    if match:
                        rule_data = match.groupdict()
                        rule_data['id'] = i + 1
                        rule_data['raw'] = line_content
                        rule_data['options'] = rule_data.get('options', '') or ''
                        rules.append(rule_data)
                    else:
                        rules.append({'id': i + 1, 'raw': line_content, 'error': 'parse_failed'})
        except FileNotFoundError:
            return []
        except Exception as e:
            traceback.print_exc()
            raise
        return rules

    def format_rule_to_string(self, rule_data):
        required = ['action', 'protocol', 'source_ip', 'source_port', 'direction', 'destination_ip', 'destination_port']
        if not all(k in rule_data for k in required):
            raise ValueError("Missing required fields to format rule")
        options_str = rule_data.get('options', '')
        if options_str:
            if options_str.count('(') != options_str.count(')'):
                raise ValueError("Rule options contain unbalanced parentheses")
            options_part = f" ({options_str})"
        else:
            options_part = ""
        return (
            f"{rule_data['action']} {rule_data['protocol']} {rule_data['source_ip']} {rule_data['source_port']} "
            f"{rule_data['direction']} {rule_data['destination_ip']} {rule_data['destination_port']}"
            f"{options_part}"
        ).strip()

    def write_rules_to_file(self, lines):
        with open(self.rules_file, 'w') as f:
            f.write("\n".join(lines) + "\n")

    # CRUD, reorder, apply methods sẽ được định nghĩa trong routes 
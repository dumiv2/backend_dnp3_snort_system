from datetime import datetime, timedelta
import os
import re
import subprocess
import tarfile
import traceback
from flask import Flask, request, jsonify
import MySQLdb
import tempfile
import shutil
from functools import wraps
import jwt
from datetime import datetime, timedelta
import hashlib
from flask_cors import CORS

# Import modules
from modules.auth import AuthManager, init_routes as init_auth_routes
from modules.users import UserManager, init_routes as init_user_routes
from modules.events import EventManager, init_routes as init_event_routes
from modules.snort import SnortManager, init_routes as init_snort_routes
from modules.rules import RuleManager, init_routes as init_rule_routes
from modules.config import ConfigManager, init_routes as init_config_routes

app = Flask(__name__)
# Cấu hình CORS chi tiết hơn
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

app.config['SECRET_KEY'] = 'your-secret-key-here'  # Thay đổi thành key bảo mật thực tế
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Database config
DB_CONFIG = {
    "host": "localhost",
    "user": "snort_user",
    "passwd": "your_password",
    "db": "snort_db",
    "charset": "utf8"
}

# Snort configuration paths
CONF_PATH = "/etc/snort/snort.conf"
CONFIG_FILES = [
    "/etc/snort/snort.conf",
    "/etc/snort/rules/local.rules"
]

# Initialize managers
auth_manager = AuthManager(DB_CONFIG, app.config['SECRET_KEY'], app.config['JWT_ACCESS_TOKEN_EXPIRES'])
user_manager = UserManager(DB_CONFIG)
event_manager = EventManager(DB_CONFIG)
snort_manager = SnortManager()
rule_manager = RuleManager()
config_manager = ConfigManager()

# Initialize routes
has_permission = init_auth_routes(app, auth_manager)
init_user_routes(app, user_manager, has_permission)
init_event_routes(app, event_manager, has_permission)
init_snort_routes(app, snort_manager, has_permission)
init_rule_routes(app, rule_manager, has_permission)
init_config_routes(app, config_manager, has_permission)

# Initialize database on startup
auth_manager.init_db()
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

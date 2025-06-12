import os
import re
import tarfile
import shutil
from datetime import datetime

CONF_PATH = "/etc/snort/snort.conf"
CONFIG_FILES = [
    "/etc/snort/snort.conf",
    "/etc/snort/rules/local.rules"
]
BACKUP_DIR = "/etc/snort/backup"

class ConfigManager:
    def __init__(self, conf_path=CONF_PATH, config_files=CONFIG_FILES, backup_dir=BACKUP_DIR):
        self.conf_path = conf_path
        self.config_files = config_files
        self.backup_dir = backup_dir

    def get_vars(self):
        variables = {}
        pattern = re.compile(r'^(ipvar|var)\s+(\w+)\s+(.*)$')
        with open(self.conf_path, "r") as f:
            for line in f:
                match = pattern.match(line.strip())
                if match:
                    _, name, value = match.groups()
                    variables[name] = value
        return variables

    def update_var(self, varname, new_value):
        updated = False
        pattern = re.compile(rf'^(ipvar|var)\s+{re.escape(varname)}\s+.*$')
        lines = []
        with open(self.conf_path, "r") as f:
            for line in f:
                if pattern.match(line):
                    lines.append(f"ipvar {varname} {new_value}\n")
                    updated = True
                else:
                    lines.append(line)
        if not updated:
            lines.append(f"ipvar {varname} {new_value}\n")
        with open(self.conf_path, "w") as f:
            f.writelines(lines)
        return True

    def backup(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"snort_backup_{timestamp}.tar.gz"
        backup_path = os.path.join(self.backup_dir, backup_name)
        with tarfile.open(backup_path, "w:gz") as tar:
            for file in self.config_files:
                if os.path.exists(file):
                    tar.add(file, arcname=file.lstrip("/"))
        return backup_name

    def restore(self, backup_name):
        backup_path = os.path.join(self.backup_dir, backup_name)
        if not os.path.exists(backup_path):
            return False
        with tarfile.open(backup_path, "r:gz") as tar:
            for member in tar.getmembers():
                target_path = os.path.join("/", member.name)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with tar.extractfile(member) as source_file, open(target_path, "wb") as dest_file:
                    shutil.copyfileobj(source_file, dest_file)
        return True

    def list_backups(self):
        if not os.path.exists(self.backup_dir):
            return []
        return sorted(os.listdir(self.backup_dir), reverse=True) 
import subprocess
import traceback
from datetime import datetime

class SnortManager:
    def __init__(self):
        self.snort_cmd = "snort -c /etc/snort/snort.conf"
        self.snort_args = "-Q -i ens37:ens38 -A fast"
        self.full_cmd = f"{self.snort_cmd} {self.snort_args}"

    def check_status(self):
        """Kiểm tra trạng thái của Snort"""
        try:
            pgrep_process = subprocess.run(
                ["pgrep", "-f", self.snort_cmd], 
                capture_output=True, 
                text=True
            )
            
            is_running = bool(pgrep_process.stdout.strip())
            
            return {
                "status": "running" if is_running else "stopped",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

    def stop_snort(self):
        """Dừng tất cả process Snort"""
        try:
            pgrep_process = subprocess.run(
                ["pgrep", "-f", self.snort_cmd], 
                capture_output=True, 
                text=True
            )
            snort_pids = pgrep_process.stdout.strip().split()

            if snort_pids:
                print(f"Attempting to kill existing Snort processes with PIDs: {snort_pids}")
                kill_cmd = ["sudo", "pkill", "-f", self.full_cmd]
                kill_process = subprocess.run(kill_cmd, check=False, capture_output=True, text=True)
                print(f"Kill stdout: {kill_process.stdout}")
                print(f"Kill stderr: {kill_process.stderr}")
                return True
            return False
        except Exception as e:
            print(f"Error stopping Snort: {str(e)}")
            return False

    def start_snort(self):
        """Khởi động Snort"""
        try:
            # Dừng các process hiện tại trước
            self.stop_snort()

            # Khởi động Snort
            start_cmd = ["sudo", "snort", "-c", "/etc/snort/snort.conf", "-Q", "-i", "ens37:ens38", "-A", "fast"]
            print(f"Starting Snort with command: {' '.join(start_cmd)}")
            subprocess.Popen(
                start_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            return {
                "message": "Snort started successfully",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        except Exception as e:
            traceback.print_exc()
            return {
                "error": f"Failed to start Snort: {str(e)}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            } 
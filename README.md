# LOG-MONITOR-USING-LINUX
#!/usr/bin/env python3

import os
import time
import subprocess
from datetime import datetime

LOG_FILES = [
    '/var/log/auth.log',
    '/var/log/syslog',
    '/var/log/kern.log',
    '/var/log/apt/history.log',
    '/var/log/dpkg.log',
    '/var/log/faillog',
    '/var/log/ufw.log',        # 👈 Added for ping/Nmap scan detection
    '/var/log/iptables.log',   # 👈 Optional
    '/var/log/messages'        # 👈 Optional on some systems
]

OUTPUT_FILE = 'all_logs_combined.txt'

# Sound files (make sure these exist or adjust paths)
SUCCESS_SOUND = "login_success.wav"    # 🔊 successful login
FAIL_SOUND = "login_fail.wav"          # 🔊 failed login
SCAN_ALERT_SOUND = "network_alert.wav" # 🔊 scan or ping alert

# Keywords to look for
KEYWORDS = [
    "Failed password",
    "Accepted password",
    "authentication failure",
    "sudo",
    "apt install",
    "upgrade",
    "reinstall",
    "remove",
    "session opened",
    "session closed",
    "useradd",
    "passwd",
    "reboot",
    "shutdown",
    "Remote",
    "local",
    "connection",
    "login",
    "ICMP",
    "PROTO=ICMP",
    "nmap",
    "SYN",
    "Scan"
]

# Custom alert messages
COMMAND_ALERTS = {
    "Failed password": "❌ Failed SSH Login Attempt",
    "Accepted password": "✅ Successful SSH Login",
    "authentication failure": "🔐 Authentication Failure",
    "sudo": "⚠️ Sudo Command Executed",
    "apt install": "📦 Remote Install Command",
    "upgrade": "⬆️ System Upgrade",
    "reinstall": "♻️ Package Reinstall",
    "remove": "🧹 Package Removal",
    "session opened": "🔓 Session Opened",
    "session closed": "🔐 Session Closed",
    "useradd": "👤 New User Added",
    "passwd": "🔑 Password Modified",
    "reboot": "🔁 Reboot Triggered",
    "shutdown": "⏻ Shutdown Initiated",
    "Remote": "🌐 Remote Access Activity",
    "local": "🖥️ Local User Activity",
    "connection": "🔌 Network Connection Event",
    "login": "🔑 Login Attempt",
    "ICMP": "📡 Ping Detected (ICMP)",
    "PROTO=ICMP": "📡 Incoming Ping Attempt",
    "nmap": "🧪 Nmap Scan Detected!",
    "SYN": "🌐 Possible Port Scan (TCP SYN)",
    "Scan": "🔍 Network Scanning Activity Detected"
}

def tail(filepath):
    try:
        with open(filepath, 'r') as f:
            f.seek(0, os.SEEK_END)
            return f.tell()
    except FileNotFoundError:
        return 0

def is_text_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            return b'\x00' not in f.read(1024)
    except:
        return False

def send_alert(title, message, sound=None):
    try:
        subprocess.run(['notify-send', title, message])
        if sound and os.path.exists(sound):
            subprocess.run(['aplay', sound])
        elif sound:
            subprocess.run(['espeak', title])
    except Exception as e:
        print(f"[ERROR] Alert failed: {e}")

def enable_icmp_logging():
    try:
        subprocess.run(['sudo', 'iptables', '-C', 'INPUT', '-p', 'icmp', '--icmp-type', 'echo-request', '-j', 'LOG'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'icmp', '--icmp-type', 'echo-request', '-j', 'LOG'])
        print("✅ ICMP ping logging rule added via iptables.")

def monitor_logs():
    print("🔍 Monitoring logs for ALL event types including sudo, ping and scan events...\n")
    enable_icmp_logging()
    file_positions = {log: tail(log) for log in LOG_FILES}

    try:
        while True:
            for log in LOG_FILES:
                if not is_text_file(log):
                    continue

                try:
                    with open(log, 'r') as f:
                        f.seek(file_positions[log])
                        lines = f.readlines()
                        file_positions[log] = f.tell()

                    for line in lines:
                        lower_line = line.lower()
                        for keyword in KEYWORDS:
                            if keyword.lower() in lower_line:
                                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                formatted_line = f"[{timestamp}] 📄 {os.path.basename(log)}: {line.strip()}"
                                print(formatted_line)

                                with open(OUTPUT_FILE, 'a') as out:
                                    out.write(formatted_line + '\n')

                                alert_title = COMMAND_ALERTS.get(keyword, "🔔 System Event")
                                alert_body = line.strip()

                                if "accepted password" in lower_line:
                                    send_alert(alert_title, alert_body, sound=SUCCESS_SOUND)
                                elif "failed password" in lower_line:
                                    send_alert(alert_title, alert_body, sound=FAIL_SOUND)
                                elif any(net in lower_line for net in ["icmp", "proto=icmp", "nmap", "syn", "scan"]):
                                    try:
                                        send_alert(alert_title, alert_body, sound=SCAN_ALERT_SOUND)
                                    except Exception as e:
                                        print(f"[ERROR] Ping/Nmap alert failed: {e}")
                                else:
                                    send_alert(alert_title, alert_body)

                                break

                except FileNotFoundError:
                    continue

            time.sleep(2)

    except KeyboardInterrupt:
        print("🛑 Monitoring stopped by user.")

if __name__ == '__main__':
    monitor_logs()

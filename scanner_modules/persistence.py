import platform
import subprocess
import os

def check_startup_entries():
    os_type = platform.system()
    entries = []

    if os_type == "Windows":
        keys = [
            r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        ]
        for key in keys:
            try:
                output = subprocess.check_output(f'reg query "{key}"', shell=True)
                lines = [line.strip() for line in output.decode().splitlines() if line.strip()]
                if lines:
                    entries.append(f"{key} entries:\n" + "\n".join(lines))
                else:
                    entries.append(f"{key}: <no entries>")
            except:
                entries.append(f"{key}: <no entries>")

    elif os_type == "Linux":
        # Clean crontab
        try:
            output = subprocess.check_output("crontab -l", shell=True, stderr=subprocess.DEVNULL).decode()
            clean_lines = [line for line in output.splitlines() if line.strip() and not line.strip().startswith('#')]
            if clean_lines:
                entries.append("Crontab:\n" + "\n".join(clean_lines))
        except:
            pass  # no crontab, silently skip

        # Filter only .service files (not folders)
        systemd_dir = "/etc/systemd/system/"
        if os.path.exists(systemd_dir):
            files = [f for f in os.listdir(systemd_dir) if f.endswith(".service")]
            if files:
                entries.append("Systemd services:\n" + "\n".join(files))

        # Check ~/.config/autostart/
        autostart_path = os.path.expanduser("~/.config/autostart/")
        if os.path.exists(autostart_path):
            files = [f for f in os.listdir(autostart_path) if f.endswith(".desktop")]
            if files:
                entries.append("Autostart entries:\n" + "\n".join(files))

        # Look for suspicious .bashrc lines
        bashrc_path = os.path.expanduser("~/.bashrc")
        suspicious_keywords = ["curl", "wget", "nc", "bash", "python", "sh", "eval", "base64"]
        if os.path.exists(bashrc_path):
            with open(bashrc_path, 'r') as f:
                lines = f.readlines()
            susp_lines = [line.strip() for line in lines if any(k in line for k in suspicious_keywords)]
            if susp_lines:
                entries.append("Suspicious .bashrc entries:\n" + "\n".join(susp_lines))

    return "\n\n".join(entries) if entries else "No persistence mechanisms found."

# Example call
print("=== PERSISTENCE ===")
print(check_startup_entries())

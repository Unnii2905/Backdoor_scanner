import platform
import socket
import subprocess
import json
import psutil
import os

def is_suspicious(item):
    keywords = ['keylog', 'backdoor', 'rat', 'meterpreter', 'malware',
                'shell', 'cmd.exe', 'powershell.exe', '.vbs', '.bat', '.scr', 'autorun', 'hacker']
    return any(k in item.lower() for k in keywords)

def is_benign_process(name):
    benign = ['system', 'explorer.exe', 'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe',
              'services.exe', 'fontdrvhost.exe', 'dwm.exe', 'taskhostw.exe', 'OneDrive.exe']
    return any(name.lower() == b.lower() for b in benign)

def scan_processes():
    sus = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name']
            if name and is_suspicious(name) and not is_benign_process(name):
                sus.append({'pid': proc.info['pid'], 'name': name})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sus

def scan_persistence():
    sus_entries = []
    if platform.system() == 'Windows':
        try:
            import winreg
            run_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
            ]
            for hive, path in run_keys:
                try:
                    key = winreg.OpenKey(hive, path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            if is_suspicious(value):
                                location = f"{'HKLM' if hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}\\{path}"
                                sus_entries.append(f"{location} --> {value}")
                            i += 1
                        except OSError:
                            break
                except FileNotFoundError:
                    continue
        except ImportError:
            pass
    else:
        try:
            crontab = subprocess.getoutput('crontab -l')
            for line in crontab.splitlines():
                if is_suspicious(line):
                    sus_entries.append(f"crontab --> {line}")
        except Exception:
            pass

        systemd_dirs = ['/etc/systemd/system/', os.path.expanduser('~/.config/systemd/user/')]
        for path in systemd_dirs:
            if os.path.exists(path):
                for file in os.listdir(path):
                    full = os.path.join(path, file)
                    if os.path.isfile(full) and is_suspicious(file):
                        sus_entries.append(f"systemd --> {full}")
    return sus_entries

def scan_network():
    result = []
    for c in psutil.net_connections():
        if c.status == 'ESTABLISHED' and c.raddr:
            if c.raddr.ip != '127.0.0.1' and c.raddr.ip != c.laddr.ip:
                result.append({
                    'laddr': f"{c.laddr.ip}:{c.laddr.port}",
                    'raddr': f"{c.raddr.ip}:{c.raddr.port}",
                    'pid': c.pid
                })
    return result

def handle_command(cmd):
    if cmd == 'scan_processes':
        return {'processes': scan_processes()}
    elif cmd == 'scan_persistence':
        return {'persistence': scan_persistence()}
    elif cmd == 'scan_network':
        return {'network': scan_network()}
    elif cmd == 'scan_all':
        return {
            'processes': scan_processes(),
            'persistence': scan_persistence(),
            'network': scan_network()
        }
    else:
        return {'error': 'Invalid command'}

def start_server(host='0.0.0.0', port=9999):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print("=" * 55)
        print("[+] Remote Agent is now running")
        print(f"[+] Listening for connections on {host}:{port}")
        print("=" * 55)
        conn, addr = s.accept()
        with conn:
            while True:
                cmd = conn.recv(1024).decode().strip()
                if not cmd:
                    break
                result = handle_command(cmd)
                conn.sendall(json.dumps(result).encode())

start_server()

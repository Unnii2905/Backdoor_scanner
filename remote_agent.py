import os
import platform
import socket
import subprocess
import json
import psutil

def is_suspicious(item):
    keywords = ['temp', 'appdata', 'roaming', 'startup', 'system32',
                'keylog', 'backdoor', 'rat', 'meterpreter', 'malware',
                'shell', 'cmd.exe', 'powershell.exe', '.vbs', '.bat', '.exe', 'autorun']
    return any(k in item.lower() for k in keywords)

def scan_processes():
    sus = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name']
            if name and is_suspicious(name):
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
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            ]
            for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                for path in run_keys:
                    try:
                        key = winreg.OpenKey(hive, path)
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                if is_suspicious(value):
                                    sus_entries.append({'name': name, 'command': value})
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
                    sus_entries.append({'type': 'crontab', 'entry': line})
        except Exception:
            pass

        systemd_dirs = [
            '/etc/systemd/system/',
            os.path.expanduser('~/.config/systemd/user/')
        ]
        for path in systemd_dirs:
            if os.path.exists(path):
                for file in os.listdir(path):
                    full = os.path.join(path, file)
                    if os.path.isfile(full) and is_suspicious(file):
                        sus_entries.append({'type': 'systemd', 'file': full})

    return sus_entries

def scan_network():
    conns = psutil.net_connections()
    result = []
    for c in conns:
        if c.status == 'ESTABLISHED' and c.raddr:
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
        print(f"[+] Listening on {host}:{port}")
        conn, addr = s.accept()
        with conn:
            print(f"[+] Connection from {addr}")
            while True:
                cmd = conn.recv(1024).decode().strip()
                if not cmd:
                    break
                result = handle_command(cmd)
                conn.sendall(json.dumps(result).encode())

start_server()

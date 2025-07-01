import psutil

def scan_processes():
    suspicious = []
    keywords = ["nc", "netcat", "shell", "python", "reverse", "cmd", "powershell"]
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = " ".join(proc.info['cmdline'])
            if any(k in cmdline.lower() for k in keywords):
                suspicious.append(f"PID {proc.info['pid']}: {cmdline}")
        except:
            continue
    return suspicious


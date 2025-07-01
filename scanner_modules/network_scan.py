import psutil

def scan_network():
    results = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == "ESTABLISHED" and conn.raddr:
            try:
                proc = psutil.Process(conn.pid)
                results.append(f"{conn.laddr} -> {conn.raddr}, PID={conn.pid}, Proc={proc.name()}")
            except:
                continue
    return results


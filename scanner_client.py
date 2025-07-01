import socket
import json
from colorama import init, Fore, Style

init(autoreset=True)

def print_banner():
    print(Fore.MAGENTA + Style.BRIGHT + "=" * 55)
    print(Fore.CYAN + Style.BRIGHT + "             BACKDOOR & PERSISTENCE SCANNER             ")
    print(Fore.MAGENTA + Style.BRIGHT + "=" * 55)

def main():
    print_banner()

    # Colored input prompts
    print(Fore.YELLOW + Style.BRIGHT + "\nPlease enter the scan details below:\n")
    target_ip = input(Fore.GREEN + Style.BRIGHT + "👉 Target IP: ")
    command = input(Fore.GREEN + Style.BRIGHT + "👉 Command (scan_all / scan_persistence / scan_processes / scan_network): ")

    try:
        s = socket.socket()
        s.connect((target_ip, 9999))
        s.send(command.encode())

        print(Fore.LIGHTBLUE_EX + Style.BRIGHT + "\n[+] Scanning, please wait......\n")

        data = s.recv(100000).decode()
        response = json.loads(data)

        if 'persistence' in response:
            print(Fore.CYAN + Style.BRIGHT + "\n=== SUSPICIOUS PERSISTENCE ENTRIES ===")
            if response['persistence']:
                for item in response['persistence']:
                    print(Fore.RED + "[!] " + item)
            else:
                print(Fore.GREEN + "No suspicious persistence found.")

        if 'processes' in response:
            print(Fore.CYAN + Style.BRIGHT + "\n=== SUSPICIOUS PROCESSES ===")
            if response['processes']:
                for proc in response['processes']:
                    print(Fore.RED + "[!] PID {}: {}".format(proc['pid'], proc['name']))
            else:
                print(Fore.GREEN + "No suspicious processes found.")

        if 'network' in response:
            print(Fore.CYAN + Style.BRIGHT + "\n=== ACTIVE NETWORK CONNECTIONS ===")
            for conn in response['network']:
                print(Fore.YELLOW + f"{conn['laddr']} --> {conn['raddr']} (PID {conn['pid']})")

        s.close()

    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[!] Error: {str(e)}")

if __name__ == "__main__":
    main()

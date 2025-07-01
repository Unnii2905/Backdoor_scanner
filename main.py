from persistence import check_startup_entries
from process_scan import check_suspicious_processes
from network_scan import check_network_connections
from cron_cleaner import clean_crontab
from colorama import init, Fore

init(autoreset=True)

def log_output(line):
    if "[!]" in line:
        print(Fore.RED + line)
    elif "[*]" in line:
        print(Fore.CYAN + line)
    elif "[+]" in line:
        print(Fore.GREEN + line)
    elif "[-]" in line:
        print(Fore.YELLOW + line)
    else:
        print(line)
    with open("scan_report.txt", "a") as f:
        f.write(line + "\n")

def main():
    print("=== Cross-Platform Backdoor & Persistence Scanner ===\n")
    with open("scan_report.txt", "w") as f:
        f.write("=== Scan Report ===\n")
        
    choice = input("Choose scan mode: (1) Scan Only (2) Scan + Kill (3) Scan + Quarantine): ")
    action = {"1": "none", "2": "kill", "3": "quarantine"}.get(choice, "none")

    check_startup_entries(log_output)
    clean_crontab(log_output)  # <<< Integrated Crontab Cleaner
    check_suspicious_processes(log_output, action)
    check_network_connections(log_output)

if __name__ == "__main__":
    main()

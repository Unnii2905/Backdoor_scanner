# 🛡️ Backdoor & Persistence Scanner

A cross-platform Python-based tool to detect suspicious processes, persistence mechanisms, and active network connections on a remote machine.

## 🔍 Features

- Detects suspicious **processes** using simple heuristics.
- Identifies suspicious **persistence mechanisms** (e.g., crontabs, systemd services, and registry entries on Windows).
- Displays **active network connections** along with the process responsible.
- Remote scanning via **client-server architecture**.
- Works on both **Linux** and **Windows**.

## 🚀 Usage

1. **Start the agent** on the target system:

python3 remote_agent.py

# 2. From the local machine,run:
python3 scanner_client.py
 
#3.Enter the target IP and the scan type:

scan_all

scan_persistence

scan_processes

scan_network

Project Structure

Backdoor_scanner/
├── main.py
├── scanner_client.py
├── remote_agent.py
├── scanner_modules/
├── requirements.txt
├── scan_report.txt
├── .gitignore

 Installation

git clone https://github.com/yourusername/Backdoor_scanner.git
cd Backdoor_scanner
python3 -m venv venv
source venv/bin/activate  # For Windows: venv\Scripts\activate
pip install -r requirements.txt

Dependencies

Listed in requirements.txt. Includes:

psutil

colorama

platform

socket

License
This project is licensed under the MIT License. You may use or modify it for personal, educational, or research purposes.

 Disclaimer: This tool is meant for educational and authorized testing only. Do not use it on any system you do not own or have permission to analyze.

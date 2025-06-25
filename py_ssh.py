# NOTE device.json format -

{
    "router": [
      { "hostname": "router1", "ip": "192.168.1.138" }
    ],

    "disa": [
      { "hostname": "r1", "ip": "10.98.1.1" },
      { "hostname": "r2", "ip": "10.98.1.2" },
      { "hostname": "r3", "ip": "10.100.16.15" },
      { "hostname": "r4", "ip": "10.100.16.16" }
    ]
}

# Mac kerying cred 
# creat: python3 -c 'import keyring; keyring.set_password("py_ssh", "wder1", "xxxxxxxxxxx")'
# delete python3 -c 'import keyring; keyring.delete_password("py_ssh", "wder1")

import paramiko
import json
import os
from datetime import datetime
import getpass
import time
import re
import concurrent.futures
import argparse
import shutil
import keyring

TARGET = ["campus"]
THREAD = 10

# === Commands to Run ===
"""
COMMANDS = [
    "show run",
    "show inventory",
    "show version",
    "show arp",
    "show vrf",
    "show ip interface brief",
    "show interfaces description",
    "show ip access-lists",
    "show cdp neigh",
    "show cdp neigh detail",
    "show cdp interface",
    "show ip route summary",
    "show ip route",
    "show ip bgp",
    "show ip bgp neigh",
    "show ip ospf neigh",
    "show int trunk",
    "show module",
]
"""

COMMANDS = [
    "show run"
]

# === Input JSON File ===
# Get directory of the current script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Build full path to the devices.json file
DEVICE_FILE = os.path.join(SCRIPT_DIR, 'device.json')

# Output directory relative to the script
OUTPUT_DIR = os.path.join(SCRIPT_DIR, 'outputs')

# Archive directory relative to the script
ARCHIVE_DIR = os.path.join(SCRIPT_DIR, 'outputs', 'archive')

def archive():
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    
    for filename in os.listdir(OUTPUT_DIR):
        fullpath = os.path.join(OUTPUT_DIR, filename)
        if filename.endswith(".txt") and os.path.isfile(fullpath):
            shutil.move(os.path.join(OUTPUT_DIR, filename), os.path.join(ARCHIVE_DIR, filename))
            print(f"Moved: {filename} -> {ARCHIVE_DIR}")
        else:
            print(f"Not moved: {filename}")

def load_devices(file_path, categories=None):
    """
    Load devices from specific categories in a JSON file.
    :param file_path: Path to the JSON file
    :param categories: List of category keys to load, or None to load all
    :return: List of device dicts
    """
    try:
        with open(file_path) as f:
            data = json.load(f)

        all_devices = []

        if categories is None:
            # Load everything
            for group in data.values():
                if isinstance(group, list):
                    all_devices.extend(group)
        else:
            # Load only specified categories
            for cat in categories:
                group = data.get(cat)
                if isinstance(group, list):
                    all_devices.extend(group)
                else:
                    print(f"[WARN] Category '{cat}' not found or invalid in JSON.")

        return all_devices

    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in {file_path}: {e}")
        exit(0)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        exit(0)

def read_until_prompt(shell, hostname, prompt_regex=r'[>#]\s*$', timeout=60):
    buffer = ''
    last_data_time = time.time()

    while True:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode(errors='ignore')
            buffer += chunk
            last_data_time = time.time()
        else:
            time.sleep(0.2)

        # if no new data for a while, check if we're done
        if time.time() - last_data_time > 2:
            lines = buffer.strip().splitlines()
            if lines and re.search(prompt_regex, lines[-1]):
                break

        # hard timeout
        if time.time() - last_data_time > timeout:
            print("[WARN] Prompt not detected, breaking read loop - "+hostname)
            break

    return buffer


def ssh_and_run(ip, username, password, commands, hostname):
    error = []
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ip, 
            username=username, 
            password=password, 
            timeout=10,
            banner_timeout=80,
            auth_timeout=120
        )

        shell = client.invoke_shell()
        time.sleep(1)
        shell.recv(1000)  # clear welcome message

        shell.send("terminal length 0\n")
        read_until_prompt(shell, hostname)  # clear its output

        output = ""
        for cmd in commands:
            output += f"\n################################################ {cmd}\n"
            shell.send(cmd + "\n")
            cmd_output = read_until_prompt(shell, hostname)
            output += cmd_output

        client.close()
        return output + "\n\n\n\n\n"

    except Exception as e:
        error_msg = f"[ERROR] Failed to connect to {hostname} ({ip}): {e}\n"
        print(error_msg)
        error.append(error_msg)
        return None

def main(a=None):
    if a:
        archive()
        print("Archived all TXT files\n\n")
    
    # check credential
    USERNAME = 'wder1'
    PASSWORD = keyring.get_password("py_ssh", "wder1")
    #print(keyring.get_password("py_ssh", "wder1"))
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    max_threads = THREAD
    devices = load_devices(DEVICE_FILE, categories=TARGET)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    errorfile = f"error_{timestamp}.log"
    errorfilepath = os.path.join(OUTPUT_DIR, errorfile)
    
    #print(devices)
    #USERNAME = input("Enter SSH username: ")
    #PASSWORD = getpass.getpass("Enter SSH password: ")
    print(f'Username: {USERNAME}')
    print('Password from Kerying\n')
    
    
    ssh_fail = []

    def process_device(device):
        hostname = device['hostname']
        ip = device['ip']
        print(f"Connecting to {hostname} ({ip})...\n")
        result = ssh_and_run(ip, USERNAME, PASSWORD, COMMANDS, hostname)

        if result is not None:
            saft_hostname = hostname.replace("-", "_")
            filename = f"{saft_hostname}-{ip}_{timestamp}.txt"
            filepath = os.path.join(OUTPUT_DIR, filename)
            with open(filepath, 'w') as f:
                f.write(result)
            print(f"Saved {hostname} output to {filepath}\n")
        else:
            #print(f"Skipping {hostname} due to SSH failure\n")
            ssh_fail.append('{"hostname": "'+hostname+'", "ip": "'+ip+'"},')
            
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(process_device, devices)
    
    if len(ssh_fail) > 0:
        print("\n\n\nFAILED SSH LIST:\n")
        for e in ssh_fail:
            print(f'{e}')
        
        with open(errorfilepath, 'w') as ef:
            for line in ssh_fail:
                ef.write(line)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", action="store_true")
    args = parser.parse_args()
    main(a=args.a)
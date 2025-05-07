
# Device file format: 
{
  "router": [
    { "hostname": "router1", "ip": "192.168.1.1" },
    { "hostname": "router2", "ip": "192.168.1.2" }
  ]
}



import paramiko
import json
import os
from datetime import datetime
import getpass
import time
import re

# === Commands to Run ===
COMMANDS = [
    'show version',
    'show running-config',
    'show ip interface brief',
    'show inventory',
    'show interfaces status'
]

# === Input JSON File ===
# Get directory of the current script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Build full path to the devices.json file
DEVICE_FILE = os.path.join(SCRIPT_DIR, 'device.json')

# Output directory relative to the script
OUTPUT_DIR = os.path.join(SCRIPT_DIR, 'outputs')


def load_devices(file_path):
    try:
        with open(file_path) as f:
            data = json.load(f)
            return data.get('router', [])  # <- Correct key here
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in {file_path}: {e}")
        return []
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return []

def read_until_prompt(shell, prompt_regex=r'[>#]\s*$', timeout=30):
    buffer = ''
    end_time = time.time() + timeout
    while time.time() < end_time:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode(errors='ignore')
            buffer += chunk
            if re.search(prompt_regex, buffer.splitlines()[-1]):
                break
        else:
            time.sleep(0.2)
    return buffer

def ssh_and_run(ip, username, password, commands):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=10)

        shell = client.invoke_shell()
        time.sleep(1)
        shell.recv(1000)  # clear welcome message

        shell.send("terminal length 0\n")
        read_until_prompt(shell)  # clear its output

        output = ""
        for cmd in commands:
            shell.send(cmd + "\n")
            cmd_output = read_until_prompt(shell)
            output += f"\n################################################ {cmd}\n{cmd_output}"

        client.close()
        return output + "\n\n\n\n\n"

    except Exception as e:
        error_msg = f"[ERROR] Failed to connect to {hostname} ({ip}): {e}"
        print(error_msg)
        return f"\n######## ERROR\n{error_msg}\n"

    except Exception as e:
        error_msg = f"[ERROR] Failed to connect to {hostname} ({ip}): {e}"
        print(error_msg)
        return f"\n######## ERROR\n{error_msg}\n"

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    devices = load_devices(DEVICE_FILE)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    print(devices)
    USERNAME = input("Enter SSH username: ")
    PASSWORD = getpass.getpass("Enter SSH password: ")


    for device in devices:
        hostname = device['hostname']
        ip = device['ip']
        print(f"Connecting to {hostname} ({ip})...")
        result = ssh_and_run(ip, USERNAME, PASSWORD, COMMANDS)

        filename = f"{hostname}_{timestamp}.txt"
        filepath = os.path.join(OUTPUT_DIR, filename)
        with open(filepath, 'w') as f:
            f.write(result)
        print(f"Saved output to {filepath}")

if __name__ == "__main__":
    main()
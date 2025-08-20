#!/usr/bin/env python3
import argparse
import concurrent.futures
import getpass
import json
import os
import select
import socket
import sys
import time
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional, Union

import paramiko
import keyring

# Globals
print_lock = Lock()

PER_CMD_TIMEOUT = 6.0      # seconds: hard cap per command
IDLE_QUIET = 1.2           # seconds: stop when no data arrives for this long
SELECT_WAIT = 0.50         # seconds: max wait for readability check

DEFAULT_DEVICES_FILE = (Path(__file__).with_name("device.json") if '__file__' in globals() else Path.cwd() / "device.json")
DEFAULT_SERVICE = "py_ssh"
DEFAULT_PORT = 22

TARGET = ["mpls"]
THREAD = 10
COMMANDS = [
    "terminal length 0",
    "sh int des | i up; interface description",
    "sh ip int b | i up; cisco interface status",
    "sh ip arp; arp table",
    "sh ip bgp summ; bgp summary",
    "sh ip route",
    "sh bridge-domain; bridge domain",
    "sh ip nat translations"
]

def _normalize_device(d: Dict[str, Any], default_username: Optional[str], keyring_service: str) -> Dict[str, Any]:
    if isinstance(d, str):
        d = {"host": d}
    d.setdefault("port", DEFAULT_PORT)
    if "username" not in d and default_username:
        d["username"] = default_username
    if "username" in d and "password" not in d:
        d["password"] = keyring.get_password(keyring_service, d["username"])
        if not d["password"]:
            d["password"] = getpass.getpass(f"Password for {d['username']}@{d['host']}: ")
    return d

def _load_devices(
    devices: Optional[Union[Iterable[Dict[str, Any]], str]] = None,
    device_groups: Optional[List[str]] = None,
    default_username: Optional[str] = None,
    keyring_service: str = DEFAULT_SERVICE,
) -> List[Dict[str, Any]]:
    if isinstance(devices, (str, os.PathLike)):
        text = Path(devices).read_text(encoding="utf-8")
        data = json.loads(text) if devices.endswith(".json") else text.splitlines()
        if isinstance(data, list):
            raw = data
        elif isinstance(data, dict):
            selected_keys = list(data.keys()) if not device_groups else [g for g in device_groups if g in data]
            raw = []
            for k in selected_keys:
                grp = data.get(k, [])
                if isinstance(grp, list):
                    raw.extend(grp)
        else:
            raise ValueError("Unsupported JSON structure for devices")
    else:
        raw = list(devices)
    return [_normalize_device(d, default_username, keyring_service) for d in raw]

def _load_commands(commands: Optional[List[str]], commands_file: Optional[str]) -> List[str]:
    if commands:
        return commands
    if commands_file:
        return [line.strip() for line in Path(commands_file).read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    return COMMANDS

def _ssh_run_one(device: Dict[str, Any], commands: List[str], timeout: int) -> str:
    host = device.get("host")
    port = device.get("port", DEFAULT_PORT)
    username = device.get("username")
    password = device.get("password")

    output = []
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=username, password=password, timeout=timeout)

        chan = client.invoke_shell()
        chan.settimeout(timeout)
        for cmd in commands:
            chan.send(cmd + "\n")
            buf, chunk, start_time = [], [], time.time()
            while True:
                r, _, _ = select.select([chan], [], [], SELECT_WAIT)
                if r and chan.recv_ready():
                    data = chan.recv(65535).decode("utf-8", errors="ignore")
                    chunk.append(data)
                    start_time = time.time()
                elif time.time() - start_time > IDLE_QUIET:
                    break
                elif time.time() - start_time > PER_CMD_TIMEOUT:
                    break
            buf.extend(chunk)
            output.append(f"\n##### {cmd}\n{''.join(buf)}")
        client.close()
    except Exception as e:
        output.append(f"Error on {host}: {e}")

    return "\n".join(output)

def _archive_current_txt(output_dir: Path, archive_dir: Optional[Path]) -> None:
    ts = time.strftime("%Y%m%d_%H%M%S")
    target_dir = archive_dir or (output_dir / "archives")
    target_dir = target_dir / ts
    target_dir.mkdir(parents=True, exist_ok=True)
    for f in output_dir.glob("*.txt"):
        f.rename(target_dir / f.name)

def main(
    devices: Union[List[str], str],
    commands: Optional[List[str]],
    commands_file: Optional[str],
    output_dir: Path,
    archive_dir: Optional[Path],
    per_host_prefix: Optional[str],
    max_workers: int,
    timeout: int,
    archive_flag: bool,
    loop_flag: bool,
    device_groups: Optional[List[str]],
    default_username: Optional[str],
    keyring_service: str,
    append: bool,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    if archive_flag:
        _archive_current_txt(output_dir, archive_dir)

    while True:
        devs = _load_devices(devices, device_groups, default_username, keyring_service)
        cmds = _load_commands(commands, commands_file)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(_ssh_run_one, d, cmds, timeout): d for d in devs}
            for fut in concurrent.futures.as_completed(futures):
                d = futures[fut]
                host = d.get("host")
                try:
                    result = fut.result()
                except Exception as e:
                    result = f"Error on {host}: {e}"
                fname = f"{per_host_prefix+'_' if per_host_prefix else ''}{host}.txt"
                mode = "a" if append else "w"
                with print_lock, open(output_dir / fname, mode, encoding="utf-8") as fh:
                    fh.write(result)
                    fh.write("\n")
        if not loop_flag:
            break
        time.sleep(60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH batch runner (keyring + group/file/IP aware)")
    parser.add_argument("-a", action="store_true", help="Archive existing .txt files in output dir before run")
    parser.add_argument("-l", action="store_true", help="Loop mode: repeat the run every 60s")
    parser.add_argument(
        "--devices",
        nargs="+",
        default=[str(DEFAULT_DEVICES_FILE)],
        help=f"One or more device IPs/hostnames, or path(s) to device list file(s). "
             f"Supports .json (list or dict-of-lists) or .txt (one host per line). "
             f"Default: {DEFAULT_DEVICES_FILE}",
    )
    parser.add_argument("--commands-file", help="File with one command per line (optional; ignored if positional commands are given)")
    parser.add_argument("commands", nargs="*", help="Commands to run (space-separated). If omitted and no --commands-file, built-in defaults are used.")
    parser.add_argument("--output-dir", type=Path, default=Path("./outputs"), metavar="DIR",
                        help="Directory to write per-host outputs (default: ./outputs)")
    parser.add_argument("--archive-dir", type=Path, metavar="DIR",
                        help="Archive directory (default: <output-dir>/archives)")
    parser.add_argument("--max-workers", type=int, default=THREAD, metavar="N",
                        help=f"Concurrency (default: {THREAD})")
    parser.add_argument("--timeout", type=int, default=20, metavar="SECONDS",
                        help="Per-device timeout (default: 20)")
    parser.add_argument("--prefix", dest="per_host_prefix", metavar="LABEL",
                        help="Filename prefix for per-host outputs")
    parser.add_argument("--device-groups", nargs="+", metavar="GROUP",
                        help="Groups to select when JSON is a dict-of-lists")
    parser.add_argument("--default-username", metavar="USER",
                        help="Username to use when device entry omits it (keyring applies)")
    parser.add_argument("--keyring-service", default=DEFAULT_SERVICE, metavar="SERVICE",
                        help=f"Keyring service name (default: {DEFAULT_SERVICE})")
    parser.add_argument("--append", action="store_true",
                        help="Append output to a steady file instead of timestamped files")

    args = parser.parse_args()
    main(
        devices=args.devices,
        commands=args.commands,
        commands_file=args.commands_file,
        output_dir=args.output_dir,
        archive_dir=args.archive_dir,
        per_host_prefix=args.per_host_prefix,
        max_workers=args.max_workers,
        timeout=args.timeout,
        archive_flag=args.a,
        loop_flag=args.l,
        device_groups=args.device_groups,
        default_username=args.default_username,
        keyring_service=args.keyring_service,
        append=args.append,
    )

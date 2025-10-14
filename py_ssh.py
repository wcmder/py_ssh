#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import select
import shutil
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional, Union

# ---------- Optional deps ----------
import paramiko
import keyring



# ================= Globals =================
print_lock = Lock()

PER_CMD_TIMEOUT = 30.0     # seconds: hard cap per command
IDLE_QUIET = 1.5           # seconds: stop when no data arrives for this long
SELECT_WAIT = 0.50         # seconds: max wait for readability check

DEFAULT_DEVICES_FILE = (Path(__file__).with_name("device.json") if "__file__" in globals() else Path.cwd() / "device.json")
DEFAULT_SERVICE = "py_ssh"
DEFAULT_USERNAME = "wder1"
DEFAULT_PORT = 22

TARGET = ["nipr"]          # default groups to use when none provided
THREAD = 10                # default concurrency

COMMANDS = [
    "terminal length 0",
    "sh int des | i up; interface description",
    "sh ip int b | i up; cisco interface status",
    "sh ip arp",
    "sh ip bgp summ; bgp summary",
    "sh ip route",
    "sh bridge-domain",
    "sh ip nat translations",
    "sh ip ospf data; ospf database",
]


"""
Current supported DIFF -
"ip arp" 
"mac address-table"
"cisco interface status"
"arista interface status"
"interface description"
"access-session"
"bgp summary"
"lisp status"
"portchannel"      
"isdn status"
"bridge-domain"
"sip tls"
"ospf database"
"ip route"
"""

# ================= Utilities =================
def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _write_text(fp: Path, content: str, append: bool = False) -> None:
    _ensure_dir(fp.parent)
    mode = "a" if append else "w"
    with fp.open(mode, encoding="utf-8") as f:
        f.write(content)


def _archive_current_txt(output_dir: Path, archive_dir: Path, per_host_prefix: Optional[str] = None) -> None:
    """
    Move .txt files from output_dir to a timestamped subdir under archive_dir.
    If per_host_prefix is provided, only archive files starting with that prefix.
    """
    _ensure_dir(archive_dir)
    run_dir = archive_dir / _timestamp()
    _ensure_dir(run_dir)

    pattern = re.compile(rf"^{re.escape(per_host_prefix)}.*\.txt$") if per_host_prefix else re.compile(r".*\.txt$")
    for item in output_dir.glob("*.txt"):
        if pattern.match(item.name):
            dest = run_dir / item.name
            shutil.move(str(item), str(dest))
            with print_lock:
                print(f"[archive] {item.name} -> {dest}", flush=True)


def _get_password_from_keyring(service: str, username: str) -> Optional[str]:
    if keyring is None:
        return None
    try:
        return keyring.get_password(service, username)  # type: ignore[attr-defined]
    except Exception:
        return None


# ============= Credential Prefill (main thread) =============
def _prefill_passwords(
    devices: List[Dict[str, Any]],
    default_username: Optional[str],
    keyring_service: Optional[str],
    prompt_if_missing: bool,
) -> None:
    """
    Ensure every device has username+password BEFORE threading.
    Sources (in order): device["password"], keyring(service,username), optional prompt (main thread only).
    Prompts at most once per (service, username) combo.
    """
    import getpass

    cache: Dict[tuple, Optional[str]] = {}

    def _user_svc(d: Dict[str, Any]):
        user = d.get("username") or default_username or DEFAULT_USERNAME
        svc = d.get("keyring_service") or keyring_service or DEFAULT_SERVICE
        return user, svc

    for d in devices:
        user, svc = _user_svc(d)
        d["username"] = user
        d.setdefault("keyring_service", svc)

        pw = d.get("password")

        # keyring (cached per (svc,user))
        key = (svc, user)
        if not pw:
            if key not in cache:
                cache[key] = _get_password_from_keyring(svc, user)
            pw = cache[key]

        # optional prompt (main thread only)
        if not pw and prompt_if_missing:
            with print_lock:
                print(f"[auth] password prompt for user '{user}' (service '{svc}')", flush=True)
            pw = getpass.getpass(f"Enter password for {user}: ")
            cache[key] = pw

        d["password"] = pw


# ================= SSH core =================
def _resolve_auth(device: Dict[str, Any]) -> Dict[str, Any]:
    """
    Worker-side: trust values filled by main thread; do NOT prompt here.
    If still missing, raise a clear error to avoid hangs inside threads.
    """
    username = device.get("username") or DEFAULT_USERNAME
    device["username"] = username

    password = device.get("password")
    if not password:
        raise RuntimeError(f"Missing password for {username} (not prefilled)")

    return device


def _ssh_run_one(
    device: Dict[str, Any],
    commands: List[str],
    timeout: int = 20,
    cmd_delay: float = 0.2,
    banner_timeout: int = 15,
) -> Dict[str, Any]:
    """
    Connect to a device and run commands, returning:
      {host, ip, ok, output, error}
    """
    # Connect target
    host = device.get("connect_host") or device.get("host") or device.get("ip")
    hostname = device.get("hostname") or device.get("display_name") or host
    ip = device.get("ip") or host
    display = f"{hostname} | {ip}"
    port = int(device.get("port") or DEFAULT_PORT)

    if not host:
        return {"host": hostname or "unknown", "ip": ip, "ok": False, "output": "", "error": "No host/IP provided"}

    if paramiko is None:
        return {"host": hostname, "ip": ip, "ok": False, "output": "", "error": "paramiko not installed"}

    try:
        _resolve_auth(device)
        username = device["username"]
        password = device["password"]

        with print_lock:
            print(f"[connect] {display} as {username}", flush=True)

        # Tighten connection-level timeouts
        socket.setdefaulttimeout(timeout)

        ssh = paramiko.SSHClient()  # type: ignore[attr-defined]
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # type: ignore[attr-defined]
        ssh.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,            # TCP connect
            banner_timeout=timeout,     # banner read
            auth_timeout=timeout,       # auth timeout
            look_for_keys=False,
            allow_agent=False,
        )
        chan = ssh.invoke_shell()
        chan.settimeout(timeout)
        #time.sleep(5)                   # wait for MOD

        with print_lock:
            print(f"[connected] {display}", flush=True)

        outs: List[str] = []
        for cmd in commands:
            line = cmd.rstrip("\n")
            if ";" in cmd:
                cmd_line = line.split(";", 1)[0] + "\n"
                commt_line = line.split(";", 1)[1]
            else:
                cmd_line = line + "\n"
                commt_line = line

            #with print_lock:
            #    print(f"[send] {display} :: {cmd_line.strip()}", flush=True)

            chan.send(cmd_line)
            time.sleep(cmd_delay)  # tiny pacing to allow device to respond

            start = time.monotonic()
            last_data = start
            chunks: List[str] = []
            while True:
                # hard timeout?
                now = time.monotonic()
                if now - start >= PER_CMD_TIMEOUT:
                    with print_lock:
                        print(f"[timeout] {display} exceeded per cmd timeout {PER_CMD_TIMEOUT}s", flush=True)
                    break
                # quiet long enough?
                if now - last_data >= IDLE_QUIET:
                    break

                if os.name == "nt":
                    # windows 
                    if chan.recv_ready():
                        data = chan.recv(65535).decode("utf-8", errors="ignore")
                        if data:
                            chunks.append(data)
                            last_data = time.monotonic()
                            continue
                    else:
                        time.sleep(SELECT_WAIT)
                else:
                    # wait briefly for data
                    r, _, _ = select.select([chan], [], [], SELECT_WAIT)
                    if r:
                        try:
                            if chan.recv_ready():
                                data = chan.recv(65535).decode("utf-8", errors="ignore")
                                if data:
                                    chunks.append(data)
                                    last_data = time.monotonic()
                                    continue
                        except socket.timeout:
                            pass

            outs.append(f"\n################################################ {commt_line}\n" + "".join(chunks))

        ssh.close()
        output = "".join(outs)
        with print_lock:
            print(f"[done] {display}", flush=True)
        return {"host": hostname, "ip": ip, "ok": True, "output": output, "error": None}

    except Exception as e:
        with print_lock:
            print(f"[error] {display} :: {e}", flush=True)
        return {"host": hostname, "ip": ip, "ok": False, "output": "", "error": str(e)}


def _write_output(
    output_dir: Path,
    host_label: str,
    content: str,
    append_label: Optional[str] = None,
    prefix: Optional[str] = None,
) -> Path:
    """
    Write content to output file.
    If append_label is provided, append to <append_label>.txt.
    Otherwise, create a timestamped file (optionally using prefix).
    """
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", host_label or "unknown").replace("_", "-")
    if append_label:
        steady = f"{safe_host}-{append_label}.txt"
        out_fp = output_dir / steady
        _write_text(out_fp, content, append=False)
        #with print_lock:
        #    print(f"[write] {safe_host} -> {out_fp.name} (append)", flush=True)
        return out_fp
    else:
        name = f"{(prefix+'-' if prefix else '')}{safe_host}_{_timestamp()}.txt"
        out_fp = output_dir / name
        _write_text(out_fp, content, append=False)
        #with print_lock:
        #    print(f"[write] {safe_host} -> {out_fp.name}", flush=True)
        return out_fp


# ============ Normalization & loading ============
def _normalize_device(
    dev: Dict[str, Any],
    default_username: Optional[str] = None,
    keyring_service: Optional[str] = None,
) -> Dict[str, Any]:
    # apply defaults safely
    if default_username is None:
        default_username = DEFAULT_USERNAME
    if keyring_service is None:
        keyring_service = DEFAULT_SERVICE

    connect_host = dev.get("ip") or dev.get("host") or dev.get("hostname")
    display_name = dev.get("hostname") or dev.get("host") or dev.get("ip") or "unknown"

    out = dict(dev)
    out["connect_host"] = connect_host
    out["display_name"] = display_name
    if default_username and not out.get("username"):
        out["username"] = default_username
    if not out.get("keyring_service"):
        out["keyring_service"] = keyring_service
    if not out.get("port"):
        out["port"] = DEFAULT_PORT
    return out


def _parse_plaintext_devices(p: Path) -> List[str]:
    return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def _flatten_json_devices(data: Any, groups: Optional[List[str]]) -> List[Dict[str, Any]]:
    # Accept list[str|dict] or dict[str, list[str|dict]]
    out: List[Dict[str, Any]] = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        keys = list(data.keys()) if not groups else [g for g in groups if g in data]
        items = []
        for k in keys:
            v = data.get(k, [])
            if isinstance(v, list):
                items.extend(v)
            else:
                items.append(v)
    else:
        items = [data]

    for it in items:
        if isinstance(it, dict):
            out.append(it)
        else:  # assume string hostname/IP
            out.append({"host": str(it)})
    return out


def _as_device_dicts(items: Iterable[Union[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for it in items:
        if isinstance(it, dict):
            out.append(it)
        else:
            out.append({"host": str(it)})
    return out


def _load_devices(
    devices: Optional[Union[Iterable[Union[Dict[str, Any], str]], str]] = None,
    device_groups: Optional[List[str]] = None,
    default_username: Optional[str] = None,
    keyring_service: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Load devices from:
      - None -> device.json next to script (DEFAULT_DEVICES_FILE)
      - CLI list of IPs/hosts (strings),
      - JSON file (list or dict-of-lists),
      - plaintext file (.txt) with one host per line).
    If JSON is dict-of-lists, optionally filter by group names.
    """
    if default_username is None:
        default_username = DEFAULT_USERNAME
    if keyring_service is None:
        keyring_service = DEFAULT_SERVICE

    def _parse_txt(p: Path):
        return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")]

    def _to_dicts(seq):
        out = []
        for it in seq:
            if isinstance(it, dict):
                out.append(it)
            else:
                out.append({"host": str(it)})
        return out

    # Case 1: devices omitted -> use DEFAULT_DEVICES_FILE
    if devices is None:
        p = DEFAULT_DEVICES_FILE
        if not p.is_file():
            raise ValueError(f"--devices not provided and default file not found: {p}")
        if p.suffix.lower() == ".json":
            data = json.loads(p.read_text(encoding="utf-8"))
            raw_devices = _flatten_json_devices(data, device_groups or TARGET)
        else:
            raw_devices = [{"host": h} for h in _parse_txt(p)]
        with print_lock:
            print(f"[devices] loaded {len(raw_devices)} from default {p}", flush=True)

    # Case 2: list/tuple of entries (IPs/hosts and/or file paths)
    elif isinstance(devices, (list, tuple, set)):
        accum: List[Union[str, Dict[str, Any]]] = []
        for entry in devices:
            if isinstance(entry, (str, os.PathLike)):
                p = Path(entry)
                if p.is_file():
                    if p.suffix.lower() == ".json":
                        data = json.loads(p.read_text(encoding="utf-8"))
                        accum.extend(_flatten_json_devices(data, device_groups or TARGET))
                    else:
                        accum.extend({"host": h} for h in _parse_txt(p))
                else:
                    accum.append(entry)  # treat as hostname/IP
            else:
                accum.append(entry)
        raw_devices = _as_device_dicts(accum)
        with print_lock:
            print(f"[devices] loaded {len(raw_devices)} from CLI", flush=True)

    # Case 3: single string: file path OR hostname/IP
    elif isinstance(devices, (str, os.PathLike)):
        p = Path(devices)
        if p.is_file():
            if p.suffix.lower() == ".json":
                data = json.loads(p.read_text(encoding="utf-8"))
                raw_devices = _flatten_json_devices(data, device_groups or TARGET)
            else:
                raw_devices = [{"host": h} for h in _parse_txt(p)]
            with print_lock:
                print(f"[devices] loaded {len(raw_devices)} from {p}", flush=True)
        else:
            raw_devices = [{"host": str(devices)}]
            with print_lock:
                print(f"[devices] using single host {devices}", flush=True)

    else:
        raw_devices = _as_device_dicts(list(devices))
        with print_lock:
            print(f"[devices] loaded {len(raw_devices)} from iterable", flush=True)

    return [_normalize_device(d, default_username, keyring_service) for d in raw_devices]


def _load_commands(
    positional: Optional[List[str]] = None,
    file_path: Optional[str] = None,
) -> List[str]:
    """
    Load commands from:
      - positional CLI args (highest priority),
      - --commands-file (one per line, '#' and blank lines ignored),
      - fallback to built-in COMMANDS global.
    """
    if positional:
        with print_lock:
            print(f"[commands] using {len(positional)} from CLI", flush=True)
        return [c for c in positional if str(c).strip()]

    if file_path:
        p = Path(file_path)
        if not p.is_file():
            raise ValueError(f"Commands file not found: {p}")
        cmds = [
            ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")
        ]
        with print_lock:
            print(f"[commands] loaded {len(cmds)} from {p}", flush=True)
        return cmds

    with print_lock:
        print(f"[commands] using built-in defaults ({len(COMMANDS)})", flush=True)
    return COMMANDS[:]  # built-in defaults


def _print_summary(summary: dict) -> None:
    """
    Print a v2-style summary of run results.
    """
    stats = summary.get("stats", {})
    results = summary.get("results", [])
    ok = stats.get("ok", 0)
    failed = stats.get("failed", 0)
    total = stats.get("total", 0)

    print("\n================ SUMMARY ================", flush=True)
    print(f"  Total: {total}   OK: {ok}   Failed: {failed}", flush=True)

    if results:
        print("\n")
        print(f"  {'Host:':25} {'Status:':15} {'File:'}")
        for r in results:
            host = r.get("host", "unknown")
            success = r.get("ok", False)
            if success:
                outfile = r.get("outfile") or ""
                print(f"  {host:25} {'OK':15} {outfile}")
            else:
                err = (r.get("error") or "").strip()
                print(f"  {host:25} {'FAIL':15} {err}")
        print("\n")


# ================= Orchestration =================
def run_batch(
    a: Optional[bool] = None,
    l: Optional[bool] = None,
    commands: Optional[List[str]] = None,
    commands_file: Optional[str] = None,
    devices: Union[str, List[Dict[str, Any]], None] = None,
    output_dir: Union[str, Path] = "./outputs",
    archive_dir: Optional[Union[str, Path]] = None,
    max_workers: int = THREAD,
    timeout: int = 20,
    per_host_prefix: Optional[str] = None,
    device_groups: Optional[List[str]] = None,
    default_username: Optional[str] = None,
    keyring_service: Optional[str] = None,
    append: Optional[str] = None,
    *,
    prompt_if_missing: bool = False,   # library default: no prompt
) -> dict:
    out_dir = Path(output_dir).expanduser().resolve()
    _ensure_dir(out_dir)
    arch_dir = Path(archive_dir).expanduser().resolve() if archive_dir else (out_dir / "archives")

    if a:
        _archive_current_txt(out_dir, arch_dir, per_host_prefix)

    normalized_devices = _load_devices(
        devices=devices,
        device_groups=device_groups or TARGET,
        default_username=default_username,
        keyring_service=keyring_service,
    )

    # Prefill creds ONCE in main thread (no worker prompts)
    _prefill_passwords(
        normalized_devices,
        default_username=default_username,
        keyring_service=keyring_service,
        prompt_if_missing=prompt_if_missing,
    )

    cmd_list = _load_commands(commands, commands_file)

    #print(cmd_list)

    results: List[Dict[str, Any]] = []
    ok = failed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_to_dev = {pool.submit(_ssh_run_one, d, cmd_list, timeout): d for d in normalized_devices}
        for fut in as_completed(fut_to_dev):
            res = fut.result()
            results.append(res)
            host_label = res.get("host", "unknown")
            if res.get("ok"):
                ok += 1
                outfile = _write_output(out_dir, host_label, res.get("output", ""),
                                        append_label=append, prefix=per_host_prefix)
                res["outfile"] = str(outfile)
            else:
                failed += 1
                _write_output(out_dir, host_label, f"ERROR: {res.get('error','unknown')}\n",
                              append_label="errors", prefix=None)

    summary = {
        "stats": {"ok": ok, "failed": failed, "total": ok + failed},
        "results": results,
        "output_dir": str(out_dir),
        "archive_dir": str(arch_dir),
    }
    return summary


# ================= CLI facade =================
def main(
    a: Optional[bool] = None,                # archive existing txt before run
    l: Optional[bool] = None,                # loop mode
    commands: Optional[List[str]] = None,
    commands_file: Optional[str] = None,
    devices: Union[str, List[Dict[str, Any]], None] = None,
    output_dir: Optional[Union[str, Path]] = None,
    archive_dir: Optional[Union[str, Path]] = None,
    max_workers: int = THREAD,
    timeout: int = 20,
    per_host_prefix: Optional[str] = None,
    device_groups: Optional[List[str]] = None,
    default_username: Optional[str] = None,
    keyring_service: Optional[str] = None,
    append: Optional[str] = None,
) -> None:
    out_dir = Path(output_dir or "./outputs").expanduser().resolve()
    arch_dir = Path(archive_dir).expanduser().resolve() if archive_dir else (out_dir / "archives")
    _ensure_dir(out_dir)

    while True:
        try:
            batch = run_batch(
                a=a,
                l=l,
                commands=commands,
                commands_file=commands_file,
                devices=devices if devices is not None else DEFAULT_DEVICES_FILE,
                output_dir=out_dir,
                archive_dir=arch_dir,
                max_workers=max_workers,
                timeout=timeout,
                per_host_prefix=per_host_prefix,
                device_groups=device_groups or TARGET,
                default_username=default_username,
                keyring_service=keyring_service,
                append=append,
                prompt_if_missing=True,   # CLI may prompt once in main thread if keyring missing
            )
            _print_summary(batch)
        except Exception as e:
            with print_lock:
                print(f"[fatal] {e}", file=sys.stderr, flush=True)
            sys.exit(1)

        if not l:
            break
        time.sleep(60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH batch runner (keyring + group/file/IP aware)")
    # flags
    parser.add_argument("-a", action="store_true", help="Archive existing .txt files in output dir before run")
    parser.add_argument("-l", action="store_true", help="Loop mode: repeat the run every 60s")

    # devices: list of IPs/hosts and/or file paths (.json or .txt).
    # Omit entirely to default to device.json next to this script.
    parser.add_argument(
        "--devices",
        nargs="+",
        default=None,
        help=(
            "One or more device IPs/hostnames, or path(s) to device list file(s). "
            "Supports .json (list or dict-of-lists) or .txt (one host per line). "
            f"Default: {DEFAULT_DEVICES_FILE} if omitted"
        ),
    )

    # commands: positional list; or --commands-file for one-per-line file
    parser.add_argument(
        "--commands-file",
        help="File with one command per line (optional; ignored if positional commands are given)"
    )
    parser.add_argument(
        "commands",
        nargs="*",
        help=(
            "Commands to run (space-separated; quote if they contain spaces/pipes). "
            "If omitted and no --commands-file, built-in defaults are used."
        ),
    )

    # other args
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
                        help="Groups to select when JSON is a dict of multiple groups of hosts")
    parser.add_argument("--default-username", metavar="USER",
                        help=f"Username to use when device entry omits it (default: {DEFAULT_USERNAME}; keyring applies)")
    parser.add_argument("--keyring-service", default=DEFAULT_SERVICE, metavar="SERVICE",
                        help=f"Keyring service name (default: {DEFAULT_SERVICE})")

    # IMPORTANT: append is a LABEL string (not a bool)
    parser.add_argument("--append", required=False, metavar="LABEL",
                        help="Append output to result file named LABEL.txt instead of timestamped files")

    args = parser.parse_args()

    # Normalize/validate some arguments
    args.output_dir = args.output_dir.expanduser().resolve()
    arch_dir = args.archive_dir.expanduser().resolve() if args.archive_dir else (args.output_dir / "archives")

    if args.max_workers < 1:
        raise SystemExit("--max-workers must be >= 1")
    if args.timeout <= 0:
        raise SystemExit("--timeout must be > 0")

    if args.per_host_prefix:
        safe = "".join(ch for ch in args.per_host_prefix if ch.isalnum() or ch in ("-", "_"))
        if not safe:
            raise SystemExit("--prefix must contain letters/numbers or -/_")
        args.per_host_prefix = safe

    try:
        # pass ALL args explicitly
        main(
            a=args.a,
            l=args.l,
            commands=args.commands if args.commands else None,
            commands_file=args.commands_file,
            devices=args.devices,
            output_dir=args.output_dir,
            archive_dir=arch_dir,
            max_workers=args.max_workers,
            timeout=args.timeout,
            per_host_prefix=args.per_host_prefix,
            device_groups=args.device_groups,
            default_username=args.default_username,
            keyring_service=args.keyring_service,
            append=args.append,
        )
    except KeyboardInterrupt:
        with print_lock:
            print("[interrupt] user cancelled", file=sys.stderr, flush=True)
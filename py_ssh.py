
#!/usr/bin/env python3
"""
py_ssh.py
- Importable API: run_batch(commands, devices, output_dir, ...)
- CLI mode with args (archive, loop, commands/devices/output paths)
- Keyring-aware auth if password is not provided
- Group-aware device JSON (dict of lists), with --device-groups filtering
"""

from __future__ import annotations
import argparse
import concurrent.futures
import json
import os
import shutil
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union
import paramiko
from threading import Lock

try:
    import keyring  # type: ignore
except Exception:  # pragma: no cover
    keyring = None

print_lock = Lock()

COMMANDS = [
    "show run"
]

DEFAULT_DEVICES_FILE = Path(__file__).with_name("device.json")

TARGET = ["mpls-new"]  # default groups to use when none provided

DEFAULT_SERVICE = "py_ssh"
DEFAULT_PORT = 22

# ---------------------------- Helpers ---------------------------- #

def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _write_text(fp: Path, content: str) -> None:
    _ensure_dir(fp.parent)
    fp.write_text(content, encoding="utf-8")


def _archive_current_txt(output_dir: Path, archive_dir: Path) -> None:
    """Move existing *.txt files from output_dir to archive_dir/<ts>/"""
    if not output_dir.exists():
        return
    ts_dir = archive_dir / f"archive_{_timestamp()}"
    _ensure_dir(ts_dir)
    for txt in output_dir.glob("*.txt"):
        shutil.move(str(txt), ts_dir / txt.name)


def _get_password_from_keyring(service: str, username: str) -> Optional[str]:
    if keyring is None:
        return None
    try:
        return keyring.get_password(service, username)
    except Exception:
        return None


def _resolve_auth(device: Dict[str, Any]) -> Dict[str, Any]:
    """
    Resolve auth inputs:
      1) password in device
      2) keyring(service=device['keyring_service'] or DEFAULT_SERVICE, username=device['username'])
      3) key_filename
      4) ssh agent / default keys
    """
    username = device.get("username") or device.get("user")
    password = device.get("password")
    key_filename = device.get("key_filename")
    service = device.get("keyring_service", DEFAULT_SERVICE)

    if not password and username:
        kr_pw = _get_password_from_keyring(service, username)
        if kr_pw:
            password = kr_pw

    return {"username": username, "password": password, "key_filename": key_filename}


# ---------------------------- SSH core ---------------------------- #

class SSHResult:
    def __init__(self, host: str, ok: bool, output: str = "", error: str = "", outfile: Optional[Path] = None):
        self.host = host            # display label in results
        self.ok = ok
        self.output = output
        self.error = error
        self.outfile = outfile

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "ok": self.ok,
            "output": self.output,
            "error": self.error,
            "outfile": str(self.outfile) if self.outfile else None,
        }


def _ssh_run_one(device: Dict[str, Any], commands: Iterable[str],
    timeout: int = 20,
    cmd_delay: float = 0.2,
    banner_timeout: int = 15,
) -> SSHResult:
    host_for_connect = device.get("connect_host") or device.get("ip") or device.get("host") or device.get("hostname")
    if not host_for_connect:
        return SSHResult(host=device.get("display_name") or str(device), ok=False, error="Missing host/ip/hostname")

    auth = _resolve_auth(device)
    username = auth["username"]
    password = auth["password"]
    key_filename = auth["key_filename"]
    port = int(device.get("port", DEFAULT_PORT))

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        host = device.get("hostname", "")
        ip = device.get("ip", "")
        with print_lock:
            print(f"connecting... {host} | {ip}", flush=True)
            
        client.connect(
            hostname=host_for_connect,
            port=port,
            username=username,
            password=password,
            key_filename=key_filename,
            look_for_keys=bool(not password and not key_filename),
            allow_agent=True,
            timeout=timeout,
            banner_timeout=banner_timeout,
        )
        chan = client.invoke_shell()
        chan.settimeout(timeout)

        with print_lock:
            print(f"connected... {host} | {ip}", flush=True)

        # read initial banner/prompt
        time.sleep(cmd_delay)
        try:
            _ = chan.recv(65535)
        except Exception:
            pass

        outs: List[str] = []
        for cmd in commands:
            line = cmd.rstrip("\n") + "\n"
            chan.send(line)
            time.sleep(cmd_delay)

            end_time = time.time() + timeout
            chunk: List[str] = []
            while time.time() < end_time:
                try:
                    if chan.recv_ready():
                        data = chan.recv(65535).decode("utf-8", errors="ignore")
                        chunk.append(data)
                        time.sleep(0.05)
                    else:
                        time.sleep(0.05)
                except socket.timeout:
                    break
            outs.append(f"\n################################################ {cmd}\n" + "".join(chunk))

        try:
            chan.close()
        finally:
            client.close()

        display = device.get("display_name") or host_for_connect
        return SSHResult(host=display, ok=True, output="\n".join(outs))
    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        display = device.get("display_name") or host_for_connect
        return SSHResult(host=display, ok=False, error=f"{type(e).__name__}: {e}")


def _write_output(output_dir: Path, host_label: str, content: str, prefix: Optional[str] = None) -> Path:
    safe_host = host_label.replace("/", "_")
    name = f"{(prefix + '_') if prefix else ''}{safe_host}_{_timestamp()}.txt"
    fp = output_dir / name
    _write_text(fp, content)
    return fp


# ---------------------------- Device loading ---------------------------- #

def _normalize_device(
    dev: Dict[str, Any],
    default_username: Optional[str],
    keyring_service: str,
) -> Dict[str, Any]:
    """
    Normalize a single device dict:
      - connect_host: prefer 'ip', else 'host'/'hostname'
      - display_name: prefer 'hostname', else 'host'/'ip'
      - username: device['username'] or default_username
      - keyring_service default
    """
    connect_host = dev.get("ip") or dev.get("host") or dev.get("hostname")
    display_name = dev.get("hostname") or dev.get("host") or dev.get("ip") or "unknown"

    out = dict(dev)
    out["connect_host"] = connect_host
    out["display_name"] = display_name
    if default_username and not out.get("username"):
        out["username"] = default_username
    if not out.get("keyring_service"):
        out["keyring_service"] = keyring_service
    return out


def _load_devices(
    devices: Optional[Union[Iterable[Dict[str, Any]], str]] = None,
    device_groups: Optional[List[str]] = None,
    default_username: Optional[str] = None,
    keyring_service: str = DEFAULT_SERVICE,
) -> List[Dict[str, Any]]:
    """
    Load devices from a list or a JSON file. If JSON is a dict-of-lists,
    optionally filter by group names.
    """
    if isinstance(devices, (str, os.PathLike)):
        data = json.loads(Path(devices).read_text(encoding="utf-8"))
        if isinstance(data, list):
            raw = data
        elif isinstance(data, dict):
            # Select groups
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


def _load_commands(commands: Optional[Iterable[str]], commands_file: Optional[str]) -> List[str]:
    if commands is not None:
        return [c for c in commands if str(c).strip()]
    if commands_file:
        return [line.strip() for line in Path(commands_file).read_text(encoding="utf-8").splitlines() if line.strip()]
    raise ValueError("No commands provided. Pass a list or --commands-file")



def _print_summary(summary: dict) -> None:
    stats = summary.get("stats", {})
    print(f"Stats: ok={stats.get('ok',0)} failed={stats.get('failed',0)} total={stats.get('total',0)}")
    results = summary.get("results", [])
    if not results:
        return
    print("Results:")
    for r in results:
        host = r.get("host", "unknown")
        ok = r.get("ok", False)
        if ok:
            outfile = r.get("outfile") or ""
            print(f"  {host:25} OK    {outfile}")
        else:
            err = (r.get("error") or "").strip()
            print(f"  {host:25} FAIL  {err}")
# ---------------------------- Batch runner ---------------------------- #

def run_batch(
    commands: Optional[Iterable[str]] = None,
    devices: Optional[Union[Iterable[Dict[str, Any]], str]] = None,
    output_dir: Union[str, os.PathLike] = "./outputs",
    archive_dir: Optional[Union[str, os.PathLike]] = None,
    max_workers: int = 20,
    timeout: int = 20,
    cmd_delay: float = 0.2,
    per_host_prefix: Optional[str] = None,
    also_return_outputs: bool = True,
    write_json_summary: bool = True,
    summary_filename: str = "summary.json",
    device_groups: Optional[List[str]] = None,        # NEW
    default_username: Optional[str] = None,           # NEW
    keyring_service: str = DEFAULT_SERVICE,           # NEW
) -> Dict[str, Any]:
    """
    Programmatic API to run commands on multiple devices.
    Uses keyring if password not provided.
    Supports dict-of-lists device JSON with optional group filtering.
    """
    if not commands:
        commands = COMMANDS
    if not devices:
        devices = DEFAULT_DEVICES_FILE
    out_dir = Path(output_dir)
    _ensure_dir(out_dir)
    arc_dir = Path(archive_dir) if archive_dir else None
    if arc_dir:
        _ensure_dir(arc_dir)

    # Default groups fallback: use TARGET if device_groups not provided
    eff_groups = device_groups if device_groups is not None else TARGET
    device_list = _load_devices(
        devices,
        device_groups=eff_groups,
        default_username=default_username,
        keyring_service=keyring_service,
    )

    results: List[SSHResult] = []
    stats = {"ok": 0, "failed": 0, "total": len(device_list)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = {
            pool.submit(_ssh_run_one, dev, list(commands), timeout, cmd_delay): dev for dev in device_list
        }
        for fut in concurrent.futures.as_completed(futs):
            dev = futs[fut]
            host_label = dev.get("display_name") or dev.get("hostname") or dev.get("host") or dev.get("ip") or "unknown"
            res: SSHResult = fut.result()
            if res.ok:
                stats["ok"] += 1
                outfile = _write_output(out_dir, host_label, res.output, prefix=per_host_prefix)
                res.outfile = outfile
                if arc_dir:
                    _write_text(arc_dir / outfile.name, res.output)
            else:
                stats["failed"] += 1
            results.append(res)

    summary = {
        "stats": stats,
        "results": [{k: v for k, v in r.to_dict().items() if k != "output"} for r in results],
        "output_dir": str(out_dir.resolve()),
    }
    if write_json_summary:
        _write_text(out_dir / summary_filename, json.dumps(summary, indent=2))
    _print_summary(summary)
    return summary


# ---------------------------- CLI facade ---------------------------- #

def main(
    a: Optional[bool] = None,                # archive existing txt before run
    l: Optional[bool] = None,                # loop mode (run once between 20:00-21:00 daily)
    commands: Optional[List[str]] = None,
    commands_file: Optional[str] = None,
    devices: str | List[Dict[str, Any]] | None = None,
    output_dir: Optional[str] = None,
    archive_dir: Optional[str] = None,
    max_workers: Optional[int] = None,
    timeout: Optional[int] = None,
    per_host_prefix: Optional[str] = None,
    device_groups: Optional[List[str]] = None,
    default_username: Optional[str] = None,
    keyring_service: str = DEFAULT_SERVICE,
) -> Optional[Dict[str, Any]]:
    """
    If an arg is None, fall back to defaults/environment.
    """
    out_dir = Path(output_dir or "./outputs")
    arc_dir = Path(archive_dir) if archive_dir else None
    if arc_dir:
        _ensure_dir(arc_dir)

    # Load commands (fallback to default COMMANDS if none provided)
    if commands is not None or commands_file:
        cmd_list = _load_commands(commands, commands_file)
    else:
        cmd_list = COMMANDS

    # Load devices; default to device.json next to this script if not provided
    if devices is None:
        devices_input = DEFAULT_DEVICES_FILE
    else:
        devices_input = devices

    # Pre-archive if requested
    if a:
        if not arc_dir:
            # default archive under output_dir/archives
            arc_dir = out_dir / "archives"
            _ensure_dir(arc_dir)
        _archive_current_txt(out_dir, arc_dir)

    def _one_run():
        return run_batch(
            commands=cmd_list,
            devices=devices_input,
            output_dir=out_dir,
            archive_dir=arc_dir,
            max_workers=max_workers or 20,
            timeout=timeout or 20,
            per_host_prefix=per_host_prefix,
            write_json_summary=True,
            device_groups=device_groups,
            default_username=default_username,
            keyring_service=keyring_service,
        )

    if l:
        print("Loop mode enabled: will run once between 20:00–21:00 local time, then sleep ~57 minutes.")
        has_run_today = False
        while True:
            now = datetime.now()
            if 20 <= now.hour < 21 and not has_run_today:
                print(f"[{now}] Window open, running once...")
                _one_run()
                has_run_today = True
            elif now.hour >= 21:
                has_run_today = False  # reset after 9 PM
            print("In the loop...")
            time.sleep(57 * 60)
    else:
        return _one_run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH batch runner (keyring + group-aware)")
    # existing flags
    parser.add_argument("-a", action="store_true", help="Archive existing .txt files in output dir before run")
    parser.add_argument("-l", action="store_true", help="Enable loop mode (run once between 8–9 PM, then repeat)")
    # new knobs
    parser.add_argument("--commands-file", help="Path to file with one command per line (optional; defaults to built-in commands)")
    parser.add_argument("--devices", help="Path to device.json (dict-of-lists supported); defaults to device.json next to this script")
    parser.add_argument("--output-dir", default="./outputs", help="Directory to write per-host outputs")
    parser.add_argument("--archive-dir", help="Optional archive directory (default: outputs/archives)")
    parser.add_argument("--max-workers", type=int, default=20, help="Concurrency")
    parser.add_argument("--timeout", type=int, default=20, help="Per-device timeout (seconds)")
    parser.add_argument("--prefix", dest="per_host_prefix", help="Filename prefix for per-host outputs")
    parser.add_argument("--device-groups", nargs="+", help="Only run against these groups from the devices JSON")
    parser.add_argument("--default-username", help="Username to use when device entry omits it (keyring lookup applies)")
    parser.add_argument("--keyring-service", default=DEFAULT_SERVICE, help=f"Keyring service name (default: {DEFAULT_SERVICE})")

    args = parser.parse_args()

    try:
        main(
            a=args.a,
            l=args.l,
            commands=None,
            commands_file=args.commands_file,
            devices=args.devices,
            output_dir=args.output_dir,
            archive_dir=args.archive_dir,
            max_workers=args.max_workers,
            timeout=args.timeout,
            per_host_prefix=args.per_host_prefix,
            device_groups=args.device_groups,
            default_username=args.default_username,
            keyring_service=args.keyring_service,
        )
    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

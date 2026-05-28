#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional, Union

try:
    import keyring
except Exception:
    keyring = None  # type: ignore[assignment]

try:
    from netmiko import ConnectHandler
except Exception:
    ConnectHandler = None  # type: ignore[assignment]


print_lock = Lock()

PER_CMD_TIMEOUT = 30.0
IDLE_QUIET = 7.0

DEFAULT_DEVICES_FILE = (
    Path(__file__).with_name("devices.json")
    if Path(__file__).with_name("devices.json").is_file()
    else Path(__file__).with_name("device.json")
)
DEFAULT_SERVICE = "py_ssh"
DEFAULT_USERNAME = "wder1"
DEFAULT_PORT = 22
DEFAULT_DEVICE_TYPE = "cisco_ios"

TARGET = ["nipr"]
THREAD = 20

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

DEVICE_TYPE_KEYS = ("device_type", "platform", "netmiko_device_type", "os")
DEFAULT_GROUP_KEYS = ("_defaults", "defaults", "__defaults__")


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


def _prefill_passwords(
    devices: List[Dict[str, Any]],
    default_username: Optional[str],
    keyring_service: Optional[str],
    prompt_if_missing: bool,
) -> None:
    cache: Dict[tuple, Optional[str]] = {}

    for d in devices:
        user = d.get("username") or default_username or DEFAULT_USERNAME
        svc = d.get("keyring_service") or keyring_service or DEFAULT_SERVICE
        d["username"] = user
        d.setdefault("keyring_service", svc)

        pw = d.get("password")
        key = (svc, user)
        if not pw:
            if key not in cache:
                cache[key] = _get_password_from_keyring(svc, user)
            pw = cache[key]

        if not pw and prompt_if_missing:
            with print_lock:
                print(f"[auth] password prompt for user '{user}' (service '{svc}')", flush=True)
            pw = getpass.getpass(f"Enter password for {user}: ")
            cache[key] = pw

        d["password"] = pw


def _resolve_auth(device: Dict[str, Any]) -> Dict[str, Any]:
    username = device.get("username") or DEFAULT_USERNAME
    device["username"] = username
    if not device.get("password"):
        raise RuntimeError(f"Missing password for {username} (not prefilled)")
    return device


def _split_command(raw_command: str) -> tuple[str, str]:
    line = raw_command.rstrip("\n")
    if ";" in line:
        command, label = line.split(";", 1)
        return command.strip(), label.strip()
    return line.strip(), line.strip()


def _device_type_from(device: Dict[str, Any], default_device_type: Optional[str]) -> str:
    for key in DEVICE_TYPE_KEYS:
        value = device.get(key)
        if value:
            return str(value)
    return default_device_type or DEFAULT_DEVICE_TYPE


def _ssh_run_one(
    device: Dict[str, Any],
    commands: List[str],
    timeout: int = 20,
    *,
    default_device_type: Optional[str] = None,
    idle_quiet: Optional[float] = None,
    per_cmd_timeout: Optional[float] = None,
    initial_wait: Optional[float] = None,
) -> Dict[str, Any]:
    host = device.get("connect_host") or device.get("host") or device.get("ip")
    hostname = device.get("hostname") or device.get("display_name") or host
    ip = device.get("ip") or host
    display = f"{hostname} | {ip}"
    port = int(device.get("port") or DEFAULT_PORT)
    device_type = _device_type_from(device, default_device_type)

    if not host:
        return {"host": hostname or "unknown", "ip": ip, "ok": False, "output": "", "error": "No host/IP provided"}
    if ConnectHandler is None:
        return {"host": hostname, "ip": ip, "ok": False, "output": "", "error": "netmiko not installed"}

    try:
        _resolve_auth(device)
        username = device["username"]
        password = device["password"]

        with print_lock:
            print(f"[connect] {display} as {username} ({device_type})", flush=True)

        conn_params: Dict[str, Any] = {
            "device_type": device_type,
            "host": host,
            "username": username,
            "password": password,
            "port": port,
            "conn_timeout": timeout,
            "auth_timeout": timeout,
            "banner_timeout": timeout,
            "timeout": timeout,
            "fast_cli": False,
            "allow_agent": False,
            "use_keys": False,
        }
        if device.get("secret"):
            conn_params["secret"] = device["secret"]

        conn = ConnectHandler(**conn_params)
        if device.get("enable") or device.get("secret"):
            conn.enable()

        with print_lock:
            print(f"[connected] {display}", flush=True)

        if initial_wait and initial_wait > 0:
            time.sleep(float(initial_wait))

        outs: List[str] = []
        effective_idle_quiet = float(idle_quiet) if idle_quiet is not None else IDLE_QUIET
        effective_per_cmd_timeout = float(per_cmd_timeout) if per_cmd_timeout is not None else PER_CMD_TIMEOUT

        for raw_cmd in commands:
            cmd, label = _split_command(raw_cmd)
            if not cmd:
                continue

            output = conn.send_command_timing(
                cmd,
                strip_command=True,
                strip_prompt=True,
                last_read=effective_idle_quiet,
                read_timeout=effective_per_cmd_timeout,
            )
            outs.append(f"\n################################################ {label} ({cmd})\n{output}")
            if output and not output.endswith("\n"):
                outs.append("\n")

        conn.disconnect()
        with print_lock:
            print(f"[done] {display}", flush=True)
        return {"host": hostname, "ip": ip, "ok": True, "output": "".join(outs), "error": None}

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
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", host_label or "unknown").replace("_", "-")
    if append_label:
        out_fp = output_dir / f"{safe_host}-{append_label}.txt"
    else:
        out_fp = output_dir / f"{(prefix + '-' if prefix else '')}{safe_host}_{_timestamp()}.txt"
    _write_text(out_fp, content, append=False)
    return out_fp


def _parse_txt(p: Path) -> List[str]:
    return [
        ln.strip()
        for ln in p.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]


def _looks_like_device_dict(item: Dict[str, Any]) -> bool:
    return any(k in item for k in ("host", "hostname", "ip", "connect_host"))


def _as_device_dict(item: Union[str, Dict[str, Any]], defaults: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    base = dict(defaults or {})
    if isinstance(item, dict):
        base.update(item)
    else:
        base["host"] = str(item)
    return base


def _flatten_json_devices(data: Any, groups: Optional[List[str]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if isinstance(data, list):
        return [_as_device_dict(item) for item in data]
    if not isinstance(data, dict):
        return [_as_device_dict(str(data))]

    global_defaults: Dict[str, Any] = {}
    for key in DEFAULT_GROUP_KEYS:
        if isinstance(data.get(key), dict):
            global_defaults.update(data[key])

    if _looks_like_device_dict(data):
        return [_as_device_dict(data, global_defaults)]

    selected_keys = groups if groups else [k for k in data.keys() if k not in DEFAULT_GROUP_KEYS]
    for group_name in selected_keys:
        if group_name not in data:
            continue
        group_value = data[group_name]
        group_defaults = dict(global_defaults)

        if isinstance(group_value, dict) and "devices" in group_value:
            group_defaults.update({k: v for k, v in group_value.items() if k != "devices"})
            items = group_value.get("devices", [])
        else:
            items = group_value

        if isinstance(items, list):
            out.extend(_as_device_dict(item, group_defaults) for item in items)
        else:
            out.append(_as_device_dict(items, group_defaults))
    return out


def _normalize_device(
    dev: Dict[str, Any],
    default_username: Optional[str],
    keyring_service: Optional[str],
    default_device_type: Optional[str],
) -> Dict[str, Any]:
    out = dict(dev)
    connect_host = out.get("ip") or out.get("host") or out.get("hostname")
    display_name = out.get("hostname") or out.get("host") or out.get("ip") or "unknown"

    out["connect_host"] = connect_host
    out["display_name"] = display_name
    out.setdefault("port", DEFAULT_PORT)
    if default_username and not out.get("username"):
        out["username"] = default_username
    if not out.get("keyring_service"):
        out["keyring_service"] = keyring_service or DEFAULT_SERVICE
    out["device_type"] = _device_type_from(out, default_device_type)
    return out


def _load_devices(
    devices: Optional[Union[Iterable[Union[Dict[str, Any], str]], str]] = None,
    device_groups: Optional[List[str]] = None,
    default_username: Optional[str] = None,
    keyring_service: Optional[str] = None,
    default_device_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    raw_devices: List[Dict[str, Any]]

    if devices is None:
        p = DEFAULT_DEVICES_FILE
        if not p.is_file():
            raise ValueError(f"--devices not provided and default file not found: {p}")
        raw_devices = _load_devices_from_file(p, device_groups)
        with print_lock:
            print(f"[devices] loaded {len(raw_devices)} from default {p}", flush=True)
    elif isinstance(devices, (str, os.PathLike)):
        p = Path(devices)
        if p.is_file():
            raw_devices = _load_devices_from_file(p, device_groups)
            with print_lock:
                print(f"[devices] loaded {len(raw_devices)} from {p}", flush=True)
        else:
            raw_devices = [{"host": str(devices)}]
            with print_lock:
                print(f"[devices] using single host {devices}", flush=True)
    elif isinstance(devices, (list, tuple, set)):
        raw_devices = []
        for entry in devices:
            if isinstance(entry, (str, os.PathLike)) and Path(entry).is_file():
                raw_devices.extend(_load_devices_from_file(Path(entry), device_groups))
            else:
                raw_devices.append(_as_device_dict(entry))
        with print_lock:
            print(f"[devices] loaded {len(raw_devices)} from CLI", flush=True)
    else:
        raw_devices = [_as_device_dict(item) for item in list(devices)]

    return [
        _normalize_device(d, default_username, keyring_service, default_device_type)
        for d in raw_devices
    ]


def _load_devices_from_file(p: Path, device_groups: Optional[List[str]]) -> List[Dict[str, Any]]:
    if p.suffix.lower() == ".json":
        return _flatten_json_devices(json.loads(p.read_text(encoding="utf-8")), device_groups or TARGET)
    return [{"host": host} for host in _parse_txt(p)]


def _load_commands(positional: Optional[List[str]] = None, file_path: Optional[str] = None) -> List[str]:
    if positional:
        with print_lock:
            print(f"[commands] using {len(positional)} from CLI", flush=True)
        return [c for c in positional if str(c).strip()]

    if file_path:
        p = Path(file_path)
        if not p.is_file():
            raise ValueError(f"Commands file not found: {p}")
        cmds = _parse_txt(p)
        with print_lock:
            print(f"[commands] loaded {len(cmds)} from {p}", flush=True)
        return cmds

    with print_lock:
        print(f"[commands] using built-in defaults ({len(COMMANDS)})", flush=True)
    return COMMANDS[:]


def _print_summary(summary: dict) -> None:
    stats = summary.get("stats", {})
    results = summary.get("results", [])
    print("\n================ SUMMARY ================", flush=True)
    print(f"  Total: {stats.get('total', 0)}   OK: {stats.get('ok', 0)}   Failed: {stats.get('failed', 0)}", flush=True)

    if results:
        print("\n")
        print(f"  {'Host/Target:':30} {'Status:':15} {'File:'}")
        for r in results:
            host = r.get("host", "unknown")
            if r.get("ok"):
                print(f"  {host:30} {'OK':15} {r.get('outfile') or ''}")
            else:
                print(f"  {host:30} {'FAIL':15} {(r.get('error') or '').strip()}")
        print("\n")


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
    default_device_type: Optional[str] = None,
    *,
    prompt_if_missing: bool = False,
    idle_quiet: Optional[float] = None,
    per_cmd_timeout: Optional[float] = None,
    initial_wait: Optional[float] = None,
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
        default_device_type=default_device_type,
    )
    _prefill_passwords(normalized_devices, default_username, keyring_service, prompt_if_missing)
    cmd_list = _load_commands(commands, commands_file)

    results: List[Dict[str, Any]] = []
    ok = failed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_to_dev = {
            pool.submit(
                _ssh_run_one,
                d,
                cmd_list,
                timeout,
                default_device_type=default_device_type,
                idle_quiet=idle_quiet,
                per_cmd_timeout=per_cmd_timeout,
                initial_wait=initial_wait,
            ): d
            for d in normalized_devices
        }
        for fut in as_completed(fut_to_dev):
            res = fut.result()
            results.append(res)
            host_label = res.get("host", "unknown")
            if res.get("ok"):
                ok += 1
                outfile = _write_output(out_dir, host_label, res.get("output", ""), append, per_host_prefix)
                res["outfile"] = str(outfile)
            else:
                failed += 1
                _write_output(out_dir, host_label, f"ERROR: {res.get('error', 'unknown')}\n", "errors", None)

    return {
        "stats": {"ok": ok, "failed": failed, "total": ok + failed},
        "results": results,
        "output_dir": str(out_dir),
        "archive_dir": str(arch_dir),
    }


def main(
    a: Optional[bool] = None,
    l: Optional[bool] = None,
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
    diff: Optional[bool] = False,
    default_device_type: Optional[str] = None,
    initial_wait: Optional[float] = None,
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
                default_device_type=default_device_type,
                initial_wait=initial_wait,
                prompt_if_missing=True,
            )
            _print_summary(batch)
        except Exception as e:
            with print_lock:
                print(f"[fatal] {e}", file=sys.stderr, flush=True)
            sys.exit(1)

        if not l:
            break
        time.sleep(60)

    if diff:
        print("================ DIFF sh ================")
        print("[info] diff flag is on, calling diff_sh.py")
        subprocess.run([sys.executable, "diff_sh.py"], check=True)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Netmiko SSH batch runner")
    parser.add_argument("-a", action="store_true", help="Archive existing .txt files in output dir before run")
    parser.add_argument("-l", action="store_true", help="Loop mode: repeat the run every 60s")
    parser.add_argument(
        "--devices",
        nargs="+",
        default=None,
        help=(
            "One or more device IPs/hostnames, or path(s) to device list file(s). "
            "Supports .json or .txt. Default: devices.json, then device.json"
        ),
    )
    parser.add_argument("--commands", dest="commands_flag", nargs="+", help="One or more commands to run")
    parser.add_argument("--commands-file", help="File with one command per line")
    parser.add_argument("commands_positional", nargs="*", help="Commands to run")
    parser.add_argument("--output-dir", type=Path, default=Path("./outputs"), metavar="DIR")
    parser.add_argument("--archive-dir", type=Path, metavar="DIR")
    parser.add_argument("--max-workers", type=int, default=THREAD, metavar="N")
    parser.add_argument("--timeout", type=int, default=20, metavar="SECONDS")
    parser.add_argument("--prefix", dest="per_host_prefix", metavar="LABEL")
    parser.add_argument("--device-groups", nargs="+", metavar="GROUP")
    parser.add_argument("--default-username", metavar="USER")
    parser.add_argument("--keyring-service", default=DEFAULT_SERVICE, metavar="SERVICE")
    parser.add_argument("--append", required=False, metavar="LABEL")
    parser.add_argument("--device-type", default=None, help=f"Netmiko device_type fallback (default: {DEFAULT_DEVICE_TYPE})")
    parser.add_argument("--idle-quiet", type=float, default=None, metavar="SECONDS")
    parser.add_argument("--per-cmd-timeout", type=float, default=None, metavar="SECONDS")
    parser.add_argument("--initial-wait", type=float, default=None, metavar="SECONDS")
    parser.add_argument("-d", "--diff", action="store_true", help="call diff_sh")
    return parser


if __name__ == "__main__":
    parser = _build_parser()
    args = parser.parse_args()

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

    cli_commands = args.commands_flag if args.commands_flag else args.commands_positional

    try:
        main(
            a=args.a,
            l=args.l,
            commands=cli_commands if cli_commands else None,
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
            diff=args.diff,
            default_device_type=args.device_type,
            initial_wait=args.initial_wait,
        )
    except KeyboardInterrupt:
        with print_lock:
            print("[interrupt] user cancelled", file=sys.stderr, flush=True)

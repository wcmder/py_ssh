#!/usr/bin/env python3
"""Read-only IOS XE SD-WAN VPN neighbor/ARP audit. See VPN_AUDIT.md."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import glob
import ipaddress
import logging
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable

import py_ssh as ssh


# This is the entire application show-command allowlist. Commands containing
# placeholders are expanded only with validated router-discovered names.
COMMANDS = [
    ("version", "show version", "Always: platform, release, hostname"),
    ("vrfs", "show vrf", "Always: VRF inventory; fallback on unsupported"),
    ("vrfs_fallback", "show ip vrf brief", "Fallback for show vrf"),
    ("membership", "show ip vrf interfaces", "Always: interface-to-VRF mapping"),
    ("vrf_config", "show sdwan running-config | section ^vrf definition", "Verify VPN mapping"),
    ("vrf_config_fallback", "show running-config | section ^vrf definition", "Fallback on unsupported"),
    ("interfaces", "show sdwan running-config | section ^interface", "Always: VRFs, local IPs, virtual addresses"),
    ("interfaces_fallback", "show running-config | section ^interface", "Fallback on unsupported"),
    ("arp", "show ip arp vrf <VRF>", "Selected VRF: IP/MAC/interface mapping"),
    ("arp_fallback", "show arp vrf <VRF>", "Fallback on unsupported"),
    ("interface", "show interfaces <INTERFACE>", "Each selected interface and unique physical parent"),
    ("ip_interface", "show ip interface <INTERFACE>", "Each selected logical interface: local addresses"),
    ("cdp_status", "show cdp", "Always: global CDP availability"),
    ("cdp_interfaces", "show cdp interface", "Always: interface CDP availability"),
    ("cdp", "show cdp neighbors detail", "Always, independent of ARP counts"),
    ("lldp_status", "show lldp", "Always: global LLDP availability"),
    ("lldp_interfaces", "show lldp interface", "Always: interface LLDP availability"),
    ("lldp", "show lldp neighbors detail", "Always, independent of ARP counts"),
]
TEMPLATES = {key: command for key, command, _ in COMMANDS}
GOOD = {"success_with_entries", "success_empty"}
COLORS = {"Green": "C6EFCE", "Red": "FFC7CE", "Amber": "FFEB9C", "Neutral": "FFFFFF"}
SAFE_NAME = re.compile(r"^[A-Za-z0-9_./:-]+$")
IF_TOKEN = re.compile(r"\b(?:GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE|FastEthernet|Ethernet|Port-channel|Loopback|Tunnel|Vlan|BDI|Gi|Te|Twe|Fo|Hu|Fa|Eth|Et|Po|Lo|Tu|Vl)\d[\w/.:_-]*", re.I)
PREFIXES = [("TwentyFiveGigE", ("twe",)), ("TenGigabitEthernet", ("te",)),
            ("FortyGigabitEthernet", ("fo",)), ("HundredGigE", ("hu",)),
            ("GigabitEthernet", ("gi",)), ("FastEthernet", ("fa",)),
            ("Ethernet", ("eth", "et")), ("Port-channel", ("po",)),
            ("Loopback", ("lo",)), ("Tunnel", ("tu",)), ("Vlan", ("vl",)), ("BDI", ())]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def ssh_diagnostics(path: Path):
    """Keep Paramiko's background-thread tracebacks out of the console."""
    logger = logging.getLogger("paramiko")
    previous = (logger.handlers[:], logger.level, logger.propagate)
    handler = logging.FileHandler(path, encoding="utf-8", delay=True)
    handler.setLevel(logging.ERROR)
    handler.setFormatter(logging.Formatter("%(asctime)s %(name)s [%(threadName)s] %(levelname)s: %(message)s"))
    logger.handlers = [handler]
    logger.setLevel(logging.ERROR)
    logger.propagate = False
    try:
        yield
    finally:
        logger.handlers, level, logger.propagate = previous
        logger.setLevel(level)
        handler.close()


def interface_name(value: str) -> str:
    value = value.strip().rstrip(",")
    match = re.fullmatch(r"([A-Za-z-]+)(\d[\w/.:_-]*)", value)
    if not match:
        return value
    prefix, number = match.groups()
    for full, aliases in PREFIXES:
        if prefix.lower() in (full.lower(), *aliases):
            return full + number
    return value


def physical_parent(interface: str) -> str:
    if interface.startswith(("GigabitEthernet", "TenGigabitEthernet", "TwentyFiveGigE", "FortyGigabitEthernet", "HundredGigE", "FastEthernet", "Ethernet")):
        return interface.split(".", 1)[0]
    return ""  # An SVI, tunnel, loopback or bundle has no inferred physical port.


def mac_address(value: str) -> str:
    if not re.fullmatch(r"(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}|(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}|[0-9a-fA-F]{12}", value):
        return ""
    raw = re.sub(r"[.:-]", "", value).lower()
    if raw == "0" * 12 or int(raw[:2], 16) & 1:
        return ""
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2))


def domain_name(value: str) -> str:
    value = value.strip().lstrip(".").rstrip(".").lower()
    labels = value.split(".")
    if len(labels) < 2 or len(value) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise ValueError("Domain must be a DNS domain such as example.org")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("Domain must not be an IP address")


def neighbor_domain(name: str, domain: str | list[str]) -> str:
    domains = [domain] if isinstance(domain, str) else domain
    name = name.strip().rstrip(".").lower()
    # A serial suffix in parentheses is not part of an advertised DNS name.
    name = re.sub(r"\([A-Za-z0-9_-]+\)$", "", name)
    try:
        ipaddress.ip_address(name)
        return "Neighbor domain undetermined"
    except ValueError:
        pass
    if mac_address(name):
        return "Neighbor domain undetermined"
    if "." not in name:
        if re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", name) and re.search(r"[a-z_]", name):
            return "Neighbor hostname without domain"
        return "Neighbor domain undetermined"
    # Discovery IDs are advertised names, not DNS lookups. Network devices often
    # use underscores; accept those here while keeping configured domains strict.
    if len(name) > 253 or any(not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label)
                              for label in name.split(".")):
        return "Neighbor domain undetermined"
    if any(name.endswith("." + suffix) for suffix in domains):
        return "Our domain"
    if name in domains:
        return "Neighbor domain undetermined"
    return "Different advertised domain"


def split_values(values: str | int | list) -> list[str]:
    items = values if isinstance(values, list) else [values]
    return list(dict.fromkeys(token for item in items for token in re.split(r"[,\s]+", str(item).strip()) if token))


def vpn_numbers(values: str | int | list) -> list[int]:
    numbers = list(dict.fromkeys(int(value) for value in split_values(values)))
    if not numbers or any(not 1 <= number <= 65525 or number == 512 for number in numbers):
        raise ValueError("Select service VPNs from 1–65525, excluding management VPN 512")
    return numbers


def vrf_overrides(values: str | list[str] | None, vpns: list[int]) -> dict[str, str]:
    overrides = {}
    for value in split_values(values or []):
        if "=" in value:
            vpn, name = value.split("=", 1)
            vpn = str(int(vpn))
            if int(vpn) not in vpns:
                raise ValueError(f"VRF override VPN {vpn} is not selected")
        elif len(vpns) == 1:
            vpn, name = str(vpns[0]), value
        else:
            raise ValueError("For multiple VPNs use --vrf 20=LAN20 30=LAN30")
        if not SAFE_NAME.fullmatch(name):
            raise ValueError("Invalid VRF name")
        if vpn in overrides and overrides[vpn] != name:
            raise ValueError(f"Conflicting VRF overrides for VPN {vpn}")
        overrides[vpn] = name
    return overrides


@dataclass
class Result:
    command: str
    purpose: str
    timestamp: str = field(default_factory=now)
    status: str = "pending"
    output: str = ""
    error: str = ""
    vrf: str = ""

    def parsed(self, entries: Any) -> Any:
        self.status = "success_with_entries" if entries else "success_empty"
        return entries


class Collector:
    def __init__(self, conn: Any, timeout: float):
        self.conn, self.timeout = conn, timeout
        self.results: list[Result] = []
        self.broken = False
        self.vrf = ""

    def run(self, key: str, value: str = "") -> Result:
        if value and not SAFE_NAME.fullmatch(value):
            raise ValueError(f"Unsafe CLI identifier: {value!r}")
        command = TEMPLATES[key].replace("<VRF>", value).replace("<INTERFACE>", value)
        result = Result(command, key, vrf=self.vrf)
        self.results.append(result)
        if self.broken:
            result.status, result.error = "failed", "Session stopped after command exception; reconnect required"
            return result
        try:
            result.output = self.conn.send_command(command, strip_command=True, strip_prompt=True,
                                                   read_timeout=self.timeout, cmd_verify=False)
        except Exception as exc:
            result.status, result.error = "failed", str(exc)
            # Do not let late output from a timed-out command enter another block.
            self.broken = True
            return result
        return self.check_output(result, key)

    @staticmethod
    def check_output(result: Result, key: str) -> Result:
        text = result.output
        if re.search(r"(?im)^\s*%.*(?:invalid input|unrecognized|unknown command|incomplete command|ambiguous command|not supported)", text):
            result.status, result.error = "unsupported", text.strip()
        elif re.search(r"(?i)(?:not enabled|is disabled|not running)", text) and key.startswith(("cdp", "lldp")):
            result.status, result.error = "disabled", text.strip()
        elif re.search(r"(?im)^\s*%|authorization failed|permission denied|access denied|error opening", text):
            result.status, result.error = "failed", text.strip()
        elif not text.strip():
            result.status, result.error = "parse_error", "Blank output: empty result cannot be confirmed"
        else:
            result.status = "received"
        return result

    def get(self, key: str, parser: Callable, value: str = "", fallback: str = "") -> tuple[Result, Any]:
        result = self.run(key, value)
        if result.status in {"unsupported", "missing"} and fallback:
            result = self.run(fallback, value)
        if result.status != "received":
            return result, None
        try:
            return result, result.parsed(parser(result.output))
        except (ValueError, IndexError) as exc:
            result.status, result.error = "parse_error", str(exc)
            return result, None


def saved_command_key(command: str) -> str:
    """Normalize CLI whitespace and common show abbreviations, not VRF names."""
    command = " ".join(command.strip().split())
    command = re.sub(r"^sh\b", "show", command, flags=re.I)
    command = re.sub(r"^show (?:int|interface)\b", "show interfaces", command, flags=re.I)
    command = re.sub(r"^show ip int\b", "show ip interface", command, flags=re.I)
    command = re.sub(r"\s*\|\s*", " | ", command)
    # Interface abbreviations in arguments must agree with live normalization.
    tokens = command.split()
    if tokens and IF_TOKEN.fullmatch(tokens[-1]):
        tokens[-1] = interface_name(tokens[-1])
    return " ".join(tokens)


class SavedCollector(Collector):
    """Replay one saved router snapshot; never establishes an SSH connection."""
    def __init__(self, path: Path):
        super().__init__(None, 0)
        self.path = path
        text = path.read_text(encoding="utf-8-sig")
        headers = list(re.finditer(r"(?m)^#{16,}[ \t]*([^\r\n]*)", text))
        if not headers:
            raise ValueError("No saved command blocks found; use raw output from this audit or py_ssh.py")
        preamble = text[:headers[0].start()]
        def metadata(label: str) -> str:
            match = re.search(rf"(?m)^{re.escape(label)}:[ \t]*(.*)$", preamble)
            return match.group(1).strip() if match else ""
        self.router_name = metadata("Router name")
        self.ssh_address = metadata("SSH address")
        if not self.ssh_address:
            # Historical audit files include the SSH IPv4 address in the filename.
            matches = re.findall(r"-(\d{1,3}(?:\.\d{1,3}){3})(?=[_-]|$)", path.stem)
            if matches:
                try:
                    self.ssh_address = str(ipaddress.IPv4Address(matches[-1]))
                except ValueError:
                    pass
        self.blocks: list[Result] = []
        for index, header in enumerate(headers):
            label = header.group(1).strip()
            match = re.search(r"\((.*)\)$", label)
            command = match.group(1).strip() if match else label
            if not re.match(r"(?:sh|show)\s+", command, re.I):
                continue  # Skip generated VRF/router summaries and terminal setup.
            end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
            body = text[header.end():end].lstrip("\r\n")
            fields = {}
            while True:
                field_match = re.match(r"(Timestamp UTC|VRF|Status):[ \t]*([^\r\n]*)(?:\r?\n|$)", body)
                if not field_match:
                    break
                fields[field_match.group(1)] = field_match.group(2).strip()
                body = body[field_match.end():]
            error = ""
            if "Status" in fields:
                parts = re.split(r"(?m)^ERROR:[ \t]*", body, maxsplit=1)
                body = parts[0]
                if len(parts) > 1:
                    error = parts[1].strip()
            self.blocks.append(Result(command, "saved", timestamp=fields.get("Timestamp UTC", ""),
                status=fields.get("Status", "received"), output=body.rstrip(), error=error,
                vrf=fields.get("VRF", "")))
        if not self.blocks:
            raise ValueError("No recognizable show command blocks found in saved file")

    def run(self, key: str, value: str = "") -> Result:
        if value and not SAFE_NAME.fullmatch(value):
            raise ValueError(f"Unsafe CLI identifier: {value!r}")
        command = TEMPLATES[key].replace("<VRF>", value).replace("<INTERFACE>", value)
        candidates = [block for block in self.blocks if saved_command_key(block.command) == saved_command_key(command)]
        scoped = [block for block in candidates if block.vrf == self.vrf]
        candidates = scoped or [block for block in candidates if not block.vrf]
        result = Result(command, key, timestamp="", vrf=self.vrf)
        self.results.append(result)
        if not candidates:
            result.status, result.error = "missing", "Command not present in saved file"
            return result
        saved = candidates[-1]
        result.timestamp, result.output = saved.timestamp, saved.output
        if saved.status in {"failed", "unsupported", "disabled", "missing"}:
            result.status, result.error = saved.status, saved.error or f"Saved command status: {saved.status}"
            return result
        # Reparse old parse errors with the current parser; do not reuse old scores.
        return self.check_output(result, key)


def saved_targets(values: list[str]) -> list[dict]:
    paths = []
    for value in values:
        path = Path(value).expanduser()
        matches = [path] if path.exists() else [Path(item) for item in sorted(glob.glob(str(path)))]
        if not matches:
            raise ValueError(f"Saved input not found: {value}")
        for match in matches:
            files = sorted(match.glob("*.txt")) if match.is_dir() else [match]
            if not files:
                raise ValueError(f"No .txt files in {match}")
            for item in files:
                if not item.is_file() or item.suffix.lower() != ".txt":
                    raise ValueError(f"Saved input must be a .txt file: {item}")
                if item.resolve() not in paths:
                    paths.append(item.resolve())
    return [{"hostname": path.stem, "connect_host": "", "saved_file": path} for path in paths]


def parse_vrfs(text: str) -> dict[str, set[str]]:
    if not re.search(r"(?i)\bName\b.*\b(?:RD|Interfaces)\b", text):
        raise ValueError("Unrecognized VRF table header")
    out: dict[str, set[str]] = {}
    current = ""
    for line in text.splitlines():
        if re.search(r"(?i)\bName\b.*\b(?:RD|Interfaces)\b", line):
            continue
        cols = line.split()
        if len(cols) >= 2 and (":" in cols[1] or cols[1] == "<not"):
            current = cols[0]
            out.setdefault(current, set())
        if current:
            out[current].update(interface_name(x) for x in IF_TOKEN.findall(line))
    return out


def parse_membership(text: str) -> dict[str, set[str]]:
    if not re.search(r"(?i)Interface\s+IP-Address\s+VRF", text):
        raise ValueError("Unrecognized interface/VRF table header")
    out: dict[str, set[str]] = {}
    for line in text.splitlines():
        cols = line.split()
        if cols and IF_TOKEN.fullmatch(cols[0]):
            if len(cols) < 3:
                raise ValueError(f"Incomplete VRF interface row: {line}")
            out.setdefault(cols[2], set()).add(interface_name(cols[0]))
    return out


def parse_vrf_config(text: str) -> set[str]:
    names = set(re.findall(r"(?m)^vrf definition\s+(\S+)", text))
    if not names:
        raise ValueError("No recognizable VRF definitions")
    return names


def parse_config(text: str) -> dict[str, dict]:
    blocks = re.split(r"(?m)^interface\s+", text)[1:]
    if not blocks:
        raise ValueError("No recognizable interface configuration")
    out = {}
    for block in blocks:
        lines = block.splitlines()
        name = interface_name(lines[0].strip())
        vrf = re.search(r"(?m)^\s+(?:ip )?vrf forwarding\s+(\S+)", block)
        ips = set(re.findall(r"(?m)^\s+ip address\s+(\d+\.\d+\.\d+\.\d+)\b", block))
        virtual = set(re.findall(r"(?m)^\s+(?:standby\s+(?:\d+\s+)?ip|vrrp\s+\d+\s+ip)\s+(\d+\.\d+\.\d+\.\d+)", block))
        # Include configured local MACs; operational output supplies burned-in/active MACs.
        macs = {mac_address(x) for x in re.findall(r"(?m)^\s+mac-address\s+(\S+)", block)} - {""}
        out[name] = {"vrf": vrf.group(1) if vrf else "", "ips": ips | virtual,
                     "macs": macs, "config": block}
    return out


def parse_arp(text: str) -> list[dict]:
    if not re.search(r"Protocol\s+Address\s+Age.*Hardware Addr.*Interface", text, re.I):
        if re.fullmatch(r"\s*(?:No ARP (?:entries|entry)(?: found)?\.?|Total (?:number of )?entries\s*:?\s*0)\s*", text, re.I):
            return []
        raise ValueError("Unrecognized ARP table header")
    rows = []
    for line in text.splitlines():
        if not line.strip() or re.search(r"Protocol\s+Address\s+Age.*Hardware Addr.*Interface", line, re.I):
            continue
        if re.fullmatch(r"\s*Total (?:number of )?entries\s*:?\s*\d+\s*", line, re.I):
            continue
        if not re.match(r"\s*Internet\s", line, re.I):
            raise ValueError(f"Unrecognized ARP row: {line}")
        cols = line.split()
        if len(cols) < 4:
            raise ValueError(f"Incomplete ARP row: {line}")
        ipaddress.IPv4Address(cols[1])
        incomplete = cols[3].lower() == "incomplete"
        interface = interface_name(cols[-1]) if IF_TOKEN.fullmatch(cols[-1]) else ""
        mac = mac_address(cols[3])
        if not incomplete and (not mac or not interface):
            raise ValueError(f"Invalid complete ARP row: {line}")
        rows.append({"IP address": cols[1], "MAC address": mac, "Logical interface": interface,
                     "Age": cols[2], "Complete": not incomplete})
    return rows


def parse_neighbors(text: str, protocol: str) -> list[dict]:
    if protocol == "CDP":
        blocks = re.split(r"(?m)^\s*Device ID:\s*", text)[1:]
    else:
        blocks = re.split(r"(?im)^\s*Local (?:Intf|Interface):\s*", text)[1:]
    if not blocks:
        if re.search(r"(?i)(?:Total (?:cdp )?entries displayed\s*:\s*0\b|Total (?:number of )?entries\s*:?\s*0\b|No (?:CDP |LLDP )?neighbors(?: found)?\b)", text):
            return []
        raise ValueError(f"Unrecognized {protocol} neighbor detail output")
    out = []
    for block in blocks:
        def find(pattern: str) -> str:
            match = re.search(pattern, block, re.M | re.I)
            return match.group(1).strip() if match else ""
        if protocol == "CDP":
            name = block.splitlines()[0].strip()
            local = find(r"^\s*Interface:\s*([^,\n]+)")
            port = find(r"Port ID \(outgoing port\):\s*([^\n]+)")
            model = find(r"^\s*Platform:\s*([^\n]+)")
            desc = find(r"^\s*Version\s*:\s*\n([\s\S]*?)(?:\n\s*advertisement|\n\s*Duplex|\n\s*---|\Z)")
        else:
            local = block.splitlines()[0].strip()
            name = find(r"^[ \t]*System Name:[ \t]*([^\n]*)")
            port = find(r"^[ \t]*Port id:[ \t]*([^\n]*)")
            model = ""
            desc = find(r"^\s*System Description:\s*\n?([\s\S]*?)(?:\n\s*Time remaining|\n\s*System Capabilities|\n\s*Enabled Capabilities|\Z)")
        if not IF_TOKEN.fullmatch(local):
            raise ValueError(f"Cannot identify {protocol} local interface: {local!r}")
        out.append({"Protocol": protocol, "Local interface": interface_name(local), "Neighbor name": name,
                    "Neighbor port": port, "Advertised platform": model, "System description": desc})
    totals = re.findall(r"(?i)Total (?:cdp )?entries displayed\s*:\s*(\d+)", text)
    if totals and int(totals[-1]) != len(out):
        raise ValueError(f"{protocol} parsed count does not match advertised total")
    return out


def parse_interface(text: str) -> dict:
    if not re.search(r"(?m)^\S+ is .*, line protocol is", text):
        raise ValueError("Unrecognized show interfaces output")
    macs = {mac_address(x) for x in re.findall(r"(?:address is|bia)\s+([0-9a-fA-F.:-]+)", text)} - {""}
    ips = set(re.findall(r"Internet address is\s+(\d+\.\d+\.\d+\.\d+)", text))
    return {"macs": macs, "ips": ips}


def parse_ip_interface(text: str) -> set[str]:
    if not re.search(r"(?m)^\S+ is .*, line protocol is", text):
        raise ValueError("Unrecognized show ip interface output")
    return set(re.findall(r"(?:Internet address is|Secondary address)\s+(\d+\.\d+\.\d+\.\d+)", text, re.I))


def parse_status(text: str, key: str) -> bool:
    patterns = {"cdp_status": r"Sending CDP packets|CDP is enabled|CDP version",
                "lldp_status": r"Status:\s*ACTIVE|LLDP.*(?:ACTIVE|enabled)|LLDP advertisements",
                "cdp_interfaces": r"Sending CDP packets|Encapsulation|No CDP interfaces",
                "lldp_interfaces": r"\bRx:\s*(?:enabled|disabled)|Receive:|LLDP.*(?:enabled|disabled)|No LLDP interfaces"}
    if not re.search(patterns[key], text, re.I):
        raise ValueError(f"Unrecognized {key} output")
    return True


def discovery_enabled(protocol: str, local: str, status: Result, interfaces: Result) -> bool:
    if status.status not in GOOD or interfaces.status not in GOOD:
        return False
    parent = physical_parent(local) or local
    text = interfaces.output
    if protocol == "CDP":
        for block in re.split(r"(?m)(?=^\S+ is )", text):
            if interface_name(block.split(" is ", 1)[0].strip()) in {local, parent}:
                return bool(re.search(r"Sending CDP packets", block, re.I))
    else:
        blocks = re.split(r"(?m)(?=^\S+:\s*$)", text)
        for block in blocks:
            heading = block.splitlines()[0].strip().rstrip(":") if block.splitlines() else ""
            if interface_name(heading) in {local, parent}:
                return bool(re.search(r"(?:Rx|Receive):\s*(?:enabled|yes)", block, re.I))
    return False


def classify(neighbors: list[dict], mac_count: int | None, errors: list[str]) -> tuple[str, str, str]:
    findings = {n["Domain classification"] for n in neighbors}
    if neighbors:
        finding = ("Different advertised domain" if "Different advertised domain" in findings else
                   "Neighbor hostname without domain" if "Neighbor hostname without domain" in findings else
                   "Neighbor domain undetermined" if "Neighbor domain undetermined" in findings else "Our domain")
    elif mac_count is None:
        finding = "ARP count unavailable"
    else:
        finding = "Likely third-party switch" if mac_count > 1 else "Unknown"
    if errors:
        return "Amber", "Collection incomplete", finding
    color = {"Our domain": "Green", "Different advertised domain": "Red", "Neighbor hostname without domain": "Red", "Neighbor domain undetermined": "Amber",
             "Likely third-party switch": "Red", "Unknown": "Neutral"}.get(finding, "Amber")
    observed = finding
    if color == "Neutral":
        observed = f"{mac_count} {'host' if mac_count == 1 else 'hosts'} found, likely not a switch"
    return color, finding, observed


def audit_vrf(vpn: int, vrf: str, collector: Collector, report: dict,
              args: argparse.Namespace, configs: dict, vrfs: dict, memberships: dict,
              known: set, discovery: dict, neighbors: list, config_result: Result,
              global_issues: list[str]) -> None:
    base = report["base"]
    issues = list(global_issues)

    def note(result: Result, label: str) -> None:
        if result.status not in GOOD:
            issues.append(f"{label}: {result.status}: {result.error}")

    if vrf not in known:
        raise ValueError(f"VPN {vpn}: VRF {vrf!r} not verified on router; use --vrf or inventory vpn_vrf_map for a named VRF")
    configs = configs or {}
    selected = set((vrfs or {}).get(vrf, set())) | set((memberships or {}).get(vrf, set()))
    selected.update(i for i, c in configs.items() if c["vrf"] == vrf)
    if not selected:
        report["error"] = "; ".join(issues)
    for interface in selected:
        if interface in configs and configs[interface]["vrf"] != vrf:
            issues.append(f"Conflicting VRF membership for {interface}")
    arp_result, arp = collector.get("arp", parse_arp, vrf, "arp_fallback")
    note(arp_result, "ARP")
    # Addresses can overlap between VRFs. Only addresses in THIS VRF are local
    # ownership evidence for this ARP table.
    own_ips = set().union(*(c["ips"] for c in configs.values() if c["vrf"] == vrf))
    own_macs = set().union(*(c["macs"] for c in configs.values())) if configs else set()
    interface_errors = {i: [] for i in selected}
    for interface in selected:
        if interface not in configs:
            interface_errors[interface].append("Interface missing from configuration; local/virtual ownership cannot be verified")
    for interface in sorted(selected | ({physical_parent(i) for i in selected} - {""})):
        result, data = collector.get("interface", parse_interface, interface)
        if data:
            if interface in selected:
                own_ips.update(data["ips"])
            own_macs.update(data["macs"])
        for logical in selected:
            if interface in {logical, physical_parent(logical)} and result.status not in GOOD:
                interface_errors[logical].append(f"{result.command}: {result.status}: {result.error}")
            if interface == physical_parent(logical) and data and not data["macs"]:
                interface_errors[logical].append(f"Local MAC unavailable for {interface}")
    for interface in sorted(selected):
        result, addresses = collector.get("ip_interface", parse_ip_interface, interface)
        own_ips.update(addresses or set())
        if result.status not in GOOD:
            interface_errors[interface].append(f"{result.command}: {result.status}: {result.error}")
    # Reject unexplained complete entries outside the discovered VPN interface set.
    if any(a["Complete"] and a["Logical interface"] not in selected for a in arp or []):
        issues.append("ARP includes interfaces absent from selected VRF discovery")
    count_trusted = arp_result.status in GOOD and config_result.status in GOOD
    for entry in arp or []:
        reason = ("Incomplete" if not entry["Complete"] else
                  "Router-owned IP" if entry["IP address"] in own_ips else
                  "Router-owned MAC" if entry["MAC address"] in own_macs else
                  "Outside selected interfaces" if entry["Logical interface"] not in selected else "Included")
        # Well-known HSRP/VRRP MACs alone do not prove local ownership.
        row = {**base, **entry, "Physical parent": physical_parent(entry["Logical interface"]), "Disposition": reason}
        report["arp"].append(row)
    for interface in sorted(selected):
        errors = issues + interface_errors[interface]
        parent = physical_parent(interface)
        matched = []
        for proto in ("CDP", "LLDP"):
            exact = [n for n in neighbors if n["Protocol"] == proto and n["Local interface"] == interface]
            candidates = exact or [n for n in neighbors if n["Protocol"] == proto and parent and n["Local interface"] == parent]
            for neighbor in candidates:
                n = {**base, **neighbor, "Logical interface": interface, "Physical parent": parent,
                     "Match scope": "Logical interface" if exact else "Physical parent",
                     "Domain classification": neighbor_domain(neighbor["Neighbor name"], args.domain)}
                matched.append(n)
                report["neighbors"].append(n)
            sr, ir, nr = discovery[proto]
            for r in (sr, ir, nr):
                if r.status not in GOOD:
                    errors.append(f"{r.command}: {r.status}: {r.error}")
            if not candidates and not discovery_enabled(proto, interface, sr, ir):
                errors.append(f"{proto} receive/discovery not verified on {parent or interface}")
        entries = [a for a in report["arp"] if a["Logical interface"] == interface and a["Disposition"] == "Included"]
        trusted = count_trusted and not interface_errors[interface]
        ip_count = len({a["IP address"] for a in entries}) if trusted else None
        mac_count = len({a["MAC address"] for a in entries}) if trusted else None
        color, classification, finding = classify(matched, mac_count, errors)
        if not matched and any(e.startswith(("show cdp", "show lldp", "CDP receive", "LLDP receive")) for e in errors):
            finding = "Neighbor absence unverified"
        def join(key: str) -> str:
            return "\n".join(f"{n['Protocol']}: {n[key]}" for n in matched)
        report["interfaces"].append({**base, "Logical interface": interface, "Physical parent": parent,
            "ARP IP count": ip_count, "Unique MAC count": mac_count,
            "Neighbor protocol": ", ".join(sorted({n["Protocol"] for n in matched})),
            "Neighbor name": join("Neighbor name"), "Neighbor port": join("Neighbor port"),
            "Advertised platform": join("Advertised platform"), "System description": join("System description"),
            "Match scope": join("Match scope"), "Classification": classification, "Observed finding": finding,
            "Neighbor": "\n".join(dict.fromkeys(n["Neighbor name"] for n in matched
                if n["Neighbor name"].strip())) or "Unknown",
            "Row color": color, "Collection errors": "\n".join(dict.fromkeys(errors)), "Timestamp UTC": now()})
    if not selected:
        report["error"] = "; ".join(issues)


def audit_device(device: dict, args: argparse.Namespace) -> dict:
    host = device.get("hostname") or device.get("display_name") or device["connect_host"]
    base = {"Router name": host, "SSH address": device["connect_host"], "VRF": ""}
    report: dict = {"interfaces": [], "arp": [], "neighbors": [], "collection": [], "base": base, "error": ""}
    conn, collector = None, None
    saved_file = device.get("saved_file")
    if saved_file:
        base["Source file"] = str(saved_file)
    issues: list[str] = []
    try:
        if saved_file:
            with ssh.print_lock:
                print(f"[load] {Path(saved_file).name}", flush=True)
            collector = SavedCollector(Path(saved_file))
            base["Router name"] = collector.router_name or host
            base["SSH address"] = collector.ssh_address
        else:
            ssh._resolve_auth(device)
            if ssh.ConnectHandler is None:
                raise RuntimeError("netmiko is not installed")
            with ssh.print_lock:
                print(f"[connect] {host} | {device['connect_host']}", flush=True)
            params = dict(device_type=ssh._device_type_from(device, args.device_type), host=device["connect_host"],
                          username=device["username"], password=device["password"], port=int(device.get("port") or 22),
                          conn_timeout=args.timeout, auth_timeout=args.timeout, banner_timeout=args.timeout,
                          timeout=args.timeout, fast_cli=False, allow_agent=False, use_keys=False)
            if device.get("secret"):
                params["secret"] = device["secret"]
            conn = ssh.ConnectHandler(**params)
            if device.get("enable") or device.get("secret"):
                conn.enable()
            with ssh.print_lock:
                print(f"[connected] {host} | {device['connect_host']}", flush=True)
            collector = Collector(conn, args.per_cmd_timeout)
        def note(result: Result, label: str) -> None:
            if result.status not in GOOD:
                issues.append(f"{label}: {result.status}: {result.error}")

        def parse_version(text: str) -> str:
            if not re.search(r"Cisco IOS|IOS XE", text):
                raise ValueError("Unrecognized IOS version output")
            return text

        version, _ = collector.get("version", parse_version)
        note(version, "Version")
        identity = re.search(r"(?m)^(\S+) uptime is", version.output)
        if identity:
            base["Router name"] = identity.group(1)
        release = re.search(r"(?:Cisco IOS XE Software, Version|Version)\s+(17\.[\w.]+)", version.output)
        if not release or not re.fullmatch(r"17\.15\.0*6", release.group(1)):
            issues.append("Software release is not verified as 17.15.6")
        vr, vrfs = collector.get("vrfs", parse_vrfs, fallback="vrfs_fallback")
        member_result, memberships = collector.get("membership", parse_membership)
        definition_result, definitions = collector.get("vrf_config", parse_vrf_config, fallback="vrf_config_fallback")
        config_result, configs = collector.get("interfaces", parse_config, fallback="interfaces_fallback")
        known = set(vrfs or {}) | set(memberships or {}) | (definitions or set()) | {c["vrf"] for c in (configs or {}).values()}
        # Always run both neighbor collections, even if VRF discovery failed.
        discovery = {}
        neighbors = []
        for proto in ("CDP", "LLDP"):
            prefix = proto.lower()
            sr, _ = collector.get(prefix + "_status", lambda t, k=prefix + "_status": parse_status(t, k))
            ir, _ = collector.get(prefix + "_interfaces", lambda t, k=prefix + "_interfaces": parse_status(t, k))
            nr, entries = collector.get(prefix, lambda t, p=proto: parse_neighbors(t, p))
            discovery[proto] = (sr, ir, nr)
            neighbors.extend(entries or [])
        for result in (vr, member_result, config_result):
            note(result, result.purpose)
        vpns = vpn_numbers(args.vpn)
        overrides = vrf_overrides(args.vrf, vpns)
        mapping = device.get("vpn_vrf_map", {})
        if not isinstance(mapping, dict):
            raise ValueError("Inventory vpn_vrf_map must be a mapping")
        resolved = set()
        for vpn in vpns:
            vrf = overrides.get(str(vpn)) or mapping.get(str(vpn)) or str(vpn)
            part = {"base": {**base, "VRF": vrf}, "interfaces": [], "arp": [], "neighbors": [], "error": ""}
            collector.vrf = vrf if isinstance(vrf, str) else ""
            try:
                if not isinstance(vrf, str) or not SAFE_NAME.fullmatch(vrf):
                    raise ValueError("Invalid resolved VRF name")
                if vrf in resolved:
                    raise ValueError(f"Multiple selected VPNs resolve to the same VRF {vrf!r}")
                resolved.add(vrf)
                audit_vrf(vpn, vrf, collector, part, args, configs or {}, vrfs or {},
                          memberships or {}, known, discovery, neighbors, config_result, issues)
            except Exception as exc:
                part["error"] = str(exc)
                console_error = "VRF not found or unverified" if isinstance(vrf, str) and vrf not in known else "VRF collection failed"
                with ssh.print_lock:
                    print(f"[error] {host} | VRF {vrf}: {console_error}", flush=True)
            for key in ("interfaces", "arp", "neighbors"):
                report[key].extend(part[key])
            errors = part["error"] or "\n".join(dict.fromkeys(e for row in part["interfaces"] for e in row["Collection errors"].splitlines()))
            collector.results.append(Result("", "VRF summary", status="failed" if errors else
                "success_with_entries" if part["interfaces"] else "success_empty", error=errors, vrf=collector.vrf))
            if errors:
                report["error"] = "\n".join(filter(None, [report["error"], f"VRF {vrf}: {errors}"]))
        collector.vrf = ""
    except Exception as exc:
        report["error"] = "; ".join(issues + [str(exc)])
        if saved_file:
            console_error = "Saved output could not be analyzed"
        elif "auth" in type(exc).__name__.lower() or re.search(r"authenticat|permission denied|access denied", str(exc), re.I):
            console_error = "Authentication failed"
        elif conn is None:
            console_error = "SSH connection failed"
        elif collector is None:
            console_error = "Enable authentication failed"
        else:
            console_error = "Collection failed"
        with ssh.print_lock:
            target = Path(saved_file).name if saved_file else f"{host} | {device['connect_host']}"
            print(f"[error] {target}: {console_error}", flush=True)
    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass
        results = collector.results if collector else []
        report["collection"] = [{**base, "VRF": r.vrf, "Command": r.command, "Purpose": r.purpose,
            "Status": r.status, "Collection errors": r.error, "Timestamp UTC": r.timestamp} for r in results]
        report["collection"].append({**base, "Command": "", "Purpose": "Router summary",
            "Status": "failed" if report["error"] or any(i["Collection errors"] for i in report["interfaces"]) else "success_with_entries" if report["interfaces"] else "success_empty",
            "Collection errors": report["error"] or "\n".join(dict.fromkeys(e for i in report["interfaces"] for e in i["Collection errors"].splitlines())), "Timestamp UTC": now()})
        raw = f"Router name: {base['Router name']}\nSSH address: {base['SSH address']}\n"
        raw += "".join(f"\n################################################ ({r.command})\nTimestamp UTC: {r.timestamp}\nVRF: {r.vrf}\nStatus: {r.status}\n{r.output}\nERROR: {r.error}\n" for r in results)
        if report["error"]:
            raw += f"\nERROR: {report['error']}\n"
        # Include address in the label so duplicate inventory hostnames do not collide.
        label = f"{host}-{device['connect_host']}"
        if not saved_file:
            ssh._write_output(args.output_dir, label, raw, args.append, args.prefix)
    if collector is not None:
        with ssh.print_lock:
            print(f"[done] {base['Router name']}: {len(report['interfaces'])} selected interfaces", flush=True)
    return report


BASE_COLUMNS = ["Router name", "SSH address", "VRF", "Logical interface", "Physical parent"]
INTERFACES_HEADER_ROW = 8


def write_workbook(path: Path, reports: list[dict], args: argparse.Namespace) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE

    wb = Workbook()
    wb.remove(wb.active)
    sheets = [
        ("Interfaces", "interfaces", BASE_COLUMNS + ["Neighbor", "Observed finding", "ARP IP count", "Unique MAC count", "Neighbor protocol", "Neighbor name", "Neighbor port", "Advertised platform", "System description", "Row color", "Collection errors", "Timestamp UTC"]),
        ("ARP Details", "arp", BASE_COLUMNS + ["IP address", "MAC address", "Age", "Complete", "Disposition"]),
        ("Neighbors", "neighbors", BASE_COLUMNS + ["Protocol", "Local interface", "Neighbor name", "Neighbor port", "Advertised platform", "System description", "Domain classification"]),
        ("Collection", "collection", ["Router name", "SSH address", "VRF", "Command", "Purpose", "Status", "Collection errors", "Timestamp UTC"]),
    ]
    for title, key, columns in sheets:
        if any(report["base"].get("Source file") for report in reports):
            columns = columns + ["Source file"]
        ws = wb.create_sheet(title)
        header_row = INTERFACES_HEADER_ROW if key == "interfaces" else 1
        for _ in range(header_row - 1):
            ws.append([])
        ws.append(columns)
        for report in reports:
            for row in report[key]:
                values = [row.get(col) for col in columns]
                ws.append(values)
                if key == "interfaces":
                    fill = PatternFill("solid", fgColor=COLORS[row["Row color"]])
                    for cell in ws[ws.max_row]:
                        cell.fill = fill
                elif key == "collection" and row["Status"] not in GOOD:
                    for cell in ws[ws.max_row]:
                        cell.fill = PatternFill("solid", fgColor=COLORS["Amber"])
        ws.freeze_panes = f"F{header_row + 1}" if key in {"interfaces", "arp", "neighbors"} else "D2"
        ws.auto_filter.ref = f"A{header_row}:{get_column_letter(len(columns))}{ws.max_row}"
        ws.sheet_view.showGridLines = False
        for cells in ws.iter_rows(min_row=header_row):
            for cell in cells:
                if isinstance(cell.value, str):
                    cell.value = ILLEGAL_CHARACTERS_RE.sub("", cell.value)[:32767]
                    cell.data_type = "s"  # Treat untrusted advertised names as text, never formulas.
                cell.alignment = Alignment(vertical="top", wrap_text=True)
                if cell.row == header_row:
                    cell.fill = PatternFill("solid", fgColor="17365D")
                    cell.font = Font(name="Arial", color="FFFFFF", bold=True, size=11)
                    cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
                else:
                    cell.font = Font(name="Arial", color="172B4D", size=11)
                if key == "interfaces" and columns[cell.column - 1] in {"ARP IP count", "Unique MAC count"}:
                    cell.number_format = "#,##0"
        for index, column in enumerate(columns, 1):
            width = 45 if column in {"Collection errors", "System description", "Observed finding", "Neighbor", "Command", "Source file"} else 28 if column in {"Neighbor name", "Advertised platform", "Timestamp UTC"} else 23
            ws.column_dimensions[get_column_letter(index)].width = width
        ws.row_dimensions[header_row].height = 34
        for row in range(header_row + 1, ws.max_row + 1):
            lines = max((sum(max(1, (len(part) + 39) // 40) for part in str(c.value or "").split("\n")) for c in ws[row]), default=1)
            ws.row_dimensions[row].height = min(300, max(30, lines * 16))
        if key == "interfaces":
            ws["A1"] = "Color meaning"
            ws["A1"].font = Font(name="Arial", size=14, bold=True, color="17365D")
            ws.row_dimensions[1].height = 24
            legend = [
                ("Green", "Neighbor hostname matches any configured domain, including its subdomains."),
                ("Red", "Different/no advertised hostname domain, OR no neighbor and 2+ non-router MACs on one interface: Likely third-party switch (unconfirmed)."),
                ("Neutral", "No neighbor and 0–1 distinct non-router MACs on one interface: Unknown; likely not a switch. White fill appears uncolored."),
                ("Amber", "Neighbor name missing or unusable, or collection disabled, unsupported, incomplete or failed. Overrides other colors."),
            ]
            for row, (color, meaning) in enumerate(legend, 2):
                ws.cell(row, 1, "Neutral (no color)" if color == "Neutral" else color)
                ws.cell(row, 1).fill = PatternFill("solid", fgColor=COLORS[color])
                ws.cell(row, 1).font = Font(name="Arial", size=11, bold=True, color="172B4D")
                ws.cell(row, 1).alignment = Alignment(vertical="center", wrap_text=True)
                ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=5)
                ws.cell(row, 2, meaning)
                ws.cell(row, 2).font = Font(name="Arial", size=11, color="172B4D")
                ws.cell(row, 2).alignment = Alignment(vertical="center", wrap_text=True)
                ws.row_dimensions[row].height = 36
            ws.row_dimensions[6].height = 8
            ws.row_dimensions[7].height = 8
    manifest = wb.create_sheet("Command Manifest")
    manifest.append(["Purpose", "Command template", "When used", "Device verification"])
    for key, command, purpose in COMMANDS:
        manifest.append([key, command, purpose, "See Collection for actual router result; not pre-certified for 17.15.6"])
    notes = wb.create_sheet("Readme")
    for row in [
        ["Setting", "Value"], ["Selected VRF numbers", ", ".join(split_values(args.vpn))],
        ["Our domains", ", ".join(split_values(args.domain))], ["Generated UTC", now()],
        ["Input mode", "Saved command output (offline)" if getattr(args, "from_files", None) else "SSH"],
        ["Threshold", "More than 1 distinct complete, non-router MAC on the SAME logical interface; parent ports are only used for neighbor matching."],
        ["Green", "Advertised neighbor hostname has exact dot-delimited domain suffix."],
        ["Red", "Different advertised domain, hostname without a domain, or no neighbor with >1 unique MAC: Likely third-party switch."],
        ["Neutral", "No neighbor and 0–1 unique MACs: Unknown. Observed finding reports 0 hosts or 1 host found, likely not a switch. Device type/model cannot be determined."],
        ["Amber", "Neighbor identity missing/unusable or incomplete collection. Observed finding retains known evidence."],
        ["Unknown counts", "Blank cells mean unavailable counts; zero requires successful parsed ARP and local identity collection."],
        ["ARP limits", "Cached IPv4 only. Proxy ARP, stale entries, virtualization and multiple IPs per MAC limit inference. Device type/model and switch presence are not confirmed."],
        ["Neighbor limits", "Advertised names are unverified claims. Parent-port evidence does not prove connectivity in an individual VLAN. Discovery disabled/unsupported cannot establish absence."],
        ["Ownership", "Known local/virtual IPs and local interface MACs are excluded. Age '-' alone does not mean local. Remote static entries remain included."],
        ["Collection", "Saved command blocks reparsed; no SSH or credentials used. See Source file columns for provenance." if getattr(args, "from_files", None) else "Read-only show commands. Netmiko may issue terminal width/length session setup, prompt detection and optional enable; no configuration or active probes."],
        ["Release", "Target 17.15.6. Commands/parsers require verification on actual hardware; unsupported and unknown output remain explicit."],
    ]:
        notes.append(row)
    for ws in (manifest, notes):
        ws.sheet_view.showGridLines = False
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        for col in range(1, ws.max_column + 1):
            ws.column_dimensions[get_column_letter(col)].width = 30 if col == 1 else 65
        for row in ws:
            for cell in row:
                cell.alignment = Alignment(wrap_text=True, vertical="top")
                cell.font = Font(name="Arial", size=11, color="172B4D")
                if cell.row == 1:
                    cell.font = Font(name="Arial", size=11, bold=True, color="FFFFFF")
                    cell.alignment = Alignment(wrap_text=True, horizontal="center", vertical="center")
                    cell.fill = PatternFill("solid", fgColor="17365D")
            ws.row_dimensions[row[0].row].height = 34 if row[0].row == 1 else 48
    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vpn", "--vpns", nargs="+", action="extend", help="Service VPN number(s), space/comma separated; prompt if omitted")
    parser.add_argument("--domain", "--domains", nargs="+", action="extend", help="Accepted DNS domain(s), space/comma separated; prompt if omitted")
    parser.add_argument("--vrf", nargs="+", action="extend", help="Named VRF, or mappings such as 20=LAN20 30=LAN30 for multiple VPNs")
    parser.add_argument("--devices", nargs="+", help="Inventory JSON/text file(s); defaults match py_ssh.py")
    parser.add_argument("--from-files", nargs="+", action="extend", metavar="PATH",
                        help="Offline: saved router .txt files, folders or quoted globs; no SSH or credentials")
    parser.add_argument("--device-groups", nargs="+")
    parser.add_argument("--device-type", default="cisco_ios")
    parser.add_argument("--default-username")
    parser.add_argument("--keyring-service", default=ssh.DEFAULT_SERVICE)
    parser.add_argument("--out", "--output-dir", dest="output_dir", type=Path)
    parser.add_argument("--prefix", default="vpn-audit")
    parser.add_argument("--append", help="Stable filename label; overwrites like py_ssh.py")
    parser.add_argument("--max-workers", "--threads", dest="max_workers", type=int, default=10,
                        help="Maximum concurrent router threads (default: 10)")
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--per-cmd-timeout", type=float, default=ssh.PER_CMD_TIMEOUT)
    parser.add_argument("--list-commands", action="store_true", help="Print every show command and fallback; no SSH/prompts")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_commands:
        purpose_width = max(len("Purpose"), *(len(key) for key, _, _ in COMMANDS))
        command_width = max(len("CMD"), *(len(command) for _, command, _ in COMMANDS))
        print(f"{'Purpose':<{purpose_width}}  {'CMD':<{command_width}}  When used")
        print(f"{'-' * purpose_width}  {'-' * command_width}  {'-' * 9}")
        for key, command, when in COMMANDS:
            print(f"{key:<{purpose_width}}  {command:<{command_width}}  {when}")
        print()
        print("Session setup: Netmiko cisco_ios may issue terminal width 511, terminal length 0, prompt discovery and optional enable.")
        return 0
    try:
        args.vpn = vpn_numbers(args.vpn if args.vpn is not None else input("VPN number(s), space/comma separated: "))
        raw_domains = args.domain if args.domain is not None else input("Our domain name(s), space/comma separated: ")
        args.domain = list(dict.fromkeys(domain_name(value) for value in split_values(raw_domains)))
        if not args.domain:
            raise ValueError("Enter at least one DNS domain")
        vrf_overrides(args.vrf, args.vpn)
        if args.max_workers < 1 or args.timeout <= 0 or args.per_cmd_timeout <= 0:
            raise ValueError("Workers and timeout values must be positive")
        for label in (args.prefix, args.append):
            if label and not re.fullmatch(r"[A-Za-z0-9_-]+", label):
                raise ValueError("Output labels may contain only letters, numbers, underscores and hyphens")
        args.output_dir = ssh._resolve_cli_output_folder(args.output_dir)
        import openpyxl  # noqa: F401 -- fail before connecting if exporter is missing
        if args.from_files:
            if args.devices or args.device_groups:
                raise ValueError("--from-files cannot be combined with --devices or --device-groups")
            devices = saved_targets(args.from_files)
        else:
            devices = ssh._load_devices(args.devices, args.device_groups, args.default_username,
                                        args.keyring_service, args.device_type)
        if not devices:
            raise ValueError("Inventory selection contains no devices; check --device-groups")
        if not args.from_files:
            ssh._prefill_passwords(devices, args.default_username, args.keyring_service, True)
        reports = []
        name = f"{args.prefix}-{args.append}" if args.append else f"{args.prefix}_{ssh._timestamp()}"
        args.output_dir.mkdir(parents=True, exist_ok=True)
        with ssh_diagnostics(args.output_dir / f"{name}-ssh.log"), ThreadPoolExecutor(max_workers=args.max_workers) as pool:
            futures = [pool.submit(audit_device, device, args) for device in devices]
            for future in as_completed(futures):
                reports.append(future.result())
        reports.sort(key=lambda r: (r["base"]["Router name"], r["base"]["SSH address"], r["base"].get("Source file", "")))
        path = args.output_dir / f"{name}.xlsx"
        write_workbook(path, reports, args)
        failed = sum(bool(r["error"]) or any(i["Collection errors"] for i in r["interfaces"]) for r in reports)
        try:
            display_path = "./" + Path(os.path.relpath(path)).as_posix()
        except ValueError:  # Windows paths on another drive cannot be relative.
            display_path = str(path)
        label = "Snapshots" if args.from_files else "Routers"
        print(f"[summary] {label}: {len(reports)}; incomplete: {failed}; workbook: {display_path}")
        return 1 if failed else 0
    except (ValueError, OSError, ImportError, EOFError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit("[interrupt] user cancelled")

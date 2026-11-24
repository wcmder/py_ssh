"""Offline fixtures, deliberately not a claim of device certification."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import io
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vpn_neighbor_audit as audit


HEADER = "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
CONFIG = """interface GigabitEthernet0/0/1
 no ip address
!
interface GigabitEthernet0/0/1.20
 encapsulation dot1Q 20
 vrf forwarding 20
 ip address 10.20.0.1 255.255.255.0
!
interface GigabitEthernet0/0/1.21
 encapsulation dot1Q 21
 vrf forwarding 20
 ip address 10.21.0.1 255.255.255.0
!
interface GigabitEthernet0/0/2.30
 vrf forwarding 30
 ip address 10.20.0.99 255.255.255.0
!
"""
CDP = """-------------------------
Device ID: switch.example.org
Entry address(es):
  IP address: 192.0.2.1
Platform: cisco C9300, Capabilities: Switch IGMP
Interface: GigabitEthernet0/0/1, Port ID (outgoing port): GigabitEthernet1/0/1
Holdtime : 123 sec
Version :
Cisco IOS XE Software
advertisement version: 2
Total cdp entries displayed : 1
"""
LLDP = """------------------------------------------------
Local Intf: Gi0/0/1
Chassis id: aabb.ccdd.eeff
Port id: Gi1/0/1
Port Description: uplink
System Name: switch.example.org
System Description:
Cisco IOS XE Software, C9300
Time remaining: 100 seconds
System Capabilities: B,R
Enabled Capabilities: B,R
Total entries displayed: 1
"""


def arp(ip, mac, interface="GigabitEthernet0/0/1.20", age="5"):
    return f"Internet  {ip}  {age}  {mac}  ARPA  {interface}\n"


def port_channel_fixture(logical="Port-channel1"):
    root = "interface Port-channel1\n no ip address\n!\n" if "." in logical else ""
    config = root + f"interface {logical}\n vrf forwarding 20\n ip address 10.20.0.1 255.255.255.0\n!\n"
    for number, group in ((1, 1), (2, 1), (3, 2)):
        config += f"interface GigabitEthernet0/0/{number}\n channel-group {group} mode active\n!\n"
    return {
        "show vrf": f"Name Default RD Protocols Interfaces\n20 1:20 ipv4 {logical}",
        "show ip vrf interfaces": f"Interface IP-Address VRF Protocol\n{logical} 10.20.0.1 20 up",
        "show sdwan running-config | section ^interface": config,
        "show etherchannel summary": "Group Port-channel Protocol Ports\n1 Po1(RU) LACP Gi0/0/1(P) Gi0/0/2(P)\n2 Po2(RU) LACP Gi0/0/3(P)",
        f"show ip interface {logical}": f"{logical} is up, line protocol is up\n Internet address is 10.20.0.1/24",
        "show ip arp vrf 20": HEADER + arp("10.20.0.1", "0011.2233.4455", logical) +
            arp("10.20.0.2", "aaaa.bbbb.0001", logical) + arp("10.20.0.3", "aaaa.bbbb.0002", logical),
        "show cdp neighbors detail": CDP,
        "show lldp neighbors detail": LLDP.replace("Local Intf: Gi0/0/1", "Local Intf: Gi0/0/2"),
        "show cdp interface": "GigabitEthernet0/0/1 is up, line protocol is up\n Sending CDP packets every 60 seconds\nGigabitEthernet0/0/2 is up, line protocol is up\n Sending CDP packets every 60 seconds",
        "show lldp interface": "GigabitEthernet0/0/1:\n Tx: enabled\n Rx: enabled\nGigabitEthernet0/0/2:\n Tx: enabled\n Rx: enabled",
    }


class FakeConnection:
    def __init__(self, overrides=None):
        self.overrides = overrides or {}
        self.sent = []
        self.disconnected = False

    def send_command(self, command, **kwargs):
        self.sent.append(command)
        if command in self.overrides:
            value = self.overrides[command]
            if isinstance(value, Exception):
                raise value
            return value
        answers = {
            "show version": "Cisco IOS XE Software, Version 17.15.06\nactual-router uptime is 1 day",
            "show vrf": "  Name  Default RD  Protocols  Interfaces\n  20  1:20  ipv4  Gi0/0/1.20\n                                 Gi0/0/1.21",
            "show ip vrf interfaces": "Interface IP-Address VRF Protocol\nGi0/0/1.20 10.20.0.1 20 up\nGi0/0/1.21 10.21.0.1 20 down",
            "show sdwan running-config | section ^vrf definition": "vrf definition 20\n rd 1:20\nvrf definition 30\n rd 1:30",
            "show sdwan running-config | section ^interface": CONFIG,
            "show ip arp vrf 20": HEADER,
            "show cdp": "Global CDP information:\n Sending CDP packets every 60 seconds",
            "show cdp interface": "GigabitEthernet0/0/1 is up, line protocol is up\n Encapsulation 802.1Q\n Sending CDP packets every 60 seconds",
            "show cdp neighbors detail": "Total cdp entries displayed : 0",
            "show lldp": "Global LLDP Information:\n Status: ACTIVE",
            "show lldp interface": "GigabitEthernet0/0/1:\n Tx: enabled\n Rx: enabled",
            "show lldp neighbors detail": "Total entries displayed: 0",
        }
        if command in answers:
            return answers[command]
        if command.startswith("show interfaces "):
            name = command.split()[-1]
            return f"{name} is up, line protocol is up\n Hardware is vNIC, address is 0011.2233.4455 (bia 0011.2233.4455)"
        if command.startswith("show ip interface "):
            name = command.split()[-1]
            ip = "10.20.0.1" if name.endswith(".20") else "10.21.0.1"
            return f"{name} is up, line protocol is up\n Internet address is {ip}/24"
        raise AssertionError(f"Unexpected command: {command}")

    def disconnect(self):
        self.disconnected = True


class AuditTests(unittest.TestCase):
    def test_port_channel_member_neighbors_keep_bundle_arp_counts(self):
        for logical in ("Port-channel1", "Port-channel1.20"):
            with self.subTest(logical=logical):
                result, conn, _ = self.collect(port_channel_fixture(logical))
                self.assertFalse(result["error"], result["error"])
                self.assertEqual(len(result["interfaces"]), 1)
                row = result["interfaces"][0]
                self.assertEqual(row["Logical interface"], logical)
                self.assertEqual((row["ARP IP count"], row["Unique MAC count"]), (2, 2))
                self.assertEqual(row["Neighbor"], "switch.example.org")
                self.assertEqual(row["Row color"], "Green")
                self.assertEqual(row["Physical parent"], "GigabitEthernet0/0/1, GigabitEthernet0/0/2")
                self.assertEqual({n["Local interface"] for n in result["neighbors"]}, {"GigabitEthernet0/0/1", "GigabitEthernet0/0/2"})
                self.assertEqual(conn.sent.count("show etherchannel summary"), 1)

    def test_etherchannel_summary_flags_and_wrapped_members(self):
        text = "Group Port-channel Protocol Ports\n1 Po1(RU) LACP Gi0/0/1(P)\n Gi0/0/2(bndl) Gi0/0/3(hot-sby) Gi0/0/4(D)\n2 Po2(RD) LACP Gi0/0/5(P)"
        bundles = audit.parse_etherchannels(text)
        self.assertEqual(bundles["Port-channel1"]["active"], {"GigabitEthernet0/0/1", "GigabitEthernet0/0/2"})
        self.assertEqual(len(bundles["Port-channel1"]["members"]), 4)
        self.assertFalse(bundles["Port-channel2"]["active"])
        self.assertEqual(audit.parse_etherchannels("Number of channel-groups in use: 0"), {})
        with self.assertRaises(ValueError):
            audit.parse_etherchannels("unrecognized output")

    def test_port_channel_multiple_vrfs_collect_summary_once(self):
        overrides = port_channel_fixture("Port-channel1.20")
        overrides["show sdwan running-config | section ^interface"] += "interface Port-channel1.30\n vrf forwarding 30\n ip address 10.30.0.1 255.255.255.0\n!\n"
        overrides["show ip interface Port-channel1.30"] = "Port-channel1.30 is up, line protocol is up\n Internet address is 10.30.0.1/24"
        overrides["show ip arp vrf 30"] = HEADER + arp("10.20.0.1", "aaaa.bbbb.0003", "Po1.30")
        result, conn, _ = self.collect(overrides, arg_extra={"vpn": [20, 30]})
        self.assertFalse(result["error"], result["error"])
        self.assertEqual(conn.sent.count("show etherchannel summary"), 1)
        self.assertEqual([(row["VRF"], row["Unique MAC count"], row["Row color"]) for row in result["interfaces"]],
                         [("20", 2, "Green"), ("30", 1, "Green")])

    def test_port_channel_no_active_members_does_not_infer_switch(self):
        overrides = port_channel_fixture()
        overrides.update({"show etherchannel summary": "Group Port-channel Protocol Ports\n1 Po1(RD) LACP Gi0/0/1(D) Gi0/0/2(D)",
                          "show cdp neighbors detail": "Total cdp entries displayed : 0",
                          "show lldp neighbors detail": "Total entries displayed: 0"})
        result, _, _ = self.collect(overrides)
        row = result["interfaces"][0]
        self.assertEqual(row["Row color"], "Amber")
        self.assertEqual(row["Observed finding"], "Neighbor absence unverified")
        self.assertEqual(row["Unique MAC count"], 2)

    def test_port_channel_does_not_match_another_bundles_neighbor(self):
        overrides = port_channel_fixture()
        overrides.update({"show cdp neighbors detail": CDP.replace("GigabitEthernet0/0/1,", "GigabitEthernet0/0/3,").replace("example.org", "other.org"),
                          "show lldp neighbors detail": "Total entries displayed: 0"})
        result, _, _ = self.collect(overrides)
        self.assertEqual(result["interfaces"][0]["Neighbor"], "Unknown")
        self.assertEqual(result["interfaces"][0]["Observed finding"], "Likely third-party switch")
        self.assertFalse(result["neighbors"])

    def test_port_channel_failed_membership_is_amber_counts_still_available(self):
        overrides = port_channel_fixture()
        overrides["show etherchannel summary"] = "% Invalid input detected at '^' marker."
        result, _, _ = self.collect(overrides)
        row = result["interfaces"][0]
        self.assertEqual(row["Row color"], "Amber")
        self.assertEqual(row["Neighbor"], "switch.example.org")
        self.assertEqual(row["Unique MAC count"], 2)
        self.assertIn("show etherchannel summary: unsupported", row["Collection errors"])

    def test_port_channel_replay_and_missing_membership(self):
        original, _, args = self.collect(port_channel_fixture())
        source = next(args.output_dir.glob("*.txt"))
        device = {"hostname": source.stem, "connect_host": "", "saved_file": source}
        with redirect_stdout(io.StringIO()):
            replay = audit.audit_device(device, args)
        self.assertEqual(replay["interfaces"][0]["Neighbor"], original["interfaces"][0]["Neighbor"])
        self.assertEqual(replay["interfaces"][0]["Row color"], "Green")
        text = source.read_text()
        start = text.index("\n################################################ (show etherchannel summary)")
        end = text.index("\n################################################", start + 2)
        source.write_text(text[:start] + text[end:])
        with redirect_stdout(io.StringIO()):
            missing = audit.audit_device(device, args)
        self.assertEqual(missing["interfaces"][0]["Row color"], "Amber")
        self.assertEqual(missing["interfaces"][0]["Unique MAC count"], 2)
        self.assertIn("show etherchannel summary: missing", missing["interfaces"][0]["Collection errors"])

    def test_transport_traceback_goes_to_file_not_console(self):
        logger = logging.getLogger("paramiko")
        previous = (logger.handlers[:], logger.level, logger.propagate)
        with tempfile.TemporaryDirectory() as folder, redirect_stderr(io.StringIO()) as console:
            path = Path(folder) / "audit-ssh.log"
            with audit.ssh_diagnostics(path):
                child = logging.getLogger("paramiko.transport")
                child.error("Exception (client): Invalid packet blocking")
                child.error("Traceback: packet diagnostic details")
            self.assertEqual(console.getvalue(), "")
            self.assertIn("Invalid packet blocking", path.read_text())
            self.assertIn("Traceback: packet diagnostic details", path.read_text())
        self.assertEqual((logger.handlers, logger.level, logger.propagate), previous)

    def collect(self, overrides=None, device_extra=None, arg_extra=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        args = argparse.Namespace(vpn=20, domain="example.org", vrf=None, device_type="cisco_ios",
                                  timeout=20, per_cmd_timeout=30, output_dir=Path(temp.name),
                                  prefix="audit", append=None)
        for key, value in (arg_extra or {}).items():
            setattr(args, key, value)
        device = {"hostname": "inventory-router", "connect_host": "192.0.2.10", "username": "test", "password": "test"}
        device.update(device_extra or {})
        conn = FakeConnection(overrides)
        with patch.object(audit.ssh, "ConnectHandler", return_value=conn), redirect_stdout(io.StringIO()):
            result = audit.audit_device(device, args)
        self.assertTrue(conn.disconnected)
        return result, conn, args

    def test_interface_normalization_and_parent(self):
        self.assertEqual(audit.interface_name("Gi0/0/1.20"), "GigabitEthernet0/0/1.20")
        self.assertEqual(audit.physical_parent("GigabitEthernet0/0/1.20"), "GigabitEthernet0/0/1")
        for name in ("Vlan20", "Port-channel1.20", "Loopback20", "BDI20", "Tunnel20"):
            self.assertEqual(audit.physical_parent(name), "")

    def test_suffix_boundaries(self):
        for name in ("sw.example.org", "SW.EXAMPLE.ORG.", "sw.site.example.org", "sw.example.org(SERIAL)"):
            self.assertEqual(audit.neighbor_domain(name, "example.org"), "Our domain")
        for name in ("sw.badexample.org", "sw.example.org.evil.net", "sw.other.net"):
            self.assertEqual(audit.neighbor_domain(name, "example.org"), "Different advertised domain")
        for name in ("example.org", "192.0.2.1", "0011.2233.4455", "bad name.example.org", "001122334455", "12345"):
            finding = audit.neighbor_domain(name, "example.org")
            self.assertEqual(finding, "Neighbor name does not match configured domains")
            self.assertEqual(audit.classify([{"Domain classification": finding}], 1, [])[0], "Red")
        self.assertEqual(audit.neighbor_domain("", "example.org"), "Neighbor domain undetermined")

    def test_domain_validation(self):
        self.assertEqual(audit.domain_name(" .EXAMPLE.ORG. "), "example.org")
        for domain in ("", "example", "192.0.2.1", "bad domain.org", "a..org"):
            with self.assertRaises(ValueError):
                audit.domain_name(domain)

    def test_advertised_hostname_with_underscore(self):
        self.assertEqual(audit.neighbor_domain("btn01_sw01.example.com", "example.com"), "Our domain")
        self.assertEqual(audit.neighbor_domain("BTN01_SW01.EXAMPLE.COM.", "example.com"), "Our domain")
        self.assertEqual(audit.neighbor_domain("btn01_sw01.other.com", "example.com"), "Different advertised domain")
        self.assertEqual(audit.neighbor_domain("btn01_sw01.badexample.com", "example.com"), "Different advertised domain")
        self.assertEqual(audit.neighbor_domain("btn01_sw01.example.com.other.net", "example.com"), "Different advertised domain")
        self.assertEqual(audit.neighbor_domain("btn01_sw01", "example.com"), "Neighbor hostname without domain")
        with self.assertRaises(ValueError):
            audit.domain_name("bad_domain.com")
        result, _, _ = self.collect({"show cdp neighbors detail": CDP.replace("switch.example.org", "btn01_sw01.example.com")},
                                    arg_extra={"domain": ["example.com"]})
        self.assertEqual(result["interfaces"][0]["Row color"], "Green")
        self.assertEqual(result["interfaces"][0]["Neighbor"], "btn01_sw01.example.com")

    def test_multiple_domains_exact_suffix(self):
        domains = ["example.org", "another.org"]
        for name in ("sw.s1.example.org", "sw.another.org", "sw.site.another.org"):
            self.assertEqual(audit.neighbor_domain(name, domains), "Our domain")
        for name in ("sw.badanother.org", "sw.another.org.evil.net", "sw.other.org"):
            self.assertEqual(audit.neighbor_domain(name, domains), "Different advertised domain")
        self.assertEqual(audit.neighbor_domain("sw", domains), "Neighbor hostname without domain")

    def test_multiple_input_formats_and_overrides(self):
        args = audit.build_parser().parse_args(["--vpn", "20,30", "--vpn", "20", "--domain", "example.org", "another.org"])
        self.assertEqual(audit.vpn_numbers(args.vpn), [20, 30])
        self.assertEqual(audit.vpn_numbers("20 30,20"), [20, 30])
        self.assertEqual(audit.vrf_overrides(["20=LAN20", "30=LAN30"], [20, 30]), {"20": "LAN20", "30": "LAN30"})
        for values in ([], "512", "0", "20,65526", "foo"):
            with self.assertRaises(ValueError):
                audit.vpn_numbers(values)
        with self.assertRaises(ValueError):
            audit.vrf_overrides("LAN20", [20, 30])

    def test_multiple_vpns_one_session_separate_arp_and_ownership(self):
        overrides = {
            "show ip arp vrf 20": HEADER + arp("10.20.0.99", "aaaa.bbbb.0001"),
            "show ip arp vrf 30": HEADER + arp("10.20.0.99", "0011.2233.4455", "Gi0/0/2.30") + arp("10.20.0.1", "aaaa.bbbb.0002", "Gi0/0/2.30"),
            "show ip interface GigabitEthernet0/0/2.30": "GigabitEthernet0/0/2.30 is up, line protocol is up\n Internet address is 10.20.0.99/24",
            "show cdp interface": "GigabitEthernet0/0/1 is up, line protocol is up\n Sending CDP packets every 60 seconds\nGigabitEthernet0/0/2 is up, line protocol is up\n Sending CDP packets every 60 seconds",
            "show lldp interface": "GigabitEthernet0/0/1:\n Tx: enabled\n Rx: enabled\nGigabitEthernet0/0/2:\n Tx: enabled\n Rx: enabled",
        }
        result, conn, args = self.collect(overrides, arg_extra={"vpn": [20, 30], "domain": ["example.org", "another.org"]})
        self.assertFalse(result["error"], result["error"])
        self.assertEqual(conn.sent.count("show version"), 1)
        self.assertEqual(conn.sent.count("show cdp neighbors detail"), 1)
        self.assertEqual(conn.sent.count("show lldp neighbors detail"), 1)
        rows = {(row["VRF"], row["Logical interface"]): row for row in result["interfaces"]}
        self.assertEqual(rows[("20", "GigabitEthernet0/0/1.20")]["ARP IP count"], 1)
        self.assertEqual(rows[("30", "GigabitEthernet0/0/2.30")]["ARP IP count"], 1)
        self.assertEqual(rows[("30", "GigabitEthernet0/0/2.30")]["Unique MAC count"], 1)
        arp_commands = [row for row in result["collection"] if row["Purpose"] == "arp"]
        self.assertEqual([row["VRF"] for row in arp_commands], ["20", "30"])
        from openpyxl import load_workbook
        path = args.output_dir / "multi.xlsx"
        audit.write_workbook(path, [result], args)
        wb = load_workbook(path)
        self.assertEqual(wb["Interfaces"].max_row, audit.INTERFACES_HEADER_ROW + 3)
        self.assertEqual(wb["Readme"]["B2"].value, "20, 30")
        self.assertEqual(wb["Readme"]["B3"].value, "example.org, another.org")
        self.assertNotIn("VPN", [cell.value for cell in wb["Interfaces"][audit.INTERFACES_HEADER_ROW]])
        wb.close()

    def test_missing_vpn_does_not_block_other_vpn(self):
        result, conn, _ = self.collect(arg_extra={"vpn": [999, 20]})
        self.assertIn("VRF 999", result["error"])
        self.assertEqual(len(result["interfaces"]), 2)
        self.assertEqual(result["interfaces"][0]["Row color"], "Neutral")
        self.assertIn("show ip arp vrf 20", conn.sent)
        self.assertNotIn("show ip arp vrf 999", conn.sent)
        summaries = [r for r in result["collection"] if r["Purpose"] == "VRF summary"]
        self.assertEqual([r["Status"] for r in summaries], ["failed", "success_with_entries"])

    def test_neighbor_matches_second_accepted_domain(self):
        result, _, _ = self.collect({"show cdp neighbors detail": CDP.replace("example.org", "another.org")},
                                    arg_extra={"domain": ["example.org", "another.org"]})
        self.assertEqual(result["interfaces"][0]["Classification"], "Our domain")
        self.assertEqual(result["interfaces"][0]["Row color"], "Green")

    def test_counts_remain_on_logical_interface(self):
        data = HEADER + arp("10.20.0.2", "aaaa.bbbb.0001") + arp("10.20.0.3", "aaaa.bbbb.0002")
        data += arp("10.21.0.2", "aaaa.bbbb.0003", "Gi0/0/1.21")
        result, conn, _ = self.collect({"show ip arp vrf 20": data})
        self.assertFalse(result["error"])
        self.assertEqual([r["Unique MAC count"] for r in result["interfaces"]], [2, 1])
        self.assertEqual([r["Row color"] for r in result["interfaces"]], ["Red", "Neutral"])
        self.assertEqual(result["interfaces"][0]["Classification"], "Likely third-party switch")
        self.assertEqual(result["interfaces"][1]["Classification"], "Unknown")
        self.assertIn("show lldp neighbors detail", conn.sent)
        self.assertIn("show cdp neighbors detail", conn.sent)

    def test_dedup_incomplete_local_and_overlapping_vrf(self):
        data = HEADER + arp("10.20.0.1", "0011.2233.4455", age="-")
        data += arp("10.20.0.2", "0011.2233.4455")  # local MAC
        data += arp("10.20.0.3", "aaaa.bbbb.0001") * 2
        data += arp("10.20.0.4", "aaaa.bbbb.0001", age="-")  # remote static retained
        data += arp("10.20.0.5", "aaaa.bbbb.0002")
        data += arp("10.20.0.99", "aaaa.bbbb.0003")  # local IP only in VPN 30: retain
        data += "Internet 10.20.0.9 0 Incomplete ARPA\n"
        result, _, _ = self.collect({"show ip arp vrf 20": data})
        row = result["interfaces"][0]
        self.assertEqual((row["ARP IP count"], row["Unique MAC count"]), (4, 3))
        self.assertEqual(row["Classification"], "Likely third-party switch")
        self.assertEqual(row["Row color"], "Red")
        self.assertEqual(result["arp"][-1]["Disposition"], "Incomplete")

    def test_empty_success_and_down_interface_retained(self):
        result, _, _ = self.collect()
        self.assertEqual(len(result["interfaces"]), 2)
        self.assertEqual([r["ARP IP count"] for r in result["interfaces"]], [0, 0])
        self.assertEqual(result["interfaces"][0]["Observed finding"], "0 hosts found, likely not a switch")
        self.assertEqual(next(r["Status"] for r in result["collection"] if r["Purpose"] == "arp"), "success_empty")

    def test_many_ips_one_mac_is_unknown(self):
        result, _, _ = self.collect({"show ip arp vrf 20": HEADER + "".join(arp(f"10.20.0.{i}", "aaaa.bbbb.0001") for i in range(2, 12))})
        row = result["interfaces"][0]
        self.assertEqual((row["ARP IP count"], row["Unique MAC count"]), (10, 1))
        self.assertEqual(row["Classification"], "Unknown")
        self.assertEqual(row["Observed finding"], "1 host found, likely not a switch")

    def test_parent_neighbors_without_arp(self):
        result, _, _ = self.collect({"show cdp neighbors detail": CDP, "show lldp neighbors detail": LLDP})
        for row in result["interfaces"]:
            self.assertEqual(row["Row color"], "Green")
            self.assertEqual(row["ARP IP count"], 0)
            self.assertIn("Physical parent", row["Match scope"])
        self.assertEqual(len(result["neighbors"]), 4)

    def test_different_domain_overrides_matching_neighbor(self):
        result, _, _ = self.collect({"show cdp neighbors detail": CDP,
                                    "show lldp neighbors detail": LLDP.replace("switch.example.org", "sw.other.org")})
        self.assertEqual(result["interfaces"][0]["Row color"], "Red")
        self.assertEqual(result["interfaces"][0]["Classification"], "Different advertised domain")
        self.assertEqual(result["interfaces"][0]["Neighbor"], "switch.example.org\nsw.other.org")
        self.assertIn("Cisco", result["interfaces"][0]["System description"])

    def test_hostname_without_domain_red(self):
        result, _, _ = self.collect({"show cdp neighbors detail": CDP.replace("switch.example.org", "switch")})
        self.assertEqual(result["interfaces"][0]["Classification"], "Neighbor hostname without domain")
        self.assertEqual(result["interfaces"][0]["Neighbor"], "switch")
        self.assertEqual(result["interfaces"][0]["Row color"], "Red")
        self.assertEqual(result["interfaces"][0]["Observed finding"], "Neighbor hostname without domain")

    def test_blank_arp_is_not_zero(self):
        result, _, _ = self.collect({"show ip arp vrf 20": ""})
        self.assertIsNone(result["interfaces"][0]["ARP IP count"])
        self.assertEqual(result["interfaces"][0]["Row color"], "Amber")
        self.assertIn("parse_error", result["interfaces"][0]["Collection errors"])

    def test_fallback_unsupported_retained(self):
        result, _, _ = self.collect({"show ip arp vrf 20": "% Invalid input detected at '^' marker.",
                                    "show arp vrf 20": HEADER})
        arp_results = [r for r in result["collection"] if r["Purpose"].startswith("arp")]
        self.assertEqual([r["Status"] for r in arp_results], ["unsupported", "success_empty"])
        self.assertEqual(result["interfaces"][0]["Row color"], "Neutral")

    def test_discovery_failure_preserves_finding(self):
        result, _, _ = self.collect({"show cdp neighbors detail": CDP.replace("example.org", "other.org"),
                                    "show lldp neighbors detail": "% Invalid input detected at '^' marker."})
        row = result["interfaces"][0]
        self.assertEqual(row["Row color"], "Amber")
        self.assertEqual(row["Observed finding"], "Different advertised domain")

    def test_disabled_discovery_is_not_neutral_unknown(self):
        result, _, _ = self.collect({"show lldp": "% LLDP is not enabled"})
        row = result["interfaces"][0]
        self.assertEqual(row["Row color"], "Amber")
        self.assertEqual(row["Observed finding"], "Neighbor absence unverified")

    def test_timeout_stops_session_and_keeps_previous_output(self):
        conn = FakeConnection({"show cdp": TimeoutError("timed out")})
        collector = audit.Collector(conn, 1)
        first, _ = collector.get("version", lambda x: x)
        collector.run("cdp_status")
        last = collector.run("lldp_status")
        self.assertEqual(first.status, "success_with_entries")
        self.assertEqual(last.status, "failed")
        self.assertNotIn("show lldp", conn.sent)
        self.assertIn("17.15.06", collector.results[0].output)

    def test_unrecognized_and_malformed_output_fail(self):
        for parser in (audit.parse_arp, audit.parse_membership, audit.parse_vrfs, audit.parse_config):
            with self.assertRaises(ValueError):
                parser("unexpected text")
        with self.assertRaises(ValueError):
            audit.parse_arp(HEADER + arp("10.20.0.3", "bogus"))
        with self.assertRaises(ValueError):
            audit.parse_arp(HEADER + "unrecognized nonempty data")
        with self.assertRaises(ValueError):
            audit.parse_neighbors(CDP.replace("displayed : 1", "displayed : 2"), "CDP")

    def test_explicit_named_vrf(self):
        replacements = {
            "show vrf": "Name Default RD Protocols Interfaces\nLAN20 1:20 ipv4 Gi0/0/1.20\n Gi0/0/1.21",
            "show ip vrf interfaces": "Interface IP-Address VRF Protocol\nGi0/0/1.20 10.20.0.1 LAN20 up\nGi0/0/1.21 10.21.0.1 LAN20 down",
            "show sdwan running-config | section ^vrf definition": "vrf definition LAN20\n rd 1:20",
            "show sdwan running-config | section ^interface": CONFIG.replace("vrf forwarding 20", "vrf forwarding LAN20"),
            "show ip arp vrf LAN20": HEADER,
        }
        result, conn, _ = self.collect(replacements, {"vpn_vrf_map": {"20": "LAN20"}})
        self.assertFalse(result["error"])
        self.assertEqual(result["interfaces"][0]["VRF"], "LAN20")
        self.assertIn("show ip arp vrf LAN20", conn.sent)
        self.assertNotIn("show ip arp vrf 20", conn.sent)

    def test_missing_vrf_still_checks_neighbors(self):
        replacements = {
            "show vrf": "Name Default RD Protocols Interfaces\n30 1:30 ipv4 Gi0/0/1",
            "show ip vrf interfaces": "Interface IP-Address VRF Protocol\nGi0/0/1 10.30.0.1 30 up",
            "show sdwan running-config | section ^vrf definition": "vrf definition 30\n rd 1:30",
            "show sdwan running-config | section ^interface": CONFIG.replace("vrf forwarding 20", "vrf forwarding 30"),
        }
        result, conn, _ = self.collect(replacements)
        self.assertIn("not verified", result["error"])
        self.assertFalse(result["interfaces"])
        self.assertIn("show cdp neighbors detail", conn.sent)
        self.assertIn("show lldp neighbors detail", conn.sent)
        self.assertNotIn("show ip arp vrf 20", conn.sent)

    def test_configured_virtual_ip_excluded(self):
        config = CONFIG.replace(" ip address 10.20.0.1 255.255.255.0", " ip address 10.20.0.1 255.255.255.0\n standby 1 ip 10.20.0.254")
        result, conn, _ = self.collect({
            "show sdwan running-config | section ^interface": config,
            "show ip arp vrf 20": HEADER + arp("10.20.0.254", "0000.0c07.ac01") + arp("10.20.0.2", "aaaa.bbbb.0001"),
        })
        self.assertNotIn("show standby brief", conn.sent)
        self.assertNotIn("show vrrp brief", conn.sent)
        self.assertEqual(result["interfaces"][0]["ARP IP count"], 1)
        self.assertEqual(result["arp"][0]["Disposition"], "Router-owned IP")

    def test_failed_connection_has_collection_summary(self):
        detail = "Authentication failed\nCommon causes: incorrect credentials\nDevice settings: additional diagnostic text"
        with patch.object(audit.ssh, "ConnectHandler", side_effect=RuntimeError(detail)):
            # collect's inner patch deliberately owns ConnectHandler; call directly here.
            with tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()) as console:
                args = argparse.Namespace(vpn=20, domain="example.org", vrf=None, device_type="cisco_ios", timeout=1,
                                          per_cmd_timeout=1, output_dir=Path(folder), prefix="audit", append=None)
                result = audit.audit_device({"hostname": "r1", "connect_host": "192.0.2.1", "username": "u", "password": "p"}, args)
                self.assertIn("Authentication failed", result["collection"][0]["Collection errors"])
                self.assertEqual(result["collection"][0]["Status"], "failed")
                self.assertFalse(result["interfaces"])
                self.assertIn("[error] r1 | 192.0.2.1: Authentication failed", console.getvalue())
                self.assertNotIn("Common causes", console.getvalue())
                self.assertNotIn("[done]", console.getvalue())
                self.assertIn(detail, result["collection"][0]["Collection errors"])
                self.assertIn(detail, next(Path(folder).glob("*.txt")).read_text())

    def test_cli_prompts_and_writes_report(self):
        from openpyxl import load_workbook
        with tempfile.TemporaryDirectory() as folder:
            conn = FakeConnection()
            with patch.object(audit.ssh, "ConnectHandler", return_value=conn), \
                 patch.object(audit.ssh, "_load_devices", return_value=[{"hostname": "r1", "connect_host": "192.0.2.1", "username": "u", "password": "p"}]), \
                 patch("builtins.input", side_effect=["20", "example.org"]) as prompt, redirect_stdout(io.StringIO()):
                status = audit.main(["--out", folder, "--append", "review"])
            self.assertEqual(status, 0)
            self.assertEqual(prompt.call_count, 2)
            path = Path(folder) / "vpn-audit-review.xlsx"
            self.assertTrue(path.is_file())
            wb = load_workbook(path)
            self.assertEqual(wb["Interfaces"].max_row, audit.INTERFACES_HEADER_ROW + 2)
            wb.close()
            self.assertTrue(list(Path(folder).glob("*.txt")))

    def test_cli_multiple_prompts_continue_after_missing_vrf(self):
        from openpyxl import load_workbook
        with tempfile.TemporaryDirectory() as folder:
            conn = FakeConnection()
            with patch.object(audit.ssh, "ConnectHandler", return_value=conn) as connect, \
                 patch.object(audit.ssh, "_load_devices", return_value=[{"hostname": "r1", "connect_host": "192.0.2.1", "username": "u", "password": "p"}]), \
                 patch("builtins.input", side_effect=["999,20,20", ".EXAMPLE.ORG,another.org,example.org"]), redirect_stdout(io.StringIO()):
                status = audit.main(["--out", folder, "--append", "multi", "--threads", "2"])
            self.assertEqual(status, 1)  # VRF 999 fails, but VRF 20 is exported.
            connect.assert_called_once()
            wb = load_workbook(Path(folder) / "vpn-audit-multi.xlsx")
            self.assertEqual(wb["Interfaces"].max_row, audit.INTERFACES_HEADER_ROW + 2)
            self.assertEqual(wb["Readme"]["B2"].value, "999, 20")
            self.assertEqual(wb["Readme"]["B3"].value, "example.org, another.org")
            self.assertEqual(wb["Interfaces"]["C9"].value, "20")
            wb.close()

    def test_offline_cli_roundtrip_no_ssh_credentials_or_source_changes(self):
        from openpyxl import load_workbook
        original, _, args = self.collect({"show cdp neighbors detail": CDP,
                                         "show ip arp vrf 20": HEADER + arp("10.20.0.2", "aaaa.bbbb.0001")})
        source = next(args.output_dir.glob("*.txt"))
        before = source.read_bytes()
        output = args.output_dir / "offline"
        with patch.object(audit.ssh, "ConnectHandler") as connect, \
             patch.object(audit.ssh, "_prefill_passwords") as passwords, \
             patch.object(audit.ssh, "_load_devices") as inventory, \
             patch("builtins.input") as prompt, redirect_stdout(io.StringIO()):
            status = audit.main(["--from-files", str(source), "--vpn", "20", "--domain", "example.org",
                                 "--out", str(output), "--append", "replay"])
        self.assertEqual(status, 0)
        for mock in (connect, passwords, inventory, prompt):
            mock.assert_not_called()
        self.assertEqual(source.read_bytes(), before)
        self.assertFalse(list(output.glob("*.txt")))
        wb = load_workbook(output / "vpn-audit-replay.xlsx")
        ws = wb["Interfaces"]
        self.assertEqual(ws.max_row, audit.INTERFACES_HEADER_ROW + len(original["interfaces"]))
        self.assertEqual(ws["A9"].value, "actual-router")
        self.assertEqual(ws["B9"].value, "192.0.2.10")
        self.assertEqual(ws["F9"].value, "switch.example.org")
        self.assertEqual(ws["H9"].value, 1)
        self.assertEqual(ws["I9"].value, 1)
        headers = [cell.value for cell in ws[audit.INTERFACES_HEADER_ROW]]
        self.assertEqual(ws.cell(9, headers.index("Source file") + 1).value, str(source.resolve()))
        collection_headers = [cell.value for cell in wb["Collection"][1]]
        status_column = collection_headers.index("Status") + 1
        self.assertNotIn("missing", [row[status_column - 1].value for row in wb["Collection"].iter_rows(min_row=2)])
        wb.close()

    def test_offline_missing_arp_is_not_zero(self):
        _, _, args = self.collect()
        source = next(args.output_dir.glob("*.txt"))
        text = source.read_text()
        start = text.index("\n################################################ (show ip arp vrf 20)")
        end = text.index("\n################################################", start + 2)
        source.write_text(text[:start] + text[end:])
        device = {"hostname": "snapshot", "connect_host": "", "saved_file": source}
        with patch.object(audit.ssh, "ConnectHandler") as connect, redirect_stdout(io.StringIO()):
            result = audit.audit_device(device, args)
        connect.assert_not_called()
        self.assertIsNone(result["interfaces"][0]["ARP IP count"])
        self.assertEqual(result["interfaces"][0]["Row color"], "Amber")
        self.assertIn("missing", result["interfaces"][0]["Collection errors"])

    def test_offline_legacy_blocks_aliases_and_no_invented_address(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "router_pre-status.txt"
            source.write_text("################################################ version (sh version)\nCisco IOS XE Software, Version 17.15.06\nrouter uptime is 1 day\n"
                              "################################################ (sh ip arp vrf 20)\n" + HEADER + arp("10.20.0.2", "aaaa.bbbb.0001", "Gi0/0/1.20"))
            collector = audit.SavedCollector(source)
            self.assertEqual(collector.ssh_address, "")
            result, entries = collector.get("arp", audit.parse_arp, "20")
            self.assertEqual(result.status, "success_with_entries")
            self.assertEqual(result.timestamp, "")
            self.assertEqual(entries[0]["Logical interface"], "GigabitEthernet0/0/1.20")
            self.assertEqual(collector.get("version", lambda text: text)[0].status, "success_with_entries")

    def test_offline_saved_failure_and_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "router.txt"
            source.write_text("################################################ (show arp vrf 20)\n" + HEADER +
                              "################################################ (show lldp neighbors detail)\nTimestamp UTC: 2026-11-23T12:00:00+00:00\nStatus: failed\n\nERROR: timed out\n")
            collector = audit.SavedCollector(source)
            result, entries = collector.get("arp", audit.parse_arp, "20", "arp_fallback")
            self.assertEqual(result.status, "success_empty")
            self.assertEqual(entries, [])
            self.assertEqual(collector.results[0].status, "missing")
            failed, entries = collector.get("lldp", lambda text: audit.parse_neighbors(text, "LLDP"))
            self.assertEqual(failed.status, "failed")
            self.assertEqual(failed.error, "timed out")
            self.assertIsNone(entries)

    def test_offline_does_not_mix_vrf_scopes(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "router.txt"
            source.write_text("################################################ (show interfaces Gi0/0/1)\nVRF: 30\nStatus: success_with_entries\nGigabitEthernet0/0/1 is up, line protocol is up\n")
            collector = audit.SavedCollector(source)
            collector.vrf = "20"
            self.assertEqual(collector.run("interface", "GigabitEthernet0/0/1").status, "missing")
            collector.vrf = "30"
            self.assertEqual(collector.get("interface", audit.parse_interface, "GigabitEthernet0/0/1")[0].status, "success_with_entries")

    def test_offline_paths_and_unknown_file_format(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "router.txt"
            source.write_text("unmarked command output")
            self.assertEqual(len(audit.saved_targets([folder, str(source), str(Path(folder) / "*.txt")])), 1)
            with self.assertRaises(ValueError):
                audit.SavedCollector(source)
            with self.assertRaises(ValueError):
                audit.saved_targets([str(Path(folder) / "missing*.txt")])

    def test_offline_multiple_vrf_roundtrip(self):
        original, _, args = self.collect({"show ip arp vrf 20": HEADER + arp("10.20.0.2", "aaaa.bbbb.0001"),
                                         "show ip arp vrf 30": HEADER + arp("10.30.0.2", "aaaa.bbbb.0002", "Gi0/0/2.30")},
                                        arg_extra={"vpn": [20, 30]})
        source = next(args.output_dir.glob("*.txt"))
        with patch.object(audit.ssh, "ConnectHandler") as connect, redirect_stdout(io.StringIO()):
            replay = audit.audit_device({"hostname": source.stem, "connect_host": "", "saved_file": source}, args)
        connect.assert_not_called()
        def findings(report):
            return {(row["VRF"], row["Logical interface"]):
                    (row["ARP IP count"], row["Unique MAC count"], row["Neighbor"], row["Observed finding"], row["Row color"])
                    for row in report["interfaces"]}
        self.assertEqual(findings(replay), findings(original))

    def test_offline_bad_file_does_not_block_good_snapshot(self):
        from openpyxl import load_workbook
        _, _, args = self.collect()
        (args.output_dir / "bad.txt").write_text("not a saved command file")
        with patch.object(audit.ssh, "ConnectHandler") as connect, redirect_stdout(io.StringIO()):
            status = audit.main(["--from-files", str(args.output_dir), "--vpn", "20", "--domain", "example.org",
                                 "--out", str(args.output_dir / "report"), "--append", "mixed"])
        self.assertEqual(status, 1)
        connect.assert_not_called()
        wb = load_workbook(args.output_dir / "report" / "vpn-audit-mixed.xlsx")
        self.assertEqual(wb["Interfaces"].max_row, audit.INTERFACES_HEADER_ROW + 2)
        headers = [cell.value for cell in wb["Collection"][1]]
        source_index = headers.index("Source file")
        status_index = headers.index("Status")
        self.assertTrue(any(str(row[source_index].value).endswith("bad.txt") and row[status_index].value == "failed"
                            for row in wb["Collection"].iter_rows(min_row=2)))
        wb.close()

    def test_command_manifest_never_connects_or_prompts(self):
        with patch.object(audit.ssh, "ConnectHandler") as connect, patch("builtins.input") as prompt, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(audit.main(["--list-commands"]), 0)
        connect.assert_not_called()
        prompt.assert_not_called()
        self.assertIn("show ip arp vrf <VRF>", out.getvalue())

    def test_excel_values_colors_and_untrusted_text(self):
        from openpyxl import load_workbook
        result, _, args = self.collect({"show cdp neighbors detail": CDP})
        result["neighbors"][0]["Neighbor name"] = "=1+1"
        result["collection"].append({"Status": "failed", "Collection errors": "Example failed command"})
        path = args.output_dir / "report.xlsx"
        audit.write_workbook(path, [result], args)
        wb = load_workbook(path)
        self.addCleanup(wb.close)
        self.assertEqual(wb.sheetnames, ["Interfaces", "ARP Details", "Neighbors", "Collection", "Command Manifest", "Readme"])
        for sheet in ("Interfaces", "ARP Details", "Neighbors", "Collection"):
            header_row = audit.INTERFACES_HEADER_ROW if sheet == "Interfaces" else 1
            self.assertNotIn("VPN", [cell.value for cell in wb[sheet][header_row]])
            self.assertIn("VRF", [cell.value for cell in wb[sheet][header_row]])
        self.assertEqual(wb["Interfaces"]["H9"].value, 0)
        self.assertEqual(wb["Interfaces"]["H9"].data_type, "n")
        self.assertEqual(wb["Interfaces"]["F8"].value, "Neighbor")
        self.assertEqual(wb["Interfaces"]["H8"].value, "ARP IP count")
        self.assertEqual(wb["Interfaces"]["G8"].value, "Observed finding")
        self.assertEqual(wb["Interfaces"]["F9"].value, "switch.example.org")
        self.assertEqual(wb["Interfaces"]["G9"].value, "Our domain")
        self.assertEqual(wb["Interfaces"]["I8"].value, "Unique MAC count")
        self.assertEqual(wb["Interfaces"]["I9"].value, 0)
        self.assertEqual(wb["Interfaces"]["I9"].number_format, "#,##0")
        self.assertEqual(wb["Interfaces"]["A9"].fill.fgColor.rgb, "00C6EFCE")
        self.assertEqual(wb["Neighbors"]["H2"].value, "=1+1")
        self.assertEqual(wb["Neighbors"]["H2"].data_type, "s")
        self.assertEqual(wb["Interfaces"].freeze_panes, "F9")
        self.assertEqual(wb["Interfaces"].auto_filter.ref, "A8:Q10")
        self.assertEqual(wb["Interfaces"]["A1"].value, "Color meaning")
        for row, color in enumerate(("Green", "Red", "Neutral", "Amber"), 2):
            self.assertEqual(wb["Interfaces"].cell(row, 1).fill.fgColor.rgb, "00" + audit.COLORS[color])
        self.assertIn("2+", wb["Interfaces"]["B3"].value)
        self.assertIn("0–1", wb["Interfaces"]["B4"].value)
        self.assertEqual(wb["Command Manifest"].max_row, len(audit.COMMANDS) + 1)
        self.assertEqual(wb["Collection"].cell(wb["Collection"].max_row, 1).fill.fgColor.rgb, "00FFEB9C")


if __name__ == "__main__":
    unittest.main()
